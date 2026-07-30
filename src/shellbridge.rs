//! shellbridge — the session/hook state bridge (concepts/shellbridge).
//!
//! Registers agent sessions + window addresses and records Claude Code hook
//! phases, publishing them to `song/stage/` for Quickshell to read. Writes are
//! atomic (write-temp-then-rename) so a hot-reload never sees a torn file
//! (CONTRACTS.md §4 discipline).
//!
//! The process seeds the stage files (atomic writer), then binds its unix
//! socket and serves newline-delimited JSON commands: a widget click sends
//! `{ "cmd": "focuswindow", "address": "0x…" }` and shellbridge dispatches the
//! Hyprland focus (the Terminal-Commander session-jump flow). The accept loop
//! is robust: a malformed line, an unknown command, or a dropped connection is
//! logged and skipped — nothing ever kills the service.

use crate::daemon;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
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

/// The song tree root (`~/Aoide/song/`) — the parent of the stage dir.
///
/// The stage tree is `<song>/stage`; committed songs live under
/// `<song>/songbook/<name>/` and cover art in the shared library
/// `<song>/covers/` (CONTRACTS.md §1, §4). Deriving this from
/// [`stage_dir`] rather than recomputing keeps the whole song tree coherent
/// under an `AOIDE_STAGE_DIR` override: a test points that at `<tmp>/stage` and
/// the songbook resolves under `<tmp>/` alongside it. Every `rice`/`song`
/// reader routes here.
pub fn song_dir() -> PathBuf {
    let stage = stage_dir();
    stage
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or(stage)
}

/// The committed-song notes file: `<song>/songbook/<name>/drachma.json`.
pub fn songbook_notes(name: &str) -> PathBuf {
    song_dir().join("songbook").join(name).join("drachma.json")
}

/// Atomic write-temp-then-rename into a file within a directory.
///
/// The temp is `<stem>.tmp.<pid>`; on success the rename replaces the target and
/// removes the temp in one step. A FAILED rename would strand the temp we just
/// wrote, so we unlink it. And a write INTERRUPTED between create and rename — a
/// SIGKILL, or a power-cut (a stale `graph.tmp.464255` was found on disk) — can
/// never clean up after itself, so every successful write also sweeps sibling
/// temps left by a pid that is no longer alive ([`sweep_stale_temps`]).
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
    let res = std::fs::rename(&tmp, path);
    if res.is_err() {
        // The rename failed; drop the temp we just wrote so a failed write never
        // leaks its own `<stem>.tmp.<pid>`.
        let _ = std::fs::remove_file(&tmp);
    }
    sweep_stale_temps(path);
    res
}

/// Run `f` while holding an exclusive advisory lock on the stage directory,
/// serialising the whole load-modify-write of the shared stage files across
/// every writer (per-hook processes, the ~1 Hz conduct ticks, the window
/// listener, the reaper). [`atomic_write`]'s rename prevents torn *reads*; this
/// prevents lost *updates* when two writers race the same file (two concurrent
/// read-modify-writes would otherwise silently drop each other's fields).
///
/// The lock is a `.stage.lock` file in the stage dir, `flock`ed `LOCK_EX` for
/// the closure's duration. **Not re-entrant** (each call opens its own fd), so a
/// caller must never nest it — wrap a whole mutator once at its top, never an
/// inner helper it calls. Best-effort: if the lock file can't be created or
/// locked we run `f` unlocked rather than block the desktop on a lock hiccup.
pub fn with_stage_lock<T>(f: impl FnOnce() -> T) -> T {
    use std::os::unix::io::AsRawFd;
    let dir = stage_dir();
    let _ = std::fs::create_dir_all(&dir);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(".stage.lock"))
        .ok();
    let held = lock
        .as_ref()
        .map(|f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0)
        .unwrap_or(false);
    let out = f();
    if held {
        if let Some(f) = &lock {
            unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    out
}

/// Does `/proc/<pid>` still exist? (the liveness probe [`sweep_stale_temps`] uses
/// to tell an interrupted writer's stranded temp from a live peer's in-flight one).
fn pid_is_alive(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

/// Remove leaked atomic-write temporaries for `path`: siblings named
/// `<stem>.tmp.<pid>` whose `<pid>` is no longer a live process. An atomic write
/// interrupted between create and rename (SIGKILL / power-loss) can never unlink
/// its own temp — a stale `graph.tmp.464255` sat on disk from a prior day — so the
/// next successful writer of the SAME file sweeps it. Best-effort and total: any
/// read/parse/remove miss is ignored, and our OWN in-flight temp (live pid) plus
/// every other file are left untouched, so a concurrent peer's write is safe.
fn sweep_stale_temps(path: &std::path::Path) {
    let Some(dir) = path.parent() else {
        return;
    };
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return;
    };
    let prefix = format!("{stem}.tmp.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(pid_str) = name.strip_prefix(&prefix) else {
            continue;
        };
        // Only a well-formed `<stem>.tmp.<pid>` whose pid is dead is swept; our
        // own in-flight temp (same pid) and any non-numeric suffix are spared.
        if let Ok(pid) = pid_str.parse::<u32>() {
            if pid != std::process::id() && !pid_is_alive(pid) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Rename `from` → `to` ONLY if `to` does not already exist — an atomic,
/// no-clobber move. `Ok(true)` renamed; `Ok(false)` the target already existed (a
/// concurrent writer beat us); `Err` any other failure. Linux
/// `renameat2(RENAME_NOREPLACE)` is the atomic primitive [`seed_if_absent`] needs
/// so its file-absent seed can never overwrite a roster that raced in.
fn rename_no_replace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let cfrom = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let cto = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            cfrom.as_ptr(),
            libc::AT_FDCWD,
            cto.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        Ok(false) // target already there — the concurrent registration wins.
    } else {
        Err(err)
    }
}

/// Seed a stage registry ONLY when it is absent or unreadable — a valid existing
/// file (parses as a JSON object carrying the `key` array) is PRESERVED untouched.
///
/// This is the restart-survival seam. shellbridge is `partOf
/// graphical-session.target` (modules/nucleus/shellbridge.nix), which
/// `BindsTo` the Hyprland session — so a nixos switch / compositor restart
/// STOPS+STARTS shellbridge. The old unconditional re-seed wiped every live
/// session to `[]` on each such restart, and a record can only re-register from a
/// NEW `graph session start`, so already-running claude/conduct sessions vanished
/// from the roster/DAG until they happened to re-emit. Preserving a valid file
/// keeps live sessions across the restart window; a missing/half-written/corrupt
/// file still gets the empty v0 shape so the bridge always comes up sane. Returns
/// the written path when it (re)seeded, `None` when it preserved an existing one.
///
/// The file-ABSENT path is race-safe: on a fresh boot a concurrent `graph session
/// start` can land a populated roster BETWEEN our read and our write, so we seed
/// with atomic create-if-absent ([`rename_no_replace`]) — if that roster appeared
/// first the no-replace rename refuses to clobber it and the registration wins.
/// (A corrupt file racing a writer is fine: there is no live roster to lose, and
/// the valid-file path never writes at all, so the restart bug stays closed.)
fn seed_if_absent(path: &std::path::Path, empty_body: &str, key: &str) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(existing) => {
            // A file is present. PRESERVE a valid registry (parses as an object
            // whose `key` is an ARRAY); replace anything else — non-JSON, or
            // JSON of the wrong shape (`"sessions": {}`, or the key missing) —
            // with the empty v0 body. No live roster is at stake here, so the
            // plain atomic write (last-writer-wins) is acceptable.
            let valid = serde_json::from_str::<Value>(&existing)
                .ok()
                .map(|v| v.get(key).map(Value::is_array).unwrap_or(false))
                .unwrap_or(false);
            if valid {
                return None; // a real registry lives here — never clobber it.
            }
            atomic_write(path, empty_body)
                .ok()
                .map(|_| path.to_string_lossy().into_owned())
        }
        Err(_) => {
            // Absent (or unreadable). Seed with create-if-absent so a roster that
            // appeared mid-boot is never overwritten. A distinct `.seed.<pid>`
            // temp keeps it clear of `sweep_stale_temps`'s `.tmp.<pid>` pattern.
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let tmp = path.with_extension(format!("seed.{}", std::process::id()));
            let seeded = (|| -> std::io::Result<bool> {
                {
                    let mut f = std::fs::File::create(&tmp)?;
                    f.write_all(empty_body.as_bytes())?;
                    f.sync_all()?;
                }
                rename_no_replace(&tmp, path)
            })();
            match seeded {
                Ok(true) => Some(path.to_string_lossy().into_owned()),
                // Ok(false) → a concurrent writer won the race; Err → IO failure.
                // Either way drop our temp and leave whatever is in place.
                _ => {
                    let _ = std::fs::remove_file(&tmp);
                    None
                }
            }
        }
    }
}

/// One parsed inbound command from the socket wire (newline-delimited JSON).
/// The wire shape is defined by ShellBridge.qml; the only verb today is the
/// session-jump `focuswindow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeCommand {
    /// `{ "cmd": "focuswindow", "address": "0x…" }` — jump to a window.
    Focus { address: String },
    /// `{ "cmd": "focussession", "sessionId": "…" }` — jump to a SESSION by id.
    /// The daemon resolves id → `windowAddress` (focus the exact window), or
    /// falls back to id → `workspace` (switch to it) when the address isn't
    /// resolved yet. This is the source-of-truth jump: QML sends only the
    /// sessionId a roster row already holds, never a stale/empty address.
    FocusSession { session_id: String },
}

/// Parse ONE wire line into a [`BridgeCommand`]. Pure and total: malformed
/// JSON, a missing/unknown `cmd`, or a `focuswindow` with an empty/absent
/// `address` all yield `None` (the loop logs and ignores them) — never a panic.
pub fn parse_command(line: &str) -> Option<BridgeCommand> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    match v.get("cmd").and_then(Value::as_str)? {
        "focuswindow" => {
            let address = v
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if address.is_empty() {
                return None;
            }
            Some(BridgeCommand::Focus { address })
        }
        "focussession" => {
            let session_id = v
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if session_id.is_empty() {
                return None;
            }
            Some(BridgeCommand::FocusSession { session_id })
        }
        _ => None,
    }
}

/// Run shellbridge: seed the `sessions.json`/`hooks.json` stage files (v0
/// shapes) atomically, then bind the unix socket and serve commands forever.
/// Only a fatal bind failure returns (with an error document dispatch reports);
/// on success this never returns — the systemd unit is `Type=simple` and stays
/// up on the blocking accept loop.
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

    // Seed each registry ONLY when absent/corrupt — a populated roster is
    // preserved across this restart (see [`seed_if_absent`]). The unconditional
    // re-seed this replaced was the transient-drop bug: every shellbridge restart
    // (a nixos switch / compositor restart cascades through
    // graphical-session.target) wiped all live sessions to `[]`.
    let mut wrote: Vec<String> = Vec::new();
    let s_path = stage.join("sessions.json");
    let h_path = stage.join("hooks.json");
    if let Some(p) =
        seed_if_absent(&s_path, &serde_json::to_string_pretty(&sessions).unwrap(), "sessions")
    {
        wrote.push(p);
    }
    if let Some(p) =
        seed_if_absent(&h_path, &serde_json::to_string_pretty(&hooks).unwrap(), "hooks")
    {
        wrote.push(p);
    }

    // Bind the socket. `RuntimeDirectory=aoide` on the unit creates the parent
    // dir; a stale socket from an unclean shutdown would make bind fail with
    // EADDRINUSE, so remove it first (the path is single-owner per user).
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            let _ = daemon::audit(
                &daemon::default_audit_log(),
                daemon::Door::Daemon,
                daemon::EventClass::Audit,
                "shellbridge",
                "bind-failed",
                &format!("could not bind {}: {e}", sock.display()),
            );
            return json!({
                "process": "shellbridge",
                "state": "error",
                "error": format!("bind {}: {e}", sock.display()),
                "socket": sock.to_string_lossy(),
                "stageDir": stage.to_string_lossy(),
                "wrote": wrote,
            });
        }
    };

    let _ = daemon::audit(
        &daemon::default_audit_log(),
        daemon::Door::Daemon,
        daemon::EventClass::Audit,
        "shellbridge",
        "started",
        &format!("shellbridge online; listening on {}", sock.display()),
    );

    // Spawn the Hyprland window→session event listener on a background thread:
    // it is the AUTHORITATIVE, creation-time source of each session's
    // `windowAddress` (concepts/Terminal-Commander), keeping the widget's
    // click-to-jump reliable instead of depending on the lazy hook-time backfill.
    // It runs concurrently with — and can never block or kill — the accept loop,
    // and degrades to a no-op off-Hyprland (logs once, returns).
    std::thread::spawn(crate::graph::run_hypr_window_listener);

    // Serve forever. `serve` never returns and never panics on client input.
    serve(&listener);

    // Only reached if `incoming()` ends (listener closed) — treat as a clean
    // stop so systemd's `Restart=on-failure` can bring us back.
    json!({
        "process": "shellbridge",
        "state": "stopped",
        "socket": sock.to_string_lossy(),
        "stageDir": stage.to_string_lossy(),
        "wrote": wrote,
    })
}

/// The accept loop: one connection at a time (commands are rare). A failed
/// `accept()` is logged and the loop continues — a transient accept error must
/// never end the service.
fn serve(listener: &UnixListener) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => handle_conn(stream),
            Err(e) => eprintln!("[aoide/shellbridge] accept error (continuing): {e}"),
        }
    }
}

/// Handle ONE client connection: read newline-delimited JSON lines and act on
/// each. Every failure is contained — a read error (dropped connection) ends
/// only THIS connection, an unparseable/unknown line is logged and skipped, and
/// a focus dispatch failure is logged. Nothing here can unwind into `serve`.
fn handle_conn(stream: UnixStream) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            // Dropped connection / read error: done with this connection only.
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        match parse_command(&line) {
            Some(BridgeCommand::Focus { address }) => match crate::graph::focus_window(&address) {
                Ok(()) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "focus",
                        &format!("focused window {address}"),
                    );
                }
                Err(e) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "focus-failed",
                        &format!("{} ({}): {}", address, e.reason, e.message),
                    );
                }
            },
            Some(BridgeCommand::FocusSession { session_id }) => {
                match crate::graph::focus_session(&session_id) {
                    Ok(()) => {
                        let _ = daemon::audit(
                            &daemon::default_audit_log(),
                            daemon::Door::Daemon,
                            daemon::EventClass::Audit,
                            "shellbridge",
                            "focus",
                            &format!("focused session {session_id}"),
                        );
                    }
                    Err(e) => {
                        let _ = daemon::audit(
                            &daemon::default_audit_log(),
                            daemon::Door::Daemon,
                            daemon::EventClass::Audit,
                            "shellbridge",
                            "focus-failed",
                            &format!("session {} ({}): {}", session_id, e.reason, e.message),
                        );
                    }
                }
            }
            None => eprintln!("[aoide/shellbridge] ignoring unknown/malformed command: {line}"),
        }
    }
}

// ── Tests (the AOIDE_STAGE_DIR precedence seam; CONTRACTS.md §4) ─────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_accepts_a_valid_focuswindow() {
        assert_eq!(
            parse_command(r#"{"cmd":"focuswindow","address":"0x55aabb"}"#),
            Some(BridgeCommand::Focus {
                address: "0x55aabb".to_string()
            })
        );
        // Trailing newline / surrounding whitespace is tolerated (wire lines
        // arrive newline-terminated) and the address is trimmed.
        assert_eq!(
            parse_command("  {\"cmd\":\"focuswindow\",\"address\":\" 0xABC \"}\n"),
            Some(BridgeCommand::Focus {
                address: "0xABC".to_string()
            })
        );
    }

    #[test]
    fn parse_command_accepts_a_valid_focussession() {
        assert_eq!(
            parse_command(r#"{"cmd":"focussession","sessionId":"conduct-1-2"}"#),
            Some(BridgeCommand::FocusSession {
                session_id: "conduct-1-2".to_string()
            })
        );
        // Trimmed like focuswindow's address.
        assert_eq!(
            parse_command("{\"cmd\":\"focussession\",\"sessionId\":\" abc \"}\n"),
            Some(BridgeCommand::FocusSession {
                session_id: "abc".to_string()
            })
        );
        // Empty/absent sessionId → None (never dispatch a blank session jump).
        assert_eq!(parse_command(r#"{"cmd":"focussession","sessionId":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focussession"}"#), None);
    }

    #[test]
    fn parse_command_rejects_bad_or_empty_input() {
        // Empty / absent address → None (never dispatch a blank focus).
        assert_eq!(parse_command(r#"{"cmd":"focuswindow","address":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focuswindow","address":"   "}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focuswindow"}"#), None);
        // Unknown verb → None.
        assert_eq!(parse_command(r#"{"cmd":"explode","address":"0x1"}"#), None);
        // Missing cmd → None.
        assert_eq!(parse_command(r#"{"address":"0x1"}"#), None);
        // Malformed / non-object JSON → None (the loop logs + ignores).
        assert_eq!(parse_command("not json at all"), None);
        assert_eq!(parse_command("{ broken"), None);
        assert_eq!(parse_command(""), None);
        assert_eq!(parse_command("[1,2,3]"), None);
    }

    #[test]
    fn stage_dir_honors_absolute_env_override() {
        // `stage_dir()` reads process-global env; the crate-wide lock serialises
        // this against every other env-touching test.
        let _guard = crate::env_lock().lock().unwrap();
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

    #[test]
    fn song_tree_resolves_under_the_stage_override() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();

        // Point the stage at `<tmp>/stage`; the song tree is its parent, so
        // the songbook resolves as a sibling of `stage/`.
        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-song-test/stage");
        assert_eq!(song_dir(), PathBuf::from("/tmp/aoide-song-test"));
        assert_eq!(
            songbook_notes("moonlight"),
            PathBuf::from("/tmp/aoide-song-test/songbook/moonlight/drachma.json")
        );

        // On the default layout the song tree is `~/Aoide/song`.
        std::env::remove_var("AOIDE_STAGE_DIR");
        assert!(song_dir().ends_with("Aoide/song"));
        assert!(songbook_notes("x").ends_with("Aoide/song/songbook/x/drachma.json"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    // ── The restart-survival seam: seed preserves a live roster ──────────────

    #[test]
    fn seed_preserves_a_live_roster_and_replaces_a_corrupt_one() {
        // The transient-drop regression: a shellbridge restart must NOT wipe a
        // populated sessions.json. `seed_if_absent` preserves a valid registry,
        // replaces a corrupt/half-written one with the empty v0 shape, and seeds
        // an absent one.
        let dir = std::env::temp_dir().join(format!("aoide-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("sessions.json");

        let empty_body = r#"{"schemaVersion":"0","sessions":[]}"#;

        // A populated, valid registry survives untouched (the fix).
        let populated = r#"{"schemaVersion":"0","sessions":[{"sessionId":"live"}]}"#;
        std::fs::write(&path, populated).unwrap();
        assert_eq!(
            seed_if_absent(&path, empty_body, "sessions"),
            None,
            "a live roster is preserved across a restart seed"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), populated);

        // A VALID-but-EMPTY roster is a real registry too — preserved, not re-seeded.
        std::fs::write(&path, empty_body).unwrap();
        assert_eq!(
            seed_if_absent(&path, empty_body, "sessions"),
            None,
            "a valid empty roster is preserved (classified present, not corrupt)"
        );

        // JSON-valid but WRONG SHAPE (`sessions` is an object, not an array) is
        // classified corrupt and replaced with the empty v0 shape.
        std::fs::write(&path, r#"{"schemaVersion":"0","sessions":{}}"#).unwrap();
        assert!(seed_if_absent(&path, empty_body, "sessions").is_some());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["sessions"].is_array() && v["sessions"].as_array().unwrap().is_empty());

        // Non-JSON / half-written garbage is likewise replaced.
        std::fs::write(&path, "{ not json at all").unwrap();
        assert!(seed_if_absent(&path, empty_body, "sessions").is_some());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["sessions"].is_array() && v["sessions"].as_array().unwrap().is_empty());

        // An absent file is seeded.
        let fresh = dir.join("hooks.json");
        assert!(seed_if_absent(&fresh, r#"{"schemaVersion":"0","hooks":[]}"#, "hooks").is_some());
        assert!(fresh.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_sweeps_a_leaked_temp_from_a_dead_pid() {
        // A power-cut / SIGKILL between create and rename leaves a stranded
        // `<stem>.tmp.<pid>` (a real `graph.tmp.464255` was found on disk). The
        // next successful write of the same file sweeps a dead pid's temp but
        // spares a live peer's in-flight one.
        let dir = std::env::temp_dir().join(format!("aoide-tmpsweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("graph.json");

        let leaked = dir.join(format!("graph.tmp.{}", u32::MAX)); // pid above pid_max — never alive
        std::fs::write(&leaked, "half-written").unwrap();
        let live_peer = dir.join("graph.tmp.1"); // pid 1 (init) is always alive
        std::fs::write(&live_peer, "in-flight").unwrap();

        atomic_write(&target, "{}").unwrap();

        assert!(!leaked.exists(), "a dead pid's leaked temp is swept on the next write");
        assert!(live_peer.exists(), "a live pid's in-flight temp is left untouched");
        assert!(target.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
