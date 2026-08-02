//! The stage-file FS substrate: where the stage tree lives, and the atomic
//! write/lock primitives every stage writer routes through.
//!
//! Moved from `shellbridge.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::shellbridge::{stage_dir, atomic_write, …}` caller is
//! untouched. The socket-loop code (`socket_path`, `BridgeCommand`,
//! `parse_command`, `run`) stays in root `shellbridge.rs` — it moves in
//! Phase 3b (conduct extraction).

use std::io::Write;

/// The live-state stage directory: `~/Aoide/song/stage/`.
///
/// **Contract seam (CONTRACTS.md §4):** the systemd unit
/// (`modules/nucleus/shellbridge.nix`) sets `AOIDE_STAGE_DIR=%h/Aoide/song/stage`
/// on the service — that env var wins when set to an absolute path, so the
/// daemon and the CLI door always agree on where the stage tree lives. The
/// fallback below derives the same `~/Aoide/song/stage` from
/// `aoide_protocol::aoide_home()`, so on the default layout the two paths
/// coincide; the override only matters when the unit relocates the stage (or
/// a test/smoke run points elsewhere). A relative or empty value is ignored
/// (we never resolve a runtime path against an arbitrary cwd). Every stage
/// reader/writer routes through here.
pub fn stage_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_STAGE_DIR") {
        let p = std::path::PathBuf::from(&dir);
        if p.is_absolute() {
            return p;
        }
    }
    aoide_protocol::aoide_home()
        .join("Aoide")
        .join("song")
        .join("stage")
}

/// The account/usage runtime state directory: `~/Aoide/state/`.
///
/// A NEW gitignored root-runtime dir (CONTRACTS.md §2), sibling to
/// `song/stage/` but explicitly NOT song-scoped — account/global runtime like
/// `state/usage.json` lives here, never under `song/`. Resolution mirrors
/// [`stage_dir`]: prefer `$AOIDE_STATE_DIR` when set to an **absolute** path,
/// else derive `~/Aoide/state` from `$AOIDE_USER`/`$HOME` via
/// `aoide_protocol::aoide_home`. A relative or empty override is ignored —
/// same discipline as the stage dir, so a runtime path is never resolved
/// against an arbitrary cwd.
pub fn state_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_STATE_DIR") {
        let p = std::path::PathBuf::from(&dir);
        if p.is_absolute() {
            return p;
        }
    }
    aoide_protocol::aoide_home().join("Aoide").join("state")
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
pub fn song_dir() -> std::path::PathBuf {
    let stage = stage_dir();
    stage
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or(stage)
}

/// The committed-song directory: `<song>/songbook/<name>/`.
///
/// Shares [`song_dir`]'s `AOIDE_STAGE_DIR`-relative resolution, so a test that
/// points the stage dir at a tmp dir gets an isolated songbook root alongside
/// it (no separate `$AOIDE_SONGBOOK_DIR` needed — one seam, not two).
pub fn songbook_dir(name: &str) -> std::path::PathBuf {
    song_dir().join("songbook").join(name)
}

/// The committed-song notes file: `<song>/songbook/<name>/drachma.json`.
pub fn songbook_notes(name: &str) -> std::path::PathBuf {
    songbook_dir(name).join("drachma.json")
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
///
/// `pub`, not private: root `shellbridge::run()` (the socket-loop code that
/// stays in root through Phase 3b) is this function's only caller outside this
/// crate, so it must cross the crate boundary.
pub fn seed_if_absent(path: &std::path::Path, empty_body: &str, key: &str) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(existing) => {
            // A file is present. PRESERVE a valid registry (parses as an object
            // whose `key` is an ARRAY); replace anything else — non-JSON, or
            // JSON of the wrong shape (`"sessions": {}`, or the key missing) —
            // with the empty v0 body. No live roster is at stake here, so the
            // plain atomic write (last-writer-wins) is acceptable.
            let valid = serde_json::from_str::<serde_json::Value>(&existing)
                .ok()
                .map(|v| {
                    v.get(key)
                        .map(serde_json::Value::is_array)
                        .unwrap_or(false)
                })
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

// ── Tests (the AOIDE_STAGE_DIR precedence seam; CONTRACTS.md §4) ─────────────
//
// Moved from `shellbridge.rs` alongside the functions above (Phase 3a
// restructure) — these exercise `stage_dir`/`song_dir`/`songbook_notes`/
// `seed_if_absent`/`atomic_write`, all now defined only here (some, like
// `seed_if_absent`, are private helpers of `run()`'s callers elsewhere, so
// their tests can't stay behind a root-side re-export).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_dir_honors_absolute_env_override() {
        // `stage_dir()` reads process-global env; the crate-wide lock serialises
        // this against every other env-touching test.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();

        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-test-stage");
        assert_eq!(stage_dir(), std::path::PathBuf::from("/tmp/aoide-test-stage"));

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
        assert_eq!(song_dir(), std::path::PathBuf::from("/tmp/aoide-song-test"));
        assert_eq!(
            songbook_notes("moonlight"),
            std::path::PathBuf::from("/tmp/aoide-song-test/songbook/moonlight/drachma.json")
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
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(v["sessions"].is_array() && v["sessions"].as_array().unwrap().is_empty());

        // Non-JSON / half-written garbage is likewise replaced.
        std::fs::write(&path, "{ not json at all").unwrap();
        assert!(seed_if_absent(&path, empty_body, "sessions").is_some());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
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
