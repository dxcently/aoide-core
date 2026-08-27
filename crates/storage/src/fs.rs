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

/// The CONDUCTING stage directory: `~/Aoide/state/stage/` — sessions.json,
/// hooks.json, projects.json, graph.json, pending.json, herald.json (the
/// broker-owned roster [`crate::inbox`]'s doc calls the "L4 dual-writer
/// surface", mirrored by `server/src/daemon.rs::stage_roster`). Split from
/// [`stage_dir`] (2026-08-27, command-defrag lane S1): those six files are
/// core orchestration state the `aoide`/`aoided` binaries alone read and
/// write, never rice/paint — `song/` is lyra's tree
/// (`docs/architecture/PACKAGE-LAYOUT.md`'s "Two binaries"), so conducting
/// state has no business living under it. `stage_dir` itself is UNCHANGED
/// and keeps meaning exactly what it always has — the rice/paint stage tree
/// (`livery.json`, `mode.json`, and the draft-routing symlink target) — this
/// is a NEW, separate root, not a rename.
///
/// **Precedence mirrors [`stage_dir`] exactly, on purpose:** `$AOIDE_STAGE_DIR`
/// wins when set to an absolute path (every existing test and the systemd
/// unit's env already set this to select the conducting stage tree; keeping
/// it authoritative here means every one of them needs zero changes), else
/// this falls back to [`state_dir`]`/stage` rather than [`stage_dir`]'s own
/// `song/stage` fallback. On a box that has never set `$AOIDE_STAGE_DIR` this
/// is the only path that changes; a test/unit override continues to name one
/// directory for both trees, exactly as before the split.
pub fn conducting_stage_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_STAGE_DIR") {
        let p = std::path::PathBuf::from(&dir);
        if p.is_absolute() {
            return p;
        }
    }
    let dir = state_dir().join("stage");
    MIGRATE_CONDUCTING_STAGE_ONCE.call_once(|| migrate_conducting_stage(&dir));
    dir
}

/// The six core stage-file names [`conducting_stage_dir`] owns — the same
/// roster `server/src/daemon.rs::stage_roster` watches, named here once so
/// [`migrate_conducting_stage`] doesn't hand-copy the list a second place.
const CONDUCTING_STAGE_FILES: &[&str] = &[
    "sessions.json",
    "hooks.json",
    "projects.json",
    "graph.json",
    "pending.json",
    "herald.json",
];

static MIGRATE_CONDUCTING_STAGE_ONCE: std::sync::Once = std::sync::Once::new();

/// One-shot, boot-safe move of the six core stage files from their PRE-split
/// home (`song/stage/`, i.e. [`stage_dir`]'s own resolution) into `new_dir`
/// (`state/stage/`) — the command-defrag lane S1 migration. Runs at most once
/// per process ([`MIGRATE_CONDUCTING_STAGE_ONCE`], driven from
/// [`conducting_stage_dir`]'s fallback branch only — an `$AOIDE_STAGE_DIR`
/// override names the SAME directory for both the old and new resolution, so
/// there is nothing to move and that branch never calls this).
///
/// Idempotent and safe to re-run every boot: a file only moves when it exists
/// at the OLD path and does NOT already exist at the new one — a newer
/// new-path file (a fresh boot that already migrated, or one seeded after the
/// move) is never overwritten. `rename` first (same filesystem, the common
/// case); a cross-filesystem rename falls back to copy-then-remove-source so
/// the move still completes rather than silently no-op-ing.
///
/// **Locking:** not [`with_stage_lock`] — that lock is fixed to `stage_dir()`
/// (see its own doc), and the files this function moves no longer live
/// there. A dedicated `.migrate.lock` in `new_dir`, `flock`ed for the
/// migration's duration, is enough to keep two processes racing this exact
/// function (e.g. `aoided` and a concurrently-invoked `aoide` CLI at the same
/// boot) from double-moving a file; best-effort like [`with_stage_lock`] —
/// an unlockable lock file runs the migration unlocked rather than blocking
/// boot on a lock hiccup. Ordinary CORE writers racing the migration itself
/// (a `graph session start` landing mid-move) are not specially guarded
/// beyond this: at most one host runs this migration, once, at the first
/// stage-path resolution of its lifetime — the same "known limitation,
/// acceptable at boot, not a steady-state hazard" class `peer_store`'s own
/// process-local locks already document.
fn migrate_conducting_stage(new_dir: &std::path::Path) {
    let old_dir = stage_dir();
    if old_dir == new_dir || !old_dir.exists() {
        return;
    }
    if std::fs::create_dir_all(new_dir).is_err() {
        return;
    }

    use std::os::unix::io::AsRawFd;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(new_dir.join(".migrate.lock"))
        .ok();
    let held = lock
        .as_ref()
        .map(|f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0)
        .unwrap_or(false);

    for name in CONDUCTING_STAGE_FILES {
        let src = old_dir.join(name);
        let dst = new_dir.join(name);
        if !src.exists() || dst.exists() {
            continue;
        }
        if std::fs::rename(&src, &dst).is_err() && std::fs::copy(&src, &dst).is_ok() {
            let _ = std::fs::remove_file(&src);
        }
    }

    if held {
        if let Some(f) = &lock {
            unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Screen-capture artifacts: `~/Aoide/state/captures/` (`aoide screen shot`,
/// PACKAGE-LAYOUT.md Phase-1 `screen` command family).
///
/// Under [`state_dir`], not [`stage_dir`]: a capture is a DURABLE artifact a
/// caller asked for and keeps around (like `state/usage.json`,
/// `state/peers.json`) — never song-scoped, never reset by a `rice
/// mode`/stage-reseed the way live rehearsal state is. One-line rationale:
/// lean state, not stage — captures persist, stage doesn't.
pub fn captures_dir() -> std::path::PathBuf {
    state_dir().join("captures")
}

/// Headless-conduct transcripts: `~/Aoide/state/sessions/` (one
/// `<sessionId>.log` per headless `aoide conduct` session — the pty-master
/// mirror `logPath` on the session record points into).
///
/// Under [`state_dir`], not [`stage_dir`] — same reasoning as
/// [`captures_dir`]: a session's transcript is a durable artifact that
/// outlives one invocation, never song-scoped, never reset by a `rice
/// mode`/stage-reseed the way live rehearsal state is.
pub fn session_logs_dir() -> std::path::PathBuf {
    state_dir().join("sessions")
}

/// Saved pointer position: `~/Aoide/state/pointer-pos.json` (`aoide screen
/// point save`/`restore`, Phase 2 of the `screen` command family).
///
/// Under [`state_dir`], not [`stage_dir`] — same reasoning as
/// [`captures_dir`]: a saved cursor position is durable operator-convenience
/// state that outlives one invocation (the entire point of `save` in one
/// process and `restore` in a later one), never song-scoped, never reset by
/// a rice-mode/stage reseed. A single flat file, not a directory like
/// captures — there is only ever one "current" saved position, never a
/// history of them.
pub fn pointer_state_file() -> std::path::PathBuf {
    state_dir().join("pointer-pos.json")
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

/// The live-deployed QML tree the desktop shell reads from: `<Aoide>/run/qml/`
/// — a sibling of the song tree ([`song_dir`]), NOT under `stage/`.
///
/// Mirrors [`song_dir`]'s own derivation exactly: `song_dir` takes
/// [`stage_dir`]'s parent to reach the song tree root; this takes
/// `song_dir`'s parent (the `Aoide` root that `song/`, `state/`, and now
/// `run/` all sit under) and joins `run/qml`. So an `$AOIDE_STAGE_DIR`
/// override still relocates this seam — it rides the same env var, one
/// level further up — without a separate `$AOIDE_RUN_DIR`. Not yet used by
/// any Phase A caller (a later phase's widget-carry write path is the first
/// consumer); the helper + its precedence test land now so the seam exists
/// before anything depends on it.
pub fn run_qml_dir() -> std::path::PathBuf {
    let song = song_dir();
    song.parent()
        .map(|root| root.join("run").join("qml"))
        .unwrap_or_else(|| song.join("run").join("qml"))
}

/// The Aoide repo root: `~/Aoide` — the same root [`run_qml_dir`] takes as
/// `song/`'s sibling, one level up from where [`song_dir`] resolves.
///
/// Mirrors [`run_qml_dir`]'s own derivation exactly (`song_dir().parent()`),
/// so an `$AOIDE_STAGE_DIR` override relocates this too — `aoide soundcheck`
/// (`aoide-upkeep`, the mechanical-integrity command) scans the WORKING tree
/// starting here, and a test pointing the stage dir at a scratch tree gets an
/// isolated fake repo root alongside it for free, same as every other seam in
/// this file. Consequence, flagged once: `soundcheck` always inspects the ONE
/// `~/Aoide` checkout this env resolves to, never an arbitrary cwd — there is
/// no `--root` flag.
pub fn repo_root() -> std::path::PathBuf {
    let song = song_dir();
    song.parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or(song)
}

/// The Aoide FLAKE root: the git checkout `nix eval` shells out against
/// (`crate::widgets`'s songbook manifest/registry regeneration, C4/W3).
///
/// Deliberately NOT derived from [`stage_dir`]/[`repo_root`] the way every
/// other path in this file is: those are relocatable per-test so a scratch
/// tmp dir can stand in for `~/Aoide`'s RUNTIME trees (`song/stage`,
/// `run/qml`) without a real flake anywhere in sight. The committed
/// songbook `nix eval` reads (`song/songbook/`, `lib/song.nix`,
/// `flake.nix`) is not a runtime tree — it is the one git checkout on disk,
/// so relocating it per-test would mean fabricating a working flake (with
/// its own `flake.lock`) in every test that touches `rice stage`, for no
/// reason: on the DEFAULT layout `flake_root` and `repo_root` already
/// coincide (both resolve to `~/Aoide`), so this only diverges from
/// `repo_root` under an `$AOIDE_STAGE_DIR` test override — exactly the case
/// where a real flake should NOT be expected to exist at the relocated
/// path. `$AOIDE_FLAKE_ROOT` (absolute-path-wins, same precedence as every
/// other override here) exists for the one caller that DOES want to point
/// at a different flake checkout — a fixture flake, or a second clone.
pub fn flake_root() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_FLAKE_ROOT") {
        let p = std::path::PathBuf::from(&dir);
        if p.is_absolute() {
            return p;
        }
    }
    aoide_protocol::aoide_home().join("Aoide")
}

/// The committed-song directory: `<song>/songbook/<name>/`.
///
/// Shares [`song_dir`]'s `AOIDE_STAGE_DIR`-relative resolution, so a test that
/// points the stage dir at a tmp dir gets an isolated songbook root alongside
/// it (no separate `$AOIDE_SONGBOOK_DIR` needed — one seam, not two).
pub fn songbook_dir(name: &str) -> std::path::PathBuf {
    song_dir().join("songbook").join(name)
}

/// The committed-song notes file: `<song>/songbook/<name>/livery.json`.
pub fn songbook_notes(name: &str) -> std::path::PathBuf {
    songbook_dir(name).join("livery.json")
}

/// A committed song's drafts root: `<song>/songbook/<name>/drafts/` —
/// durable scratch for `rice draft save`, gitignored and outside `stage/` (a
/// draft is NOT the live stage, and NOT committed truth; that distinction is
/// the entire point of the feature). Nested under the song it varies, not a
/// flat top-level dir: a draft is fundamentally a variation of an ALREADY
/// COMPOSED song, so it belongs inside that song's own directory, not a
/// separate global namespace. Shares [`songbook_dir`]'s
/// `AOIDE_STAGE_DIR`-relative resolution.
pub fn song_drafts_dir(song: &str) -> std::path::PathBuf {
    songbook_dir(song).join("drafts")
}

/// One named draft's directory: `<song>/songbook/<name>/drafts/<draft>/` —
/// holds a snapshot of `stage/livery.json` (always) and `stage/cover.json`
/// (when the stage had one) at the moment `rice draft save <draft>` was run.
pub fn draft_dir(song: &str, draft: &str) -> std::path::PathBuf {
    song_drafts_dir(song).join(draft)
}

/// Atomic write-temp-then-rename into a file within a directory —
/// symlink-transparent: if `path` is CURRENTLY a symlink, the temp is
/// renamed into whatever it points at instead, leaving the symlink itself
/// intact.
///
/// POSIX `rename()` replaces whatever directory entry sits at its
/// destination — it does NOT dereference a symlink there and write through
/// it. Without this, the very first write after something pointed `path` at
/// a symlink (rice draft mode's `stage/livery.json` → `songbook/<song>/
/// drafts/<name>/livery.json` routing) would silently REPLACE the symlink
/// with a plain file, breaking the routing after one write. Resolving the
/// link ourselves (`symlink_metadata` to detect it without following,
/// `read_link` to read where it points, resolved against `path`'s parent
/// when the link is relative) and renaming into THAT path instead makes
/// every caller of `atomic_write` symlink-transparent for free — this is
/// general behavior, not draft-specific, since every stage-file writer in
/// the codebase routes through here.
///
/// The temp is `<stem>.tmp.<pid>`; on success the rename replaces the target and
/// removes the temp in one step. A FAILED rename would strand the temp we just
/// wrote, so we unlink it. And a write INTERRUPTED between create and rename — a
/// SIGKILL, or a power-cut (a stale `graph.tmp.464255` was found on disk) — can
/// never clean up after itself, so every successful write also sweeps sibling
/// temps left by a pid that is no longer alive ([`sweep_stale_temps`]).
///
/// Bytes-oriented; [`atomic_write`] is the `&str` convenience wrapper every
/// existing JSON/text caller uses. Binary payloads (a widget QML file carried
/// verbatim into the runtime tree, `crate::widgets`-equivalent callers) route
/// through here directly instead of paying a lossy UTF-8 round-trip.
pub fn atomic_write_bytes(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    atomic_write_bytes_impl(path, contents, None)
}

/// Shared write-temp-then-rename core for [`atomic_write_bytes`] and
/// [`atomic_write_private`]. `create_mode` is `None` for the ordinary
/// (`atomic_write_bytes`) path — the temp is created via `File::create`,
/// whatever mode the process umask leaves it at, matching every existing
/// caller's behavior byte-for-byte — and `Some(0o600)` for the private
/// path, which creates the temp ALREADY locked down via
/// `OpenOptions::mode` (review fix: an earlier revision created the temp at
/// the default mode and `chmod`ed the FINAL path only after the rename,
/// leaving the private seed briefly world/group-readable under this box's
/// 022 umask between the rename landing and the chmod call — see
/// [`atomic_write_private`]'s own doc for the exact defect and why creating
/// the temp pre-locked closes the window instead of narrowing it).
fn atomic_write_bytes_impl(
    path: &std::path::Path,
    contents: &[u8],
    create_mode: Option<u32>,
) -> std::io::Result<()> {
    let target = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let link = std::fs::read_link(path)?;
            if link.is_absolute() {
                link
            } else {
                path.parent().map(|p| p.join(&link)).unwrap_or(link)
            }
        }
        _ => path.to_path_buf(),
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = target.with_extension(format!("tmp.{}", std::process::id()));
    write_temp_file(&tmp, contents, create_mode)?;
    let res = std::fs::rename(&tmp, &target);
    if res.is_err() {
        // The rename failed; drop the temp we just wrote so a failed write never
        // leaks its own `<stem>.tmp.<pid>`.
        let _ = std::fs::remove_file(&tmp);
    }
    sweep_stale_temps(&target);
    res
}

/// Create `tmp` and write `contents` into it, optionally via
/// `OpenOptions::mode(create_mode)` when `create_mode` is `Some` — the ONE
/// place [`atomic_write_bytes_impl`] creates a temp file, factored out so a
/// test can call it directly and inspect the temp's mode BEFORE any rename
/// happens, rather than only observing the final path after the whole
/// write-then-rename round trip completes (see
/// `fs::tests::the_private_temp_is_created_already_0600_before_any_rename`).
/// `create_mode` is `None`'s ordinary case: `File::create`'s default,
/// whatever the process umask leaves it at, matching every existing
/// `atomic_write_bytes` caller's behavior byte-for-byte.
fn write_temp_file(
    tmp: &std::path::Path,
    contents: &[u8],
    create_mode: Option<u32>,
) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    if let Some(mode) = create_mode {
        use std::os::unix::fs::OpenOptionsExt;
        // `open(2)`'s O_CREAT mode is still subject to the process umask,
        // but 0600 carries no group/other bits for a umask to strip in the
        // first place — the temp is created AT 0600, not narrowed to it
        // afterward, so there is no instant where it exists on disk under
        // any wider mode.
        opts.mode(mode);
    }
    let mut f = opts.open(tmp)?;
    f.write_all(contents)?;
    f.sync_all()
}

/// `&str` convenience wrapper over [`atomic_write_bytes`] — every existing
/// JSON/text stage-file writer routes through here.
pub fn atomic_write(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    atomic_write_bytes(path, contents.as_bytes())
}

/// Atomic write of a SENSITIVE file, locked to `0600` (owner rw only) with
/// NO window at any wider mode — this crate's own precedent for private
/// material that must never enter a `Serialize`/`Deserialize` type (the
/// identity keypair's private-key file, `identity.rs`'s own module doc is
/// the first caller), mirroring `aoide-secrets/src/store.rs`'s
/// `save_policies`/`save_totp_secret` discipline: secure the TEMP file
/// BEFORE the rename, never the final path after it. Here that means
/// creating the temp with `OpenOptions::mode(0o600)` set from the very
/// first `open(2)` call (see [`atomic_write_bytes_impl`]'s doc) rather than
/// `File::create`-then-`chmod` — since `rename(2)` preserves the SOURCE
/// file's mode when replacing a destination, the temp already being 0600
/// means the destination is 0600 the instant the rename lands, never
/// briefly world/group-readable under the process umask the way a
/// create-then-chmod-the-final-path ordering would leave it (review fix:
/// an earlier revision of this function did exactly that — wrote the temp
/// at `File::create`'s default mode, renamed onto the live path, and
/// `chmod`ed only afterward, leaving `state/identity/ed25519.key` briefly
/// world/group-readable on a 022-umask box between the rename and the
/// chmod). Every OTHER concern (symlink transparency, stale-temp sweeping,
/// the rename-failure cleanup) is identical to [`atomic_write_bytes`] —
/// both route through the same [`atomic_write_bytes_impl`] core.
pub fn atomic_write_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    atomic_write_bytes_impl(path, contents, Some(0o600))
}

/// Create `dir` (if absent) and lock it down to `0700` (owner rwx only) —
/// the directory-level half of [`atomic_write_private`]'s discipline
/// (review rider: nothing else in this crate secured the DIRECTORY a
/// private file lives in, only the file itself, so a state dir left at
/// `create_dir_all`'s umask-derived default — 0755 under this box's normal
/// 022 — would leave `identity/`'s directory entries world-LISTABLE even
/// with `ed25519.key` itself locked to 0600). Mirrors `aoide-secrets`'s
/// `home::secure_dir` for one directory inside this crate's own state tree
/// rather than that crate's whole secrets home. `create_dir_all` is
/// idempotent on an already-present directory, and so is the chmod that
/// follows it — calling this on every mint (not only the very first one)
/// costs nothing and never regresses a directory some earlier run already
/// locked down.
pub fn secure_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
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
///
/// **Still locks `stage_dir()`'s own lock file, even for [`conducting_stage_dir`]
/// callers (command-defrag S1).** `sessions.json`/`hooks.json`/`projects.json`/
/// `graph.json`/`pending.json`/`herald.json` moved to `state/stage/`, but every
/// mutator of them still calls this exact function unchanged — the SAME
/// precedent [`crate::inbox::receive`] already set for `state/inbox.json`
/// ("one process-wide lock file is enough … a second lock file would be a new
/// abstraction for zero added correctness"). A second `.stage.lock` under
/// `state/stage/` would serialise the six core files against each other
/// without serialising them against `stage_dir()`'s own rice writers sharing
/// this same lock today — no new hazard exists to close, so none was added.
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
            std::path::PathBuf::from("/tmp/aoide-song-test/songbook/moonlight/livery.json")
        );

        // On the default layout the song tree is `~/Aoide/song`.
        std::env::remove_var("AOIDE_STAGE_DIR");
        assert!(song_dir().ends_with("Aoide/song"));
        assert!(songbook_notes("x").ends_with("Aoide/song/songbook/x/livery.json"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn song_drafts_dir_and_draft_dir_nest_under_the_songs_own_songbook_entry() {
        // Mirrors `song_tree_resolves_under_the_stage_override`: a draft nests
        // under ITS song's songbook dir, not a flat top-level `drafts/` —
        // a draft is a variation of an already-composed song.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();

        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-drafts-test/stage");
        assert_eq!(
            song_drafts_dir("sonata"),
            std::path::PathBuf::from("/tmp/aoide-drafts-test/songbook/sonata/drafts")
        );
        assert_eq!(
            draft_dir("sonata", "neon-night"),
            std::path::PathBuf::from("/tmp/aoide-drafts-test/songbook/sonata/drafts/neon-night")
        );

        // On the default layout: `~/Aoide/song/stage` → songbook_dir("x") =
        // `~/Aoide/song/songbook/x` → song_drafts_dir("x") =
        // `~/Aoide/song/songbook/x/drafts`.
        std::env::remove_var("AOIDE_STAGE_DIR");
        assert!(song_drafts_dir("x").ends_with("Aoide/song/songbook/x/drafts"));
        assert!(draft_dir("x", "y").ends_with("Aoide/song/songbook/x/drafts/y"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn run_qml_dir_resolves_as_a_sibling_of_song_under_the_stage_override() {
        // Mirrors `song_tree_resolves_under_the_stage_override` above: the
        // override's tmp root plays the role of the real `~/Aoide/` root, its
        // child the role of `song/`, so `run/qml` lands as THAT root's sibling
        // `run/qml`, one level up from where `song_dir()` resolves.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();

        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-run-qml-test/stage");
        assert_eq!(
            run_qml_dir(),
            std::path::PathBuf::from("/tmp/run/qml"),
            "run/qml is a sibling of song_dir(), not under stage/"
        );

        // On the default layout: `~/Aoide/song/stage` → song_dir() = `~/Aoide/song`
        // → run_qml_dir() = `~/Aoide/run/qml`.
        std::env::remove_var("AOIDE_STAGE_DIR");
        assert!(run_qml_dir().ends_with("Aoide/run/qml"));
        assert!(!run_qml_dir().ends_with("Aoide/song/run/qml"), "not nested under song/");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn repo_root_resolves_as_the_grandparent_of_stage_dir_and_honors_its_override() {
        // Mirrors `run_qml_dir_resolves_as_a_sibling_of_song_under_the_stage_override`:
        // the override's tmp root plays the role of the real `~/Aoide/` root,
        // its child the role of `song/`, so `repo_root()` lands on that root
        // itself — one level up from where `song_dir()` resolves, same as
        // `run_qml_dir`'s own `Aoide` root.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();

        // `song_dir` peels one level (stage → its parent); `repo_root` peels
        // ANOTHER (song_dir → its parent) — so the override needs a `song/`
        // segment between the repo root and `stage` to land on a real root,
        // same shape the default layout itself uses (`<root>/song/stage`).
        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-repo-root-test/song/stage");
        assert_eq!(
            repo_root(),
            std::path::PathBuf::from("/tmp/aoide-repo-root-test"),
            "repo_root is song_dir's parent, not song_dir itself"
        );

        // On the default layout: `~/Aoide/song/stage` → song_dir() = `~/Aoide/song`
        // → repo_root() = `~/Aoide`.
        std::env::remove_var("AOIDE_STAGE_DIR");
        assert!(repo_root().ends_with("Aoide"));
        assert!(!repo_root().ends_with("Aoide/song"), "one level above song_dir, not song_dir itself");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn flake_root_ignores_the_stage_dir_override_and_honors_its_own() {
        // `flake_root` is deliberately NOT `AOIDE_STAGE_DIR`-relative (unlike
        // every other path above) — see its own doc for why: the committed
        // git checkout `nix eval` reads doesn't move just because a test
        // relocated the runtime trees.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_flake = std::env::var("AOIDE_FLAKE_ROOT").ok();

        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-flake-root-test/song/stage");
        std::env::remove_var("AOIDE_FLAKE_ROOT");
        assert!(
            !flake_root().starts_with("/tmp/aoide-flake-root-test"),
            "an AOIDE_STAGE_DIR relocation must not move flake_root: {:?}",
            flake_root()
        );
        assert!(flake_root().ends_with("Aoide"));

        std::env::set_var("AOIDE_FLAKE_ROOT", "/tmp/aoide-flake-root-test/fixture-flake");
        assert_eq!(
            flake_root(),
            std::path::PathBuf::from("/tmp/aoide-flake-root-test/fixture-flake"),
            "an explicit AOIDE_FLAKE_ROOT wins outright"
        );

        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_flake {
            Some(v) => std::env::set_var("AOIDE_FLAKE_ROOT", v),
            None => std::env::remove_var("AOIDE_FLAKE_ROOT"),
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

    // ── atomic_write is symlink-transparent (rice draft mode's routing) ──

    #[test]
    fn atomic_write_writes_through_a_symlink_leaving_the_link_itself_intact() {
        let dir = std::env::temp_dir().join(format!("aoide-atomic-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.json");
        let link = dir.join("link.json");
        std::fs::write(&real, "seed").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        atomic_write(&link, "first").unwrap();
        assert!(
            std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
            "the symlink itself must survive the write, not get replaced by rename()"
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "first", "the LINK TARGET carries the content");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "first", "reading through the link agrees");

        // A second write must keep working the same way — the fix isn't a
        // one-shot "first write creates a real file" side effect.
        atomic_write(&link, "second").unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "second");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_resolves_a_relative_symlink_target() {
        // The exact shape `rice mode draft` creates: stage/livery.json (a
        // relative symlink) → ../../songbook/<song>/drafts/<name>/livery.json.
        let dir = std::env::temp_dir().join(format!("aoide-atomic-symlink-rel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sub = dir.join("drafts").join("neon-night");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(dir.join("stage")).unwrap();
        let real = sub.join("livery.json");
        std::fs::write(&real, "seed").unwrap();
        let link = dir.join("stage").join("livery.json");
        std::os::unix::fs::symlink("../drafts/neon-night/livery.json", &link).unwrap();

        atomic_write(&link, "routed").unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "routed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_bytes_round_trips_binary_content() {
        // The bytes-oriented primitive `atomic_write` now delegates to — a
        // widget QML file (or any non-UTF-8 payload) must round-trip exactly,
        // not just the `&str` callers `atomic_write` itself covers.
        let dir = std::env::temp_dir().join(format!("aoide-atomic-bytes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("binary.dat");

        let bytes: &[u8] = &[0u8, 159, 146, 150];
        atomic_write_bytes(&path, bytes).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_creates_a_plain_file_when_path_is_not_a_symlink() {
        // Regression coverage: the overwhelming common case (no symlink at
        // all) must behave exactly as before this fix.
        let dir = std::env::temp_dir().join(format!("aoide-atomic-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plain.json");

        atomic_write(&path, "content").unwrap();
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "content");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_private_locks_the_file_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aoide-atomic-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.key");

        atomic_write_private(&path, b"private bytes").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "atomic_write_private must lock to 0600, got {mode:o}");
        assert_eq!(std::fs::read(&path).unwrap(), b"private bytes");

        // A second write to the SAME path (the re-mint-never-happens case,
        // but the primitive itself must stay correct either way) is still
        // locked to 0600 afterward.
        atomic_write_private(&path, b"replaced").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"replaced");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_private_temp_is_created_already_0600_before_any_rename() {
        // The review-bounced defect: an earlier revision of
        // `atomic_write_private` created its temp at `File::create`'s
        // umask-derived default mode and `chmod`ed the FINAL path only
        // AFTER the rename, leaving the live private-key path briefly
        // world/group-readable under this box's 022 umask between the
        // rename landing and the chmod call. Calling `write_temp_file`
        // directly — the one place `atomic_write_bytes_impl` ever creates a
        // temp — proves the mode is right at the moment of CREATION, before
        // any rename has happened at all, rather than only checking the
        // final path after the whole write-then-rename round trip returns
        // (which the OLD, buggy code would also have passed, since its
        // chmod ran before returning — the defect was a window DURING the
        // call, not a wrong end state).
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aoide-write-temp-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tmp = dir.join("secret.key.tmp");

        write_temp_file(&tmp, b"private seed bytes", Some(0o600)).unwrap();
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the TEMP file itself must already be 0600 the instant it's created, got {mode:o}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_private_locks_the_final_path_to_0600_under_a_permissive_umask() {
        // Complements the test above: end-to-end through the public
        // `atomic_write_private` entry point, forcing a wide-open umask
        // (000 — even more permissive than this box's normal 022, so a
        // regression to "create at the umask default, chmod after" would
        // show up as a would-be-0666 window rather than a merely-0644 one)
        // to prove the FINAL path is 0600 regardless of what the process
        // umask would otherwise have widened a plain `File::create` to.
        let _g = crate::env_lock().lock().unwrap();
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aoide-atomic-private-umask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.key");

        // SAFETY: umask(2) takes a plain mode_t and cannot fail; restored
        // unconditionally immediately after, under the same env_lock every
        // other process-global-state test in this crate already serializes
        // behind (umask is process-wide, wider even than an env var).
        let old_umask = unsafe { libc::umask(0o000) };
        let result = atomic_write_private(&path, b"private seed bytes");
        unsafe { libc::umask(old_umask) };
        result.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the file at its FINAL path must be 0600 immediately after mint even under an 000 umask, got {mode:o}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn captures_dir_nests_under_state_dir_and_honors_its_override() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();

        std::env::set_var("AOIDE_STATE_DIR", "/tmp/aoide-captures-test/state");
        assert_eq!(
            captures_dir(),
            std::path::PathBuf::from("/tmp/aoide-captures-test/state/captures")
        );

        // On the default layout: `~/Aoide/state` → captures_dir() = `~/Aoide/state/captures`.
        std::env::remove_var("AOIDE_STATE_DIR");
        assert!(captures_dir().ends_with("Aoide/state/captures"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    #[test]
    fn pointer_state_file_nests_under_state_dir_and_honors_its_override() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();

        std::env::set_var("AOIDE_STATE_DIR", "/tmp/aoide-pointer-test/state");
        assert_eq!(
            pointer_state_file(),
            std::path::PathBuf::from("/tmp/aoide-pointer-test/state/pointer-pos.json")
        );

        std::env::remove_var("AOIDE_STATE_DIR");
        assert!(pointer_state_file().ends_with("Aoide/state/pointer-pos.json"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }

    // ── `conducting_stage_dir` / the command-defrag S1 migration ───────────

    const CORE_STAGE_FILE_NAMES: &[&str] =
        &["sessions.json", "hooks.json", "projects.json", "graph.json", "pending.json", "herald.json"];

    /// Save/restore the four env vars every migration test pins, so a test
    /// that panics mid-body still leaves the crate's env in whatever shape
    /// the NEXT test expects (the same discipline every other `AOIDE_*`
    /// override test in this module already holds, widened to the one extra
    /// var — `HOME` — the migration path additionally depends on through
    /// [`stage_dir`]/[`state_dir`]'s own `aoide_protocol::aoide_home`).
    struct MigrationEnvGuard {
        home: Option<String>,
        user: Option<String>,
        stage: Option<String>,
        state: Option<String>,
    }
    impl MigrationEnvGuard {
        fn capture_and_clear() -> Self {
            let g = MigrationEnvGuard {
                home: std::env::var("HOME").ok(),
                user: std::env::var("AOIDE_USER").ok(),
                stage: std::env::var("AOIDE_STAGE_DIR").ok(),
                state: std::env::var("AOIDE_STATE_DIR").ok(),
            };
            std::env::remove_var("AOIDE_USER");
            std::env::remove_var("AOIDE_STAGE_DIR");
            std::env::remove_var("AOIDE_STATE_DIR");
            g
        }
    }
    impl Drop for MigrationEnvGuard {
        fn drop(&mut self) {
            match &self.home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match &self.user {
                Some(v) => std::env::set_var("AOIDE_USER", v),
                None => std::env::remove_var("AOIDE_USER"),
            }
            match &self.stage {
                Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
                None => std::env::remove_var("AOIDE_STAGE_DIR"),
            }
            match &self.state {
                Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
                None => std::env::remove_var("AOIDE_STATE_DIR"),
            }
        }
    }

    #[test]
    fn migrate_conducting_stage_moves_every_core_file_from_old_to_new() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = MigrationEnvGuard::capture_and_clear();
        let home = std::env::temp_dir().join(format!("aoide-migrate-basic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let old_dir = stage_dir(); // `<home>/Aoide/song/stage`, unset-override fallback
        let new_dir = state_dir().join("stage");
        std::fs::create_dir_all(&old_dir).unwrap();
        for name in CORE_STAGE_FILE_NAMES {
            std::fs::write(old_dir.join(name), format!("{{\"marker\":\"{name}\"}}")).unwrap();
        }

        migrate_conducting_stage(&new_dir);

        for name in CORE_STAGE_FILE_NAMES {
            assert!(!old_dir.join(name).exists(), "{name} must have moved off the old path");
            let body = std::fs::read_to_string(new_dir.join(name)).unwrap();
            assert!(body.contains(name), "{name}'s content must have moved verbatim, got {body}");
        }

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn migrate_conducting_stage_second_run_is_a_no_op() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = MigrationEnvGuard::capture_and_clear();
        let home = std::env::temp_dir().join(format!("aoide-migrate-idempotent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let old_dir = stage_dir();
        let new_dir = state_dir().join("stage");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("sessions.json"), "first-boot").unwrap();

        migrate_conducting_stage(&new_dir);
        assert_eq!(std::fs::read_to_string(new_dir.join("sessions.json")).unwrap(), "first-boot");
        assert!(!old_dir.join("sessions.json").exists());

        // Second call: nothing left at the old path, and the new path is
        // already populated — must run cleanly and change nothing.
        migrate_conducting_stage(&new_dir);
        assert_eq!(
            std::fs::read_to_string(new_dir.join("sessions.json")).unwrap(),
            "first-boot",
            "a second migration pass must be a pure no-op"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn migrate_conducting_stage_never_clobbers_a_newer_new_path_file() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = MigrationEnvGuard::capture_and_clear();
        let home = std::env::temp_dir().join(format!("aoide-migrate-no-clobber-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let old_dir = stage_dir();
        let new_dir = state_dir().join("stage");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&new_dir).unwrap();
        // A STALE old-path file (predates the boot that already migrated)
        // alongside a NEWER new-path file (written since) — the newer file
        // must win, and the stale old file is left in place for inspection
        // rather than silently destroyed.
        std::fs::write(old_dir.join("sessions.json"), "stale").unwrap();
        std::fs::write(new_dir.join("sessions.json"), "fresh").unwrap();

        migrate_conducting_stage(&new_dir);

        assert_eq!(std::fs::read_to_string(new_dir.join("sessions.json")).unwrap(), "fresh");
        assert_eq!(std::fs::read_to_string(old_dir.join("sessions.json")).unwrap(), "stale");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn migrate_conducting_stage_leaves_rice_files_where_they_are() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = MigrationEnvGuard::capture_and_clear();
        let home = std::env::temp_dir().join(format!("aoide-migrate-rice-untouched-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let old_dir = stage_dir();
        let new_dir = state_dir().join("stage");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("sessions.json"), "core").unwrap();
        std::fs::write(old_dir.join("livery.json"), "rice-palette").unwrap();
        std::fs::write(old_dir.join("mode.json"), "rice-mode").unwrap();

        migrate_conducting_stage(&new_dir);

        assert!(!old_dir.join("sessions.json").exists(), "the core file must have moved");
        assert_eq!(
            std::fs::read_to_string(old_dir.join("livery.json")).unwrap(),
            "rice-palette",
            "rice files are never part of this migration"
        );
        assert_eq!(std::fs::read_to_string(old_dir.join("mode.json")).unwrap(), "rice-mode");
        assert!(!new_dir.join("livery.json").exists());
        assert!(!new_dir.join("mode.json").exists());

        let _ = std::fs::remove_dir_all(&home);
    }

    /// The one test in this binary that resolves [`conducting_stage_dir`]
    /// itself with no `$AOIDE_STAGE_DIR` override — proving the Once-guarded
    /// wiring end to end, not just [`migrate_conducting_stage`] in isolation.
    /// [`MIGRATE_CONDUCTING_STAGE_ONCE`] fires at most once for the whole
    /// test binary, so this must be the ONLY call site in this module that
    /// reaches [`conducting_stage_dir`]'s fallback branch — every other
    /// migration test above calls [`migrate_conducting_stage`] directly to
    /// stay independent of that one-shot guard.
    #[test]
    fn conducting_stage_dir_resolves_under_state_and_migrates_on_first_call() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = MigrationEnvGuard::capture_and_clear();
        let home = std::env::temp_dir().join(format!("aoide-migrate-wiring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("HOME", &home);

        let old_dir = home.join("Aoide").join("song").join("stage");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("graph.json"), "pre-existing-graph").unwrap();

        let dir = conducting_stage_dir();
        assert!(dir.ends_with("Aoide/state/stage"));
        assert_eq!(
            std::fs::read_to_string(dir.join("graph.json")).unwrap(),
            "pre-existing-graph",
            "conducting_stage_dir()'s own resolution must have driven the migration"
        );

        let _ = std::fs::remove_dir_all(&home);
    }
}
