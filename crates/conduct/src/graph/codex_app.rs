//! Desktop Codex/ChatGPT task association — the pure core of the P-CX design
//! (`docs/architecture/CODEX-INTEGRATION.md`). One `SessionRecord` per NATIVE
//! Codex thread, keyed by the thread's own id verbatim — never a synthetic
//! prefix, never an aoide-minted id, unlike
//! [`super::window::reconcile_untracked_terminals`]'s `win:<addr>` records:
//! a window address is not a stable id on its own, but a Codex thread id
//! already is one.
//!
//! Holds the pure reconciler ([`reconcile_codex_app_threads`]) and its input
//! shape ([`CodexThread`]) — P-CX-1 — plus P-CX-2's discovery primitives:
//! [`codex_home`] (the one authority for `$CODEX_HOME`/`$HOME/.codex`,
//! also called from `reap.rs::refresh_codex_titles`), a try-flock liveness
//! probe over `~/.codex/thread-writer-locks/*.lock`
//! ([`lock_is_held`], never `/proc`), and ownership resolution from ONE
//! parsed `ps -axo pid=,ppid=,command=` table keyed on the app-server argv
//! ([`codex_app_servers`], [`lock_holder`]) — the same primitives on every
//! OS, with exactly one `cfg(target_os = "linux")` extra
//! ([`holder_via_proc_fd`]): an app-server owns a lock only when its own
//! `/proc/<pid>/fd` table holds it — the sole evidence, for one server or
//! many, never a shortcut and never a tie-break reserved for the
//! multi-server case.
//!
//! Every gather of the live thread set produces a [`ThreadScan`]:
//! `Observed` carries positive evidence for EVERY lock in the directory —
//! including an empty vec, which means every lock was proven released, not
//! merely unexamined — while `Unknown` means the scan could not complete
//! and says nothing about any thread. [`reconcile_codex_app_threads`] acts
//! on `Observed` alone; an `Unknown` scan changes no record, because a
//! failed or incomplete observation is not the same fact as a confirmed
//! thread exit (Codex ruling seq 211). Only a positively observed, empty
//! thread set ever removes an existing `kind:"app"` record.
//!
//! [`codex_app_threads`] assembles the live set and [`sync_codex_app_threads`]
//! is the I/O wrapper over [`reconcile_codex_app_threads`], called from
//! `window.rs`'s own reap tick. The taught transport/lifecycle refusals
//! (`send`, `session kill`) are a later slice (P-CX-3).
//!
//! `sync_codex_app_threads` also merges each live thread's own
//! [`super::codex_capture::capture_for`] onto its `"app"` record (P-CX-5 S2):
//! `say`/`tool`/`activity`/`model`/`context_tokens`/`context_ceiling`/
//! `sources`, set only when the capture produced a value and only when it
//! actually differs — the same "never clear, only set" discipline
//! `session_store.rs`'s `refresh_transcript_fields` already holds for the
//! very same fields. `sources` keys remap from `CodexCapture`'s own
//! snake_case field names to `SessionRecord`'s wire camelCase
//! (`context_tokens` → `contextTokens`, etc. — [`MERGED_SOURCE_FIELDS`]),
//! and only ever carry an entry for a field this merge actually applies:
//! `state`, `parentSessionId`, `title`, and `nickname` stay untouched by
//! this merge (a later slice's own territory — S3, S4), and their pointers
//! in `cap.sources` are never copied either. See [`apply_codex_capture`].

use super::codex_capture::{capture_for, CodexCapture};
use super::doc::restage_graph;
use super::model::{
    load_stage, sessions_path, write_stage, SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One live Codex thread, already resolved to its writer-lock holder — the
/// pure-core input for [`reconcile_codex_app_threads`], so the reconciliation
/// is testable without touching `~/.codex` or `/proc` (that I/O belongs to
/// the eventual `sync_codex_app_threads` wrapper).
#[derive(Debug, Clone)]
pub(crate) struct CodexThread {
    /// The native Codex thread id, verbatim (`session_index.jsonl`'s `id`,
    /// the lock filename, the rollout's `session_meta.id`) — becomes
    /// `sessionId` unchanged, so the reaper's `apply_codex_titles`
    /// (`reap.rs:1289`) names the card for free with zero change to the
    /// title invariant.
    pub id: String,
    /// The thread's cwd, read once from its rollout header
    /// (`session_meta.payload.cwd`) at enrolment — never re-read per tick.
    pub cwd: String,
    /// The pid of the `app-server` process PROVEN (`holder_via_proc_fd`'s
    /// own fd table holds this exact lock) to own this thread's writer
    /// lock. A `CodexThread` exists at all only for a lock with such a
    /// proven owner — [`codex_app_threads_with`]'s assembly loop never
    /// constructs one otherwise, so this field is never optional. Feeds
    /// exactly two things downstream: the existing window sweep's
    /// pid-ancestry walk, and the reaper's pid-DEATH signal — NEVER proof
    /// of life either way. A shared app-server pid backs every thread it
    /// holds a lock for, so the staleness arm must stay closed to it
    /// regardless of this pid's liveness (that's what `kind:"app"` buys,
    /// below).
    pub pid: u32,
}

/// One gather of the desktop-thread set — the seam that keeps a FAILED or
/// INCOMPLETE observation from ever reading as a CONFIRMED thread exit
/// (Codex ruling seq 211). `Observed` carries positive evidence for every
/// lock in the directory — an empty vec means every lock was proven
/// released, not merely unexamined. `Unknown` means the scan could not
/// complete and says nothing about any thread; see [`ScanFailure`] for
/// which step gave up. [`reconcile_codex_app_threads`] acts on `Observed`
/// alone.
#[derive(Debug)]
pub(crate) enum ThreadScan {
    Observed(Vec<CodexThread>),
    Unknown(ScanFailure),
}

/// Why a [`ThreadScan`] came back `Unknown` — which step of
/// [`codex_app_threads`]'s gather could not complete. Every variant is a
/// genuine "don't know," never a stand-in for "no."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFailure {
    /// `thread-writer-locks` exists but [`live_thread_locks`] could not read
    /// it (permissions, an I/O error). A MISSING directory is
    /// `Observed(empty)` instead — see that function's own doc.
    LockDirUnreadable,
    /// A lock file [`live_thread_locks`] listed could not be opened by
    /// [`lock_is_held`] for a reason other than having simply vanished since
    /// the listing (a vanished file is positively released, not unknown).
    LockProbeUnavailable,
    /// At least one lock came back held and [`process_table`] returned
    /// `None` — no `ps` on `PATH` is the live case this exists for.
    ProcessTableUnavailable,
    /// An already-enrolled thread's candidate app-server has an unreadable
    /// `/proc/<pid>/fd` table — the fd scan is the SOLE ownership evidence
    /// ([`holder_via_proc_fd`]), so this thread's continued existence can be
    /// neither confirmed nor denied. A candidate id with no existing
    /// `kind:"app"` record takes the ordinary "no proven owner → no record"
    /// reading instead, unchanged — enrolment still needs positive fd
    /// evidence; only a record this crate ALREADY carries is ever put at
    /// risk by an unreadable fd table.
    LockOwnerUnavailable,
}

/// Reconcile `kind:"app"` Codex-desktop records against a [`ThreadScan`] —
/// the PURE CORE (fed fake scans in tests), mirroring
/// [`super::window::reconcile_untracked_terminals`] rule for rule. A
/// `ThreadScan::Unknown` changes nothing — `(sessions, false)`, sessions
/// returned exactly as given — because a scan that could not complete
/// carries no evidence any thread has closed; every rule below fires only
/// for [`ThreadScan::Observed`]:
///
///   * A desired thread with no existing record is INSERTED, keyed by its
///     native id verbatim (no synthetic prefix — see the module doc).
///   * An existing `kind:"app"` record for a still-desired thread is upserted
///     IN PLACE, change-only — `changed` flips only on an actual field
///     difference, so a re-scan of an unchanged thread is a no-op.
///   * A `kind:"app"` record whose thread is no longer desired (its lock is
///     gone) is REMOVED — mirrors a closed window dropping its `win:*` row.
///   * A native id already claimed by a NON-`"app"` record (a real tracked
///     session somehow already sitting on that id) is left entirely alone:
///     never inserted, never overwritten, never removed by this function —
///     the tracked record carries the rich state and always wins (the
///     ruling's "ambiguous records retain known CLI classification",
///     P-CX-2b).
///
/// Every record this function writes carries a fixed identity
/// (`agent:"codex"`, `kind:"app"`, `state:"idle"`), re-applied on every
/// upsert rather than assumed. `kind:"app"` is why `crate::reap::is_agent_kind`
/// reads false for these records — which keeps them out of BOTH
/// `superseded_agent_duplicates` (N threads legitimately share one app
/// window address; that dedup would otherwise retire N−1 of them) and
/// `is_session_dead`'s staleness arm (a shared app-server pid must never
/// stand as proof any one thread is alive). `windowAddress`/`workspace` are
/// left empty here by design — the existing `resolve_pending_session_windows`
/// sweep fills them later; this function has no compositor access and must
/// not invent one.
pub(crate) fn reconcile_codex_app_threads(
    mut sessions: Vec<SessionRecord>,
    scan: &ThreadScan,
) -> (Vec<SessionRecord>, bool) {
    let threads: &[CodexThread] = match scan {
        ThreadScan::Unknown(_) => return (sessions, false),
        ThreadScan::Observed(threads) => threads,
    };

    // Native ids already claimed by a TRACKED (non-`"app"`) record — never
    // ours to insert, overwrite, or remove.
    let claimed: HashSet<String> = sessions
        .iter()
        .filter(|s| s.kind.as_deref() != Some("app"))
        .map(|s| s.session_id.clone())
        .collect();

    // The `"app"` roster we WANT: one entry per live thread, keyed by its
    // native id, skipping any id a tracked record already owns.
    let mut desired: HashMap<&str, &CodexThread> = HashMap::new();
    for t in threads {
        if claimed.contains(t.id.as_str()) {
            continue;
        }
        desired.insert(t.id.as_str(), t);
    }

    let mut changed = false;

    // Drop `"app"` records whose thread is no longer desired (lock gone, or
    // a tracked session now claims the id).
    let before = sessions.len();
    sessions.retain(|s| {
        s.kind.as_deref() != Some("app") || desired.contains_key(s.session_id.as_str())
    });
    if sessions.len() != before {
        changed = true;
    }

    // Upsert a record per desired thread.
    for (id, t) in &desired {
        if let Some(rec) = sessions.iter_mut().find(|s| s.session_id.as_str() == *id) {
            if rec.pid != Some(t.pid) {
                rec.pid = Some(t.pid);
                changed = true;
            }
            if rec.cwd != t.cwd {
                rec.cwd = t.cwd.clone();
                changed = true;
            }
            // The fixed identity, re-applied every upsert — never left to
            // drift even if something else touched the record in between.
            if rec.agent != "codex" {
                rec.agent = "codex".to_string();
                changed = true;
            }
            if rec.state != "idle" {
                rec.state = "idle".to_string();
                changed = true;
            }
            if rec.kind.as_deref() != Some("app") {
                rec.kind = Some("app".to_string());
                changed = true;
            }
        } else {
            let petname = aoide_storage::petname::mint_for(&sessions);
            sessions.push(SessionRecord {
                session_id: id.to_string(),
                agent: "codex".to_string(),
                cwd: t.cwd.clone(),
                state: "idle".to_string(),
                kind: Some("app".to_string()),
                pid: Some(t.pid),
                petname: Some(petname),
                ..Default::default()
            });
            changed = true;
        }
    }

    (sessions, changed)
}

/// `$CODEX_HOME` if set and non-empty, else `$HOME/.codex` — env only,
/// portable as written. Lifted VERBATIM from what was
/// `reap.rs::refresh_codex_titles`'s own inline lookup (the one prior copy
/// of this logic) so a single authority remains; that function now calls
/// this instead of repeating it.
pub(crate) fn codex_home() -> Option<PathBuf> {
    std::env::var_os("CODEX_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".codex")))
}

/// The taught story for a platform with neither primitive this design
/// needs. Asserted at the const level
/// (`tests::the_unsupported_platform_string_names_flock_and_the_process_table`)
/// so the non-unix seam cannot rot unnoticed by drifting out of sync with
/// what it claims to explain.
pub(crate) const UNSUPPORTED_PLATFORM: &str =
    "codex desktop association needs unix file locks and a POSIX process table; this platform has neither";

/// List the thread-writer lock FILES under `dir` (typically
/// `<codex_home>/thread-writer-locks`) — names only; whether one is
/// currently HELD is [`lock_is_held`]'s question, not this one.
/// `.coordination.lock` is a cross-thread coordination file, never a
/// per-thread lock, and is always skipped. A MISSING directory reads as
/// `Ok(empty)` — no desktop app has ever run on this box, today's story,
/// and that is a genuine fact, not a failed observation. Any OTHER read
/// error (permissions, a directory that stopped being readable mid-scan)
/// comes back `Err`: the caller cannot tell "no threads" from "couldn't
/// look," so it must not either.
pub(crate) fn live_thread_locks(dir: &Path) -> Result<Vec<PathBuf>, ScanFailure> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(ScanFailure::LockDirUnreadable),
    };
    Ok(entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lock"))
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some(".coordination.lock"))
        .collect())
}

/// Is the thread-writer lock at `path` currently HELD by some process? The
/// try-flock itself IS the liveness signal — never `/proc`, never a pid read
/// out of the file (the file is 0 bytes and carries no pid). A three-way
/// answer: `Some(true)` — `LOCK_EX | LOCK_NB` failed (`EWOULDBLOCK`), so
/// another open file description already holds it; `Some(false)` — the file
/// is simply gone (`NotFound` on open), positively released, not merely
/// unobserved; `None` — the open failed for any OTHER reason, which is not
/// evidence either way. Opens `O_RDONLY` only, never `O_CREAT`, so a
/// missing lock file is never brought into existence by asking, and a lock
/// this probe DID acquire is released and the fd closed in the same breath
/// (`file` drops at the end of this function) — the probe itself never
/// leaves a lock held.
#[cfg(unix)]
pub(crate) fn lock_is_held(path: &Path) -> Option<bool> {
    use std::os::unix::io::AsRawFd;
    let file = match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let fd = file.as_raw_fd();
    let acquired = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
    Some(!acquired)
}

/// No unix file locks on this platform — see [`UNSUPPORTED_PLATFORM`]. No
/// probe, no enrolment, no code: this platform never has anything held.
#[cfg(not(unix))]
pub(crate) fn lock_is_held(_path: &Path) -> Option<bool> {
    Some(false)
}

/// The whole system's process table, `ps -axo pid=,ppid=,command=` — the
/// SAME argv shape on Linux and BSD/macOS (precedent and shape:
/// [`super::window::hyprctl_clients`]'s shell-out). Callers must gate this
/// behind "at least one lock came back held" (see [`codex_app_threads`]) so
/// a box with no desktop app installed forks nothing.
#[cfg(unix)]
pub(crate) fn process_table() -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// No POSIX process table on this platform.
#[cfg(not(unix))]
pub(crate) fn process_table() -> Option<String> {
    None
}

/// One row of a parsed `ps -axo pid=,ppid=,command=` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub argv: Vec<String>,
    pub argv0_base: String,
}

/// Basename of a `/`-separated argv0. Argv paths from `ps` are always
/// `/`-separated regardless of the OS this code itself is compiled for, so
/// this splits on `/` explicitly rather than leaning on `std::path::Path`'s
/// host-dependent separator handling.
fn argv0_basename(argv0: &str) -> &str {
    argv0.rsplit('/').next().unwrap_or(argv0)
}

/// Parse `ps -axo pid=,ppid=,command=` output — PURE, no I/O, so a fixture
/// string pins it on any host. One row per line, ASCII-whitespace split:
/// the first token is `pid`, the second `ppid`, everything after is the
/// command's argv. LOSSY for an argument that itself contains a space (`ps`
/// gives no other column boundary); accepted, because neither
/// [`codex_app_servers`]'s predicate nor [`lock_holder`]'s pid resolution
/// can be created or destroyed by that split — only `argv[0]`'s basename
/// and an exact `"app-server"` element matter. A line with fewer than three
/// tokens (no command) is skipped.
pub(crate) fn parse_process_table(table: &str) -> Vec<Proc> {
    table
        .lines()
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            let pid = tokens.next()?.parse().ok()?;
            let ppid = tokens.next()?.parse().ok()?;
            let argv: Vec<String> = tokens.map(str::to_string).collect();
            let argv0_base = argv0_basename(argv.first()?).to_string();
            Some(Proc {
                pid,
                ppid,
                argv,
                argv0_base,
            })
        })
        .collect()
}

/// The ONE predicate this whole design keys ownership on: `argv0`'s
/// basename is exactly `codex` AND some argv element is exactly
/// `app-server` — never the "ChatGPT" brand, a window class, or a store
/// path. A renamed, resigned or relocated build is found the same way a
/// terminal `codex app-server` invocation would be; a `codex` TUI/`exec`
/// invocation (no `app-server` token) never matches.
pub(crate) fn codex_app_servers(procs: &[Proc]) -> Vec<u32> {
    procs
        .iter()
        .filter(|p| p.argv0_base == "codex" && p.argv.iter().any(|a| a == "app-server"))
        .map(|p| p.pid)
        .collect()
}

/// Resolve which app-server owns a lock, given the servers the process
/// table yielded: an app-server owns a lock only when its own fd table
/// holds that lock ([`holder_via_proc_fd`]) — anything less is not a
/// desktop thread. Zero servers is `Ok(None)`, the routine CLI case, not an
/// anomaly — `holder_via_proc_fd` is never even called, so a lock nothing
/// on the process table claims to own can never come back `Err` from here.
pub(crate) fn lock_holder(servers: &[u32], lock: &Path) -> Result<Option<u32>, ()> {
    match servers {
        [] => Ok(None),
        many => holder_via_proc_fd(many, lock),
    }
}

/// The ONE permitted `cfg(target_os = "linux")` extra (§4 P-CX-2 of the
/// P-CX design brief): scan each candidate's `/proc/<pid>/fd` for a
/// descriptor whose target is this exact lock path — the ONLY evidence
/// [`lock_holder`] accepts, for one server or many, never a tie-break
/// reserved for the multi-server case. `lock` is canonicalized once before
/// the scan so a symlinked `~/.codex` cannot defeat the match; never
/// consulted for liveness (that is always [`lock_is_held`]'s flock).
///
/// `Ok(Some(pid))` — a candidate's fd table proved ownership. `Ok(None)` —
/// every candidate's fd table was readable and none held this lock, a
/// routine CLI thread or an idle server, never an anomaly. `Err(())` — at
/// least one candidate's `/proc/<pid>/fd` could not be READ for a reason
/// other than that candidate having already exited (an exited candidate is
/// skipped exactly as before: a dead process holds no fd on anything, so
/// its own vanished `/proc` entry is not evidence of anything) before any
/// candidate proved ownership; the caller decides what an unreadable
/// candidate is allowed to mean.
#[cfg(target_os = "linux")]
fn holder_via_proc_fd(candidates: &[u32], lock: &Path) -> Result<Option<u32>, ()> {
    let target = lock.canonicalize().unwrap_or_else(|_| lock.to_path_buf());
    let mut unreadable = false;
    for &pid in candidates {
        let entries = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                unreadable = true;
                continue;
            }
        };
        for entry in entries.flatten() {
            if std::fs::read_link(entry.path()).map(|t| t == target).unwrap_or(false) {
                return Ok(Some(pid));
            }
        }
    }
    if unreadable {
        Err(())
    } else {
        Ok(None)
    }
}

/// No positive ownership evidence is available on this platform, so no
/// desktop thread is ever enrolled here — see [`UNSUPPORTED_PLATFORM`].
/// Always `Ok(None)`, never `Err`: the platform has no failure mode to
/// report, only nothing to find.
#[cfg(not(target_os = "linux"))]
fn holder_via_proc_fd(_candidates: &[u32], _lock: &Path) -> Result<Option<u32>, ()> {
    Ok(None)
}

/// A thread's cwd, read ONCE per enrolment from its rollout header
/// (`session_meta.payload.cwd`) — never re-read per tick (the P-CX design's
/// §6 Q5 accepts the walk cost on that basis). Walks
/// `<codex_home>/sessions/**` for the file named `rollout-*-<thread_id>.jsonl`
/// and reads only its first line — the header is always ordinal 0.
pub(crate) fn thread_cwd(codex_home: &Path, thread_id: &str) -> Option<String> {
    let path = find_rollout(&codex_home.join("sessions"), thread_id)?;
    let file = std::fs::File::open(path).ok()?;
    let mut first_line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(file), &mut first_line).ok()?;
    let header: serde_json::Value = serde_json::from_str(first_line.trim()).ok()?;
    header
        .get("payload")
        .and_then(|p| p.get("cwd"))
        .and_then(|c| c.as_str())
        .map(str::to_string)
}

/// Depth-first search for `rollout-*-<thread_id>.jsonl` under `dir`
/// (typically `sessions/<year>/<month>/<day>/`, but the walk makes no
/// assumption about nesting depth). `pub(crate)` so [`super::codex_capture::
/// capture_for`] reuses this exact walk rather than growing a second one —
/// the crate's own "widen it, don't fork it" rule.
pub(crate) fn find_rollout(dir: &Path, thread_id: &str) -> Option<PathBuf> {
    let suffix = format!("-{thread_id}.jsonl");
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_match = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("rollout-") && n.ends_with(&suffix));
            if is_match {
                return Some(path);
            }
        }
    }
    None
}

/// Assemble the live thread set straight off `~/.codex` as a [`ThreadScan`]
/// — the ONLY I/O this module performs before handing off to
/// [`reconcile_codex_app_threads`]. Delegates to
/// [`codex_app_threads_with`] with the real [`process_table`]; split out so
/// a test can inject a table (or its absence) without shelling out to a
/// real `ps`. `known` is the id→cwd map of threads a `kind:"app"` record
/// already carries (built by the caller from the current stage, BEFORE this
/// function runs) — see [`codex_app_threads_with`] for what it's for.
pub(crate) fn codex_app_threads(known: &BTreeMap<String, String>) -> ThreadScan {
    codex_app_threads_with(known, process_table)
}

/// The testable core of [`codex_app_threads`], taking the process-table
/// gather as a parameter. No `codex_home` (env has neither `CODEX_HOME` nor
/// `HOME`): no work, `Observed(empty)` — an absent desktop app is a genuine
/// fact, not a failed observation. Every OTHER dead end is `Unknown`: an
/// unreadable lock directory, a lock file that fails to open for any reason
/// but having vanished, `process_table` coming back `None` while a lock is
/// genuinely held, or an already-enrolled thread's candidate fd table going
/// unreadable — see [`ScanFailure`] for which is which. `held` coming back
/// empty (every lock positively released) short-circuits to
/// `Observed(empty)` without ever calling `process_table` — a box with no
/// desktop app installed forks nothing.
///
/// `known`'s `sessions/**` walk cost ([`thread_cwd`]/[`find_rollout`],
/// unbounded DFS) is paid once per NEW thread id only: an id already
/// `known` with a non-empty cwd carries that cwd through UNCHANGED (see
/// [`resolved_cwd`]), never re-walked on a later tick.
fn codex_app_threads_with(
    known: &BTreeMap<String, String>,
    process_table: impl Fn() -> Option<String>,
) -> ThreadScan {
    let Some(home) = codex_home() else {
        return ThreadScan::Observed(Vec::new());
    };
    let locks = match live_thread_locks(&home.join("thread-writer-locks")) {
        Ok(locks) => locks,
        Err(failure) => return ThreadScan::Unknown(failure),
    };

    let mut held = Vec::new();
    for lock in locks {
        match lock_is_held(&lock) {
            Some(true) => held.push(lock),
            Some(false) => {}
            None => return ThreadScan::Unknown(ScanFailure::LockProbeUnavailable),
        }
    }
    if held.is_empty() {
        return ThreadScan::Observed(Vec::new());
    }

    let Some(table) = process_table() else {
        return ThreadScan::Unknown(ScanFailure::ProcessTableUnavailable);
    };
    let procs = parse_process_table(&table);
    let servers = codex_app_servers(&procs);

    let mut threads = Vec::new();
    for lock in held {
        let Some(id) = lock.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        match lock_holder(&servers, &lock) {
            Ok(Some(pid)) => {
                let cwd = resolved_cwd(known, &home, id);
                threads.push(CodexThread {
                    id: id.to_string(),
                    cwd,
                    pid,
                });
            }
            // No proven owner among readable candidates — a CLI thread or
            // unknown, never a desktop app record. Unchanged from before.
            Ok(None) => {}
            Err(()) => {
                if known.contains_key(id) {
                    return ThreadScan::Unknown(ScanFailure::LockOwnerUnavailable);
                }
                // No existing `kind:"app"` record carries this id: today's
                // "no proven owner → no record" reading, unchanged.
            }
        }
    }
    ThreadScan::Observed(threads)
}

/// A thread's cwd for [`codex_app_threads_with`]'s assembly step: the cached
/// value from `known` when non-empty, else a fresh [`thread_cwd`] walk.
/// Pulled out on its own so the caching rule stays testable without a
/// process that can genuinely hold a `/proc/<pid>/fd` on the fixture lock
/// (see the P-CX-2b tests below) — [`codex_app_servers`] keys ownership on
/// the real system process table, which a unit test cannot spoof.
fn resolved_cwd(known: &BTreeMap<String, String>, home: &Path, id: &str) -> String {
    match known.get(id) {
        Some(cwd) if !cwd.is_empty() => cwd.clone(),
        _ => thread_cwd(home, id).unwrap_or_default(),
    }
}

/// The FIRST time this process observes
/// [`ScanFailure::ProcessTableUnavailable`], one audit line notes that the
/// desktop-Codex scan is being skipped and existing records are being kept
/// — the daemon's own tick has no operator watching stderr, and a "ps not
/// on PATH" tick that just goes quiet forever would leave that fact
/// undiscoverable. Every OTHER [`ScanFailure`], and every later
/// `ProcessTableUnavailable` tick on this same process, stays silent: the
/// fix is what stops a failed scan from mattering (no record is ever
/// removed on `Unknown`), not a growing log.
static PROCESS_TABLE_UNKNOWN_AUDITED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn audit_scan_unknown_once(failure: &ScanFailure) {
    if !matches!(failure, ScanFailure::ProcessTableUnavailable) {
        return;
    }
    if PROCESS_TABLE_UNKNOWN_AUDITED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let log = aoide_protocol::default_audit_log();
    let _ = aoide_protocol::audit(
        &log,
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Audit,
        "session.reap",
        "skipped",
        "desktop codex scan skipped: ps not on PATH (records kept)",
    );
}

/// The subset of [`CodexCapture`]'s own (snake_case, Rust-field-name)
/// `sources` keys this merge actually applies to `rec`, paired with the
/// WIRE (camelCase) name a `sources` entry must carry on `SessionRecord`
/// (`storage/src/records.rs`'s `#[serde(rename)]`s) — S1's own capture keys
/// its internal map by Rust field name (`codex_capture.rs`'s own tests pin
/// that); S2 remaps at this exact boundary, the one place a capture's
/// internal shape crosses into the wire-facing record it lands on.
const MERGED_SOURCE_FIELDS: &[(&str, &str)] = &[
    ("say", "say"),
    ("tool", "tool"),
    ("activity", "activity"),
    ("model", "model"),
    ("context_tokens", "contextTokens"),
    ("context_ceiling", "contextCeiling"),
];

/// Merge [`CodexCapture`]'s fields onto `rec` — `say`/`tool`/`activity`/
/// `model`/`context_tokens`/`context_ceiling`/`sources`, each set only when
/// `cap` produced `Some` AND the value actually differs: a quiet or
/// partial tail read (every field `None`) changes nothing, and a value
/// this merge already set is never blanked back out just because a LATER
/// tick's tail window no longer covers the record that set it — the same
/// "never clear, only set" discipline `session_store.rs`'s
/// `refresh_transcript_fields` already holds for these very fields.
/// `sources` is EXTENDED, never replaced, and restricted to
/// [`MERGED_SOURCE_FIELDS`]: a `state`/`parent_thread_id`/`thread_source`/
/// `nickname` pointer `cap.sources` may carry is never copied here, because
/// this merge never sets those VALUES — a `sources` entry names a field
/// THIS record actually carries from a pointed source, never a promise
/// about one a later slice (S3, S4) has not landed yet. An entry already on
/// `rec.sources` with no counterpart in `cap.sources` this tick is left
/// standing — a shown datum's pointer must not vanish just because a later
/// capture happened not to re-see the record that set it. Returns whether
/// anything changed.
///
/// Deliberately never touches `state`, `parent_session_id`, `title`, or
/// `nickname` even though `cap` may carry values for them — those are S3's
/// (`state`) and S4's (the subagent edge) own slices, never this merge's.
fn apply_codex_capture(rec: &mut SessionRecord, cap: &CodexCapture) -> bool {
    let mut changed = false;

    if let Some(say) = &cap.say {
        if rec.say.as_deref() != Some(say.as_str()) {
            rec.say = Some(say.clone());
            changed = true;
        }
    }
    if let Some(tool) = &cap.tool {
        if rec.tool.as_deref() != Some(tool.as_str()) {
            rec.tool = Some(tool.clone());
            changed = true;
        }
    }
    if let Some(activity) = &cap.activity {
        if rec.activity.as_deref() != Some(activity.as_str()) {
            rec.activity = Some(activity.clone());
            changed = true;
        }
    }
    if let Some(model) = &cap.model {
        if rec.model.as_deref() != Some(model.as_str()) {
            rec.model = Some(model.clone());
            changed = true;
        }
    }
    if let Some(tokens) = cap.context_tokens {
        if rec.context_tokens != Some(tokens) {
            rec.context_tokens = Some(tokens);
            changed = true;
        }
    }
    if let Some(ceiling) = cap.context_ceiling {
        if rec.context_ceiling != Some(ceiling) {
            rec.context_ceiling = Some(ceiling);
            changed = true;
        }
    }
    if let Some(cap_sources) = &cap.sources {
        for (snake, camel) in MERGED_SOURCE_FIELDS {
            let Some(ptr) = cap_sources.get(*snake) else {
                continue;
            };
            let merged = rec.sources.get_or_insert_with(BTreeMap::new);
            if merged.get(*camel) != Some(ptr) {
                merged.insert((*camel).to_string(), ptr.clone());
                changed = true;
            }
        }
    }

    changed
}

/// The I/O wrapper over [`reconcile_codex_app_threads`] — gathers a
/// [`ThreadScan`], reconciles under the stage lock, merges each live
/// thread's own [`capture_for`] onto its `"app"` record
/// ([`apply_codex_capture`]), and re-stages `graph.json` only when
/// something changed. Mirrors [`super::window::sync_untracked_terminal_windows`]'s
/// shape. An `Unknown` scan takes NO stage lock and writes NOTHING —
/// [`audit_scan_unknown_once`] notes it and this returns `false`, same as
/// an ordinary no-op tick.
///
/// Reads the stage TWICE: once here (outside the lock) to build
/// [`codex_app_threads`]'s `known` id→cwd map off the current `kind:"app"`
/// records — so an already-enrolled thread's `sessions/**` walk runs once
/// per NEW id, never once per tick — and once more inside
/// `with_stage_lock` for the actual reconcile. The gather itself (the lock
/// probes, the `ps` shell-out, the rollout walk for a genuinely new id, and
/// now each live thread's bounded rollout tail) stays OUTSIDE the stage
/// lock either way, unchanged from before.
pub(crate) fn sync_codex_app_threads() -> bool {
    let known: BTreeMap<String, String> = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| {
            f.sessions
                .into_iter()
                .filter(|s| s.kind.as_deref() == Some("app"))
                .map(|s| (s.session_id, s.cwd))
                .collect()
        })
        .unwrap_or_default();
    let scan = codex_app_threads(&known);
    let threads: &Vec<CodexThread> = match &scan {
        ThreadScan::Unknown(failure) => {
            audit_scan_unknown_once(failure);
            return false;
        }
        ThreadScan::Observed(threads) => threads,
    };

    // One bounded rollout tail per live thread, gathered here — OUTSIDE the
    // stage lock, alongside the scan's own I/O above — then merged onto
    // each thread's `"app"` record below. A thread whose rollout can't be
    // found or read captures `CodexCapture::default()` (every field
    // `None`) and changes nothing on that record.
    let captures: BTreeMap<String, CodexCapture> = match codex_home() {
        Some(home) => threads
            .iter()
            .map(|t| (t.id.clone(), capture_for(&home, &t.id)))
            .collect(),
        None => BTreeMap::new(),
    };

    // A thread this tick no longer observes has its capture memo evicted
    // right here — the exact set the scan just produced, not the roster a
    // later reconcile settles on, so a thread never lingers in memory past
    // the tick it stops being live.
    super::codex_capture::retain_capture_memo(&threads.iter().map(|t| t.id.clone()).collect());

    aoide_storage::fs::with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let (mut sessions, mut changed) =
            reconcile_codex_app_threads(std::mem::take(&mut file.sessions), &scan);
        for rec in sessions.iter_mut() {
            if rec.kind.as_deref() != Some("app") {
                continue;
            }
            if let Some(cap) = captures.get(&rec.session_id) {
                if apply_codex_capture(rec, cap) {
                    changed = true;
                }
            }
        }
        file.sessions = sessions;
        if !changed {
            return false;
        }
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        if write_stage(&sessions_path(), &file).is_ok() {
            let _ = restage_graph();
            return true;
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::{session, unique_stage, EnvVars};

    fn thread(id: &str, cwd: &str, pid: u32) -> CodexThread {
        CodexThread {
            id: id.to_string(),
            cwd: cwd.to_string(),
            pid,
        }
    }

    #[test]
    fn a_live_thread_becomes_one_record_keyed_by_its_native_id() {
        let (out, changed) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![thread(
                "01a07d89-5f9b-7900-b909-d5eb9457c195",
                "/home/khoa/Aoide",
                2598256,
            )]),
        );
        assert!(changed);
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.session_id, "01a07d89-5f9b-7900-b909-d5eb9457c195");
        assert_eq!(r.agent, "codex");
        assert_eq!(r.kind.as_deref(), Some("app"));
        assert_eq!(r.state, "idle");
        assert_eq!(r.pid, Some(2598256));
        assert_eq!(r.cwd, "/home/khoa/Aoide");
        assert!(
            r.window_address.is_empty(),
            "windowAddress is filled later by the window sweep, never here"
        );
        assert_eq!(r.workspace, None);
        assert!(
            r.petname.is_some(),
            "a freshly enrolled app record must mint a petname"
        );
        assert_eq!(r.title, None, "title is apply_codex_titles's alone to fill");
        assert_eq!(r.conductable, None);
        assert_eq!(r.socket, None);
        assert_eq!(r.parent_session_id, None);
    }

    #[test]
    fn two_threads_of_one_app_are_two_records() {
        let (out, changed) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![
                thread("01a07d89-thread-one", "/home/khoa/Aoide", 2598256),
                thread(
                    "01a08a23-thread-two",
                    "/home/khoa/Documents/Codex/2026-09-10/wha",
                    2598256,
                ),
            ]),
        );
        assert!(changed);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|r| r.session_id == "01a07d89-thread-one"));
        assert!(out.iter().any(|r| r.session_id == "01a08a23-thread-two"));
        assert!(out.iter().all(|r| r.kind.as_deref() == Some("app")));
        // One shared app-server pid, two distinct records — never collapsed.
        assert_ne!(
            out[0].petname, out[1].petname,
            "two distinct threads must never share a minted petname"
        );
    }

    #[test]
    fn a_thread_whose_lock_is_gone_loses_its_record() {
        let (first, _) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![thread("01a07d89-gone", "/home/khoa/Aoide", 2598256)]),
        );
        assert_eq!(first.len(), 1);
        let (second, changed) =
            reconcile_codex_app_threads(first, &ThreadScan::Observed(Vec::new()));
        assert!(changed);
        assert!(
            second.is_empty(),
            "a thread with no live lock keeps no record"
        );
    }

    #[test]
    fn a_record_a_tracked_session_already_owns_is_never_overwritten() {
        // A real tracked session happens to sit on the same id a codex thread
        // reports (should not occur in practice, but the rule is absolute).
        let tracked = session("01a07d89-claimed", "/home/khoa/Aoide", "working", "t", None);
        let (out, changed) = reconcile_codex_app_threads(
            vec![tracked.clone()],
            &ThreadScan::Observed(vec![thread(
                "01a07d89-claimed",
                "/home/khoa/Aoide",
                2598256,
            )]),
        );
        assert!(
            !changed,
            "a claimed id must never be touched by the app reconciler"
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent, tracked.agent);
        assert_eq!(out[0].kind, tracked.kind);
        assert_eq!(out[0].state, tracked.state);
        assert_eq!(out[0].pid, tracked.pid);
    }

    #[test]
    fn an_app_record_is_never_agent_kind_so_dedup_and_staleness_skip_it() {
        let (out, _) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![thread("01a07d89-live", "/home/khoa/Aoide", 2598256)]),
        );
        let rec = &out[0];
        assert!(
            !crate::reap::is_agent_kind(rec),
            "kind:\"app\" must never read as an agent for dedup"
        );
        assert!(
            !crate::reap::is_session_dead(rec, None, None, |_| true, 0, |_| None),
            "a live holder pid must never let staleness condemn an app record"
        );
    }

    #[test]
    fn an_app_record_never_publishes_a_state_other_than_idle() {
        // Simulate a record whose state drifted away from "idle" by some
        // other path; the next reconcile must force it back.
        let mut drifted = session("01a07d89-drift", "/home/khoa/Aoide", "working", "t", None);
        drifted.agent = "codex".to_string();
        drifted.kind = Some("app".to_string());
        drifted.pid = Some(2598256);
        let (out, changed) = reconcile_codex_app_threads(
            vec![drifted],
            &ThreadScan::Observed(vec![thread("01a07d89-drift", "/home/khoa/Aoide", 2598256)]),
        );
        assert!(
            changed,
            "correcting a drifted state must report a change"
        );
        assert_eq!(
            out[0].state, "idle",
            "an app record must never publish a state other than idle"
        );
    }

    // ---- P-CX-2: discovery fixtures --------------------------------------
    //
    // Real `ps -axo pid=,ppid=,command=` output has NO header (the `=`
    // suppresses it) — every fixture below starts straight at row one.

    /// Electron main, its crashpad handler, three `--type=zygote` children,
    /// a gpu and a utility child, ONE codex app-server child, and a
    /// terminal-launched bare `codex` TUI (no `app-server` token) sitting
    /// alongside it — the shape `a_codex_tui_argv_is_never_an_app_server`
    /// and `a_zygote_or_gpu_child_is_never_an_app_server` both probe.
    const PS_LINUX_ELECTRON: &str = "\
2597865       1 /opt/chatgpt-linux/chatgpt --no-sandbox
2597870 2597865 /opt/chatgpt-linux/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler
2597900 2597865 /opt/chatgpt-linux/chatgpt --type=zygote --no-zygote-sandbox
2597901 2597900 /opt/chatgpt-linux/chatgpt --type=zygote
2597902 2597900 /opt/chatgpt-linux/chatgpt --type=zygote
2597950 2597865 /opt/chatgpt-linux/chatgpt --type=gpu-process --field-trial-handle=1,2,3,4
2597960 2597865 /opt/chatgpt-linux/chatgpt --type=utility --utility-sub-type=network.mojom.NetworkService
2598256 2597865 /opt/chatgpt-linux/resources/codex -c features.code_mode_host=true app-server
2599000       1 /home/khoa/.cargo/bin/codex
";

    /// Two independent desktop installs, each with its own Electron main
    /// and its own codex app-server child — the multi-server case where
    /// neither's fd table holds a given lock, so `lock_holder` owns nothing.
    const PS_TWO_APP_SERVERS: &str = "\
2597865       1 /opt/chatgpt-linux/chatgpt --no-sandbox
2598256 2597865 /opt/chatgpt-linux/resources/codex -c features.code_mode_host=true app-server
3000001       1 /opt/chatgpt-linux2/chatgpt --no-sandbox
3000002 3000001 /opt/chatgpt-linux2/resources/codex -c features.code_mode_host=true app-server
";

    /// macOS-shaped paths with BSD `ps` column padding (extra leading/
    /// interior spaces) — `split_whitespace` must not care.
    const PS_MACOS: &str = "\
  501     1 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT
  601   501 /Applications/ChatGPT.app/Contents/Resources/codex -c features.code_mode_host=true app-server
";

    /// One command argument containing a literal space — `ps` gives no
    /// other column boundary, so this is lossy for `argv` by design; `pid`/
    /// `ppid` (the first two whitespace tokens) must still parse cleanly.
    const PS_SPACE_ARG: &str = "  700     1 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT --crash-dir=/Users/x/Library/Application Support/ChatGPT/Crash Reports\n";

    #[test]
    fn an_electron_table_yields_exactly_one_app_server() {
        let procs = parse_process_table(PS_LINUX_ELECTRON);
        let servers = codex_app_servers(&procs);
        assert_eq!(servers, vec![2598256]);
    }

    #[test]
    fn a_zygote_or_gpu_child_is_never_an_app_server() {
        let procs = parse_process_table(PS_LINUX_ELECTRON);
        let servers = codex_app_servers(&procs);
        for zygote_or_gpu_or_utility in [2597900, 2597901, 2597902, 2597950, 2597960] {
            assert!(
                !servers.contains(&zygote_or_gpu_or_utility),
                "pid {zygote_or_gpu_or_utility} is a chatgpt child, never a codex app-server"
            );
        }
    }

    #[test]
    fn a_codex_tui_argv_is_never_an_app_server() {
        let procs = parse_process_table(PS_LINUX_ELECTRON);
        let servers = codex_app_servers(&procs);
        assert!(
            !servers.contains(&2599000),
            "a bare `codex` invocation carries no app-server token"
        );
    }

    #[test]
    fn a_macos_table_yields_the_same_one_app_server() {
        let procs = parse_process_table(PS_MACOS);
        let servers = codex_app_servers(&procs);
        assert_eq!(
            servers,
            vec![601],
            "the same predicate, a different path shape — no special-casing"
        );
    }

    #[test]
    fn a_command_argument_containing_a_space_still_parses_its_pid_and_ppid() {
        let procs = parse_process_table(PS_SPACE_ARG);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 700);
        assert_eq!(procs[0].ppid, 1);
    }

    #[test]
    fn two_app_servers_own_nothing_when_neither_fds_the_lock() {
        let procs = parse_process_table(PS_TWO_APP_SERVERS);
        let servers = codex_app_servers(&procs);
        assert_eq!(servers, vec![2598256, 3000002]);
        // Neither pid actually holds any real `/proc/<pid>/fd` entry for
        // this path, so even the REAL fd scan compiled into this test
        // binary finds no owner — the fd scan is the ONLY evidence
        // `lock_holder` accepts, for one server or a hundred, never a
        // tie-break reserved for the multi-server case.
        let lock = Path::new("/nonexistent/thread-writer-locks/some-thread.lock");
        assert_eq!(lock_holder(&servers, lock), Ok(None));
    }

    #[test]
    fn one_app_server_with_no_fd_on_the_lock_owns_nothing() {
        let dir = unique_stage("codex-lock-owner-no-fd");
        let lock = dir.join("never-opened.lock");
        std::fs::write(&lock, b"").unwrap();
        let servers = [std::process::id()];
        assert_eq!(
            lock_holder(&servers, &lock),
            Ok(None),
            "one server with no fd on the lock still owns nothing"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn the_process_whose_fd_holds_the_lock_is_its_owner() {
        // Linux-only: the evidence path reads `/proc/<pid>/fd`.
        let dir = unique_stage("codex-lock-owner-fd");
        let lock = dir.join("held.lock");
        std::fs::write(&lock, b"").unwrap();
        let held = std::fs::OpenOptions::new().read(true).open(&lock).unwrap();
        let servers = [std::process::id()];
        assert_eq!(lock_holder(&servers, &lock), Ok(Some(std::process::id())));

        // Canonicalization: a symlinked parent directory must not defeat
        // the match.
        let link = dir
            .parent()
            .unwrap()
            .join(format!("{}-link", dir.file_name().unwrap().to_string_lossy()));
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let lock_via_link = link.join("held.lock");
        assert_eq!(
            lock_holder(&servers, &lock_via_link),
            Ok(Some(std::process::id())),
            "a symlinked parent directory must not defeat the fd match"
        );

        drop(held);
        std::fs::remove_file(&link).ok();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_cli_thread_and_a_desktop_thread_side_by_side_enrol_only_the_desktop_one() {
        // Linux-only: the evidence path reads `/proc/<pid>/fd`.
        let dir = unique_stage("codex-mixed-cli-desktop");
        let lock_a = dir.join("desktop-thread.lock");
        let lock_b = dir.join("cli-thread.lock");
        std::fs::write(&lock_a, b"").unwrap();
        std::fs::write(&lock_b, b"").unwrap();
        // Only A is held open by this process's own fd — B is never
        // opened, so it carries no positive ownership evidence.
        let held_a = std::fs::OpenOptions::new().read(true).open(&lock_a).unwrap();

        let servers = [std::process::id()];
        assert_eq!(lock_holder(&servers, &lock_a), Ok(Some(std::process::id())));
        assert_eq!(lock_holder(&servers, &lock_b), Ok(None));

        let id_a = lock_a.file_stem().unwrap().to_str().unwrap().to_string();
        let id_b = lock_b.file_stem().unwrap().to_str().unwrap().to_string();

        // B is already a TRACKED (non-app) record — a real CLI session's
        // own bookkeeping — untouched by this reconciler either way.
        let mut cli_record = session(&id_b, "/home/khoa/Aoide", "working", "t", None);
        cli_record.agent = "codex".to_string();
        cli_record.pid = Some(424242);

        let desktop_thread = thread(&id_a, "/home/khoa/Aoide", std::process::id());

        let (out, _changed) = reconcile_codex_app_threads(
            vec![cli_record.clone()],
            &ThreadScan::Observed(vec![desktop_thread]),
        );

        let b_after = out
            .iter()
            .find(|r| r.session_id == id_b)
            .expect("B's tracked record must survive untouched");
        assert_eq!(b_after.kind, cli_record.kind);
        assert_eq!(b_after.pid, cli_record.pid);
        assert_eq!(b_after.session_id, cli_record.session_id);

        let app_records: Vec<_> = out
            .iter()
            .filter(|r| r.kind.as_deref() == Some("app"))
            .collect();
        assert_eq!(
            app_records.len(),
            1,
            "exactly one app record — the desktop thread, never the CLI one"
        );
        assert_eq!(app_records[0].session_id, id_a);
        assert_eq!(app_records[0].pid, Some(std::process::id()));

        drop(held_a);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_lock_another_fd_holds_reads_as_live() {
        use std::os::unix::io::AsRawFd;
        let dir = unique_stage("codex-lock-live");
        let path = dir.join("thread.lock");
        std::fs::write(&path, b"").unwrap();
        // Hold the lock on a fd of its own, independent of the probe's.
        let held = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        let rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "the test's own fd must acquire the lock first");
        assert_eq!(
            lock_is_held(&path),
            Some(true),
            "a lock another open file description holds must read as live"
        );
        unsafe {
            libc::flock(held.as_raw_fd(), libc::LOCK_UN);
        }
        drop(held);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_unheld_lock_is_not_a_live_thread() {
        let dir = unique_stage("codex-lock-unheld");
        let path = dir.join("thread.lock");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(lock_is_held(&path), Some(false));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_probe_never_creates_a_missing_lock_file() {
        let dir = unique_stage("codex-lock-missing");
        let path = dir.join("thread.lock");
        assert!(!path.exists());
        assert_eq!(
            lock_is_held(&path),
            Some(false),
            "a missing lock file is positively released, not unknown"
        );
        assert!(
            !path.exists(),
            "the probe must never create the file it is checking"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn lock_is_held_on_an_unreadable_file_is_unknown_not_released() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permissions cannot make a file unreadable");
            return;
        }
        let dir = unique_stage("codex-lock-unreadable-file");
        let path = dir.join("thread.lock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(
            lock_is_held(&path),
            None,
            "an unreadable lock file is unknown, never a stand-in for released"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn codex_home_prefers_the_configured_root() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["CODEX_HOME", "HOME"]);
        let configured = unique_stage("codex-home-configured");
        std::env::set_var("CODEX_HOME", &configured);
        std::env::set_var("HOME", configured.join("unused-home"));
        assert_eq!(codex_home(), Some(configured.clone()));
        std::fs::remove_dir_all(configured).ok();
    }

    #[test]
    fn a_rollout_header_yields_the_thread_cwd() {
        let home = unique_stage("codex-rollout");
        let day_dir = home.join("sessions").join("2026").join("09").join("10");
        std::fs::create_dir_all(&day_dir).unwrap();
        let thread_id = "01a07d89-5f9b-7900-b909-d5eb9457c195";
        let rollout = day_dir.join(format!("rollout-2026-09-10T06-57-03-{thread_id}.jsonl"));
        std::fs::write(
            &rollout,
            format!(
                "{{\"timestamp\":\"2026-09-10T10:57:03.070Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{thread_id}\",\"cwd\":\"/home/khoa/Aoide\"}}}}\n"
            ),
        )
        .unwrap();
        assert_eq!(
            thread_cwd(&home, thread_id).as_deref(),
            Some("/home/khoa/Aoide")
        );
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn no_codex_home_does_no_work_and_writes_nothing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["CODEX_HOME", "HOME"]);
        std::env::remove_var("CODEX_HOME");
        std::env::remove_var("HOME");
        assert_eq!(codex_home(), None);
        assert!(
            matches!(codex_app_threads(&BTreeMap::new()), ThreadScan::Observed(t) if t.is_empty()),
            "no codex_home means no work at all — a genuine fact, not a failed scan"
        );
    }

    #[test]
    fn a_known_thread_keeps_its_cwd_without_a_walk_while_a_new_one_still_walks() {
        // Exercises `resolved_cwd` directly rather than `codex_app_threads`:
        // ownership resolution now needs a REAL fd on a REAL process
        // (`codex_app_servers` keys off the live system `ps` table), which a
        // unit test cannot fake, so this test's own concern — the caching
        // rule, not enrolment — is isolated at the level that carries it.
        let home = unique_stage("codex-known-vs-new");
        let known_id = "01a07d89-already-known";
        let new_id = "01a08a23-brand-new";

        // Only the NEW id has a rollout on disk — the known id deliberately
        // has NONE, so if the walk ran for it anyway, `thread_cwd` would
        // find nothing and its cwd would come back empty, not the known
        // value asserted below.
        let day_dir = home.join("sessions").join("2026").join("09").join("10");
        std::fs::create_dir_all(&day_dir).unwrap();
        let rollout = day_dir.join(format!("rollout-2026-09-10T06-57-03-{new_id}.jsonl"));
        std::fs::write(
            &rollout,
            format!(
                "{{\"timestamp\":\"2026-09-10T10:57:03.070Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{new_id}\",\"cwd\":\"/home/khoa/NewProject\"}}}}\n"
            ),
        )
        .unwrap();

        let mut known = BTreeMap::new();
        known.insert(known_id.to_string(), "/home/khoa/AlreadyKnown".to_string());

        assert_eq!(
            resolved_cwd(&known, &home, known_id),
            "/home/khoa/AlreadyKnown",
            "a known id must carry its known cwd through, never re-walk for it"
        );
        assert_eq!(
            resolved_cwd(&known, &home, new_id),
            "/home/khoa/NewProject",
            "a genuinely new id must still get its header cwd off the rollout walk"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_unsupported_platform_string_names_flock_and_the_process_table() {
        assert!(UNSUPPORTED_PLATFORM.contains("file locks"));
        assert!(UNSUPPORTED_PLATFORM.contains("process table"));
    }

    // ---- P-CX-4: a failed/incomplete scan is Unknown, never "no threads" ---

    #[test]
    fn unknown_scan_leaves_existing_app_records_completely_untouched() {
        let (seeded, _) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![
                thread("01a-unknown-keep-1", "/home/khoa/Aoide", 111),
                thread("01a-unknown-keep-2", "/home/khoa/Elsewhere", 222),
            ]),
        );
        assert_eq!(seeded.len(), 2);

        let (after, changed) = reconcile_codex_app_threads(
            seeded.clone(),
            &ThreadScan::Unknown(ScanFailure::ProcessTableUnavailable),
        );
        assert!(!changed, "an Unknown scan must report no change");
        assert_eq!(after.len(), seeded.len());
        for (before, after) in seeded.iter().zip(after.iter()) {
            assert_eq!(after.session_id, before.session_id);
            assert_eq!(
                after.petname, before.petname,
                "a petname must never be re-minted under Unknown"
            );
            assert_eq!(after.pid, before.pid);
            assert_eq!(after.cwd, before.cwd);
        }
    }

    #[test]
    fn observed_empty_still_removes_genuinely_closed_threads() {
        let (with_two, _) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![
                thread("01a-close-1", "/home/khoa/Aoide", 111),
                thread("01a-close-2", "/home/khoa/Elsewhere", 222),
            ]),
        );
        assert_eq!(with_two.len(), 2);
        let (after, changed) =
            reconcile_codex_app_threads(with_two, &ThreadScan::Observed(Vec::new()));
        assert!(changed);
        assert!(
            after.is_empty(),
            "a positively observed empty set still closes every app record"
        );
    }

    #[test]
    fn observed_subset_removes_the_dropped_thread_and_keeps_the_survivor_petname() {
        let (with_two, _) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![
                thread("01a-survivor", "/home/khoa/Aoide", 111),
                thread("01a-dropped", "/home/khoa/Elsewhere", 222),
            ]),
        );
        let survivor_petname = with_two
            .iter()
            .find(|r| r.session_id == "01a-survivor")
            .and_then(|r| r.petname.clone());

        let (after, changed) = reconcile_codex_app_threads(
            with_two,
            &ThreadScan::Observed(vec![thread("01a-survivor", "/home/khoa/Aoide", 111)]),
        );
        assert!(changed);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].session_id, "01a-survivor");
        assert_eq!(
            after[0].petname, survivor_petname,
            "the surviving thread must keep its original petname — an in-place upsert, never a re-mint"
        );
    }

    #[test]
    fn lock_is_held_missing_path_is_positively_released() {
        let dir = unique_stage("codex-lock-is-held-missing");
        let path = dir.join("thread.lock");
        assert_eq!(lock_is_held(&path), Some(false));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn live_thread_locks_missing_dir_is_observed_empty_shape() {
        let dir = unique_stage("codex-locks-missing-dir");
        let missing = dir.join("thread-writer-locks");
        assert_eq!(live_thread_locks(&missing), Ok(Vec::new()));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn live_thread_locks_unreadable_dir_is_unknown() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permissions cannot make a directory unreadable");
            return;
        }
        let dir = unique_stage("codex-locks-unreadable-dir");
        let locks = dir.join("thread-writer-locks");
        std::fs::create_dir_all(&locks).unwrap();
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(
            live_thread_locks(&locks),
            Err(ScanFailure::LockDirUnreadable)
        );
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn held_lock_with_no_process_table_is_unknown() {
        use std::os::unix::io::AsRawFd;
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["CODEX_HOME", "HOME"]);
        let home = unique_stage("codex-threads-no-process-table");
        let locks_dir = home.join("thread-writer-locks");
        std::fs::create_dir_all(&locks_dir).unwrap();
        let lock = locks_dir.join("01a-held.lock");
        std::fs::write(&lock, b"").unwrap();
        let held = std::fs::OpenOptions::new().read(true).open(&lock).unwrap();
        let rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "the test's own fd must acquire the lock first");
        std::env::set_var("CODEX_HOME", &home);

        let scan = codex_app_threads_with(&BTreeMap::new(), || None);
        assert!(
            matches!(
                scan,
                ThreadScan::Unknown(ScanFailure::ProcessTableUnavailable)
            ),
            "a held lock with no process table must read Unknown, never Observed(empty)"
        );

        unsafe {
            libc::flock(held.as_raw_fd(), libc::LOCK_UN);
        }
        drop(held);
        std::fs::remove_dir_all(home).ok();
    }

    #[test]
    fn a_tracked_non_app_record_survives_an_unknown_scan_untouched() {
        // Extends the P-CX-2b mixed-fixture case
        // (`a_cli_thread_and_a_desktop_thread_side_by_side_enrol_only_the_desktop_one`
        // above): a tracked CLI record must survive an Unknown scan exactly
        // as untouched as it survives an Observed one.
        let mut cli_record = session("01a-cli-tracked", "/home/khoa/Aoide", "working", "t", None);
        cli_record.agent = "codex".to_string();
        cli_record.pid = Some(424242);

        let (out, changed) = reconcile_codex_app_threads(
            vec![cli_record.clone()],
            &ThreadScan::Unknown(ScanFailure::ProcessTableUnavailable),
        );
        assert!(!changed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].session_id, cli_record.session_id);
        assert_eq!(out[0].kind, cli_record.kind);
        assert_eq!(out[0].pid, cli_record.pid);
    }

    #[test]
    fn alternating_unknown_then_observed_same_set_causes_no_churn() {
        let (seeded, _) = reconcile_codex_app_threads(
            vec![],
            &ThreadScan::Observed(vec![
                thread("01a-alt-1", "/home/khoa/Aoide", 111),
                thread("01a-alt-2", "/home/khoa/Elsewhere", 222),
            ]),
        );
        let petnames_before: Vec<_> = seeded.iter().map(|r| r.petname.clone()).collect();

        let (after_unknown, changed_1) = reconcile_codex_app_threads(
            seeded,
            &ThreadScan::Unknown(ScanFailure::LockProbeUnavailable),
        );
        assert!(!changed_1, "an Unknown pass must never churn the roster");

        let (after_observed, changed_2) = reconcile_codex_app_threads(
            after_unknown,
            &ThreadScan::Observed(vec![
                thread("01a-alt-1", "/home/khoa/Aoide", 111),
                thread("01a-alt-2", "/home/khoa/Elsewhere", 222),
            ]),
        );
        assert!(
            !changed_2,
            "re-observing the identical set right after an Unknown pass must not churn either"
        );
        let petnames_after: Vec<_> = after_observed.iter().map(|r| r.petname.clone()).collect();
        assert_eq!(petnames_before, petnames_after);
    }

    // `apply_codex_capture` — the capture merge onto a `kind:"app"` record
    // (P-CX-5 S2).

    fn app_record(id: &str) -> SessionRecord {
        let mut rec = session(
            id,
            "/home/khoa/Aoide",
            "idle",
            "2026-09-12T09:00:00.000Z",
            None,
        );
        rec.kind = Some("app".to_string());
        rec
    }

    #[test]
    fn an_unreadable_rollout_changes_no_record() {
        // `capture_for` on a missing/unreadable rollout yields
        // `CodexCapture::default()` (every field `None`); merging that must
        // change nothing and never remove/blank an existing value.
        let mut rec = app_record("01a-unreadable");
        rec.say = Some("still here".to_string());
        rec.model = Some("gpt-6-astra".to_string());
        let changed = apply_codex_capture(&mut rec, &CodexCapture::default());
        assert!(!changed);
        assert_eq!(rec.say.as_deref(), Some("still here"));
        assert_eq!(rec.model.as_deref(), Some("gpt-6-astra"));
        assert_eq!(rec.sources, None);
    }

    #[test]
    fn a_second_identical_tick_reports_no_change() {
        let mut rec = app_record("01a-idempotent");
        let mut sources = BTreeMap::new();
        sources.insert(
            "say".to_string(),
            "/home/khoa/.codex/sessions/rollout-x.jsonl#4".to_string(),
        );
        let cap = CodexCapture {
            say: Some("building the fold".to_string()),
            sources: Some(sources),
            ..Default::default()
        };
        assert!(
            apply_codex_capture(&mut rec, &cap),
            "the first tick must apply the captured value"
        );
        let say_after_first = rec.say.clone();
        let sources_after_first = rec.sources.clone();
        assert!(
            !apply_codex_capture(&mut rec, &cap),
            "an identical second tick must report no change"
        );
        assert_eq!(rec.say, say_after_first);
        assert_eq!(rec.sources, sources_after_first);
    }

    #[test]
    fn a_quiet_capture_never_blanks_a_value_a_prior_tick_set() {
        // A `None` field on `cap` must never regress an already-set field
        // back to blank — the same "never clear, only set" discipline
        // `session_store.rs`'s `refresh_transcript_fields` holds.
        let mut rec = app_record("01a-sticky");
        rec.say = Some("earlier say".to_string());
        rec.model = Some("gpt-6-astra".to_string());
        let changed = apply_codex_capture(&mut rec, &CodexCapture::default());
        assert!(!changed);
        assert_eq!(rec.say.as_deref(), Some("earlier say"));
        assert_eq!(rec.model.as_deref(), Some("gpt-6-astra"));
    }

    #[test]
    fn the_merge_never_touches_state_lineage_or_title() {
        // `cap` carries values for `state`/`parent_thread_id`/`nickname`
        // (a real capture off a rollout with a `session_meta` header would),
        // but this merge must never read them: `state` is S3's slice,
        // `parent_thread_id`/`nickname` (the subagent edge) is S4's — R2/R3
        // forbid touching either here.
        let mut rec = app_record("01a-lineage");
        rec.title = Some("original title".to_string());
        let before = rec.clone();
        let cap = CodexCapture {
            state: Some("working".to_string()),
            parent_thread_id: Some("01a-parent".to_string()),
            thread_source: Some("subagent".to_string()),
            nickname: Some("Laplace".to_string()),
            ..Default::default()
        };
        let changed = apply_codex_capture(&mut rec, &cap);
        assert!(
            !changed,
            "none of cap's set fields are ones this merge reads"
        );
        assert_eq!(rec.state, before.state);
        assert_eq!(rec.parent_session_id, before.parent_session_id);
        assert_eq!(rec.title, before.title);
    }

    #[test]
    fn sources_extends_rather_than_replaces() {
        // A key a PRIOR tick set (and whose value `refresh`-style merges
        // never clear) must survive a later tick whose own tail window no
        // longer covers that record — `sources` is extended, never wiped
        // wholesale, so a still-shown datum never loses its pointer.
        let mut rec = app_record("01a-sources");
        let mut existing = BTreeMap::new();
        existing.insert(
            "model".to_string(),
            "/home/khoa/.codex/sessions/rollout-old.jsonl#2".to_string(),
        );
        rec.sources = Some(existing);

        let mut fresh = BTreeMap::new();
        fresh.insert(
            "say".to_string(),
            "/home/khoa/.codex/sessions/rollout-new.jsonl#9".to_string(),
        );
        let cap = CodexCapture {
            say: Some("fresh say".to_string()),
            sources: Some(fresh),
            ..Default::default()
        };
        let changed = apply_codex_capture(&mut rec, &cap);
        assert!(changed);
        let sources = rec.sources.expect("sources must still be Some");
        assert_eq!(
            sources.get("model"),
            Some(&"/home/khoa/.codex/sessions/rollout-old.jsonl#2".to_string()),
            "a key the fresh capture didn't re-see must survive"
        );
        assert_eq!(
            sources.get("say"),
            Some(&"/home/khoa/.codex/sessions/rollout-new.jsonl#9".to_string())
        );
    }

    #[test]
    fn sources_keys_remap_to_the_wire_camelcase_names() {
        // `CodexCapture::sources` keys by the struct's own snake_case field
        // names (`codex_capture.rs`'s own tests pin that); a `sources` entry
        // landing on `SessionRecord` must use the record's wire spelling
        // instead (`storage/src/records.rs`'s `#[serde(rename)]`s).
        let mut rec = app_record("01a-camelcase");
        let mut sources = BTreeMap::new();
        sources.insert(
            "context_tokens".to_string(),
            "/home/khoa/.codex/sessions/rollout-x.jsonl#5".to_string(),
        );
        sources.insert(
            "context_ceiling".to_string(),
            "/home/khoa/.codex/sessions/rollout-x.jsonl#5".to_string(),
        );
        let cap = CodexCapture {
            context_tokens: Some(1234),
            context_ceiling: Some(258_400),
            sources: Some(sources),
            ..Default::default()
        };
        assert!(apply_codex_capture(&mut rec, &cap));
        let merged = rec.sources.expect("sources must be Some");
        assert_eq!(
            merged.get("contextTokens"),
            Some(&"/home/khoa/.codex/sessions/rollout-x.jsonl#5".to_string())
        );
        assert_eq!(
            merged.get("contextCeiling"),
            Some(&"/home/khoa/.codex/sessions/rollout-x.jsonl#5".to_string())
        );
        assert!(
            !merged.contains_key("context_tokens"),
            "the snake_case capture key must never survive onto the record"
        );
        assert!(!merged.contains_key("context_ceiling"));
    }

    #[test]
    fn a_state_or_lineage_pointer_in_cap_sources_is_never_copied() {
        // A capture off a `session_meta` header points `state`/
        // `parent_thread_id`/`thread_source`/`nickname` even though this
        // merge never applies their VALUES (S3/S4's own slices) — a
        // `sources` entry must never promise a field the record does not
        // actually carry from that source yet.
        let mut rec = app_record("01a-no-lineage-pointer");
        let mut sources = BTreeMap::new();
        sources.insert("state".to_string(), "/rollout.jsonl#0".to_string());
        sources.insert(
            "parent_thread_id".to_string(),
            "/rollout.jsonl#0".to_string(),
        );
        sources.insert("thread_source".to_string(), "/rollout.jsonl#0".to_string());
        sources.insert("nickname".to_string(), "/rollout.jsonl#0".to_string());
        let cap = CodexCapture {
            state: Some("working".to_string()),
            parent_thread_id: Some("01a-parent".to_string()),
            thread_source: Some("subagent".to_string()),
            nickname: Some("Laplace".to_string()),
            sources: Some(sources),
            ..Default::default()
        };
        let changed = apply_codex_capture(&mut rec, &cap);
        assert!(
            !changed,
            "none of cap.sources's keys are ones this merge ever copies"
        );
        assert_eq!(rec.sources, None);
    }
}
