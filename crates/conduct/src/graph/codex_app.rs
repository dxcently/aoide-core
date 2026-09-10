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
//! OS, with exactly one `cfg(target_os = "linux")` tie-break
//! ([`holder_via_proc_fd`]) for when several app-servers run.
//!
//! [`codex_app_threads`] assembles the live set and [`sync_codex_app_threads`]
//! is the I/O wrapper over [`reconcile_codex_app_threads`] — but NEITHER has
//! a call site yet. The listener/daemon-tick wiring and the taught
//! transport/lifecycle refusals (`send`, `session kill`) are a later slice
//! (P-CX-3). Until then this module is reachable only from its own tests.

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
    /// The pid of the `app-server` process holding this thread's writer
    /// lock — `None` when two or more app-servers are running and the OS
    /// cannot say which one holds it (P-CX-2's `lock_holder`: an "owner
    /// ambiguous" refusal, never a guess). Feeds exactly two things
    /// downstream when `Some`: the existing window sweep's pid-ancestry
    /// walk, and the reaper's pid-DEATH signal — NEVER proof of life either
    /// way. A shared app-server pid backs every thread it holds a lock for,
    /// so the staleness arm must stay closed to it regardless of this pid's
    /// liveness or presence (that's what `kind:"app"` buys, below); an
    /// absent pid costs only the window (no ancestry walk to run).
    pub pid: Option<u32>,
}

/// Reconcile `kind:"app"` Codex-desktop records against the live thread set —
/// the PURE CORE (fed fake [`CodexThread`]s in tests), mirroring
/// [`super::window::reconcile_untracked_terminals`] rule for rule:
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
///     the tracked record carries the rich state and always wins.
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
    threads: &[CodexThread],
) -> (Vec<SessionRecord>, bool) {
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
            if rec.pid != t.pid {
                rec.pid = t.pid;
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
                pid: t.pid,
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
/// per-thread lock, and is always skipped. A missing/unreadable directory
/// (no desktop app has ever run on this box) reads as "no threads", never
/// an error.
pub(crate) fn live_thread_locks(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("lock"))
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some(".coordination.lock"))
        .collect()
}

/// Is the thread-writer lock at `path` currently HELD by some process? The
/// try-flock itself IS the liveness signal — never `/proc`, never a pid read
/// out of the file (the file is 0 bytes and carries no pid). `LOCK_EX |
/// LOCK_NB`: failure (`EWOULDBLOCK` on a real lock file) means another open
/// file description already holds it, so the thread is live; success means
/// nothing does, so the lock just taken is released and the fd closes in
/// the same breath (`file` drops at the end of this function) — the probe
/// itself never leaves a lock held. Opens `O_RDONLY` only, never `O_CREAT`,
/// so a missing lock file reads as "not live" and is never brought into
/// existence by asking.
#[cfg(unix)]
pub(crate) fn lock_is_held(path: &Path) -> bool {
    use std::os::unix::io::AsRawFd;
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(path) else {
        return false;
    };
    let fd = file.as_raw_fd();
    let acquired = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
    !acquired
}

/// No unix file locks on this platform — see [`UNSUPPORTED_PLATFORM`]. No
/// probe, no enrolment, no code: this is the whole Windows story.
#[cfg(not(unix))]
pub(crate) fn lock_is_held(_path: &Path) -> bool {
    false
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
/// table yielded. Zero servers: nothing enrols (`None`). Exactly one: it
/// owns every live lock — the overwhelmingly common case. Two or more: only
/// the Linux tie-break ([`holder_via_proc_fd`]) can disambiguate; wherever
/// it can't (a non-Linux unix, or a Linux fd-scan miss) this taught-refuses
/// to `None` with one audit line rather than guess.
pub(crate) fn lock_holder(servers: &[u32], lock: &Path) -> Option<u32> {
    match servers {
        [] => None,
        [only] => Some(*only),
        many => holder_via_proc_fd(many, lock).or_else(|| {
            eprintln!(
                "[aoide/codex_app] codex app-server owner ambiguous ({} servers)",
                many.len()
            );
            None
        }),
    }
}

/// The ONE permitted `cfg(target_os = "linux")` extra (§4 P-CX-2 of the
/// P-CX design brief): scan each candidate's `/proc/<pid>/fd` for a
/// descriptor whose target is this exact lock path. A tie-break only —
/// never the primary discovery path, and never consulted for liveness
/// (that is always [`lock_is_held`]'s flock).
#[cfg(target_os = "linux")]
fn holder_via_proc_fd(candidates: &[u32], lock: &Path) -> Option<u32> {
    for &pid in candidates {
        let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for entry in entries.flatten() {
            if std::fs::read_link(entry.path()).map(|t| t == lock).unwrap_or(false) {
                return Some(pid);
            }
        }
    }
    None
}

/// No `/proc` on this platform — see [`lock_holder`]'s doc for what an
/// unresolved tie leads to (a taught "owner ambiguous", never a guess).
#[cfg(not(target_os = "linux"))]
fn holder_via_proc_fd(_candidates: &[u32], _lock: &Path) -> Option<u32> {
    None
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
/// assumption about nesting depth).
fn find_rollout(dir: &Path, thread_id: &str) -> Option<PathBuf> {
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

/// Assemble the live [`CodexThread`] set straight off `~/.codex` — the ONLY
/// I/O this module performs before handing off to
/// [`reconcile_codex_app_threads`]. No `codex_home` (env has neither
/// `CODEX_HOME` nor `HOME`): no work, no directory read. The process table
/// is read ONLY when at least one lock came back held, so a box with no
/// desktop app installed forks nothing.
///
/// `known` is the id→cwd map of threads a `kind:"app"` record already
/// carries (built by the caller from the current stage, BEFORE this
/// function runs). A `sessions/**` walk ([`thread_cwd`]/[`find_rollout`],
/// unbounded DFS) is expensive to repeat every tick for no reason: an id
/// already `known` with a non-empty cwd carries that cwd through UNCHANGED,
/// and the walk runs only for an id that is new or whose known cwd is
/// empty — once per NEW thread id, never once per tick for an
/// already-enrolled one.
pub(crate) fn codex_app_threads(known: &BTreeMap<String, String>) -> Vec<CodexThread> {
    let Some(home) = codex_home() else {
        return Vec::new();
    };
    let locks = live_thread_locks(&home.join("thread-writer-locks"));
    let held: Vec<PathBuf> = locks.into_iter().filter(|p| lock_is_held(p)).collect();
    if held.is_empty() {
        return Vec::new();
    }
    let procs = process_table()
        .map(|table| parse_process_table(&table))
        .unwrap_or_default();
    let servers = codex_app_servers(&procs);
    held.into_iter()
        .filter_map(|lock| {
            let id = lock.file_stem()?.to_str()?.to_string();
            let pid = lock_holder(&servers, &lock);
            let cwd = match known.get(&id) {
                Some(cwd) if !cwd.is_empty() => cwd.clone(),
                _ => thread_cwd(&home, &id).unwrap_or_default(),
            };
            Some(CodexThread { id, cwd, pid })
        })
        .collect()
}

/// The I/O wrapper over [`reconcile_codex_app_threads`] — gathers the live
/// thread set, reconciles under the stage lock, and re-stages `graph.json`
/// only when something changed. Mirrors
/// [`super::window::sync_untracked_terminal_windows`]'s shape exactly. NO
/// CALL SITE YET (P-CX-3 wires the listener/daemon tick); reachable only
/// from its own tests until then — the same standing
/// [`reconcile_codex_app_threads`] itself has carried since P-CX-1.
///
/// Reads the stage TWICE: once here (outside the lock) to build
/// [`codex_app_threads`]'s `known` id→cwd map off the current `kind:"app"`
/// records — so an already-enrolled thread's `sessions/**` walk runs once
/// per NEW id, never once per tick — and once more inside
/// `with_stage_lock` for the actual reconcile. The gather itself (the lock
/// probes, the `ps` shell-out, the rollout walk for a genuinely new id)
/// stays OUTSIDE the stage lock either way, unchanged from before.
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
    let threads = codex_app_threads(&known);
    aoide_storage::fs::with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let (sessions, changed) =
            reconcile_codex_app_threads(std::mem::take(&mut file.sessions), &threads);
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

    fn thread(id: &str, cwd: &str, pid: Option<u32>) -> CodexThread {
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
            &[thread(
                "01a07d89-5f9b-7900-b909-d5eb9457c195",
                "/home/khoa/Aoide",
                Some(2598256),
            )],
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
            &[
                thread("01a07d89-thread-one", "/home/khoa/Aoide", Some(2598256)),
                thread(
                    "01a08a23-thread-two",
                    "/home/khoa/Documents/Codex/2026-09-10/wha",
                    Some(2598256),
                ),
            ],
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
            &[thread("01a07d89-gone", "/home/khoa/Aoide", Some(2598256))],
        );
        assert_eq!(first.len(), 1);
        let (second, changed) = reconcile_codex_app_threads(first, &[]);
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
            &[thread("01a07d89-claimed", "/home/khoa/Aoide", Some(2598256))],
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
            &[thread("01a07d89-live", "/home/khoa/Aoide", Some(2598256))],
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
            &[thread("01a07d89-drift", "/home/khoa/Aoide", Some(2598256))],
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

    #[test]
    fn an_ambiguous_owner_enrols_the_thread_with_no_pid_and_no_window() {
        let (out, changed) = reconcile_codex_app_threads(
            vec![],
            &[thread("01a07d89-ambiguous", "/home/khoa/Aoide", None)],
        );
        assert!(changed);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].pid, None,
            "an ambiguous owner enrols the thread with no pid"
        );
        assert!(
            out[0].window_address.is_empty(),
            "and no window — nothing may guess one"
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
    /// and its own codex app-server child — the genuine multi-server case
    /// `lock_holder` cannot resolve without the Linux tie-break.
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
    fn two_app_servers_leave_the_holder_unresolved_without_the_linux_tiebreak() {
        let procs = parse_process_table(PS_TWO_APP_SERVERS);
        let servers = codex_app_servers(&procs);
        assert_eq!(servers, vec![2598256, 3000002]);
        // Neither pid actually holds any real `/proc/<pid>/fd` entry for
        // this path, so even the REAL Linux tie-break compiled into this
        // test binary cannot resolve it — the ambiguity is genuine, not a
        // stubbed-out cfg swapped in for the test.
        let lock = Path::new("/nonexistent/thread-writer-locks/some-thread.lock");
        assert_eq!(lock_holder(&servers, lock), None);
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
        assert!(
            lock_is_held(&path),
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
        assert!(!lock_is_held(&path));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_probe_never_creates_a_missing_lock_file() {
        let dir = unique_stage("codex-lock-missing");
        let path = dir.join("thread.lock");
        assert!(!path.exists());
        assert!(!lock_is_held(&path));
        assert!(
            !path.exists(),
            "the probe must never create the file it is checking"
        );
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
            codex_app_threads(&BTreeMap::new()).is_empty(),
            "no codex_home means no work at all"
        );
    }

    #[test]
    fn a_known_thread_keeps_its_cwd_without_a_walk_while_a_new_one_still_walks() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["CODEX_HOME", "HOME"]);
        let home = unique_stage("codex-known-vs-new");
        std::env::set_var("CODEX_HOME", &home);
        std::env::set_var("HOME", home.join("unused-home"));

        let lock_dir = home.join("thread-writer-locks");
        std::fs::create_dir_all(&lock_dir).unwrap();
        let known_id = "01a07d89-already-known";
        let new_id = "01a08a23-brand-new";
        let known_lock = lock_dir.join(format!("{known_id}.lock"));
        let new_lock = lock_dir.join(format!("{new_id}.lock"));
        std::fs::write(&known_lock, b"").unwrap();
        std::fs::write(&new_lock, b"").unwrap();

        // Hold both locks (a separate fd each) so both read as live threads.
        use std::os::unix::io::AsRawFd;
        let held_known = std::fs::OpenOptions::new().read(true).open(&known_lock).unwrap();
        let held_new = std::fs::OpenOptions::new().read(true).open(&new_lock).unwrap();
        assert_eq!(
            unsafe { libc::flock(held_known.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert_eq!(
            unsafe { libc::flock(held_new.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );

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

        let threads = codex_app_threads(&known);

        unsafe {
            libc::flock(held_known.as_raw_fd(), libc::LOCK_UN);
            libc::flock(held_new.as_raw_fd(), libc::LOCK_UN);
        }
        drop(held_known);
        drop(held_new);
        std::fs::remove_dir_all(&home).ok();

        let known_thread = threads.iter().find(|t| t.id == known_id).expect("known thread enrolled");
        assert_eq!(
            known_thread.cwd, "/home/khoa/AlreadyKnown",
            "a known id must carry its known cwd through, never re-walk for it"
        );
        let new_thread = threads.iter().find(|t| t.id == new_id).expect("new thread enrolled");
        assert_eq!(
            new_thread.cwd, "/home/khoa/NewProject",
            "a genuinely new id must still get its header cwd off the rollout walk"
        );
    }

    #[test]
    fn the_unsupported_platform_string_names_flock_and_the_process_table() {
        assert!(UNSUPPORTED_PLATFORM.contains("file locks"));
        assert!(UNSUPPORTED_PLATFORM.contains("process table"));
    }
}
