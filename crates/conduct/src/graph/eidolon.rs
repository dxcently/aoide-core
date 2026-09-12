//! Eidolon presence reconciliation (P-EIDOLON slice E1b, readiness E2 folded
//! in) — enrolling a live `eidolon` session, observed from OUTSIDE, as a
//! `SessionRecord`. Mirrors `codex_app.rs` rule for rule: one record per
//! NATIVE presence id, keyed verbatim (no synthetic prefix — the id is
//! already stable), a [`PresenceScan`] seam where `Observed` carries
//! positive evidence and `Unknown` changes nothing, a pure reconciler
//! ([`reconcile_eidolon_sessions`]) plus one I/O wrapper
//! ([`sync_eidolon_sessions`]), and a petname minted only on INSERT so a
//! rescan preserves it.
//!
//! Two differences from the Codex precedent, both because eidolon's own
//! liveness contract differs from a try-flock:
//!
//!   * **Liveness is the presence socket answering `{"op":"ping"}` with
//!     `{"ok":true}`** (eidolon's own `crates/swarm/src/socket.rs:94-117`,
//!     `:33`'s 250ms timeout) — never a stat, never `/proc`. Aoide never
//!     sweeps `$XDG_RUNTIME_DIR/eidolon` the way eidolon's own `scan` does
//!     as a side effect of listing it (`presence.rs:328-353`) — reading is
//!     not owning.
//!   * **This IS an agent session** (`kind:"agent"`, not codex's
//!     `kind:"app"`), so it is a normal dedup/staleness candidate once
//!     enrolled, unlike a codex "app" record. `parentSessionId` IS drawn
//!     here (codex defers that to a later slice) — the first conducted
//!     ancestor via the same `/proc` ancestry walk `identity::attested_wrap`
//!     already uses, narrowed to `conductable == Some(true)` and injected as
//!     a pure function so the reconciler stays testable without a real
//!     `/proc` (the codex P-CX-2b precedent for splitting pure core from
//!     I/O: `codex_app.rs`'s own module doc).
//!
//! Readiness (E2, folded in per the brief: "the state a record carries is
//! written by the same reconciler in the same function"): a TUI owner's
//! `busy` (`meta.json`) is a real fact — `true` → `"working"`, `false` →
//! `"idle"`. A non-TUI owner's `busy` is eidolon's own producer-side defect
//! P3 (`crates/cli/src/main.rs:1550` never calls `set_busy`) — permanently
//! `false` — so such a record carries the literal `state:"unknown"` rather
//! than a guessed working/idle: `aoide_protocol::canonical_state("unknown")`
//! folds that to `"idle"` (the vocabulary's own "absence of evidence" arm),
//! which is deliberate, not a gap — the safety property belongs to the
//! transport (E3), never to inventing a sixth state. `awaiting`/`error`/
//! `cancel` are never producible here: eidolon's pending-approval and
//! streaming events live only on the in-process `Event` bus
//! (`core/src/event.rs:1-7`), never in `meta.json`.
//!
//! TUI-vs-not is read off the presence pid's own argv, via the SAME parsed
//! `ps -axo pid=,ppid=,command=` table `codex_app.rs` already owns
//! ([`super::codex_app::process_table`]/[`super::codex_app::
//! parse_process_table`]) — never a second discovery path, never a raw
//! `/proc/<pid>/cmdline` read.

use super::codex_app::{parse_process_table, process_table, Proc};
use super::doc::restage_graph;
use super::model::{
    canonical_state, load_stage, sessions_path, write_stage, SessionRecord, SessionsFile,
    STAGE_GRAPH_VERSION,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One live eidolon presence, already resolved from its `meta.json` and the
/// process table — the pure-core input for [`reconcile_eidolon_sessions`],
/// mirroring `codex_app::CodexThread`. `tui` is resolved by the GATHER step
/// (the presence pid's argv against the process table), never by the
/// reconciler itself — same split as `CodexThread.pid`'s ownership proof.
#[derive(Debug, Clone)]
pub(crate) struct EidolonSession {
    /// The native presence id, verbatim (`meta.json`'s own `id`, the
    /// directory name) — becomes `sessionId` unchanged.
    pub id: String,
    pub pid: u32,
    pub cwd: String,
    /// `meta.json.log` — this session's own durable transcript path.
    pub log: String,
    pub model: String,
    pub title: String,
    /// `meta.json.busy` — a real fact for a TUI owner (P3), permanently
    /// `false` for anything else.
    pub busy: bool,
    /// No subcommand, or an explicit `tui` token, on the presence pid's own
    /// argv (`main.rs:313-320`) — read off the process table, not guessed.
    pub tui: bool,
}

/// One gather of the live presence set — keeps a FAILED or INCOMPLETE
/// observation from ever reading as a confirmed exit, the identical contract
/// `codex_app::ThreadScan` holds (`codex_app.rs:88-104`). `Observed` carries
/// positive evidence for every directory under the presence root, including
/// a positively observed empty set; `Unknown` means some step of the gather
/// could not complete and says nothing about any session.
/// [`reconcile_eidolon_sessions`] acts on `Observed` alone.
#[derive(Debug)]
pub(crate) enum PresenceScan {
    Observed(Vec<EidolonSession>),
    Unknown(ScanFailure),
}

/// Why a [`PresenceScan`] came back `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanFailure {
    /// The presence root exists but could not be listed (permissions, an
    /// I/O error). A MISSING root is `Observed(empty)` instead — no eidolon
    /// session has ever registered, a genuine fact.
    RootUnreadable,
    /// A presence directory's `meta.json` could not be read/parsed for a
    /// reason other than having simply vanished since the listing (a
    /// vanished directory is skipped, not unknown — the same race eidolon's
    /// own `GRACE_MS` exists for on the producer side).
    MetaUnavailable,
    /// At least one presence socket answered and [`process_table`] returned
    /// `None` — no `ps` on `PATH`.
    ProcessTableUnavailable,
}

/// Reconcile `agent:"eidolon"` records against a [`PresenceScan`] — the PURE
/// CORE (fed fake scans and an injected ancestry walk in tests), mirroring
/// [`super::codex_app::reconcile_codex_app_threads`] rule for rule:
///
///   * A desired presence with no existing record is INSERTED, keyed by its
///     native id verbatim.
///   * An existing `agent:"eidolon"` record for a still-desired presence is
///     upserted IN PLACE, change-only.
///   * A record whose presence is no longer desired (its socket stopped
///     answering) is REMOVED — only ever on an `Observed` pass, never on
///     `Unknown`.
///   * A native id already claimed by a non-eidolon record is left entirely
///     alone: never inserted, overwritten, or removed here (`codex_app.rs`'s
///     `claimed` set, same shape).
///
/// `ancestry_of(pid)` is the self-first `/proc` ancestry walk
/// ([`aoide_storage::attest::pid_ancestry`] in production) — injected so
/// this stays testable without a real process tree, the same P-CX-2b split
/// `codex_app.rs`'s own module doc explains. `parentSessionId` is the
/// nearest ancestor that is itself a conducted wrap (`conductable ==
/// Some(true)`, not already `done`) — no ancestor found means a top-level
/// record, never an invented parent edge. The wrap's own record (and its
/// petname) is only ever READ here, never written.
///
/// `windowAddress`/`workspace` are left at their `Default` (empty/absent) on
/// every insert and never touched on upsert — the existing
/// `resolve_pending_session_windows` sweep fills them from the same
/// ancestry, because the record carries a pid and an empty address.
pub(crate) fn reconcile_eidolon_sessions(
    mut sessions: Vec<SessionRecord>,
    scan: &PresenceScan,
    ancestry_of: impl Fn(u32) -> Vec<i32>,
) -> (Vec<SessionRecord>, bool) {
    let live: &[EidolonSession] = match scan {
        PresenceScan::Unknown(_) => return (sessions, false),
        PresenceScan::Observed(live) => live,
    };

    // Native ids already claimed by a TRACKED, non-eidolon record — never
    // ours to insert, overwrite, or remove.
    let claimed: HashSet<String> = sessions
        .iter()
        .filter(|s| s.agent != "eidolon")
        .map(|s| s.session_id.clone())
        .collect();

    let mut desired: HashMap<&str, &EidolonSession> = HashMap::new();
    for t in live {
        if claimed.contains(t.id.as_str()) {
            continue;
        }
        desired.insert(t.id.as_str(), t);
    }

    let mut changed = false;

    // Drop `agent:"eidolon"` records whose presence is no longer desired.
    let before = sessions.len();
    sessions.retain(|s| s.agent != "eidolon" || desired.contains_key(s.session_id.as_str()));
    if sessions.len() != before {
        changed = true;
    }

    for (id, t) in &desired {
        let parent = resolve_parent(t.pid, &sessions, &ancestry_of);
        let state = eidolon_state(t.busy, t.tui);
        if let Some(rec) = sessions.iter_mut().find(|s| s.session_id.as_str() == *id) {
            if rec.pid != Some(t.pid) {
                rec.pid = Some(t.pid);
                changed = true;
            }
            if rec.cwd != t.cwd {
                rec.cwd = t.cwd.clone();
                changed = true;
            }
            if rec.model.as_deref() != Some(t.model.as_str()) {
                rec.model = Some(t.model.clone());
                changed = true;
            }
            if rec.title.as_deref() != Some(t.title.as_str()) {
                rec.title = Some(t.title.clone());
                changed = true;
            }
            if rec.log_path.as_deref() != Some(t.log.as_str()) {
                rec.log_path = Some(t.log.clone());
                changed = true;
            }
            if rec.state != state {
                rec.state = state.to_string();
                changed = true;
            }
            if rec.parent_session_id != parent {
                rec.parent_session_id = parent.clone();
                changed = true;
            }
            // The fixed identity, re-applied every upsert.
            if rec.agent != "eidolon" {
                rec.agent = "eidolon".to_string();
                changed = true;
            }
            if rec.kind.as_deref() != Some("agent") {
                rec.kind = Some("agent".to_string());
                changed = true;
            }
        } else {
            let petname = aoide_storage::petname::mint_for(&sessions);
            sessions.push(SessionRecord {
                session_id: id.to_string(),
                agent: "eidolon".to_string(),
                cwd: t.cwd.clone(),
                state: state.to_string(),
                kind: Some("agent".to_string()),
                pid: Some(t.pid),
                model: Some(t.model.clone()),
                title: Some(t.title.clone()),
                log_path: Some(t.log.clone()),
                parent_session_id: parent,
                petname: Some(petname),
                ..Default::default()
            });
            changed = true;
        }
    }

    (sessions, changed)
}

/// A TUI owner's `busy` is a real fact (P3); anything else carries the
/// literal `"unknown"` — never a guessed `working`/`idle` for a shape
/// eidolon's own producer cannot report on. `awaiting`/`error`/`cancel` are
/// not in this function's range at all: they cannot be produced.
fn eidolon_state(busy: bool, tui: bool) -> &'static str {
    if !tui {
        return "unknown";
    }
    if busy {
        "working"
    } else {
        "idle"
    }
}

/// The nearest ancestor of `pid` (self-first) that is itself a conducted wrap
/// currently on the roster — the identical `conductable == Some(true)` +
/// not-`done` narrowing `identity::attested_wrap` applies, minus the seal
/// verification (this is a plain lineage read, not a security gate).
/// `ancestry_of` is the injected walk; production passes
/// `aoide_storage::attest::pid_ancestry`.
fn resolve_parent(
    pid: u32,
    sessions: &[SessionRecord],
    ancestry_of: &impl Fn(u32) -> Vec<i32>,
) -> Option<String> {
    for ancestor in ancestry_of(pid) {
        if ancestor < 0 {
            continue;
        }
        if let Some(rec) = sessions.iter().find(|s| {
            s.pid == Some(ancestor as u32)
                && s.conductable == Some(true)
                && canonical_state(&s.state) != "done"
        }) {
            return Some(rec.session_id.clone());
        }
    }
    None
}

// ── Discovery: read-only over $XDG_RUNTIME_DIR/eidolon ──────────────────

/// `$XDG_RUNTIME_DIR/eidolon`, falling back to the temp dir — the identical
/// derivation eidolon's own `Presence::root()` uses
/// (`crates/swarm/src/presence.rs:104-110`), reproduced read-only here since
/// Aoide does not depend on the eidolon crate. Aoide only ever LISTS and
/// READS this tree; it never sweeps a dead entry out of it — that stays the
/// producer's own job (`presence.rs::scan`, `:328-353`).
fn presence_root() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("eidolon")
}

/// The subset of `meta.json`'s fields this reconciler needs — a read-only
/// reproduction of eidolon's own `Meta` (`presence.rs:29-51`), not a
/// dependency on it. Field names match verbatim (no `#[serde(rename)]` on
/// eidolon's own struct), so no remapping is needed; extra fields on disk
/// (`repo`, `started_ms`) are simply ignored by `serde_json`.
#[derive(Debug, serde::Deserialize)]
struct PresenceMeta {
    id: String,
    pid: u32,
    log: String,
    cwd: String,
    model: String,
    title: String,
    busy: bool,
}

/// Does the presence socket at `path` answer `{"op":"ping"}` with
/// `{"ok":true}`, inside the SAME 250ms budget the producer's own client
/// enforces (`socket.rs:33`)? Liveness IS this answer — never a stat, never
/// `/proc`. Every failure (no such socket, a refused connection, a timeout,
/// a reply that isn't exactly `{"ok":true}`) reads as NOT LIVE: eidolon's
/// own client (`socket.rs::probe`) draws the identical binary line, with no
/// third "can't tell" state for one directory's probe.
fn socket_answers(path: &Path) -> bool {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    const PING_TIMEOUT: Duration = Duration::from_millis(250);

    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    if stream.set_read_timeout(Some(PING_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(PING_TIMEOUT)).is_err()
    {
        return false;
    }
    if stream.write_all(br#"{"op":"ping"}"#).is_err() {
        return false;
    }
    if stream.shutdown(std::net::Shutdown::Write).is_err() {
        return false;
    }
    let mut buf = String::new();
    if stream.read_to_string(&mut buf).is_err() {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(&buf)
        .ok()
        .and_then(|v| v.get("ok").and_then(serde_json::Value::as_bool))
        == Some(true)
}

/// No subcommand, or an explicit `tui` token, on this argv is the TUI
/// (`main.rs:313-320`); `run`/`chat`/`resume`/anything else is not. Pure —
/// `argv` is one row of the SAME parsed process table
/// [`eidolon_presence_sessions_with`] already owns, never a second
/// discovery path.
fn is_tui_argv(argv: &[String]) -> bool {
    match argv.get(1) {
        None => true,
        Some(sub) => sub == "tui",
    }
}

/// Assemble the live presence set straight off `$XDG_RUNTIME_DIR/eidolon` as
/// a [`PresenceScan`] — the ONLY I/O this module performs before handing off
/// to [`reconcile_eidolon_sessions`]. Delegates to
/// [`eidolon_presence_sessions_with`] with the real
/// [`super::codex_app::process_table`], split out so a test can inject a
/// table without shelling out to a real `ps`.
pub(crate) fn eidolon_presence_sessions() -> PresenceScan {
    eidolon_presence_sessions_with(process_table)
}

/// The testable core of [`eidolon_presence_sessions`]. A missing presence
/// root is `Observed(empty)` — no eidolon session has ever registered on
/// this box, a genuine fact, not a failed observation. An unreadable root,
/// an unreadable/unparseable `meta.json` (short of it simply having
/// vanished since the listing), or `process_table` coming back `None` while
/// at least one socket answered are all `Unknown` — the identical "a failed
/// step invalidates the whole pass" discipline `codex_app_threads_with`
/// holds. A directory whose socket does not answer contributes nothing —
/// positively not live, exactly like a released flock — never `Unknown`.
fn eidolon_presence_sessions_with(process_table: impl Fn() -> Option<String>) -> PresenceScan {
    let root = presence_root();
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PresenceScan::Observed(Vec::new())
        }
        Err(_) => return PresenceScan::Unknown(ScanFailure::RootUnreadable),
    };

    let mut live_meta = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let raw = match std::fs::read(dir.join("meta.json")) {
            Ok(raw) => raw,
            // Gone between the listing and the read: a genuine, transient
            // race (eidolon's own `GRACE_MS`-style window), not evidence
            // this pass cannot trust.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return PresenceScan::Unknown(ScanFailure::MetaUnavailable),
        };
        let meta: PresenceMeta = match serde_json::from_slice(&raw) {
            Ok(meta) => meta,
            Err(_) => return PresenceScan::Unknown(ScanFailure::MetaUnavailable),
        };
        if !socket_answers(&dir.join("sock")) {
            continue;
        }
        live_meta.push(meta);
    }

    if live_meta.is_empty() {
        return PresenceScan::Observed(Vec::new());
    }

    let Some(table) = process_table() else {
        return PresenceScan::Unknown(ScanFailure::ProcessTableUnavailable);
    };
    let procs: Vec<Proc> = parse_process_table(&table);

    let sessions = live_meta
        .into_iter()
        .map(|meta| {
            // Absent from the table (a race, or a truncated `ps` read) never
            // aborts the whole pass — a live socket already proved the
            // session real; missing TUI evidence degrades to `false`, which
            // can only ever under-report `"unknown"` in place of
            // `working`/`idle`, never invent either.
            let tui = procs
                .iter()
                .find(|p| p.pid == meta.pid)
                .is_some_and(|p| is_tui_argv(&p.argv));
            EidolonSession {
                id: meta.id,
                pid: meta.pid,
                cwd: meta.cwd,
                log: meta.log,
                model: meta.model,
                title: meta.title,
                busy: meta.busy,
                tui,
            }
        })
        .collect();
    PresenceScan::Observed(sessions)
}

/// Guards [`audit_scan_unknown_once`] to one audit line per process, the
/// identical guard [`super::codex_app`] keeps for its own
/// `ProcessTableUnavailable` case: `ps` missing from `PATH` is a host
/// misconfiguration that won't self-heal tick to tick, so a tick that keeps
/// hitting it stays silent after the first line — the fix is what stops a
/// failed scan from mattering (no record is ever removed on `Unknown`), not
/// a growing log.
static PROCESS_TABLE_UNKNOWN_AUDITED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// One audit line, at most once per process, for the one [`ScanFailure`]
/// worth flagging: `ps` absent from `PATH`. `RootUnreadable`/
/// `MetaUnavailable` are per-tick, per-directory races (permissions, a
/// vanished file) that the next tick routinely clears on its own — logging
/// those would just be noise.
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
        "eidolon presence scan skipped: ps not on PATH (records kept)",
    );
}

/// The I/O wrapper over [`reconcile_eidolon_sessions`] — gathers a
/// [`PresenceScan`], reconciles under the stage lock, re-stages `graph.json`
/// only when something changed. Mirrors
/// [`super::codex_app::sync_codex_app_threads`]'s shape. An `Unknown` scan
/// takes NO stage lock and writes NOTHING.
pub(crate) fn sync_eidolon_sessions() -> bool {
    let scan = eidolon_presence_sessions();
    if let PresenceScan::Unknown(failure) = &scan {
        audit_scan_unknown_once(failure);
        return false;
    }
    aoide_storage::fs::with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let (sessions, changed) =
            reconcile_eidolon_sessions(std::mem::take(&mut file.sessions), &scan, |pid| {
                aoide_storage::attest::pid_ancestry(pid as i32)
            });
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

    fn presence(id: &str, pid: u32, cwd: &str, busy: bool, tui: bool) -> EidolonSession {
        EidolonSession {
            id: id.to_string(),
            pid,
            cwd: cwd.to_string(),
            log: format!("/home/khoa/.local/share/eidolon/sessions/{id}.eid"),
            model: "claude-cli:opus".to_string(),
            title: "ng".to_string(),
            busy,
            tui,
        }
    }

    /// No ancestry chain matches anything on the roster — a top-level record.
    fn no_ancestry(_pid: u32) -> Vec<i32> {
        Vec::new()
    }

    #[test]
    fn a_live_presence_becomes_one_record_keyed_by_its_native_id() {
        let (out, changed) = reconcile_eidolon_sessions(
            vec![],
            &PresenceScan::Observed(vec![presence(
                "khoa-253b",
                3514983,
                "/home/khoa",
                false,
                true,
            )]),
            no_ancestry,
        );
        assert!(changed);
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.session_id, "khoa-253b");
        assert_eq!(r.agent, "eidolon");
        assert_eq!(r.kind.as_deref(), Some("agent"));
        assert_eq!(r.pid, Some(3514983));
        assert_eq!(r.cwd, "/home/khoa");
        assert_eq!(r.model.as_deref(), Some("claude-cli:opus"));
        assert_eq!(r.title.as_deref(), Some("ng"));
        assert_eq!(
            r.log_path.as_deref(),
            Some("/home/khoa/.local/share/eidolon/sessions/khoa-253b.eid")
        );
        assert_eq!(r.state, "idle", "busy:false on a TUI owner is idle");
        assert_eq!(r.parent_session_id, None, "no ancestor -> top-level");
        assert!(
            r.window_address.is_empty(),
            "windowAddress is filled later by the window sweep, never here"
        );
        assert_eq!(r.workspace, None);
        assert!(
            r.petname.is_some(),
            "a freshly enrolled record mints a petname"
        );
    }

    /// The live-target shape (`P-EIDOLON` rev 3 §1's acceptance table): a
    /// wrap (`conduct-3513862-…`, petname `plucky-comet`), a bash shell
    /// under it, and eidolon under that — the FIRST conducted ancestor via
    /// pid ancestry is the wrap, not the intervening shell.
    #[test]
    fn the_live_target_shape_enrols_with_the_wraps_petname_untouched() {
        let mut wrap = session(
            "conduct-3513862-1789234665",
            "/home/khoa",
            "working",
            "t",
            None,
        );
        wrap.agent = "shell".to_string();
        wrap.conductable = Some(true);
        wrap.pid = Some(3513862);
        wrap.petname = Some("plucky-comet".to_string());

        let ancestry = |pid: u32| -> Vec<i32> {
            assert_eq!(pid, 3514983, "walked from meta.json's own pid");
            vec![3514983, 3513878, 3513862]
        };

        let (out, changed) = reconcile_eidolon_sessions(
            vec![wrap.clone()],
            &PresenceScan::Observed(vec![presence(
                "khoa-253b",
                3514983,
                "/home/khoa",
                false,
                true,
            )]),
            ancestry,
        );
        assert!(changed);
        assert_eq!(out.len(), 2);

        let eidolon_rec = out.iter().find(|s| s.session_id == "khoa-253b").unwrap();
        assert_eq!(eidolon_rec.agent, "eidolon");
        assert_eq!(eidolon_rec.kind.as_deref(), Some("agent"));
        assert_eq!(
            eidolon_rec.parent_session_id.as_deref(),
            Some("conduct-3513862-1789234665"),
            "the FIRST conducted ancestor, skipping the intervening bash shell"
        );

        let wrap_after = out
            .iter()
            .find(|s| s.session_id == "conduct-3513862-1789234665")
            .unwrap();
        assert_eq!(
            wrap_after.petname, wrap.petname,
            "the wrap's own petname is never touched"
        );
    }

    #[test]
    fn a_second_reconcile_changes_nothing_and_re_mints_no_petname() {
        let scan = PresenceScan::Observed(vec![presence(
            "khoa-253b",
            3514983,
            "/home/khoa",
            false,
            true,
        )]);
        let (first, changed1) = reconcile_eidolon_sessions(vec![], &scan, no_ancestry);
        assert!(changed1);
        let petname_after_first = first[0].petname.clone();

        let (second, changed2) = reconcile_eidolon_sessions(first, &scan, no_ancestry);
        assert!(
            !changed2,
            "an unchanged presence must report no change on rescan"
        );
        assert_eq!(
            second[0].petname, petname_after_first,
            "rescan must never re-mint a petname"
        );
    }

    #[test]
    fn two_presences_in_one_cwd_are_two_distinct_records() {
        let (out, changed) = reconcile_eidolon_sessions(
            vec![],
            &PresenceScan::Observed(vec![
                presence("aoide-aa11", 111, "/home/khoa/Aoide", false, true),
                presence("aoide-bb22", 222, "/home/khoa/Aoide", false, true),
            ]),
            no_ancestry,
        );
        assert!(changed);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|r| r.session_id == "aoide-aa11"));
        assert!(out.iter().any(|r| r.session_id == "aoide-bb22"));
        assert_ne!(
            out[0].petname, out[1].petname,
            "two distinct presences must never share a minted petname"
        );
    }

    #[test]
    fn a_presence_whose_socket_stopped_answering_loses_its_record() {
        let (first, _) = reconcile_eidolon_sessions(
            vec![],
            &PresenceScan::Observed(vec![presence("khoa-gone", 111, "/home/khoa", false, true)]),
            no_ancestry,
        );
        assert_eq!(first.len(), 1);
        let (second, changed) =
            reconcile_eidolon_sessions(first, &PresenceScan::Observed(Vec::new()), no_ancestry);
        assert!(changed);
        assert!(
            second.is_empty(),
            "a presence with no live socket keeps no record"
        );
    }

    #[test]
    fn an_unknown_scan_changes_nothing() {
        let existing = {
            let (out, _) = reconcile_eidolon_sessions(
                vec![],
                &PresenceScan::Observed(vec![presence("khoa-x", 1, "/home/khoa", false, true)]),
                no_ancestry,
            );
            out
        };
        let before = existing.clone();
        let (out, changed) = reconcile_eidolon_sessions(
            existing,
            &PresenceScan::Unknown(ScanFailure::ProcessTableUnavailable),
            no_ancestry,
        );
        assert!(!changed);
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }

    #[test]
    fn busy_and_tui_map_to_the_three_state_shape_with_the_unknown_trap_pinned() {
        assert_eq!(eidolon_state(true, true), "working");
        assert_eq!(eidolon_state(false, true), "idle");
        // A non-TUI owner (P3: busy is permanently false) carries the
        // LITERAL "unknown" -- and canonical_state folds it to "idle", not a
        // deferred/awaiting verdict. Both assertions live in this one test
        // so the trap stays pinned together.
        assert_eq!(eidolon_state(false, false), "unknown");
        assert_eq!(
            eidolon_state(true, false),
            "unknown",
            "a non-TUI owner's busy is never trusted"
        );
        assert_eq!(canonical_state("unknown"), "idle");
    }

    #[test]
    fn awaiting_error_and_cancel_are_never_produced() {
        for busy in [true, false] {
            for tui in [true, false] {
                let s = eidolon_state(busy, tui);
                assert!(
                    !matches!(s, "awaiting" | "error" | "cancel"),
                    "eidolon_state({busy}, {tui}) produced the taught-absent {s:?}"
                );
            }
        }
    }

    #[test]
    fn a_record_with_a_pid_and_no_address_is_left_for_the_window_sweep() {
        let (out, _) = reconcile_eidolon_sessions(
            vec![],
            &PresenceScan::Observed(vec![presence("khoa-y", 1, "/home/khoa", false, true)]),
            no_ancestry,
        );
        assert_eq!(out[0].pid, Some(1));
        assert!(
            out[0].window_address.is_empty(),
            "never stamped by this reconciler"
        );
    }

    #[test]
    fn an_id_already_claimed_by_a_tracked_non_eidolon_record_is_left_alone() {
        let tracked = session("khoa-claimed", "/home/khoa/Aoide", "working", "t", None);
        let (out, changed) = reconcile_eidolon_sessions(
            vec![tracked.clone()],
            &PresenceScan::Observed(vec![presence(
                "khoa-claimed",
                1,
                "/home/khoa/Aoide",
                false,
                true,
            )]),
            no_ancestry,
        );
        assert!(
            !changed,
            "a claimed id must never be touched by the eidolon reconciler"
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent, tracked.agent);
        assert_eq!(out[0].kind, tracked.kind);
        assert_eq!(out[0].pid, tracked.pid);
    }

    // ── discovery primitives ───────────────────────────────────────────

    #[test]
    fn is_tui_argv_reads_no_subcommand_or_an_explicit_tui_token_as_the_tui() {
        let no_sub = vec!["/home/khoa/.local/bin/eidolon".to_string()];
        assert!(is_tui_argv(&no_sub));
        let tui = vec![
            "/home/khoa/.local/bin/eidolon".to_string(),
            "tui".to_string(),
        ];
        assert!(is_tui_argv(&tui));
        for sub in ["run", "chat", "resume", "sessions", "send"] {
            let argv = vec!["/home/khoa/.local/bin/eidolon".to_string(), sub.to_string()];
            assert!(!is_tui_argv(&argv), "`{sub}` is not the TUI");
        }
    }

    #[test]
    fn socket_answers_is_false_for_a_socket_nothing_is_listening_on() {
        let dir = unique_stage("eidolon-socket-dead");
        assert!(!socket_answers(&dir.join("sock")), "no listener at all");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn socket_answers_true_only_for_an_exact_ok_reply() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = unique_stage("eidolon-socket-live");
        let path = dir.join("sock");
        let listener = UnixListener::bind(&path).unwrap();
        let accept_path = path.clone();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(br#"{"ok":true}"#);
            let _ = accept_path;
        });
        assert!(socket_answers(&path));
        handle.join().unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn eidolon_presence_sessions_with_a_live_meta_and_socket_resolves_tui_off_the_table() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["XDG_RUNTIME_DIR"]);
        let root = unique_stage("eidolon-presence-root");
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        let presence_dir = presence_root();
        std::fs::create_dir_all(presence_dir.join("khoa-253b")).unwrap();
        std::fs::write(
            presence_dir.join("khoa-253b").join("meta.json"),
            serde_json::json!({
                "id": "khoa-253b",
                "pid": 3514983,
                "log": "/home/khoa/.local/share/eidolon/sessions/1789234755480.eid",
                "cwd": "/home/khoa",
                "repo": null,
                "model": "claude-cli:opus",
                "started_ms": 0,
                "title": "ng",
                "busy": false
            })
            .to_string(),
        )
        .unwrap();

        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let sock_path = presence_dir.join("khoa-253b").join("sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(br#"{"ok":true}"#);
        });

        let table = "3514983 3513878 /home/khoa/.local/bin/eidolon\n";
        let scan = eidolon_presence_sessions_with(|| Some(table.to_string()));
        handle.join().unwrap();

        match scan {
            PresenceScan::Observed(sessions) => {
                assert_eq!(sessions.len(), 1);
                let s = &sessions[0];
                assert_eq!(s.id, "khoa-253b");
                assert_eq!(s.pid, 3514983);
                assert_eq!(s.cwd, "/home/khoa");
                assert!(s.tui, "no subcommand on the table row is the TUI");
                assert!(!s.busy);
            }
            PresenceScan::Unknown(f) => panic!("expected Observed, got Unknown({f:?})"),
        }
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_dead_socket_is_excluded_without_ever_consulting_the_process_table() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["XDG_RUNTIME_DIR"]);
        let root = unique_stage("eidolon-presence-dead");
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        let presence_dir = presence_root();
        std::fs::create_dir_all(presence_dir.join("khoa-dead")).unwrap();
        std::fs::write(
            presence_dir.join("khoa-dead").join("meta.json"),
            serde_json::json!({
                "id": "khoa-dead", "pid": 1, "log": "x", "cwd": "/home/khoa",
                "repo": null, "model": "m", "started_ms": 0, "title": "t", "busy": false
            })
            .to_string(),
        )
        .unwrap();
        // No socket bound at all -- a dead leftover directory.
        let scan = eidolon_presence_sessions_with(|| panic!("ps must never be shelled out to"));
        assert!(matches!(scan, PresenceScan::Observed(v) if v.is_empty()));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn no_presence_root_at_all_is_observed_empty_not_unknown() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["XDG_RUNTIME_DIR"]);
        let root = unique_stage("eidolon-presence-none");
        std::fs::remove_dir_all(&root).ok(); // exists() must be false
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        let scan = eidolon_presence_sessions_with(|| panic!("ps must never be shelled out to"));
        assert!(matches!(scan, PresenceScan::Observed(v) if v.is_empty()));
    }
}
