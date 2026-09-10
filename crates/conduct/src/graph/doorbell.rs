//! The doorbell's RING (P-M5a-2, `docs/architecture/MAIL.md` "Delivery and
//! the doorbell"). Slice 1 (971cad8) stored the latch —
//! `aoide_storage::mail`'s `arms`/`ring_targets`/`stamp_rung`/
//! `armed_names_for_reader`/`enrol_reader`. This module is what actually
//! rings: when an arming entry (a `letter`) is filed to a mailbox name,
//! every armed reader of that name whose wrap is headless and whose agent
//! child is at the prompt gets one line written to the wrap's control
//! socket and submitted — latched (never repeated) until the reader reads.
//!
//! **One cross-process critical section, never the stage lock.** The whole
//! select → inject → stamp sequence for a name runs under
//! [`aoide_storage::mail::with_ring_lock`]'s dedicated `.ring.lock` file —
//! held across the real socket I/O and the submit-keystroke delay, which the
//! ordinary stage `flock` (`aoide_storage::fs::with_stage_lock`, taken only
//! briefly and never nested, inside the storage primitives this module
//! calls) must never be asked to do. Any process that links this crate may
//! ring — the daemon on a reader's Stop hook, the CLI on `mail ring` by
//! hand, `aoide-server`'s A2A door on a deposit — and two concurrent rings
//! simply serialize on the file lock: the second selects after the first
//! stamped, and finds the latch already closed.
//!
//! **Raw injection, never [`super::send::session_send`].** A ring writes
//! directly with [`super::send::write_delivery`] — no gate, no pending
//! queue, no provenance prefix, no title rename. The nudge line is the only
//! thing that ever reaches the socket, followed by the target's own submit
//! keystroke.
//!
//! **The client crate cannot see this module.** `aoide-client`'s `mail send`
//! (self branch) forwards `mail ring` through `aoide_client::daemon::
//! daemon_dispatch` instead of calling [`ring`] directly (the crate DAG:
//! `aoide-client` sits below `aoide-conduct`); `aoide-server`'s deposit arm,
//! which already depends on this crate, calls [`ring`] in-process.

use super::doc::is_conductable_now;
use super::model::{load_stage, sessions_path, SessionRecord, SessionsFile};
use super::permit::profile_for_agent;
use super::send::{write_delivery, SUBMIT_KEYSTROKE_DELAY};
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;
use std::collections::HashSet;
use std::os::unix::net::UnixStream;

/// One `ring(name, _)` call's outcome, per target wrap id — the shape both
/// [`mail_ring`]'s JSON data and a caller inspecting [`ring`] directly want.
/// A wrap id never appears in more than one of the three vectors.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RingReport {
    /// The mailbox name this report is for.
    pub name: String,
    /// Wrap ids the nudge was actually written to (and receipted + latched).
    pub rung: Vec<String>,
    /// (wrap id, canonical child state) — armed, ready in every other way,
    /// but the child's own turn is not yet settled (`working`/`awaiting`/
    /// `done`). The latch is untouched: the NEXT trigger (another letter, or
    /// this reader's own Stop hook) tries again.
    pub deferred: Vec<(String, String)>,
    /// (wrap id, reason) — `unknown` (armed but no session record),
    /// `not-conductable` (`is_conductable_now` false, including a socket
    /// file that no longer exists), `interactive-composer` (not headless),
    /// `no-readiness-signal` (no hook-fed agent child), or `write-failed`
    /// (the socket connect/write itself failed). The latch is untouched in
    /// every case.
    pub skipped: Vec<(String, String)>,
}

/// The one line ever written to a target's socket ahead of its own submit
/// keystroke — `<name>` substituted, nothing else. Never carries the
/// letter's own text: the function's only input is the mailbox name, so
/// there is no parameter through which a letter's bytes could ride along.
fn nudge_line(name: &str) -> String {
    format!("[aoide mail] new mail for {name} — aoide mail read --for {name}")
}

/// Self-check-then-walk-up (the shape `window.rs`'s `windowless_by_lineage`/
/// `windowless_by_lineage_from_parent` pair walks, generalized to a
/// different question): is `id` itself a conducted wrap
/// (`conductable == Some(true)`), or does its `parentSessionId` chain reach
/// one? Cycle-guarded; `None` for a dangling link, a chain that never
/// crosses a conducted record, or an unknown starting id.
fn conducted_ancestor(id: &str, sessions: &[SessionRecord]) -> Option<String> {
    let mut current = id.to_string();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return None; // cycle guard
        }
        let rec = sessions.iter().find(|s| s.session_id == current)?;
        if rec.conductable == Some(true) {
            return Some(rec.session_id.clone());
        }
        current = rec.parent_session_id.clone()?;
    }
}

/// The petname fallback (MAIL.md "Delivery and the doorbell"): called ONLY
/// when [`aoide_storage::mail::ring_targets`] reports `enrolled == 0` for
/// `name` — a real reader already enrolled (armed or latched) must never be
/// second-guessed by a display-name coincidence. Every session record whose
/// `petname` equals `name` is resolved to its [`conducted_ancestor`] and
/// that ancestor is `enrol_reader`-ed, deduplicated (a fan of hook-fed
/// children sharing one wrap enrols the wrap once, not once per child).
/// Best-effort: an enrol failure for one match never stops the others.
fn petname_fallback(name: &str, sessions: &[SessionRecord]) {
    let mut enrolled = HashSet::new();
    for rec in sessions {
        if rec.petname.as_deref() != Some(name) {
            continue;
        }
        let Some(ancestor) = conducted_ancestor(&rec.session_id, sessions) else {
            continue;
        };
        if enrolled.insert(ancestor.clone()) {
            let _ = aoide_storage::mail::enrol_reader(name, &ancestor);
        }
    }
}

/// The select → inject → stamp core, run ONLY from inside
/// [`aoide_storage::mail::with_ring_lock`]'s closure (see [`ring`]) — never
/// call this directly outside that lock.
fn ring_locked(name: &str, exclude: Option<&str>) -> RingReport {
    let mut report = RingReport { name: name.to_string(), ..Default::default() };

    let mut targets = match aoide_storage::mail::ring_targets(name) {
        Ok(t) => t,
        Err(_) => return report,
    };

    if targets.enrolled == 0 {
        if let Ok(file) = load_stage::<SessionsFile>(&sessions_path()) {
            petname_fallback(name, &file.sessions);
        }
        targets = match aoide_storage::mail::ring_targets(name) {
            Ok(t) => t,
            Err(_) => return report,
        };
    }

    let sessions: Vec<SessionRecord> = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions)
        .unwrap_or_default();

    for (wrap_id, seq) in &targets.armed {
        // The filer's own wrap is never rung for its own letter — not even
        // reported: it was never really a candidate.
        if exclude.is_some_and(|ex| ex == wrap_id) {
            continue;
        }

        let Some(wrap) = sessions.iter().find(|s| &s.session_id == wrap_id) else {
            report.skipped.push((wrap_id.clone(), "unknown".to_string()));
            continue;
        };

        if !is_conductable_now(wrap) {
            report.skipped.push((wrap_id.clone(), "not-conductable".to_string()));
            continue;
        }

        if !wrap.headless {
            report.skipped.push((wrap_id.clone(), "interactive-composer".to_string()));
            continue;
        }

        // Readiness is the CHILD's hook state — the hook-fed agent session
        // whose parent is this wrap and whose `agent` names a registered
        // harness profile (`agent_profile` returning `None` is the
        // "unknown/never hooked" signal; `profile_for_agent`'s own
        // CLAUDE_PROFILE fallback would hide that signal instead).
        let child = sessions.iter().find(|s| {
            s.parent_session_id.as_deref() == Some(wrap_id.as_str())
                && aoide_protocol::agents::agent_profile(&s.agent).is_some()
        });
        let Some(child) = child else {
            report.skipped.push((wrap_id.clone(), "no-readiness-signal".to_string()));
            continue;
        };

        let state = aoide_protocol::state::canonical_state(&child.state);
        if state != "stopped" && state != "idle" {
            report.deferred.push((wrap_id.clone(), state.to_string()));
            continue;
        }

        // `is_conductable_now` already proved `wrap.socket` is `Some`,
        // non-empty, and exists on disk.
        let socket = wrap.socket.as_deref().unwrap_or_default();
        let line = nudge_line(name);
        let payload = format!("{line}\n");
        let profile = profile_for_agent(&child.agent);

        let wrote = (|| -> std::io::Result<()> {
            let mut stream = UnixStream::connect(socket)?;
            write_delivery(&mut stream, payload.as_bytes(), true, profile.submit_key, SUBMIT_KEYSTROKE_DELAY)
        })();

        match wrote {
            Ok(()) => {
                // Best-effort filing + latch, exactly like `deliver_local_with`'s
                // own receipt write (`send.rs`): a mailbase problem must never
                // turn an already-delivered nudge into a reported failure, but
                // the stamp itself only ever follows a socket write that
                // returned `Ok` — a failed write leaves the reader armed.
                let _ = aoide_storage::mail::file_receipt(name, wrap_id, &line);
                let _ = aoide_storage::mail::stamp_rung(name, wrap_id, *seq);
                report.rung.push(wrap_id.clone());
            }
            Err(_) => {
                report.skipped.push((wrap_id.clone(), "write-failed".to_string()));
            }
        }
    }

    report
}

/// Ring every armed reader of `name`, excluding `exclude` (the filer's own
/// session, never rung for its own letter) if given. `Err("invalid-name")`
/// for a name that fails [`aoide_storage::node_store::valid_node_name`] —
/// checked BEFORE the lock is even attempted, so a bad name never touches
/// the filesystem. Any other `Err` is a lock-acquisition failure
/// ([`aoide_storage::mail::with_ring_lock`]'s own fail-closed contract).
pub fn ring(name: &str, exclude: Option<&str>) -> Result<RingReport, String> {
    if !aoide_storage::node_store::valid_node_name(name) {
        return Err("invalid-name".to_string());
    }
    let name = name.to_string();
    let exclude = exclude.map(str::to_string);
    aoide_storage::mail::with_ring_lock(move || ring_locked(&name, exclude.as_deref()))
}

/// `mail ring --for <name> [--from <session-id>]` — the local doorbell
/// (`commands/graph.rs::register_mail_ring`). Rings IN-PROCESS regardless of
/// which door dispatched it: the `.ring.lock` file is the serializer, not a
/// daemon-only code path. `--from` is the filer's own session id, excluded
/// from the ring exactly like [`ring`]'s own `exclude` parameter.
pub fn mail_ring(inv: &Invocation) -> Outcome {
    let cmd = "mail.ring";
    let name = match inv.flags.get("for").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, "usage: aoide mail ring --for <name>"),
    };
    let exclude = inv.flags.get("from").map(String::as_str).filter(|s| !s.is_empty());
    match ring(name, exclude) {
        Ok(report) => Outcome::ok(cmd, format!("rang {} reader(s) for {name}", report.rung.len())).with_data(json!({
            "name": report.name,
            "rung": report.rung,
            "deferred": report.deferred,
            "skipped": report.skipped,
        })),
        Err(reason) if reason == "invalid-name" => {
            Outcome::error(cmd, "mailbox name must match ^[a-z0-9][a-z0-9-]*$")
                .with_data(json!({ "reason": "invalid-name" }))
        }
        Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::conduct::conduct_socket_path;
    use crate::graph::model::{load_stage, sessions_path, write_stage, SessionsFile};
    use crate::graph::session_store::{do_session_phase, do_session_start, stamp_headless};
    use crate::graph::testutil::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// Point every state/stage/runtime env var this crate's writers read at
    /// a fresh, isolated temp dir — the same six vars
    /// `a_delivered_local_send_is_filed_into_the_mailbase` (`send.rs`)
    /// saves/restores around itself. Caller owns the returned dir (remove it
    /// when done) and must hold `crate::env_lock()` for the test's duration
    /// (env vars are process-global).
    fn setup(tag: &str) -> PathBuf {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");
        root
    }

    /// Bind `id`'s control socket and register it as a HEADLESS conducted
    /// wrap — `do_session_start` first, `stamp_headless` right after, the
    /// same two-step `graph/conduct.rs`'s own `--headless` registration
    /// takes. Returns the bound listener so a test can accept the ring's
    /// connection.
    fn headless_wrap(id: &str) -> UnixListener {
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(id, Some("claude"), Some("/w"), None, None, Some(true), Some(socket.to_str().unwrap()), None, None);
        stamp_headless(id);
        listener
    }

    /// Register `id` as an ordinary hook-fed session, child of `parent`,
    /// running `agent` — the shape a real harness's SessionStart hook
    /// registers. Starts `idle`; a test moves it with `do_session_phase`.
    fn hook_child(id: &str, parent: &str, agent: &str) {
        do_session_start(id, Some(agent), Some("/w"), None, Some(parent), None, None, None, None);
    }

    /// Stamp a display name directly onto an already-registered record —
    /// there is no dedicated petname mutator (`session_store.rs` mints one
    /// at registration for a real caller); direct field assignment is the
    /// same shape `doc.rs`'s own petname tests already use.
    fn set_petname(id: &str, name: &str) {
        let mut file: SessionsFile = load_stage(&sessions_path()).unwrap();
        if let Some(rec) = file.sessions.iter_mut().find(|s| s.session_id == id) {
            rec.petname = Some(name.to_string());
        }
        write_stage(&sessions_path(), &file).unwrap();
    }

    fn read_all(listener: UnixListener) -> Vec<u8> {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let _ = conn.read_to_end(&mut buf);
        buf
    }

    #[test]
    fn nudge_text_contains_no_letter_bytes() {
        let line = nudge_line("claude-mail");
        assert_eq!(line, "[aoide mail] new mail for claude-mail — aoide mail read --for claude-mail");
        // The function's only input is the mailbox NAME — there is no
        // parameter through which a letter's own text could reach here.
        assert!(!line.contains('\n'), "exactly one line, nothing appended: {line:?}");
    }

    #[test]
    fn an_invalid_name_is_refused_and_never_rewritten() {
        for bad in ["\u{1b}bad", "$(rm -rf)", "bad;name", "bad\rname", "bad\nname", "Uppercase"] {
            match ring(bad, None) {
                Err(e) => assert_eq!(e, "invalid-name", "input {bad:?}"),
                Ok(r) => panic!("expected invalid-name for {bad:?}, got {r:?}"),
            }
        }
    }

    #[test]
    fn a_name_with_no_enrolled_reader_and_no_matching_petname_rings_nothing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-empty");

        let report = ring("claude-mail", None).unwrap();
        assert!(report.rung.is_empty());
        assert!(report.deferred.is_empty());
        assert!(report.skipped.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_latched_reader_blocks_the_petname_fallback() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-latched");
        let name = "claude-mail";

        aoide_storage::mail::enrol_reader(name, "wrap-1").unwrap();
        let entry = aoide_storage::mail::file_letter("someone", name, "hello").unwrap();
        aoide_storage::mail::stamp_rung(name, "wrap-1", entry.seq).unwrap();

        // A session record whose petname matches `name` exists on disk — if
        // the fallback ran despite an already-enrolled reader, this is who
        // it would (wrongly) enrol and ring.
        let mut file: SessionsFile = load_stage(&sessions_path()).unwrap_or_default();
        let mut rec = session("petname-match", "/w", "idle", "t0", None);
        rec.petname = Some(name.to_string());
        rec.conductable = Some(true);
        file.sessions.push(rec);
        write_stage(&sessions_path(), &file).unwrap();

        let report = ring(name, None).unwrap();
        assert!(report.rung.is_empty());
        assert!(report.deferred.is_empty());
        assert!(report.skipped.is_empty());

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.enrolled, 1, "the fallback must never enrol on top of an already-enrolled reader");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_petname_match_on_an_agent_child_enrols_and_rings_its_conducted_ancestor() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-petname");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";

        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        set_petname(child_id, name);

        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        assert_eq!(report.rung, vec![wrap_id.to_string()], "{report:?}");
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.enrolled, 1, "the ANCESTOR is enrolled, not the child");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_letter_after_a_fallback_ring_finds_the_target_enrolled_and_latched() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-fallback-twice");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";

        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        set_petname(child_id, name);

        aoide_storage::mail::file_letter("someone", name, "first").unwrap();
        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        acc.join().unwrap();
        assert_eq!(report.rung, vec![wrap_id.to_string()]);

        // A second letter arrives before the reader has read anything.
        aoide_storage::mail::file_letter("someone", name, "second").unwrap();
        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.enrolled, 1, "no duplicate enrolment from a second fallback pass");
        assert!(targets.armed.is_empty(), "still latched: the reader has not read yet");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_recorded_reader_whose_socket_file_is_gone_is_skipped_and_stays_armed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-gone-socket");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let socket = conduct_socket_path(wrap_id);
        // Recorded, conductable, headless — but nothing ever bound the path.
        do_session_start(wrap_id, Some("claude"), Some("/w"), None, None, Some(true), Some(socket.to_str().unwrap()), None, None);
        stamp_headless(wrap_id);

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.skipped, vec![(wrap_id.to_string(), "not-conductable".to_string())]);
        assert!(report.rung.is_empty());

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "the latch stays armed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_working_child_defers_and_stays_armed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-working");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let _listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "working");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.deferred, vec![(wrap_id.to_string(), "working".to_string())]);
        assert!(report.rung.is_empty());

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "the latch stays armed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_awaiting_child_defers_and_stays_armed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-awaiting");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let _listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "awaiting");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.deferred, vec![(wrap_id.to_string(), "awaiting".to_string())]);
        assert!(report.rung.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stopped_or_idle_child_under_a_headless_wrap_is_rung() {
        for state in ["stopped", "idle"] {
            let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
            let _env = EnvVars::save(&[
                "AOIDE_STAGE_DIR",
                "AOIDE_STATE_DIR",
                "XDG_RUNTIME_DIR",
                "AOIDE_AUDIT_LOG",
                "AOIDE_CONDUCT_AUTOGATE",
                "AOIDE_SESSION_ID",
            ]);
            let root = setup(&format!("ring-ready-{state}"));
            let name = "claude-mail";
            let wrap_id = "wrap-1";
            let child_id = "wrap-1-child";
            let listener = headless_wrap(wrap_id);
            hook_child(child_id, wrap_id, "claude");
            do_session_phase(child_id, state);

            aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
            aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

            let acc = std::thread::spawn(move || read_all(listener));
            let report = ring(name, None).unwrap();
            acc.join().unwrap();
            assert_eq!(report.rung, vec![wrap_id.to_string()], "state {state}: {report:?}");

            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn an_interactive_wrap_is_skipped_untouched_and_stays_armed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-interactive");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let socket = conduct_socket_path(wrap_id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        // conductable + a real socket, but NEVER `stamp_headless` — an
        // ordinary interactive conducted terminal.
        do_session_start(wrap_id, Some("claude"), Some("/w"), None, None, Some(true), Some(socket.to_str().unwrap()), None, None);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.skipped, vec![(wrap_id.to_string(), "interactive-composer".to_string())]);
        assert!(report.rung.is_empty());

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "the latch stays armed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_wrap_with_no_hook_fed_child_is_skipped_no_readiness_signal() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-no-child");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let _listener = headless_wrap(wrap_id);
        // No child registered at all.

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.skipped, vec![(wrap_id.to_string(), "no-readiness-signal".to_string())]);
        assert!(report.rung.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_submit_key_is_the_childs_harness_key_not_the_wraps() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-submit-key");
        let name = "claude-mail";
        let wrap_id = "wrap-1"; // registered with agent "claude" (submit "\n")
        let child_id = "wrap-1-child"; // agent "kimi" (submit "\r")
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "kimi");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();
        assert_eq!(report.rung, vec![wrap_id.to_string()]);

        let expected = format!("{}\n\r", nudge_line(name));
        assert_eq!(bytes, expected.as_bytes(), "kimi's own \\r, never claude's \\n");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_ring_is_two_writes_the_line_then_the_targets_own_submit_key() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-two-writes");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "kimi");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let _ = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        // `write_delivery` writes `payload` (the line + its own trailing
        // `\n`), flushes, then SEPARATELY writes the submit key alone — kimi's
        // `\r` is chosen here precisely because it differs from the payload's
        // own trailing `\n`, so the join is unambiguous.
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.ends_with('\r'), "the LAST byte is the submit key: {bytes:?}");
        assert_eq!(&bytes[..bytes.len() - 1], format!("{}\n", nudge_line(name)).as_bytes());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_ring_never_retitles_or_prefixes_the_target() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-no-retitle");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();
        assert_eq!(report.rung, vec![wrap_id.to_string()]);

        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with(&nudge_line(name)), "raw line only: {text:?}");
        assert!(!text.contains("from "), "no provenance prefix: {text:?}");

        let file: SessionsFile = load_stage(&sessions_path()).unwrap();
        let wrap = file.sessions.iter().find(|s| s.session_id == wrap_id).unwrap();
        assert!(wrap.title.is_none(), "a ring must never rename its target");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_filing_session_is_never_rung_for_its_own_letter() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-exclude-self");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let _listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter(wrap_id, name, "hello").unwrap();

        let report = ring(name, Some(wrap_id)).unwrap();
        assert!(report.rung.is_empty());
        assert!(report.deferred.is_empty());
        assert!(report.skipped.is_empty());

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "excluded, not consumed — still armed for a later, non-excluded ring");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_ring_files_one_receipt_and_never_a_letter() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-one-receipt");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();
        let before = aoide_storage::mail::read_base().unwrap().len();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        acc.join().unwrap();
        assert_eq!(report.rung, vec![wrap_id.to_string()]);

        let after = aoide_storage::mail::read_base().unwrap();
        assert_eq!(after.len(), before + 1, "exactly one new entry: the receipt");
        let filed = after.last().unwrap();
        assert_eq!(filed.kind, aoide_storage::mail::ENTRY_TYPE_RECEIPT);
        assert_eq!(filed.envelope.header.from.name, name);
        assert_eq!(filed.envelope.header.to.name, wrap_id);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_concurrent_burst_of_filers_rings_once() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-burst");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let name = name.to_string();
                std::thread::spawn(move || ring(&name, None).unwrap())
            })
            .collect();
        let reports: Vec<RingReport> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let bytes = acc.join().unwrap();

        let total_rung: usize = reports.iter().map(|r| r.rung.len()).sum();
        assert_eq!(total_rung, 1, "exactly one of the 8 concurrent calls actually rings: {reports:?}");
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

        let receipts = aoide_storage::mail::read_base()
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == aoide_storage::mail::ENTRY_TYPE_RECEIPT)
            .count();
        assert_eq!(receipts, 1, "exactly one receipt, never one per racing caller");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_socket_write_leaves_the_latch_armed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-write-failed");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let socket = conduct_socket_path(wrap_id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // Bind, then drop: the socket special file is left behind on disk
        // (`is_conductable_now` sees it), but nothing is listening, so the
        // connect itself fails — the write-failed path, not not-conductable.
        drop(UnixListener::bind(&socket).unwrap());
        do_session_start(wrap_id, Some("claude"), Some("/w"), None, None, Some(true), Some(socket.to_str().unwrap()), None, None);
        stamp_headless(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.skipped, vec![(wrap_id.to_string(), "write-failed".to_string())], "{report:?}");
        assert!(report.rung.is_empty());

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "the latch stays armed after a failed write");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_stop_hook_replays_a_deferred_ring() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-stop-replay");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "working");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        // Working: a direct ring defers, never consuming the letter.
        let pre = ring(name, None).unwrap();
        assert_eq!(pre.deferred, vec![(wrap_id.to_string(), "working".to_string())]);

        // The child's OWN Stop hook fires next — no direct `ring` call.
        let acc = std::thread::spawn(move || read_all(listener));
        let payload = format!(r#"{{"session_id":"{child_id}","hook_event_name":"Stop"}}"#);
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("__daemon-stdin-payload".to_string(), payload);
        let inv = Invocation {
            path: vec!["session".to_string(), "hook".to_string()],
            args: Vec::new(),
            flags,
            door: aoide_protocol::Door::Cli,
        };
        let out = super::super::send::session_hook(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);

        let bytes = acc.join().unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)), "the Stop hook replayed the ring");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hundred_letters_ring_once_until_the_reader_reads() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-hundred");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();

        for n in 0..100 {
            aoide_storage::mail::file_letter("someone", name, &format!("letter {n}")).unwrap();
        }

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        acc.join().unwrap();
        assert_eq!(report.rung, vec![wrap_id.to_string()], "one hundred arming letters still ring exactly once");

        let receipts = aoide_storage::mail::read_base()
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == aoide_storage::mail::ENTRY_TYPE_RECEIPT)
            .count();
        assert_eq!(receipts, 1);

        // Read: catches the mark up, clearing the latch.
        aoide_storage::mail::read_for(name, false, Some(wrap_id)).unwrap();
        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert!(targets.armed.is_empty(), "read catches the mark up — no residual arm");

        // A 101st letter re-arms it, and a second ring fires again. The
        // first listener was consumed by `read_all`'s own `accept`, so the
        // wrap's socket needs a fresh bind at the same path.
        aoide_storage::mail::file_letter("someone", name, "letter 101").unwrap();
        let socket = conduct_socket_path(wrap_id);
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).unwrap();
        let acc = std::thread::spawn(move || read_all(listener));
        let report2 = ring(name, None).unwrap();
        acc.join().unwrap();
        assert_eq!(report2.rung, vec![wrap_id.to_string()], "re-armed after the read, rings again");

        let _ = std::fs::remove_dir_all(&root);
    }
}
