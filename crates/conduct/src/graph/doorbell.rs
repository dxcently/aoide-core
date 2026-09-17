//! The doorbell's RING (P-M5a-2, corrected at P-M5a-2c, transport choice
//! added at P-M5c-3 — `docs/architecture/MAIL.md` "Delivery and the
//! doorbell"). Slice 1 (971cad8) stored the latch — `aoide_storage::mail`'s
//! `arms`/`ring_targets`/`stamp_rung`/`armed_names_for_reader`/
//! `enrol_reader`. This module is what actually rings: when an arming entry
//! (a `letter`) is filed to a mailbox name, every armed reader of that name
//! whose agent child is at the prompt gets nudged — over its live Claude
//! Code channel socket ([`channel_socket_path`]) when one is bound, which
//! needs no submit keystroke and so works for an interactive composer too;
//! otherwise, for a headless wrap, one line written to the wrap's control
//! socket and submitted — latched (never repeated) until the reader reads.
//!
//! **A ring executes only inside the resident daemon — the policy and audit
//! boundary for every ring, not merely a serialization detail (the
//! architecture owner's ruling on b8af466, P-M5a-2c).** [`ring`] itself is
//! called from exactly two places: [`mail_ring`]'s own `Door::Daemon` arm,
//! and the Stop-hook replay (`send.rs`) when that hook is likewise being
//! handled under `Door::Daemon`. Every other door — the CLI, MCP, a bare
//! `mail ring` typed at a terminal with no daemon behind it yet — forwards
//! through [`aoide_client::daemon::daemon_dispatch`] instead of ringing
//! locally; no daemon reachable reports `"ring": "no-daemon"` and writes
//! nothing to any socket.
//!
//! **One cross-process critical section, never the stage lock.** The whole
//! select → inject → stamp sequence for a name runs under
//! [`aoide_storage::mail::with_ring_lock`]'s dedicated `.ring.lock` file —
//! held across the real socket I/O and the submit-keystroke delay, which the
//! ordinary stage `flock` (`aoide_storage::fs::with_stage_lock`, taken only
//! briefly and never nested, inside the storage primitives this module
//! calls) must never be asked to do. `.ring.lock` is the DAEMON's OWN
//! serializer for concurrent rings inside one process (and across a restart
//! overlap), never a second policy boundary of its own — the boundary above
//! is what makes the daemon the only process that ever reaches this file at
//! all; two overlapping rings simply serialize on it, the second selecting
//! after the first stamped and finding the latch already closed.
//!
//! **Raw injection, never [`super::send::session_send`].** A channel ring
//! writes the nudge line to the channel socket, once, then closes — no
//! submit keystroke, nothing else on the wire. A PTY ring (headless, no
//! live channel) writes directly with [`super::send::write_delivery`] — no
//! gate, no pending queue, no provenance prefix, no title rename — and that
//! one is followed by the target's own submit keystroke.
//!
//! **Every other door forwards, never rings.** `aoide-client`'s `mail send`
//! (self branch) already forwarded `mail ring` through
//! [`aoide_client::daemon::daemon_dispatch`] rather than calling [`ring`]
//! directly (the crate DAG: `aoide-client` sits below `aoide-conduct`);
//! [`mail_ring`] now does the identical forward for its own CLI/MCP callers.
//! `aoide-server`'s A2A deposit arm no longer calls [`ring`] at all — a
//! remotely deposited letter arms its readers and waits for the next
//! daemon-side trigger; the remote door's own forward path is P-M5b-2's,
//! deliberately deferred out of this slice.

use super::conduct::channel_socket_path;
use super::doc::is_conductable_now;
use super::model::{load_stage, sessions_path, SessionRecord, SessionsFile};
use super::permit::profile_for_agent;
use super::send::{write_delivery, SUBMIT_KEYSTROKE_DELAY};
use aoide_protocol::output::Outcome;
use aoide_protocol::{Door, Invocation};
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
    /// file that no longer exists), `interactive-composer` (interactive
    /// AND no live channel socket), `no-readiness-signal` (no hook-fed
    /// agent child), or `write-failed` (the chosen transport's connect/
    /// write itself failed — channel or PTY alike). The latch is untouched
    /// in every case.
    pub skipped: Vec<(String, String)>,
}

/// The one line ever written to a target's socket ahead of its own submit
/// keystroke — `<name>` substituted, nothing else. Never carries the
/// letter's own text: the function's only input is the mailbox name, so
/// there is no parameter through which a letter's bytes could ride along.
fn nudge_line(name: &str) -> String {
    format!("[aoide mail] new mail for {name} — aoide mail read --for {name}")
}

/// The channel write itself (P-M5c-3): `payload` once, then a flush — no
/// submit key, ever, and no [`super::send::write_delivery`] (that one
/// exists to add a keystroke this transport must never send). Generic over
/// `Write` because a post-connect write failure is not reproducibly
/// inducible on a real unix socket; the error path is proven against a
/// fake writer, and [`ring_locked`]'s shared `match` on the result is the
/// block the PTY transport's failure test already covers.
///
/// `pub(in crate::graph)`: the ping-back (`graph/pingback.rs`, P-EIDOLON
/// slice E5b) is the SECOND production caller of this one channel write —
/// the same one-write-then-close transport, never a second implementation
/// of it.
pub(in crate::graph) fn write_channel(mut stream: impl std::io::Write, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(payload)?;
    stream.flush()
}

/// How long one of `ring_locked`'s socket writes may block before this
/// module gives up on it (P-M5c-4). `ring_locked` runs its whole
/// select → inject → stamp sequence for a mailbox name under
/// [`aoide_storage::mail::with_ring_lock`]'s `.ring.lock` — held, uniquely
/// in this crate, across real socket I/O, inside the resident daemon — so a
/// peer that accepts the connection but never reads (a wedged agent child, a
/// stopped process, a socket whose owner has hung) fills the kernel buffer
/// and blocks the write forever with no bound in place, parking the
/// daemon's ring against every OTHER mailbox for as long as that one peer
/// stays wedged. A timed-out write returns `Err`, which `ring_locked`'s own
/// `match wrote` already treats as an ordinary transport failure: reported
/// `write-failed`, the latch left untouched, so the reader stays armed for
/// the next trigger — no new outcome, no new arm. Set on the STREAM (via
/// [`connect_for_ring`]), not per-call, so it also covers
/// [`super::send::write_delivery`]'s SECOND write — the submit keystroke —
/// not just the first.
const RING_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The one place `ring_locked` ever opens a socket — both the channel and
/// the PTY transport connect through here (see [`RING_WRITE_TIMEOUT`]'s own
/// doc for why the bound exists) so neither can regress back to a plain,
/// unbounded `UnixStream::connect`. A future third ring transport connects
/// through this too, never a fresh `UnixStream::connect` call of its own.
///
/// `pub(in crate::graph)`, like [`write_channel`]: the ping-back's own
/// delivery (`graph/pingback.rs`, E5b) is the second production caller, and
/// it must inherit this SAME bound — its write lands in a parent's composer
/// and has no business parking the daemon's tick behind a wedged peer.
pub(in crate::graph) fn connect_for_ring(path: impl AsRef<std::path::Path>) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_write_timeout(Some(RING_WRITE_TIMEOUT))?;
    Ok(stream)
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
/// when no key in [`aoide_storage::mail::ring_targets`]'s `enrolled` roster
/// resolves to a session record that [`is_conductable_now`] — a real reader
/// that is still ALIVE, armed or merely latched, must never be
/// second-guessed by a display-name coincidence, but a stale enrolment with
/// no record at all, or one whose socket is gone, must never wall off a
/// mailbox from ever being rung again. Every session record whose `petname`
/// equals `name` is resolved to its [`conducted_ancestor`] and that ancestor
/// is `enrol_reader`-ed, deduplicated (a fan of hook-fed children sharing
/// one wrap enrols the wrap once, not once per child). Best-effort: an
/// enrol failure for one match never stops the others.
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

    // Loaded once: `petname_fallback` reads session records but never
    // writes them, so the same snapshot serves both the liveness check
    // below and the target walk further down — no second load after a
    // fallback pass.
    let sessions: Vec<SessionRecord> = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions)
        .unwrap_or_default();

    let any_live_enrolled = targets
        .enrolled
        .iter()
        .any(|reader| sessions.iter().any(|s| &s.session_id == reader && is_conductable_now(s)));

    if !any_live_enrolled {
        petname_fallback(name, &sessions);
        targets = match aoide_storage::mail::ring_targets(name) {
            Ok(t) => t,
            Err(_) => return report,
        };
    }

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

        // Readiness is the CHILD's hook state — the hook-fed agent session
        // whose parent is this wrap and whose `agent` names a registered
        // harness profile (`agent_profile` returning `None` is the
        // "unknown/never hooked" signal; `profile_for_agent`'s own
        // CLAUDE_PROFILE fallback would hide that signal instead). This
        // gate runs before transport selection and binds every wrap alike,
        // channel or PTY.
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

        let line = nudge_line(name);
        let payload = format!("{line}\n");

        // Transport selection (P-M5c-3): a live Claude Code channel socket
        // outranks the control-socket PTY for ANY wrap, interactive or
        // headless — it is a one-way push into the wrap's own MCP
        // subprocess, never a keystroke, so there is no half-typed
        // composer line to clobber. A stale socket FILE with nothing
        // listening (the owning MCP subprocess died without unlinking it)
        // refuses the connect and falls through to the PTY/skip below —
        // never a stat-only check.
        let channel_write =
            connect_for_ring(channel_socket_path(wrap_id)).ok().map(|stream| write_channel(stream, payload.as_bytes()));

        let wrote = match channel_write {
            Some(result) => result,
            None if wrap.headless => {
                // `is_conductable_now` already proved `wrap.socket` is
                // `Some`, non-empty, and exists on disk.
                let socket = wrap.socket.as_deref().unwrap_or_default();
                let profile = profile_for_agent(&child.agent);
                (|| -> std::io::Result<()> {
                    let mut stream = connect_for_ring(socket)?;
                    write_delivery(&mut stream, payload.as_bytes(), true, profile.submit_key, SUBMIT_KEYSTROKE_DELAY)
                })()
            }
            None => {
                report.skipped.push((wrap_id.clone(), "interactive-composer".to_string()));
                continue;
            }
        };

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
/// (`commands/graph.rs::register_mail_ring`). Rings ONLY under
/// `Door::Daemon` (P-M5a-2c: a ring executes only inside the resident
/// daemon, the policy and audit boundary for every ring). Every other door
/// forwards this exact invocation through [`aoide_client::daemon::
/// daemon_dispatch`] instead — the daemon's own dispatch handler calls this
/// SAME function again, with `door` now `Door::Daemon`, so the ring
/// actually happens there. No daemon reachable reports the outcome's own
/// `ring` field as the literal string `"no-daemon"` and writes nothing to
/// any socket. `--from` is the filer's own session id, excluded from the
/// ring exactly like [`ring`]'s own `exclude` parameter.
pub fn mail_ring(inv: &Invocation) -> Outcome {
    let cmd = "mail.ring";
    let name = match inv.flags.get("for").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, "usage: aoide mail ring --for <name>"),
    };
    // Validated BEFORE any forward: a bad name is refused locally, with no
    // daemon round trip and no name bytes in the message, on every door.
    if !aoide_storage::node_store::valid_node_name(name) {
        return Outcome::error(cmd, "mailbox name must match ^[a-z0-9][a-z0-9-]*$")
            .with_data(json!({ "reason": "invalid-name" }));
    }
    let exclude = inv.flags.get("from").map(String::as_str).filter(|s| !s.is_empty());

    if inv.door != Door::Daemon {
        return match aoide_client::daemon::daemon_dispatch(inv) {
            Some(out) => out,
            None => Outcome::error(cmd, "no daemon reachable — nothing rung")
                .with_data(json!({ "ring": "no-daemon" })),
        };
    }

    match ring(name, exclude) {
        Ok(report) => Outcome::ok(cmd, format!("rang {} reader(s) for {name}", report.rung.len())).with_data(json!({
            "name": report.name,
            "rung": report.rung,
            "deferred": report.deferred,
            "skipped": report.skipped,
        })),
        // `ring`'s own defense-in-depth check — unreachable here in
        // practice, since the name is already validated above before this
        // point is ever reached.
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
    use std::io::{Read as _, Write as _};
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

    /// Bind `id`'s control socket and register it as an ordinary
    /// INTERACTIVE conducted wrap — conductable, a real socket, but never
    /// `stamp_headless`, the same shape `an_interactive_wrap_is_skipped_
    /// untouched_and_stays_armed` builds by hand. Returns the bound
    /// listener so a test can prove the PTY is never written to.
    fn interactive_wrap(id: &str) -> UnixListener {
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(id, Some("claude"), Some("/w"), None, None, Some(true), Some(socket.to_str().unwrap()), None, None);
        listener
    }

    /// Bind `id`'s Claude Code channel socket ([`channel_socket_path`],
    /// P-M5c-2) — the shape `aoide-server`'s stdio MCP server binds for the
    /// lifetime of its own subprocess. Returns the listener so a test can
    /// accept the ring's connection.
    fn channel_listener(id: &str) -> UnixListener {
        let socket = channel_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        UnixListener::bind(&socket).unwrap()
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

    /// Build a `["mail", "ring"]` invocation on `door`, `--for <name>`.
    fn mail_ring_inv(name: &str, door: Door) -> Invocation {
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("for".to_string(), name.to_string());
        Invocation { path: vec!["mail".to_string(), "ring".to_string()], args: Vec::new(), flags, door }
    }

    /// Assert a `UnixListener` receives nothing within a short bound —
    /// nonblocking `accept`, polled rather than a single immediate check, so
    /// a regression that rings asynchronously would still be caught.
    fn assert_nothing_arrives(listener: &UnixListener) {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        loop {
            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("the target must receive nothing: {other:?}"),
            }
            if std::time::Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn ring_outside_the_daemon_forwards_and_never_rings_locally() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
            "AOIDE_DAEMON_SOCKET",
        ]);
        let root = setup("mail-ring-forward");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        // An armed, fully ready target — proof positive it would ring if
        // this call ever reached `ring()` in this process.
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let daemon_socket = root.join("fake-daemon.sock");
        let fake = UnixListener::bind(&daemon_socket).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = fake.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap();
            let req: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
            assert_eq!(req["op"], "dispatch");
            assert_eq!(req["path"][0], "mail");
            assert_eq!(req["path"][1], "ring");
            let outcome = Outcome::ok("mail.ring", "rang 0 reader(s) for claude-mail");
            let reply = json!({ "outcome": outcome });
            let mut line = reply.to_string();
            line.push('\n');
            conn.write_all(line.as_bytes()).unwrap();
        });
        std::env::set_var("AOIDE_DAEMON_SOCKET", &daemon_socket);

        let inv = mail_ring_inv(name, Door::Cli);
        let out = mail_ring(&inv);
        handle.join().unwrap();
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);

        // Forwarded, never rung locally: the armed reader is untouched and
        // its socket never saw a connection.
        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "forwarded, never rung locally");
        assert_nothing_arrives(&listener);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_ring_without_a_daemon_reports_no_daemon_and_writes_nothing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
            "AOIDE_DAEMON_SOCKET",
        ]);
        let root = setup("mail-ring-no-daemon");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("dead.sock"));

        let inv = mail_ring_inv(name, Door::Cli);
        let out = mail_ring(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["ring"], "no-daemon");

        assert_nothing_arrives(&listener);
        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "the latch stays armed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_ring_under_the_daemon_door_rings() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
            "AOIDE_DAEMON_SOCKET",
        ]);
        let root = setup("mail-ring-daemon-door");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();
        // Even a dead daemon socket must never matter here — `Door::Daemon`
        // never forwards, it rings directly.
        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("dead.sock"));

        let acc = std::thread::spawn(move || read_all(listener));
        let inv = mail_ring_inv(name, Door::Daemon);
        let out = mail_ring(&inv);
        let bytes = acc.join().unwrap();
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_invalid_name_is_refused_before_any_forward() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
            "AOIDE_DAEMON_SOCKET",
        ]);
        let root = setup("mail-ring-invalid-name");
        // A dead daemon socket: if the name reached the forward at all, this
        // would answer `no-daemon`, not `invalid-name` — proving the order.
        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("dead.sock"));

        let inv = mail_ring_inv("Bad Name", Door::Cli);
        let out = mail_ring(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "invalid-name");

        let _ = std::fs::remove_dir_all(&root);
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
    fn a_live_latched_reader_still_blocks_the_petname_fallback() {
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
        let wrap_id = "wrap-1";

        // Genuinely live: a bound socket, conducted, headless — not merely
        // a cursor key with nothing behind it.
        let _listener = headless_wrap(wrap_id);
        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        let entry = aoide_storage::mail::file_letter("someone", name, "hello").unwrap();
        aoide_storage::mail::stamp_rung(name, wrap_id, entry.seq).unwrap();

        // A session record whose petname matches `name` exists on disk — if
        // the fallback ran despite an already-enrolled, still-live reader,
        // this is who it would (wrongly) enrol and ring.
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
        assert_eq!(
            targets.enrolled.len(),
            1,
            "the fallback must never enrol on top of an already-enrolled, still-live reader"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stale_enrolment_with_no_session_record_does_not_block_the_petname_fallback() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-stale-no-record");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";

        // A dead enrolment: a cursor key with no session record behind it
        // at all — a wrap that read this mailbox once and later vanished
        // without ever being un-enrolled.
        aoide_storage::mail::enrol_reader(name, "ghost").unwrap();

        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        set_petname(child_id, name);

        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        // The target walk is unchanged: the dead enrolment still walks and
        // still reports `unknown` — liveness governs only whether the
        // fallback runs, never the walk itself.
        assert_eq!(report.skipped, vec![("ghost".to_string(), "unknown".to_string())], "{report:?}");
        assert_eq!(report.rung, vec![wrap_id.to_string()], "the live petname match still gets rung: {report:?}");
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert!(targets.enrolled.iter().any(|r| r == "ghost"), "the stale enrolment is left in place: {targets:?}");
        assert!(targets.enrolled.iter().any(|r| r == wrap_id), "the live match is now enrolled too: {targets:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stale_enrolment_whose_socket_is_gone_does_not_block_the_petname_fallback() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-stale-gone-socket");
        let name = "claude-mail";
        let dead_wrap_id = "dead-wrap";
        let live_wrap_id = "wrap-1";
        let child_id = "wrap-1-child";

        // Recorded, conductable, headless — but nothing ever bound the
        // path (the same shape as `a_recorded_reader_whose_socket_file_
        // is_gone_is_skipped_and_stays_armed`, here as the only prior
        // enrolment a mailbox has).
        let dead_socket = conduct_socket_path(dead_wrap_id);
        do_session_start(
            dead_wrap_id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(dead_socket.to_str().unwrap()),
            None,
            None,
        );
        stamp_headless(dead_wrap_id);
        aoide_storage::mail::enrol_reader(name, dead_wrap_id).unwrap();

        let listener = headless_wrap(live_wrap_id);
        hook_child(child_id, live_wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        set_petname(child_id, name);

        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        // The target walk is unchanged: the dead enrolment still walks and
        // still reports `not-conductable` — liveness governs only whether
        // the fallback runs, never the walk itself.
        assert_eq!(
            report.skipped,
            vec![(dead_wrap_id.to_string(), "not-conductable".to_string())],
            "{report:?}"
        );
        assert_eq!(report.rung, vec![live_wrap_id.to_string()], "the live petname match still gets rung: {report:?}");
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert!(
            targets.enrolled.iter().any(|r| r == dead_wrap_id),
            "the stale enrolment is left in place: {targets:?}"
        );
        assert!(targets.enrolled.iter().any(|r| r == live_wrap_id), "the live match is now enrolled too: {targets:?}");

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
        assert_eq!(targets.enrolled.len(), 1, "the ANCESTOR is enrolled, not the child");

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
        assert_eq!(targets.enrolled.len(), 1, "no duplicate enrolment from a second fallback pass");
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

    // ── P-M5c-3: transport selection ─────────────────────────────────────

    #[test]
    fn an_interactive_wrap_with_a_live_channel_socket_is_rung_over_the_channel() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-channel-interactive");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let pty_listener = interactive_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        let channel = channel_listener(wrap_id);

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(channel));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        assert_eq!(report.rung, vec![wrap_id.to_string()], "{report:?}");
        assert_eq!(bytes, format!("{}\n", nudge_line(name)).into_bytes(), "the channel gets the line and nothing else");
        // The PTY is never touched: the channel wins, never a keystroke,
        // even though this wrap is exactly the kind (interactive, no
        // headless stamp) `an_interactive_wrap_is_skipped_untouched_and_
        // stays_armed` proves is refused when no channel exists.
        assert_nothing_arrives(&pty_listener);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_channel_ring_writes_no_submit_key() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-channel-no-submit");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child"; // agent "kimi" (a PTY ring would submit "\r")
        let _pty_listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "kimi");
        do_session_phase(child_id, "stopped");
        let channel = channel_listener(wrap_id);

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(channel));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        assert_eq!(report.rung, vec![wrap_id.to_string()]);
        // Exactly the line plus its own `\n` — never kimi's own `\r`, never
        // any submit key at all: a channel write is one write and closes.
        assert_eq!(bytes, format!("{}\n", nudge_line(name)).into_bytes());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_channel_present_beats_the_pty_on_a_headless_wrap() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-channel-beats-headless-pty");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let pty_listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        let channel = channel_listener(wrap_id);

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(channel));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        assert_eq!(report.rung, vec![wrap_id.to_string()]);
        assert_eq!(bytes, format!("{}\n", nudge_line(name)).into_bytes());
        // Headless would ordinarily earn the PTY; a live channel outranks
        // it regardless.
        assert_nothing_arrives(&pty_listener);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_headless_wrap_with_no_channel_socket_still_rings_over_the_pty() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-no-channel-still-pty");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        // No channel socket bound at all — the pre-P-M5c-3 shape.

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        assert_eq!(report.rung, vec![wrap_id.to_string()]);
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_working_child_defers_even_with_a_live_channel() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-channel-working-defers");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let _pty_listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "working");
        let channel = channel_listener(wrap_id);

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let report = ring(name, None).unwrap();
        assert_eq!(report.deferred, vec![(wrap_id.to_string(), "working".to_string())]);
        assert!(report.rung.is_empty());
        // A mid-turn child defers on every transport alike — the channel is
        // never written to either.
        assert_nothing_arrives(&channel);

        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "the latch stays armed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_channel_write_that_fails_leaves_the_latch_armed() {
        // A post-connect write failure is not reproducibly inducible on a
        // real socket, so the error path is proven against a fake writer;
        // `ring_locked`'s handling of the `Err` is the shared block
        // `a_failed_socket_write_leaves_the_latch_armed` proves for the PTY.
        struct AlwaysFails;
        impl std::io::Write for AlwaysFails {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let err = write_channel(AlwaysFails, nudge_line("claude-mail").as_bytes())
            .expect_err("a broken pipe must surface as an error, never a silent success");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn an_interactive_wrap_with_no_channel_is_still_skipped_interactive_composer() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-no-channel-interactive-skipped");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let _pty_listener = interactive_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        // No channel socket bound at all.

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
    fn a_stale_channel_socket_file_falls_through_to_the_pty_or_skip() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("ring-stale-channel-socket");
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let pty_listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "stopped");
        // Bind the channel socket, then drop the listener WITHOUT
        // unlinking — the special file is left behind on disk (the shape a
        // SIGKILLed MCP subprocess leaves), so a connect must refuse,
        // never merely stat the path.
        let channel = channel_socket_path(wrap_id);
        std::fs::create_dir_all(channel.parent().unwrap()).unwrap();
        drop(UnixListener::bind(&channel).unwrap());

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let acc = std::thread::spawn(move || read_all(pty_listener));
        let report = ring(name, None).unwrap();
        let bytes = acc.join().unwrap();

        assert_eq!(report.rung, vec![wrap_id.to_string()], "the stale channel file falls through to the PTY: {report:?}");
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)));

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
        let wrap_id = "wrap-1"; // registered with agent "claude" (submit "\r")
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

    /// A peer that accepts the connection but never reads must not be able
    /// to wedge a ring's write forever — `.ring.lock` is held across this
    /// exact call, inside the daemon, so an unbounded write here would park
    /// every OTHER mailbox's ring behind one hung process. Proves three
    /// things about `connect_for_ring`/`RING_WRITE_TIMEOUT` directly, no
    /// full `ring()`/wrap setup needed: the timeout is actually armed on the
    /// stream, a write into a full, undrained buffer gives up with a
    /// timeout-shaped error rather than succeeding or hanging, and it gives
    /// up promptly rather than merely eventually.
    #[test]
    fn a_ring_write_to_a_peer_that_never_reads_gives_up_instead_of_holding_the_ring_lock() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let root = unique_stage("ring-write-timeout");
        let socket = root.join("s.sock");
        let listener = UnixListener::bind(&socket).unwrap();

        let stream = connect_for_ring(&socket).unwrap();
        assert_eq!(
            stream.write_timeout().unwrap(),
            Some(RING_WRITE_TIMEOUT),
            "connect_for_ring must arm the write timeout production relies on"
        );

        // Accepted but never read from — the peer that wedges a ring.
        let _peer = listener.accept().unwrap().0;

        // Far larger than a unix socket's send buffer, so the write
        // genuinely blocks on a peer that never drains it rather than
        // completing in one syscall.
        let payload = vec![b'x'; 8 * 1024 * 1024];
        let started = std::time::Instant::now();
        let result = write_channel(&stream, &payload);
        let elapsed = started.elapsed();

        let err = result.expect_err("a write to a peer that never reads must give up, not succeed");
        assert!(
            matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
            "expected a timeout-shaped error, got: {err:?}"
        );
        assert!(
            elapsed < RING_WRITE_TIMEOUT * 5,
            "the write must give up well under a generous ceiling instead of hanging, took {elapsed:?}"
        );

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
        // `Door::Daemon`: the shape `invocation_from_dispatch_request`
        // (`aoide-server`'s `daemon.rs`) actually builds for a routed hook
        // (P-M5a-2c) — the replay is gated on exactly this, see
        // `the_stop_hook_replays_only_under_the_daemon_door` below.
        let acc = std::thread::spawn(move || read_all(listener));
        let payload = format!(r#"{{"session_id":"{child_id}","hook_event_name":"Stop"}}"#);
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("__daemon-stdin-payload".to_string(), payload);
        let inv = Invocation {
            path: vec!["session".to_string(), "hook".to_string()],
            args: Vec::new(),
            flags,
            door: Door::Daemon,
        };
        let out = super::super::send::session_hook(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);

        let bytes = acc.join().unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)), "the Stop hook replayed the ring");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_stop_hook_replays_only_under_the_daemon_door() {
        // P-M5a-2c: the replay is gated on `may_ring = inv.door ==
        // Door::Daemon` — same payload, same fixture as the test above,
        // fired once under `Door::Cli` (the local-fallback shape a real
        // no-daemon-reachable hook takes) and once under `Door::Daemon`
        // (the shape a real resident `aoided`'s own dispatch handler
        // produces via `invocation_from_dispatch_request`).
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
            "AOIDE_DAEMON_SOCKET",
        ]);
        let root = setup("ring-stop-door-gate");
        // No daemon reachable either way — proves the gate is `inv.door`
        // itself, never a real round trip (the STDIN_PAYLOAD_FLAG shortcut
        // below never attempts one regardless of door).
        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("dead.sock"));
        let name = "claude-mail";
        let wrap_id = "wrap-1";
        let child_id = "wrap-1-child";
        let listener = headless_wrap(wrap_id);
        hook_child(child_id, wrap_id, "claude");
        do_session_phase(child_id, "working");

        aoide_storage::mail::enrol_reader(name, wrap_id).unwrap();
        aoide_storage::mail::file_letter("someone", name, "hello").unwrap();

        let payload = format!(r#"{{"session_id":"{child_id}","hook_event_name":"Stop"}}"#);
        let mut flags = std::collections::BTreeMap::new();
        flags.insert("__daemon-stdin-payload".to_string(), payload.clone());

        // Door::Cli — the local-fallback shape: the Stop hook still settles
        // the child to `stopped`, but the replay must not fire.
        let inv_cli = Invocation {
            path: vec!["session".to_string(), "hook".to_string()],
            args: Vec::new(),
            flags: flags.clone(),
            door: Door::Cli,
        };
        let out = super::super::send::session_hook(&inv_cli);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);
        let targets = aoide_storage::mail::ring_targets(name).unwrap();
        assert_eq!(targets.armed.len(), 1, "Door::Cli must never replay — the latch stays armed");

        // The SAME payload again, this time under Door::Daemon.
        let acc = std::thread::spawn(move || read_all(listener));
        let inv_daemon = Invocation {
            path: vec!["session".to_string(), "hook".to_string()],
            args: Vec::new(),
            flags,
            door: Door::Daemon,
        };
        let out = super::super::send::session_hook(&inv_daemon);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);
        let bytes = acc.join().unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with(&nudge_line(name)), "Door::Daemon replays the ring");

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
