//! `graph resurrect --project <x>` — revive a project's most recently-ended
//! resumable session off the durable ledger (P-D8, `docs/architecture/
//! AOIDED.md`'s "L5 — harness summoning" section). The same command core
//! also backs the daemon's own boot-time auto-resume trigger
//! (`aoide-server`'s `daemon.rs`, called in-process the same way
//! `run_internal_reap` calls `crate::reap::reap_and_announce`).
//!
//! Selection: resolve `--project <x>` against `projects.json` by exact name,
//! read every ledger line whose `cwd` anchors to it (the SAME longest-
//! path-prefix rule `graph emit`'s `anchor_for` uses — reused, never
//! re-derived), then pick candidates. `--all` widens to every anchored
//! entry; `--id` narrows to one specific ledger `sessionId`; bare (neither
//! flag) resumes the project's WHOLE carried set (`state/carry.json`,
//! durable-sessions plan P-C4) — every anchored entry currently marked
//! durable, minus any id already alive in `sessions.json`, deduped by
//! `sessionId` keeping the newest `endedAt` (an append-only ledger can hold
//! more than one exit for the same carried id once it has been resurrected
//! and exited again). `--all` and `--id` are unchanged escapes: both widen
//! or narrow past the carried set regardless of the mark. Each candidate is
//! filtered through its harness's `AgentProfile.resume_args`
//! (`aoide_protocol::agents`): `None` (an unregistered agent, or a harness
//! whose resume argv has never been verified) skips that candidate with a
//! taught message naming the harness, never a guessed invocation.
//!
//! A resurrected session is ALWAYS a fresh `sessionId` — ids are never
//! recycled — spawned via the windowed path ([`super::spawn::session_spawn`]
//! with `--windowed --cwd <the ledger entry's own cwd>`, P-D7/P-D8) so it
//! reopens in a real terminal, in its original project directory. On success
//! the new record is stamped `resumedFrom` (`stamp_resumed_from`), naming the
//! ledger entry's own `sessionId` — `build_graph` projects that as a
//! `resumed` edge beside `spawned`/`anchors` (CONTRACTS.md §4). If the old id
//! was carried (`state/carry.json`, durable-sessions plan P-C3), the mark
//! transfers onto the new id in the same step — never left on the now-dead
//! old id, which would double-resurrect on the next sweep.
//!
//! Never a hard `Outcome::error` over a per-candidate spawn failure (a
//! headless host has no `$AOIDE_TERMINAL`/display — `session_spawn`'s own
//! taught error): every candidate's outcome is folded into
//! `resurrected`/`skipped`/`failed` and the command itself stays `Ok`, so a
//! `--all` batch keeps going past one bad candidate and the daemon's
//! boot-time trigger degrades gracefully (log the skip, never crash the
//! tick) instead of treating a headless box as a command failure. Only
//! genuine USAGE problems (`--project` missing, an unknown project name, an
//! `--id` that names no anchored ledger entry) are `Outcome::usage`/`error`.

use super::common::{require_flag, stage_error};
use super::model::{load_stage, projects_path, sessions_path, ProjectsFile, SessionsFile};
use super::session_store::stamp_resumed_from;
use super::spawn::session_spawn;
use aoide_protocol::agents::agent_profile;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;
use std::collections::BTreeMap;

/// Mint a fresh session id for a resurrected session — never the ledger
/// entry's own id (ids are never recycled, `docs/architecture/AOIDED.md`'s
/// invariant list, item 5). Same `<command>-<pid>-<unixts>` shape `graph spawn`
/// mints with (`spawn.rs::unix_ts`, reused rather than re-derived).
fn mint_resurrected_id() -> String {
    format!("resurrect-{}-{}", std::process::id(), super::conduct::unix_ts())
}

/// One selected, resumable ledger candidate, resolved down to what
/// [`resurrect_one`] needs — the harness profile lookup and `harnessSessionId`
/// fallback already done, so the spawn/skip decision below never re-derives
/// them.
struct Candidate {
    entry: aoide_storage::ledger::LedgerEntry,
    resume_argv: Option<Vec<String>>,
}

fn resolve_candidate(entry: aoide_storage::ledger::LedgerEntry) -> Candidate {
    let resume_argv = agent_profile(&entry.agent).and_then(|p| p.resume_args).map(|f| {
        let harness_id = entry.harness_session_id.as_deref().unwrap_or(&entry.session_id);
        f(harness_id)
    });
    Candidate { entry, resume_argv }
}

/// Spawn one candidate via the windowed path and fold the outcome into
/// `resurrected`/`skipped`/`failed`. Never returns an error — every failure
/// mode is data, per the module doc.
fn resurrect_one(
    door: aoide_protocol::Door,
    c: Candidate,
    resurrected: &mut Vec<serde_json::Value>,
    skipped: &mut Vec<serde_json::Value>,
    failed: &mut Vec<serde_json::Value>,
    changed: &mut Vec<String>,
) {
    let Some(argv) = c.resume_argv else {
        skipped.push(json!({
            "sessionId": c.entry.session_id,
            "agent": c.entry.agent,
            "reason": format!(
                "harness `{}` has no verified resume argv — skipped rather than typing a guessed invocation",
                c.entry.agent
            ),
        }));
        return;
    };
    let new_id = mint_resurrected_id();
    let mut flags = BTreeMap::new();
    flags.insert("agent".to_string(), c.entry.agent.clone());
    flags.insert("id".to_string(), new_id.clone());
    flags.insert("windowed".to_string(), "true".to_string());
    if !c.entry.cwd.is_empty() {
        flags.insert("cwd".to_string(), c.entry.cwd.clone());
    }
    let spawn_inv = Invocation {
        path: vec!["graph".to_string(), "spawn".to_string()],
        args: argv,
        flags,
        door,
    };
    let out = session_spawn(&spawn_inv);
    if out.status != aoide_protocol::output::Status::Ok {
        failed.push(json!({
            "sessionId": c.entry.session_id,
            "agent": c.entry.agent,
            "reason": out.message,
        }));
        return;
    }
    let registered = out
        .data
        .as_ref()
        .and_then(|d| d.get("registered"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // Safe no-op if the record has not landed yet (an honest `registered:
    // false` on a slow terminal open) — never a second wait loop here;
    // `session_spawn` already spent its own registration budget.
    stamp_resumed_from(&new_id, &c.entry.session_id);

    // Carry transfer (P-C3, durable-sessions plan): if the OLD id was
    // durable, move the mark onto the fresh one rather than leaving it
    // behind — a mark left on a ledger id would double-resurrect on the next
    // sweep once P-C4 selects off the carried set. A no-op when the old id
    // was never carried at all (this resurrect did not originate from the
    // carried set), so an ordinary `--all`/`--id` revive never starts
    // carrying sessions nobody marked.
    //
    // Both mutations land in ONE in-memory vector before the SINGLE
    // `save_carry` write below — mark the new id BEFORE dropping the old
    // one, so a crash between the two in-memory edits and the write is
    // impossible, and a crash right before the write leaves the OLD id
    // still carried (retry-safe) rather than neither (silent loss). Also
    // idempotent: re-running this on an already-transferred pair finds the
    // old id no longer carried and writes nothing.
    let mut carried = aoide_storage::carry::load_carry();
    if aoide_storage::carry::is_carried(&carried, &c.entry.session_id) {
        aoide_storage::carry::set_carried(&mut carried, &new_id, true);
        aoide_storage::carry::set_carried(&mut carried, &c.entry.session_id, false);
        let _ = aoide_storage::carry::save_carry(&carried);
    }
    changed.push(format!(
        "session {new_id}: resurrected from {} ({}){}",
        c.entry.session_id,
        c.entry.agent,
        if registered { "" } else { " (not yet registered)" }
    ));
    resurrected.push(json!({
        "sessionId": new_id,
        "resumedFrom": c.entry.session_id,
        "agent": c.entry.agent,
        "registered": registered,
    }));
}

/// Bare-mode selection (no `--all`/`--id`, decision 6 of the durable-sessions
/// plan): `anchored` narrowed to the project's WHOLE carried set, not just
/// its single most recent entry. Three steps, in order:
///
/// 1. keep only entries whose `sessionId` is in `state/carry.json`
///    (`aoide_storage::carry::is_carried`);
/// 2. drop any id that is already alive (non-`done`) in `sessions.json` —
///    the daemon's old `has_live` skip moves HERE, per-id instead of
///    per-project, so one live terminal no longer suppresses the rest of a
///    multi-session carried set (`server/src/daemon.rs`'s
///    `run_boot_auto_resume`, which now calls this unconditionally);
/// 3. dedup by `sessionId`, keeping the entry with the latest `endedAt` — a
///    carried id that was resurrected and exited again appears twice in the
///    append-only ledger.
fn carried_selection(
    anchored: Vec<aoide_storage::ledger::LedgerEntry>,
) -> Vec<aoide_storage::ledger::LedgerEntry> {
    let carried = aoide_storage::carry::load_carry();
    let sessions: SessionsFile = load_stage(&sessions_path()).unwrap_or_default();
    let live: std::collections::HashSet<&str> = sessions
        .sessions
        .iter()
        .filter(|s| s.state != "done")
        .map(|s| s.session_id.as_str())
        .collect();

    let mut newest: BTreeMap<String, aoide_storage::ledger::LedgerEntry> = BTreeMap::new();
    for e in anchored {
        if !aoide_storage::carry::is_carried(&carried, &e.session_id) {
            continue;
        }
        if live.contains(e.session_id.as_str()) {
            continue;
        }
        let ended = aoide_storage::time::parse_iso_utc(&e.ended_at).unwrap_or(0);
        let keep = match newest.get(&e.session_id) {
            Some(existing) => ended > aoide_storage::time::parse_iso_utc(&existing.ended_at).unwrap_or(0),
            None => true,
        };
        if keep {
            newest.insert(e.session_id.clone(), e);
        }
    }
    newest.into_values().collect()
}

/// `aoide graph resurrect --project <name> [--all | --id <ledgerSessionId>]`.
pub fn session_resurrect(inv: &Invocation) -> Outcome {
    let cmd = "graph.resurrect";
    let name = match require_flag(inv, "project") {
        Ok(v) => v,
        Err(o) => return o,
    };

    let projects: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(target_idx) = projects.projects.iter().position(|p| p.name == name) else {
        return Outcome::error(cmd, format!("no project named `{name}` — register it first with `graph project add`"))
            .with_data(json!({ "reason": "unknown-project", "project": name }));
    };

    let ledger = match aoide_storage::ledger::read_ledger() {
        Ok(v) => v,
        Err(e) => return stage_error(cmd, e.to_string()),
    };
    let anchored: Vec<aoide_storage::ledger::LedgerEntry> = ledger
        .into_iter()
        .filter(|e| super::model::anchor_for(&e.cwd, &projects.projects) == Some(target_idx))
        .collect();

    let selected: Vec<aoide_storage::ledger::LedgerEntry> = if let Some(id) = inv.flags.get("id") {
        match anchored.into_iter().find(|e| &e.session_id == id) {
            Some(e) => vec![e],
            None => {
                return Outcome::error(
                    cmd,
                    format!("no ledger entry `{id}` anchored to project `{name}`"),
                )
                .with_data(json!({ "reason": "unknown-ledger-id", "project": name, "id": id }));
            }
        }
    } else if inv.flag_present("all") {
        let mut v = anchored;
        v.sort_by(|a, b| {
            let ea = aoide_storage::time::parse_iso_utc(&a.ended_at).unwrap_or(0);
            let eb = aoide_storage::time::parse_iso_utc(&b.ended_at).unwrap_or(0);
            eb.cmp(&ea)
        });
        v
    } else {
        carried_selection(anchored)
    };

    if selected.is_empty() {
        let bare = inv.flags.get("id").is_none() && !inv.flag_present("all");
        let msg = if bare {
            format!("carried set is empty for project `{name}` — nothing to resurrect")
        } else {
            format!("no resumable session found for project `{name}`")
        };
        return Outcome::ok(cmd, msg)
            .with_data(json!({ "project": name, "resurrected": [], "skipped": [], "failed": [] }));
    }

    let mut resurrected: Vec<serde_json::Value> = Vec::new();
    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut failed: Vec<serde_json::Value> = Vec::new();
    let mut changed: Vec<String> = Vec::new();
    for e in selected {
        resurrect_one(inv.door, resolve_candidate(e), &mut resurrected, &mut skipped, &mut failed, &mut changed);
    }

    Outcome::ok(
        cmd,
        format!(
            "project `{name}`: resurrected {}, skipped {}, failed {}",
            resurrected.len(),
            skipped.len(),
            failed.len(),
        ),
    )
    .changed(changed)
    .with_data(json!({
        "project": name,
        "resurrected": resurrected,
        "skipped": skipped,
        "failed": failed,
        "sessionsFile": sessions_path().to_string_lossy(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;
    use super::super::model::write_stage;

    fn set_ledger(entries: &[aoide_storage::ledger::LedgerEntry]) {
        for e in entries {
            aoide_storage::ledger::append_ledger_entry(e).unwrap();
        }
    }

    fn ledger_entry(
        session_id: &str,
        agent: &str,
        cwd: &str,
        ended_at: &str,
    ) -> aoide_storage::ledger::LedgerEntry {
        aoide_storage::ledger::LedgerEntry {
            v: 0,
            session_id: session_id.to_string(),
            agent: agent.to_string(),
            harness_session_id: Some(session_id.to_string()),
            cwd: cwd.to_string(),
            title: None,
            petname: None,
            started_at: "2026-08-20T00:00:00Z".to_string(),
            ended_at: ended_at.to_string(),
            resumed_from: None,
            origin: None,
            restore: None,
        }
    }

    /// Common env scaffolding every test below needs: an isolated stage +
    /// state dir, a registered project anchored at that dir. Returns the
    /// project's own absolute path (also the anchor every ledger fixture
    /// entry's `cwd` should use).
    fn setup(tag: &str) -> (std::path::PathBuf, String) {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        let proj_path = root.to_str().unwrap().to_string();
        let out = crate::graph::project_add(&invocation(
            &["graph", "project", "add"],
            &["proj", &proj_path],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        (root, proj_path)
    }

    // A full windowed-spawn SUCCESS (a real `conduct` registering a real
    // agent under a real-if-nulled pty) is deliberately NOT exercised here —
    // `spawn.rs`'s own module doc draws this exact line: "the LIVE gate (a
    // real terminal opening under the compositor) is the orchestrator's and
    // the User's, never this crate's tests." What IS this crate's job —
    // that a resurrected session always mints a FRESH id, and that
    // `resumedFrom` actually lands on the record once one exists — is
    // covered directly below and in `session_store.rs`'s own
    // `stamp_resumed_from` tests, with no process ever spawned.

    #[test]
    fn mint_resurrected_id_never_reuses_the_ledger_id() {
        // Same `<command>-<pid>-<unixts>` shape (and the same second-granularity
        // caveat) as `graph spawn`'s/`conduct`'s own id minting — this only
        // asserts what P-D8 actually needs: it is never the OLD ledger id.
        for old_id in ["ledger-old-1", "resurrect-1-1"] {
            let minted = mint_resurrected_id();
            assert_ne!(minted, old_id, "a resurrected session must never reuse the ledger id");
            assert!(minted.starts_with("resurrect-"), "id: {minted}");
        }
    }

    #[test]
    fn a_no_resume_args_harness_is_skipped_with_a_taught_message() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-skip");

        set_ledger(&[ledger_entry(
            "ledger-unknown-harness",
            "no-such-harness",
            &proj_path,
            "2026-08-20T01:00:00Z",
        )]);
        // Bare selection is carried-set-driven (P-C4) — mark the entry so it
        // is even a candidate; the point of this test is the harness skip,
        // not the selection width.
        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "ledger-unknown-harness", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 0);
        let skipped = data["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1, "data: {data}");
        assert!(
            skipped[0]["reason"].as_str().unwrap().contains("no-such-harness"),
            "the skip reason must name the harness: {}",
            skipped[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_windowed_spawn_failure_degrades_gracefully_instead_of_erroring_the_command() {
        // The headless-host case (P-D8's decided trigger): no $AOIDE_TERMINAL
        // set. `session_spawn`'s own taught error fires — this proves it is
        // folded into `failed`, never turned into a hard `Outcome::error`, so
        // the daemon's boot-time trigger can call this in a loop without ever
        // treating a display-less box as a failure worth crashing a tick over.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-headless");
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        set_ledger(&[ledger_entry("ledger-old-2", "claude", &proj_path, "2026-08-20T01:00:00Z")]);
        // Bare selection is carried-set-driven (P-C4) — mark the entry so it
        // is even a candidate; the point of this test is the failure
        // handling, not the selection width.
        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "ledger-old-2", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(
            out.status,
            aoide_protocol::output::Status::Ok,
            "a per-candidate spawn failure must degrade gracefully, never error the command: {}",
            out.message
        );
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 0);
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert!(
            failed[0]["reason"].as_str().unwrap().contains("AOIDE_TERMINAL"),
            "reason: {}",
            failed[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A successful resurrect of a CARRIED old id transfers the mark: the
    /// new id ends up carried, the old id does not, and an unrelated carried
    /// id already in the set is left exactly as it was (P-C3, durable-
    /// sessions plan). `AOIDE_TERMINAL=true` is enough to make the windowed
    /// spawn itself succeed (`Status::Ok`) without a real terminal — `true`
    /// exits 0 the instant it's exec'd; the point of this test is the carry
    /// transfer, not registration, which `resurrect_one` never gates it on.
    #[test]
    fn a_successful_resurrect_transfers_the_carry_mark_from_old_to_new() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-carry-transfer");
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        set_ledger(&[ledger_entry("ledger-carried", "claude", &proj_path, "2026-08-20T01:00:00Z")]);

        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "ledger-carried", true);
        aoide_storage::carry::set_carried(&mut carried, "unrelated-id", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");
        let new_id = resurrected[0]["sessionId"].as_str().unwrap().to_string();

        let carried = aoide_storage::carry::load_carry();
        assert!(aoide_storage::carry::is_carried(&carried, &new_id), "the new id must be carried");
        assert!(
            !aoide_storage::carry::is_carried(&carried, "ledger-carried"),
            "the old id must no longer be carried"
        );
        assert!(
            aoide_storage::carry::is_carried(&carried, "unrelated-id"),
            "an unrelated carried id must be left untouched"
        );
        assert_eq!(carried.len(), 2, "exactly one id moves — the set's size is unchanged");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The failure half of the same rule: a spawn that never even reaches
    /// `Status::Ok` (the headless-host taught error, no `$AOIDE_TERMINAL`)
    /// must leave the old id carried, so the next sweep retries it.
    #[test]
    fn a_failed_resurrect_leaves_the_old_id_carried() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-carry-failed");
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        set_ledger(&[ledger_entry("ledger-carried-fail", "claude", &proj_path, "2026-08-20T01:00:00Z")]);

        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "ledger-carried-fail", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["failed"].as_array().unwrap().len(), 1);

        let carried = aoide_storage::carry::load_carry();
        assert!(
            aoide_storage::carry::is_carried(&carried, "ledger-carried-fail"),
            "a failed resurrect must leave the old id carried so the next sweep retries it"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Re-running a resurrect against the same (append-only, so still
    /// selectable) ledger entry after it has already transferred must not
    /// carry the SECOND new id or touch the set again — the transfer step
    /// only fires when the old id is currently carried, and by the second
    /// call it no longer is.
    #[test]
    fn transfer_is_idempotent_when_the_pair_has_already_transferred() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-carry-idempotent");
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        set_ledger(&[ledger_entry("ledger-idem", "claude", &proj_path, "2026-08-20T01:00:00Z")]);

        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "ledger-idem", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        let first = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(first.status, aoide_protocol::output::Status::Ok, "msg: {}", first.message);
        let first_new_id =
            first.data.as_ref().unwrap()["resurrected"][0]["sessionId"].as_str().unwrap().to_string();
        let after_first = aoide_storage::carry::load_carry();
        assert!(aoide_storage::carry::is_carried(&after_first, &first_new_id));
        assert!(!aoide_storage::carry::is_carried(&after_first, "ledger-idem"));

        // Bare selection no longer re-picks `ledger-idem` (P-C4): its mark
        // already moved to `first_new_id` above. `--id` is the unchanged
        // escape that narrows to one entry regardless of the mark (the
        // append-only ledger still holds the line), so it is what re-drives
        // the same candidate a second time here — the point of THIS test is
        // `resurrect_one`'s transfer idempotency, not bare-mode selection.
        let second = session_resurrect(&flag_invocation(
            &["graph", "resurrect"],
            &[("project", "proj"), ("id", "ledger-idem")],
        ));
        assert_eq!(second.status, aoide_protocol::output::Status::Ok, "msg: {}", second.message);
        let second_new_id =
            second.data.as_ref().unwrap()["resurrected"][0]["sessionId"].as_str().unwrap().to_string();

        let after_second = aoide_storage::carry::load_carry();
        assert!(
            !aoide_storage::carry::is_carried(&after_second, &second_new_id),
            "the old id was no longer carried, so nothing transfers to the second new id"
        );
        assert_eq!(
            after_second, after_first,
            "a re-run transfer on an already-transferred pair changes nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_ledger_history_for_the_project_is_an_ok_no_op() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, _proj_path) = setup("resurrect-empty");

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["resurrected"].as_array().unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_project_is_an_error() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, _proj_path) = setup("resurrect-unknown-project");

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "nope")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_project_flag_is_a_usage_error() {
        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
    }

    /// `--all` and `--id` are unchanged escapes (P-C4's own scope line): both
    /// widen or narrow past the carried set regardless of the mark — neither
    /// entry below is ever carried, and both still resolve.
    #[test]
    fn all_widens_to_every_anchored_entry_and_id_narrows_to_one_regardless_of_the_mark() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-all-id");

        // Two resumable-shaped entries (unresolved harness, so both land in
        // `skipped` rather than needing a real spawn) — proves the SELECTION
        // width, independent of the spawn mechanics already covered above.
        // Neither is carried: --all and --id must not care.
        set_ledger(&[
            ledger_entry("ledger-a", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("ledger-b", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
        ]);

        // --all: both, carried or not.
        let out = session_resurrect(&flag_invocation(
            &["graph", "resurrect"],
            &[("project", "proj"), ("all", "true")],
        ));
        assert_eq!(out.data.as_ref().unwrap()["skipped"].as_array().unwrap().len(), 2);

        // --id: exactly the named one, uncarried and not the newest.
        let out = session_resurrect(&flag_invocation(
            &["graph", "resurrect"],
            &[("project", "proj"), ("id", "ledger-a")],
        ));
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["sessionId"], "ledger-a");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── P-C4: bare selection drives off the carried set ─────────────────────

    /// The headline case: three carried, two uncarried, all five anchored to
    /// the same project — bare `--project` resurrects exactly the three.
    #[test]
    fn bare_default_resurrects_exactly_the_carried_set() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-carried-set");

        set_ledger(&[
            ledger_entry("carried-1", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("carried-2", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
            ledger_entry("carried-3", "no-such-harness", &proj_path, "2026-08-20T03:00:00Z"),
            ledger_entry("uncarried-1", "no-such-harness", &proj_path, "2026-08-20T04:00:00Z"),
            ledger_entry("uncarried-2", "no-such-harness", &proj_path, "2026-08-20T05:00:00Z"),
        ]);
        let mut carried = Vec::new();
        for id in ["carried-1", "carried-2", "carried-3"] {
            aoide_storage::carry::set_carried(&mut carried, id, true);
        }
        aoide_storage::carry::save_carry(&carried).unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        let mut ids: Vec<&str> = skipped.iter().map(|s| s["sessionId"].as_str().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, vec!["carried-1", "carried-2", "carried-3"], "skipped: {skipped:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A carried id still live in `sessions.json` (non-`done`) is excluded —
    /// the daemon's old per-project `has_live` skip moved down to here,
    /// per-id (P-C4's own scope line).
    #[test]
    fn bare_default_excludes_a_carried_id_still_live_in_the_roster() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-carried-live");

        set_ledger(&[
            ledger_entry("carried-alive", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("carried-dead", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
        ]);
        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "carried-alive", true);
        aoide_storage::carry::set_carried(&mut carried, "carried-dead", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        // `carried-alive` is still in the roster, non-`done`.
        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![session("carried-alive", &proj_path, "working", "2026-08-20T01:00:00Z", None)],
            },
        )
        .unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1, "skipped: {skipped:?}");
        assert_eq!(skipped[0]["sessionId"], "carried-dead");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty carried set is an `ok` no-op with an honest message — never
    /// silently treated as "nothing to do" without saying why.
    #[test]
    fn bare_default_is_an_ok_no_op_when_the_carried_set_is_empty() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-carried-empty");

        // An anchored entry exists, but nothing is carried.
        set_ledger(&[ledger_entry("uncarried-only", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z")]);

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["resurrected"].as_array().unwrap().len(), 0);
        assert!(
            out.message.contains("carried set is empty"),
            "message must say WHY, not just no-op silently: {}",
            out.message
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A carried id that exited, was resurrected, and exited again appears
    /// twice in the append-only ledger — the dedup keeps the newest
    /// `endedAt`, so only one candidate is ever selected.
    #[test]
    fn bare_default_dedups_a_repeated_carried_id_keeping_the_newest_ended_at() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-carried-dedup");

        // Same sessionId, two ledger lines (append-only, both legal): an
        // earlier exit and a later re-exit.
        set_ledger(&[
            ledger_entry("repeated-id", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("repeated-id", "no-such-harness", &proj_path, "2026-08-20T09:00:00Z"),
        ]);
        let mut carried = Vec::new();
        aoide_storage::carry::set_carried(&mut carried, "repeated-id", true);
        aoide_storage::carry::save_carry(&carried).unwrap();

        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1, "the repeated id must be deduped to one candidate: {skipped:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
