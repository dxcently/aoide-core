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
//! re-derived), then pick candidates — the single most recent by default,
//! every anchored entry with `--all`, or one specific ledger `sessionId`
//! with `--id`. Each candidate is filtered through its harness's
//! `AgentProfile.resume_args` (`aoide_protocol::agents`): `None` (an
//! unregistered agent, or a harness whose resume argv has never been
//! verified) skips that candidate with a taught message naming the harness,
//! never a guessed invocation.
//!
//! A resurrected session is ALWAYS a fresh `sessionId` — ids are never
//! recycled — spawned via the windowed path ([`super::spawn::session_spawn`]
//! with `--windowed --cwd <the ledger entry's own cwd>`, P-D7/P-D8) so it
//! reopens in a real terminal, in its original project directory. On success
//! the new record is stamped `resumedFrom` (`stamp_resumed_from`), naming the
//! ledger entry's own `sessionId` — `build_graph` projects that as a
//! `resumed` edge beside `spawned`/`anchors` (CONTRACTS.md §4).
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
use super::model::{load_stage, projects_path, sessions_path, ProjectsFile};
use super::session_store::stamp_resumed_from;
use super::spawn::session_spawn;
use aoide_protocol::agents::agent_profile;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde_json::json;
use std::collections::BTreeMap;

/// Mint a fresh session id for a resurrected session — never the ledger
/// entry's own id (ids are never recycled, `docs/architecture/AOIDED.md`'s
/// invariant list, item 5). Same `<verb>-<pid>-<unixts>` shape `graph spawn`
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
        anchored
            .into_iter()
            .max_by_key(|e| aoide_storage::time::parse_iso_utc(&e.ended_at).unwrap_or(0))
            .into_iter()
            .collect()
    };

    if selected.is_empty() {
        return Outcome::ok(cmd, format!("no resumable session found for project `{name}`"))
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
        // Same `<verb>-<pid>-<unixts>` shape (and the same second-granularity
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

    #[test]
    fn all_widens_to_every_anchored_entry_and_id_narrows_to_one() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-all-id");

        // Two resumable-shaped entries (unresolved harness, so both land in
        // `skipped` rather than needing a real spawn) — proves the SELECTION
        // width, independent of the spawn mechanics already covered above.
        set_ledger(&[
            ledger_entry("ledger-a", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("ledger-b", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
        ]);

        // Default (no --all/--id): only the single most recent (ledger-b).
        let out = session_resurrect(&flag_invocation(&["graph", "resurrect"], &[("project", "proj")]));
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1, "default must pick exactly the most recent: {skipped:?}");
        assert_eq!(skipped[0]["sessionId"], "ledger-b");

        // --all: both.
        let out = session_resurrect(&flag_invocation(
            &["graph", "resurrect"],
            &[("project", "proj"), ("all", "true")],
        ));
        assert_eq!(out.data.as_ref().unwrap()["skipped"].as_array().unwrap().len(), 2);

        // --id: exactly the named one, even though it is not the newest.
        let out = session_resurrect(&flag_invocation(
            &["graph", "resurrect"],
            &[("project", "proj"), ("id", "ledger-a")],
        ));
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["sessionId"], "ledger-a");

        let _ = std::fs::remove_dir_all(&root);
    }
}
