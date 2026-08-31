//! The session write door: session-registration commands (`session start/phase/
//! end/wrap`), transcript "say"/title/model extraction, and the sub-agent
//! node lifecycle (`do_subagent_*`). shellbridge only ever SEEDS empty
//! sessions.json/hooks.json (its socket accept loop is future work), so
//! nothing else registers a live session — a session harness (or a Claude
//! Code hook) upserts its own record here, and every mutation re-stages
//! graph.json so the read path lights up immediately.

use super::common::{require_flag, stage_error};
use super::doc::{
    doomed_subagent_descendants, ledger_session_exit, prune_done, restage_graph, would_cycle,
};
use super::model::{
    canonical_state, hooks_path, load_stage, sessions_path, write_stage, HooksFile,
    SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
#[cfg(test)]
use super::model::HookRecord;
use aoide_protocol::agents::AgentProfile;
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::fs::with_stage_lock;
use serde_json::json;
#[cfg(test)]
use serde_json::Value;
use std::collections::HashSet;

/// `now_iso_utc`/`iso_utc_from_epoch` (time) and `upsert_session`/
/// `upsert_hook` (pure Vec<Record> mutators — verified DAG-free: neither
/// touches `restage_graph`/`would_cycle`/`require_flag`/`stage_error`) moved
/// to `aoide-storage` (Phase 3a restructure,
/// docs/architecture/PACKAGE-LAYOUT.md); re-exported here so every existing
/// `crate::graph::session_store::{now_iso_utc, upsert_session, …}` caller
/// (and this file's own `do_session_*`/`do_subagent_*` handlers below, which
/// stay in root through Phase 3b) is untouched.
pub use aoide_storage::session::{upsert_hook, upsert_session};
pub use aoide_storage::time::now_iso_utc;
#[cfg(test)]
use aoide_storage::time::iso_utc_from_epoch;

/// Every ancestor (walking `parentSessionId` to the root) AND every
/// descendant (transitive children) of `id` — the same-window eviction's
/// carve-out (task #89): a member of `id`'s own lineage is never a stale
/// twin, however many hops of `conduct`/`spawn` nesting separate them.
/// Bounded against a cycle on the ancestor walk (a malformed
/// `parentSessionId` chain must never loop forever); the descendant walk is
/// naturally bounded by the finite session list. `id` itself is never
/// inserted (the caller already excludes `s.session_id != id` separately).
///
/// `pub(crate)`, not private or `pub(in crate::graph)`: `crate::reap`'s own
/// `superseded_agent_duplicates` (review round 2 of task #89) — a SIBLING
/// module, not a descendant of `graph` — reuses this SAME lineage set as its
/// own defense-in-depth carve-out — never a second, parallel lineage
/// computation.
pub(crate) fn lineage_of(id: &str, sessions: &[SessionRecord]) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut current = id.to_string();
    let mut seen_ancestors = HashSet::new();
    while let Some(rec) = sessions.iter().find(|s| s.session_id == current) {
        let Some(p) = rec.parent_session_id.clone() else {
            break;
        };
        if !seen_ancestors.insert(p.clone()) {
            break; // cycle guard
        }
        out.insert(p.clone());
        current = p;
    }
    let mut stack: Vec<String> = vec![id.to_string()];
    let mut seen_descendants: HashSet<String> = HashSet::new();
    while let Some(cur) = stack.pop() {
        for s in sessions {
            if s.parent_session_id.as_deref() == Some(cur.as_str())
                && seen_descendants.insert(s.session_id.clone())
            {
                out.insert(s.session_id.clone());
                stack.push(s.session_id.clone());
            }
        }
    }
    out
}

/// Core of `session start`: cycle-check a parent, UPSERT, re-stage.
#[allow(clippy::too_many_arguments)]
pub(in crate::graph) fn do_session_start(
    id: &str,
    agent: Option<&str>,
    cwd: Option<&str>,
    window: Option<&str>,
    parent: Option<&str>,
    conductable: Option<bool>,
    socket: Option<&str>,
    title: Option<&str>,
    pid: Option<u32>,
) -> Outcome {
    with_stage_lock(|| {
        do_session_start_inner(
            id, agent, cwd, window, parent, conductable, socket, title, pid,
        )
    })
}
#[allow(clippy::too_many_arguments)]
fn do_session_start_inner(
    id: &str,
    agent: Option<&str>,
    cwd: Option<&str>,
    window: Option<&str>,
    parent: Option<&str>,
    conductable: Option<bool>,
    socket: Option<&str>,
    title: Option<&str>,
    pid: Option<u32>,
) -> Outcome {
    let cmd = "session.start";
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    // Reuse `link`'s cycle guard: an id parented under its own descendant (or
    // itself) is refused before we mutate anything.
    if let Some(p) = parent {
        if would_cycle(&file.sessions, id, p) {
            return Outcome::error(
                cmd,
                format!("parenting `{id}` under `{p}` would create a cycle"),
            )
            .with_data(json!({ "reason": "cycle", "sessionId": id, "parent": p }));
        }
    }

    let now = now_iso_utc();
    let inserted = upsert_session(
        &mut file.sessions,
        id,
        agent,
        cwd,
        window,
        parent,
        conductable,
        socket,
        title,
        pid,
        &now,
    );
    let (r_agent, r_started) = file
        .sessions
        .iter()
        .find(|s| s.session_id == id)
        .map(|s| (s.agent.clone(), s.started_at.clone()))
        .unwrap_or_default();

    // Registration-time same-window agent eviction: Claude Code fires
    // SessionStart once per process invocation, so if this NEWLY registering
    // session is an agent sharing a window with another still-live (not-`done`)
    // agent record, the old one's process is necessarily gone already — a
    // terminal cannot hold two live foreground claudes, and a window address
    // cannot be shared by two SIMULTANEOUSLY open windows (a compositor
    // invariant), so a same-window pair always means the other side is stale
    // (typically a compact/resume that minted a fresh session id whose
    // predecessor never ran its own `SessionEnd`). Collapse it the instant the
    // new session appears — no grace needed (unlike the reaper's own dedup pass,
    // which resolves a pair it merely OBSERVES together and so must wait to tell
    // which twin is real; here the new registration itself is the deciding
    // signal). The ~12s reaper (`crate::reap`) stays the safety net for the
    // slower path where a window resolves later via the window-event listener.
    // Two carve-outs: a conducted PTY host (`conductable` — e.g. `conduct --
    // kimi`'s wrapper, which `is_agent_kind` refuses despite its published
    // "agent" kind) is the control-socket owner, not a second foreground
    // agent; and the new record's WHOLE LINEAGE (every ancestor AND
    // descendant, not just its direct parent) is excluded outright. Widened
    // from "direct parent only" (task #89): a nested headless `conduct`/
    // `spawn` chain — terminal wrap -> agent hook session -> nested headless
    // wrap -> that wrap's own hook session — can legitimately land a
    // same-window pair that are grandparent/grandchild (or cousins through a
    // shared ancestor) rather than direct parent/child, and the old
    // direct-parent-only carve-out evicted them as if they were stale twins.
    // A genuine stale twin (a compact/resume pair with NO lineage relation)
    // still has an empty intersection with the new record's lineage, so it
    // collapses exactly as before.
    let new_rec = file.sessions.iter().find(|s| s.session_id == id).cloned();
    let evicted: Vec<String> = match &new_rec {
        Some(rec) if crate::reap::is_agent_kind(rec) && !rec.window_address.is_empty() => {
            let lineage = lineage_of(id, &file.sessions);
            file.sessions
                .iter()
                .filter(|s| {
                    s.session_id != id
                        && !lineage.contains(&s.session_id)
                        && s.state != "done"
                        && s.window_address == rec.window_address
                        && crate::reap::is_agent_kind(s)
                })
                .map(|s| s.session_id.clone())
                .collect()
        }
        _ => Vec::new(),
    };
    if !evicted.is_empty() {
        let mut h_file: HooksFile = load_stage(&hooks_path()).unwrap_or_default();
        let done_at = now_iso_utc();
        for eid in &evicted {
            upsert_hook(&mut h_file.hooks, eid, "done", &done_at);
        }
        for s in file.sessions.iter_mut() {
            if evicted.contains(&s.session_id) {
                s.state = "done".to_string();
            }
        }
        let (kept_s, kept_h, _removed, _cleared) =
            prune_done(std::mem::take(&mut file.sessions), std::mem::take(&mut h_file.hooks));
        file.sessions = kept_s;
        h_file.hooks = kept_h;
        if h_file.schema_version.is_empty() {
            h_file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        let _ = write_stage(&hooks_path(), &h_file);
    }

    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &file) {
        return stage_error(cmd, e);
    }

    let mut changed = vec![if inserted {
        format!("registered session {id} (idle)")
    } else {
        format!("updated session {id}")
    }];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    let message = if inserted {
        format!("started session `{id}` (agent {r_agent}, idle)")
    } else {
        format!("re-started session `{id}` (fields updated; startedAt preserved)")
    };
    Outcome::ok(cmd, message).changed(changed).with_data(json!({
        "sessionId": id,
        "agent": r_agent,
        "startedAt": r_started,
        "inserted": inserted,
        "file": sessions_path().to_string_lossy(),
    }))
}

/// Land the canonical live `state` onto a session record in `sessions.json` —
/// the widget-facing file. This is the fix for hook states never reaching the
/// widgets: they watch `sessions.json`, whose `state` used to be only
/// `running`/`done` (hook phases lived only in `hooks.json`), so `awaiting`
/// and the dock peek could never fire. A no-op for an unregistered id.
/// Change-only, and it migrates any other legacy state it passes, so repeated
/// same-state phases and old vocab don't churn the file. `Ok(true)` when it wrote.
fn set_session_state(id: &str, state: &str) -> Result<bool, String> {
    let mut file: SessionsFile = load_stage(&sessions_path())?;
    let canon = canonical_state(state);
    let mut changed = false;
    for s in file.sessions.iter_mut() {
        let target = if s.session_id == id {
            canon
        } else {
            canonical_state(&s.state) // migrate legacy vocab in passing
        };
        if s.state != target {
            s.state = target.to_string();
            changed = true;
        }
        // A non-working session isn't running anything → drop its stale activity
        // (the last tool/command). A working session keeps it (a tool hook owns it).
        if s.session_id == id && target != "working" && s.activity.is_some() {
            s.activity = None;
            changed = true;
        }
    }
    if changed {
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        write_stage(&sessions_path(), &file)?;
    }
    Ok(changed)
}

/// Set the live state + `activity` (the current tool) on a session OR a sub-node
/// — the tool hooks' writer. The "owner" is the session, or a sub-node
/// `sub:<id>` when the tool ran inside a Task sub-agent (Fable's activity
/// routing, so a sub-agent's churn never clobbers its parent's display). Writes
/// the canonical phase to hooks.json (audit + graph merge) and the
/// state+activity to sessions.json (the widgets), under one stage lock.
///
/// hooks.json is written unconditionally — [`upsert_hook`] always stamps a
/// fresh `updatedAt`, so its content is genuinely new on every call (it's the
/// per-hook heartbeat, not a mirror of session state). sessions.json (and the
/// `graph.json` restage it triggers) is CHANGE-ONLY, same discipline as
/// `conduct.rs`'s `do_session_refresh`: a tool hook fires far more often than
/// `state`/`activity` actually change, and this file is what the widgets'
/// FileView watches — an unconditional rewrite here churns the UI on every
/// single hook, not just the ones that moved anything.
pub(in crate::graph) fn set_owner_activity(owner: &str, state: &str, activity: Option<&str>) {
    with_stage_lock(|| {
        let canon = canonical_state(state);
        let mut h: HooksFile = load_stage(&hooks_path()).unwrap_or_default();
        upsert_hook(&mut h.hooks, owner, canon, &now_iso_utc());
        if h.schema_version.is_empty() {
            h.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        let _ = write_stage(&hooks_path(), &h);

        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let want_activity = activity.filter(|a| !a.is_empty()).map(str::to_string);
        let mut changed = false;
        for s in file.sessions.iter_mut() {
            if s.session_id != owner {
                continue;
            }
            if s.state != canon {
                s.state = canon.to_string();
                changed = true;
            }
            if s.activity != want_activity {
                s.activity = want_activity.clone();
                changed = true;
            }
        }
        if changed {
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            if write_stage(&sessions_path(), &file).is_ok() {
                let _ = restage_graph();
            }
        }
    });
}

// ── Transcript "say" — the agent's latest words, straight off its JSONL ──────
//
// The transcript layout, locator, and JSONL extractors are agent-harness
// knowledge: they live in the profile (`aoide_protocol::agents::TranscriptSpec`,
// claude: `~/.claude/projects/<munge(cwd)>/<session_id>.jsonl`). The refresh
// commands below dispatch through the profile the hook door hands down.

/// Publish a harness-reported context-window ceiling onto the session record
/// (pi's extension reports its active model's `contextWindow` on every hook
/// payload). A locked read-modify-write like every other stage writer; only
/// touches the stage when the value actually changed, and an absent report
/// never clears a stored ceiling.
pub(in crate::graph) fn ensure_session_ceiling(id: &str, ceiling: u64) {
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && s.context_ceiling != Some(ceiling))
        {
            s.context_ceiling = Some(ceiling);
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
            let _ = restage_graph();
        }
    });
}

/// Stamp a headless `aoide conduct` session's `logPath` — the absolute path of
/// its pty-master transcript (`state/sessions/<id>.log`). A locked
/// read-modify-write like [`ensure_session_ceiling`]: change-only (a second
/// identical call is a no-op that never re-stages), and a silent no-op for an
/// unknown id — conduct calls this right after `do_session_start`, so the id
/// is always fresh, but the discipline matches every other stage writer here.
pub(in crate::graph) fn set_session_log_path(id: &str, path: &str) {
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && s.log_path.as_deref() != Some(path))
        {
            s.log_path = Some(path.to_string());
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
            let _ = restage_graph();
        }
    });
}

/// Stamp `hookAncestry` — up to 8 ancestor pids of the hook-firing process,
/// self-first — on a session record, ONCE, at its own SessionStart/self-heal
/// registration (`session hook`'s two Start-shaped call sites in
/// `send.rs`). A later `wrap`/`conduct`/`spawn` registration with no
/// explicit `--parent` walks ITS OWN `/proc` ancestry and looks for a live
/// agent whose `hookAncestry` intersects it — the automatic-parenting seam
/// (task #89) this field backs. Change-only: never re-stamps an
/// already-populated record (the ancestry is a birth fact, not a live
/// signal, so a later hook on the same id must not overwrite it) and never
/// writes an empty slice. No `restage_graph()` — `hookAncestry` is consumed
/// internally for parent resolution only, never rendered, so stamping it
/// must not churn the widget-facing `graph.json`. Silent no-op on a stage
/// error or an unknown id, same posture as [`set_session_log_path`].
pub(in crate::graph) fn stamp_hook_ancestry(id: &str, ancestry: &[i32]) {
    if ancestry.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && s.hook_ancestry.is_empty())
        {
            s.hook_ancestry = ancestry.to_vec();
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
        }
    });
}

/// Stamp `headless = true` on a headless `aoide conduct` wrap's OWN record —
/// a PERMANENT registration fact (task #89, review round 2), called
/// unconditionally right after `do_session_start` whenever `--headless` was
/// given, regardless of whether window discovery or the log-file open below
/// succeed. Distinct from "`windowAddress` happens to be empty right now":
/// `window::windowless_by_lineage`/`resolve_pending_session_windows` key off
/// THIS field first, so a headless wrap's windowlessness (and its whole
/// hook-child subtree's) survives even if something upstream still manages
/// to stamp a stray window onto the record. Change-only (a no-op once
/// already `true`) and a silent no-op for an unknown id, same posture as
/// [`set_session_log_path`]/[`stamp_hook_ancestry`]. No `restage_graph()` —
/// like `hookAncestry`, `headless` is consumed internally, never rendered.
pub(in crate::graph) fn stamp_headless(id: &str) {
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && !s.headless)
        {
            s.headless = true;
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
        }
    });
}

/// Stamp `origin` on a just-registered session record (P-P3,
/// `docs/architecture/PAIRING.md` decision 7). A PERMANENT birth fact, like
/// `headless`/`hookAncestry`: stamped once, change-only (a no-op once
/// already set to this exact value), never re-derived later. No
/// `restage_graph()` — like `hookAncestry`/`headless`, consumed internally
/// (the durable session ledger, via `doc::ledger_session_exit`) rather than
/// rendered into `graph.json`, so stamping it must not churn the
/// widget-facing document. A silent no-op for an unknown id or an empty
/// `origin`.
///
/// `pub` (crosses the crate boundary) and has exactly TWO legitimate
/// callers, each the record-layer authority for one origin shape (LANE
/// IDENTITY P-ID0, G16/G5 — the write-once-BY-AUTHORITY tightening at the
/// record layer, distinct from the sealed credential below):
///   - `graph/conduct.rs::session_conduct`, for a LOCAL-CLASS origin off its
///     own inherited `AOIDE_SESSION_ORIGIN` env — and that call site now
///     REFUSES a `peer:*` shape from that env read, because inherited env
///     is exactly what a same-uid process can set on itself before invoking
///     `aoide conduct` directly.
///   - `aoide-server`'s `a2a::do_spawn` (`stamp_spawn_origin`), for a
///     `peer:<name>` origin — called directly on the just-spawned session's
///     record from the DOOR that authenticated the peer name, never
///     threaded through the child's env at all. This is the only place a
///     `peer:*` value may originate.
/// The raw field is attribution, not authentication: a same-uid process
/// can still forge a LOCAL-class origin. The authenticated form is the
/// sealed credential (`stamp_seal` below, P-ID1/P-ID2) — a consumer gates
/// only on an `originClass` read off a VERIFIED seal, never this raw
/// string; consumer-NAME authentication remains a separate, unbuilt axis.
pub fn stamp_origin(id: &str, origin: &str) {
    if origin.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && s.origin.as_deref() != Some(origin))
        {
            s.origin = Some(origin.to_string());
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
        }
    });
}

/// Stamp `seal` on a just-registered session record (LANE IDENTITY P-ID1,
/// `docs/architecture/CONTRACTS.md`'s identity section). Change-only (a
/// no-op once already set to this exact value) and a silent no-op for an
/// unknown id or an empty `seal` — the same shape [`stamp_origin`] just
/// above holds, inherited rather than re-derived. Like `stamp_origin`,
/// this is NOT an immutability guard: a later call with a genuinely
/// DIFFERENT `seal` string for the same id still overwrites it, since the
/// guard only compares against the value already on the record, not
/// against "has this ever been set before." In practice its one caller
/// (below) only ever calls this once per successful registration, so it
/// behaves as a birth fact — but that is a property of the call site, not
/// an invariant this function enforces. No
/// `restage_graph()`: like `origin`/`hookAncestry`, this field is consumed
/// internally (P-ID2's verify-on-accept, not built yet) rather than
/// rendered into `graph.json`, so stamping it must not churn the
/// widget-facing document.
///
/// `pub` (crosses the crate boundary), called from `aoide-server`'s daemon
/// (LANE IDENTITY P-ID2, `CONTRACTS.md`'s identity section): once from the
/// `dispatch` handler's `session start` path (P-ID1's original caller,
/// pid already on the record), and once from the daemon tick's own
/// sealing sweep — the fix for the gap P-ID1 shipped as scaffolding
/// (module doc there): `session_conduct`'s own DIRECT, non-dispatched
/// registration — the common real-world path, `aoide conduct -- <agent>`
/// — never touches the daemon's `dispatch` handler at all, so it was
/// NEVER sealed under P-ID1. The tick sweep (`server::daemon::
/// seal_unsealed_live_sessions`) closes that: every live, pid-carrying,
/// unsealed session gets a seal within one tick (~1s) of registering,
/// regardless of which path registered it.
///
/// `issued_at` rides alongside `seal` (both stamped together, both
/// change-only against the value already on the record) — `verify_seal`
/// needs the EXACT signed `SealedIdentity` to check a signature against,
/// and `issued_at` has no live fact a verifier can re-derive it from
/// (`SessionRecord::sealed_issued_at`'s own doc) — this is the same
/// "stamp from the authority that just authenticated the fact" shape
/// [`stamp_origin`]'s own doc names.
pub fn stamp_seal(id: &str, seal: &str, issued_at: i64) {
    if seal.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && s.seal.as_deref() != Some(seal))
        {
            s.seal = Some(seal.to_string());
            s.sealed_issued_at = Some(issued_at);
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
        }
    });
}

/// Stamp `harnessSessionId` — the raw hook payload's OWN `session_id` field
/// (P-D7) — on a session record, on EVERY hook event that carries one, not
/// just at registration: unlike `hookAncestry`/`headless` (birth facts,
/// stamped once), this can legitimately be re-asserted on every event
/// without harm (a resumed/compacted session refires SessionStart with the
/// same id), so the guard is "would this write actually change anything",
/// not "is this the first time". A locked read-modify-write like
/// [`ensure_session_ceiling`]/[`set_session_log_path`]: change-only, and a
/// silent no-op for an unknown id. No `restage_graph()` — like
/// `hookAncestry`/`headless`, this field is consumed internally (a future
/// `resurrect` reader, P-D8) rather than rendered, so stamping it must
/// not churn the widget-facing `graph.json`.
pub(in crate::graph) fn stamp_harness_session_id(id: &str, harness_session_id: &str) {
    if harness_session_id.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file.sessions.iter_mut().find(|s| {
            s.session_id == id && s.harness_session_id.as_deref() != Some(harness_session_id)
        }) {
            s.harness_session_id = Some(harness_session_id.to_string());
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            let _ = write_stage(&sessions_path(), &file);
        }
    });
}

/// Stamp `resumedFrom` on a just-registered session record — the ledger
/// entry's own `sessionId` its resume argv was built from (P-D8,
/// `docs/architecture/AOIDED.md`'s "L5"). Unlike [`stamp_harness_session_id`]
/// this DOES call [`restage_graph`]: `build_graph` projects the field as a
/// `resumed` edge beside `spawned`/`anchors` (CONTRACTS.md §4), so it must be
/// RENDERED, not only held for internal use — the conductor needs to see the
/// edge without a second manual resync. Change-only; a silent no-op for an
/// unknown id (the windowed spawn's own terminal may not have registered by
/// the time `resurrect` gets here — an honest no-op, never a crash).
pub(in crate::graph) fn stamp_resumed_from(id: &str, resumed_from: &str) {
    if resumed_from.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let Some(s) = file
            .sessions
            .iter_mut()
            .find(|s| s.session_id == id && s.resumed_from.as_deref() != Some(resumed_from))
        else {
            return;
        };
        s.resumed_from = Some(resumed_from.to_string());
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        if write_stage(&sessions_path(), &file).is_ok() {
            let _ = restage_graph();
        }
    });
}

/// Best-effort: refresh a session's transcript-derived fields at a hook boundary —
/// its `say` (the agent's latest words) and, set-once, its `title` (the session
/// NAME, from `custom-title`). Change-only; never touches state/activity/pid;
/// re-stages only when something moved. Silent no-op when the transcript can't be
/// located or read. One tail read serves both fields. All harness knowledge is
/// dispatched through the session agent's `profile`.
///
/// Returns whether it actually WROTE — the hook callers ignore it; the reaper's
/// sweep counts it, so its toast can say how many agents it brought current
/// (see `reap::refresh_live_agents`).
pub(crate) fn refresh_transcript_fields(
    profile: &'static AgentProfile,
    session_id: &str,
    cwd: Option<&str>,
    transcript_hint: Option<&str>,
    preferred_ceiling: Option<u64>,
) -> bool {
    let spec = &profile.transcript;
    let Some(path) = (spec.locate)(session_id, cwd, transcript_hint) else {
        return false;
    };
    let lines = (spec.tail)(&path);
    if lines.is_empty() {
        return false;
    }
    let say = (spec.say)(&lines, true);
    let name = (spec.title)(&lines);
    let model = (spec.model)(&lines, true);
    let context_tokens = (spec.context_tokens)(&lines);
    let tool = (spec.tool)(&lines, true);
    if say.is_none()
        && name.is_none()
        && model.is_none()
        && context_tokens.is_none()
        && tool.is_none()
    {
        return false;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut changed = false;
        for s in file.sessions.iter_mut() {
            if s.session_id != session_id {
                continue;
            }
            if let Some(say) = &say {
                if s.say.as_deref() != Some(say.as_str()) {
                    s.say = Some(say.clone());
                    changed = true;
                }
            }
            if let Some(tool) = &tool {
                if s.tool.as_deref() != Some(tool.as_str()) {
                    s.tool = Some(tool.clone());
                    changed = true;
                }
            }
            // The session NAME is set ONCE — a hook-set or graph-send title wins,
            // so a renamed conductor task is never clobbered by the tab title.
            if let Some(name) = &name {
                if s.title.as_deref().unwrap_or("").is_empty() {
                    s.title = Some(name.clone());
                    changed = true;
                }
            }
            if let Some(model) = &model {
                if s.model.as_deref() != Some(model.as_str()) {
                    s.model = Some(model.clone());
                    changed = true;
                }
                // Publish the model's context ceiling (CONTRACTS.md §4). A
                // harness-reported ceiling (pi's payload `context_ceiling`)
                // WINS over the aoide catalog — a custom/provider model the
                // catalog has never heard of gets the right meter; the catalog
                // stays the fallback for harnesses that don't self-report.
                let ceiling = Some(preferred_ceiling.unwrap_or_else(|| {
                    (profile.model_ceiling)(Some(model.as_str()))
                }));
                if s.context_ceiling != ceiling {
                    s.context_ceiling = ceiling;
                    changed = true;
                }
            }
            if let Some(ctx) = context_tokens {
                if s.context_tokens != Some(ctx) {
                    s.context_tokens = Some(ctx);
                    changed = true;
                }
            }
        }
        if changed {
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            if write_stage(&sessions_path(), &file).is_ok() {
                let _ = restage_graph();
            }
        }
        changed
    })
}

/// Best-effort: refresh the `say` of a session's ACTIVE sub-agent nodes from their
/// own transcript files. Runs on each of the PARENT session's hooks, so a
/// background Task (which outlives the turn) shows its latest words on its beamed
/// child row; a synchronous Task blocks the parent and is too transient to catch.
/// Change-only and bounded to the currently-live sub-nodes (depth-1). The
/// sub-agent transcript layout is the profile's (`spec.subagents_dir` /
/// `spec.find_subagent`).
///
/// Returns whether it WROTE, same as [`refresh_transcript_fields`] and for the
/// same one caller — the reaper counts what it brought current.
pub(crate) fn refresh_subagent_says(
    profile: &'static AgentProfile,
    session_id: &str,
    cwd: Option<&str>,
) -> bool {
    let subs: Vec<String> = match load_stage::<SessionsFile>(&sessions_path()) {
        Ok(file) => file
            .sessions
            .iter()
            .filter(|s| s.kind.as_deref() == Some("subagent"))
            .filter(|s| s.parent_session_id.as_deref() == Some(session_id))
            .map(|s| s.session_id.clone())
            .collect(),
        Err(_) => return false,
    };
    if subs.is_empty() {
        return false;
    }
    let spec = &profile.transcript;
    let Some(dir) = (spec.subagents_dir)(session_id, cwd) else {
        return false;
    };
    // (sub_id, say, model, tool) — any of the three may be None for a given sub.
    let mut updates: Vec<(String, Option<String>, Option<String>, Option<String>)> = Vec::new();
    for sub_id in &subs {
        let Some(tuid) = sub_id.strip_prefix("sub:") else {
            continue;
        };
        let Some(file) = (spec.find_subagent)(&dir, tuid) else {
            continue;
        };
        // A sub-agent's OWN dedicated transcript marks every line isSidechain —
        // don't skip them here (see `extract_say`'s doc). Its model is its OWN
        // (subagents can run a different model than their parent).
        let lines = (spec.tail)(&file);
        let say = (spec.say)(&lines, false);
        let model = (spec.model)(&lines, false);
        let tool = (spec.tool)(&lines, false);
        if say.is_some() || model.is_some() || tool.is_some() {
            updates.push((sub_id.clone(), say, model, tool));
        }
    }
    if updates.is_empty() {
        return false;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut changed = false;
        for (sub_id, say, model, tool) in &updates {
            for s in file.sessions.iter_mut() {
                if &s.session_id != sub_id {
                    continue;
                }
                if let Some(say) = say {
                    if s.say.as_deref() != Some(say.as_str()) {
                        s.say = Some(say.clone());
                        changed = true;
                    }
                }
                if let Some(tool) = tool {
                    if s.tool.as_deref() != Some(tool.as_str()) {
                        s.tool = Some(tool.clone());
                        changed = true;
                    }
                }
                if let Some(model) = model {
                    if s.model.as_deref() != Some(model.as_str()) {
                        s.model = Some(model.clone());
                        changed = true;
                    }
                    // Publish the subagent's own context ceiling — parity with the
                    // parent-session derivation in `refresh_transcript_fields`, so a
                    // subagent card gets a correct meter too (it runs its own model).
                    let ceiling = Some((profile.model_ceiling)(Some(model.as_str())));
                    if s.context_ceiling != ceiling {
                        s.context_ceiling = ceiling;
                        changed = true;
                    }
                }
            }
        }
        if changed {
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            if write_stage(&sessions_path(), &file).is_ok() {
                let _ = restage_graph();
            }
        }
        changed
    })
}

/// Create (or refresh) a sub-agent node — a Task the agent spawned, a leaf of
/// the conductor tree. Keyed by `sub:<tool_use_id>`; parented to `owner` (a
/// parent sub-node when nested, else the session). An existing node is enriched
/// (keeps its parent + first name), so the PreToolUse(Task) and SubagentStart
/// paths converge on one record however they race.
///
/// `allow_create` guards the create branch: the PreToolUse spawn and the classic
/// `parent_tool_use_id` SubagentStart backstop pass `true` (they are the record's
/// origin). The async `Agent` path's SubagentStart carries ONLY an `agent_id`
/// and reaches here keyed `sub:<agent_id>` — but the authoritative node is the
/// one PreToolUse created under `sub:<tool_use_id>` and PostToolUse re-keys to
/// `sub:<agent_id>`; so that fallback passes `false` (enrich-only): it confirms
/// the node once the re-key has landed and is a harmless no-op before then,
/// never a duplicate.
pub(in crate::graph) fn do_subagent_spawn(
    sub_id: &str,
    owner: &str,
    name: &str,
    agent_type: &str,
    allow_create: bool,
) {
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if let Some(s) = file.sessions.iter_mut().find(|s| s.session_id == sub_id) {
            if s.state != "done" && s.state != "working" {
                s.state = "working".to_string();
            }
            if s.title.as_deref().unwrap_or("").is_empty() && !name.is_empty() {
                s.title = Some(name.to_string());
            }
            if (s.agent.is_empty() || s.agent == "subagent") && !agent_type.is_empty() {
                s.agent = agent_type.to_string();
            }
            s.kind = Some("subagent".to_string());
        } else if !allow_create {
            // Enrich-only: the node does not exist yet (the async re-key has not
            // landed). Do nothing rather than create a duplicate/misparented one.
            return;
        } else {
            let petname = aoide_storage::petname::mint_for(&file.sessions);
            file.sessions.push(SessionRecord {
                session_id: sub_id.to_string(),
                agent: if agent_type.is_empty() {
                    "subagent".to_string()
                } else {
                    agent_type.to_string()
                },
                state: "working".to_string(),
                started_at: now_iso_utc(),
                parent_session_id: Some(owner.to_string()),
                title: if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                },
                kind: Some("subagent".to_string()),
                petname: Some(petname),
                ..Default::default()
            });
        }
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        if write_stage(&sessions_path(), &file).is_ok() {
            let _ = restage_graph();
        }
    });
}

/// Close a sub-agent node — REMOVE it (a Task returned / a subagent stopped), so
/// the tree stays clean. Idempotent; re-stages only when it removed one.
pub(in crate::graph) fn do_subagent_end(sub_id: &str) {
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let before = file.sessions.len();
        file.sessions.retain(|s| s.session_id != sub_id);
        if file.sessions.len() != before {
            let _ = write_stage(&sessions_path(), &file);
            let _ = restage_graph();
        }
    });
}

/// Re-key a sub-agent node's `sessionId` in place. An async `Agent` dispatch is
/// created under `sub:<tool_use_id>` (all PreToolUse carries), but the only id
/// its later SubagentStart/SubagentStop carry is the `agent_id` — a different
/// string with no derivable link to the tool_use_id. The dispatch's OWN
/// PostToolUse is the single payload where both co-occur (`tool_use_id` +
/// `tool_response.agentId`), so it renames the record there from
/// `sub:<tool_use_id>` to `sub:<agent_id>` — keeping every other field (parent,
/// kind, state, title, startedAt) untouched — and reparents any child that
/// pointed at the old id. Because each dispatch re-keys using the id pair from
/// its OWN PostToolUse, two Agent calls in one turn never cross-attribute.
///
/// Idempotent: a no-op when the source is gone or the ids already match; if the
/// target id somehow already exists, the stale source is dropped rather than
/// duplicated.
pub(in crate::graph) fn do_subagent_rekey(from_sub_id: &str, to_sub_id: &str) {
    if from_sub_id == to_sub_id || from_sub_id.is_empty() || to_sub_id.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        if !file.sessions.iter().any(|s| s.session_id == from_sub_id) {
            return; // source gone (PreToolUse missed, or already re-keyed) — no-op
        }
        let target_exists = file.sessions.iter().any(|s| s.session_id == to_sub_id);
        let mut changed = false;
        if target_exists {
            // A node already lives under the new id — never duplicate; drop the
            // stale source and let the existing target stand.
            let before = file.sessions.len();
            file.sessions.retain(|s| s.session_id != from_sub_id);
            changed = file.sessions.len() != before;
        } else {
            for s in file.sessions.iter_mut() {
                if s.session_id == from_sub_id {
                    s.session_id = to_sub_id.to_string();
                    changed = true;
                }
            }
        }
        // Reparent any child that pointed at the old id (none at launch time, but
        // keeps the tree consistent if a nested node ever raced in first).
        for s in file.sessions.iter_mut() {
            if s.parent_session_id.as_deref() == Some(from_sub_id) {
                s.parent_session_id = Some(to_sub_id.to_string());
                changed = true;
            }
        }
        if changed {
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            if write_stage(&sessions_path(), &file).is_ok() {
                let _ = restage_graph();
            }
        }
    });
}

/// Core of `session phase`: UPSERT the hook record (audit), land the
/// canonical live state on sessions.json (the widget file), re-stage. The whole
/// load-modify-write is serialised against every other stage writer by the
/// stage lock (its inner helpers stay lock-free — the lock is not re-entrant).
pub(in crate::graph) fn do_session_phase(id: &str, phase: &str) -> Outcome {
    with_stage_lock(|| do_session_phase_inner(id, phase))
}
fn do_session_phase_inner(id: &str, phase: &str) -> Outcome {
    let cmd = "session.phase";
    let mut file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let now = now_iso_utc();
    upsert_hook(&mut file.hooks, id, phase, &now);
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&hooks_path(), &file) {
        return stage_error(cmd, e);
    }
    // Land the canonical live state on sessions.json (the widget file), so the
    // roster/dock render working/awaiting/idle — not just running/done.
    if let Err(e) = set_session_state(id, phase) {
        return stage_error(cmd, e);
    }
    let mut changed = vec![format!("session {id}: phase → {phase}")];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(cmd, format!("session `{id}` phase = {phase}"))
        .changed(changed)
        .with_data(json!({
            "sessionId": id,
            "phase": phase,
            "updatedAt": now,
            "file": hooks_path().to_string_lossy(),
        }))
}

/// Conditional sibling of [`do_session_phase`]: UPSERT `phase` for `id` ONLY when
/// its CURRENT hook phase equals `expected`, else an ok no-op that writes nothing.
/// hooks.json is loaded ONCE — the guard read and the write share the same load,
/// so the current phase is never read twice. This is the door the ambiguous idle
/// Notification walks: only a still-`working` turn becomes `awaiting`.
pub(in crate::graph) fn do_session_phase_if(id: &str, phase: &str, expected: &str) -> Outcome {
    with_stage_lock(|| do_session_phase_if_inner(id, phase, expected))
}
fn do_session_phase_if_inner(id: &str, phase: &str, expected: &str) -> Outcome {
    let cmd = "session.phase";
    let mut file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let current = file
        .hooks
        .iter()
        .find(|h| h.session_id == id)
        .map(|h| h.phase.clone())
        .unwrap_or_default();
    // Compare canonically so a mid-migration legacy phase (`running`) still
    // counts as `working` — the guard is about the effective state, not the
    // exact stored token.
    if canonical_state(&current) != canonical_state(expected) {
        return Outcome::ok(
            cmd,
            format!("session `{id}` phase unchanged (current `{current}` ≠ `{expected}`)"),
        )
        .with_data(json!({
            "sessionId": id,
            "phase": current,
            "skipped": true,
            "expected": expected,
        }));
    }
    let now = now_iso_utc();
    upsert_hook(&mut file.hooks, id, phase, &now);
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&hooks_path(), &file) {
        return stage_error(cmd, e);
    }
    // Land the canonical live state on sessions.json (the widget file), so the
    // roster/dock render working/awaiting/idle — not just running/done.
    if let Err(e) = set_session_state(id, phase) {
        return stage_error(cmd, e);
    }
    let mut changed = vec![format!("session {id}: phase → {phase}")];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(cmd, format!("session `{id}` phase = {phase}"))
        .changed(changed)
        .with_data(json!({
            "sessionId": id,
            "phase": phase,
            "updatedAt": now,
            "file": hooks_path().to_string_lossy(),
        }))
}

/// Core of `session end`: mark the session `done` (and its hook phase
/// `done`), re-stage. An unknown id is an ok no-op (matching `project remove`).
///
/// Also closes every ssh tunnel this session opened
/// (`aoide_client::tunnel::close_all_for_session`, ssh-transport lane P-S5) —
/// the FAST path for the lifecycle rule "persistent within a session,
/// ephemeral across sessions": a clean `session end` tears its own tunnels
/// down immediately rather than waiting on the reaper's
/// `sweep_orphan_tunnels` backstop, which exists precisely for the session
/// that never gets to run this exit path (SUPER+Q, SIGKILL). Runs AFTER the
/// stage lock is released, deliberately: closing a tunnel means signaling
/// and `waitpid`-reaping a real `ssh` child, which can take up to ~1s
/// (`terminate_pid`'s bounded waits) and has nothing to do with the
/// sessions/hooks stage files the lock actually guards. Best-effort — a
/// tunnel that fails to close here is still caught by the reaper, so its
/// error is never allowed to turn a successful `session end` into a
/// reported failure.
pub(in crate::graph) fn do_session_end(id: &str) -> Outcome {
    let outcome = with_stage_lock(|| do_session_end_inner(id));
    let _ = aoide_client::tunnel::close_all_for_session(id);
    // The check lane's own baseline for this session (task #139 review
    // finding: nothing ever deleted `state/checklane/<id>.json` — an effect
    // with no inverse). Same best-effort posture as the tunnel close above;
    // a session with no baseline (the lane was never configured) is a no-op.
    aoide_upkeep::checklane::forget_baseline(id);
    outcome
}
fn do_session_end_inner(id: &str) -> Outcome {
    let cmd = "session.end";
    let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    if !s_file.sessions.iter().any(|s| s.session_id == id) {
        return Outcome::ok(
            cmd,
            format!("session `{id}` was not registered (no change)"),
        )
        .with_data(json!({ "sessionId": id }));
    }
    let now = now_iso_utc();
    for s in s_file.sessions.iter_mut() {
        if s.session_id == id {
            // The ledger write (P-D8), gated on an ACTUAL transition: unlike
            // `reap_inner` (whose `reaped` set is only ever built from
            // not-`done` records, so it can never re-process an id), this
            // handler leaves the record present-and-`done` rather than
            // pruning it — so a REPEAT `session end` on the same id must
            // find it already `done` and skip the write, or every repeat
            // call would append a second line for one exit. Only the first
            // call (a genuine not-done → done transition) reaches
            // `ledger_session_exit` (`doc.rs`) — the same one shared call
            // `reap_inner`'s own exit routes through too.
            if s.state != "done" {
                ledger_session_exit(s, &now);
            }
            s.state = "done".to_string();
        }
    }
    // Cascade: remove the session's sub-agent subtree. Task nodes carry no pid or
    // window, so the liveness reaper can never clean them — the owning session's
    // end IS their lifecycle end. Collect the transitive `subagent` descendants
    // (shared with `prune_done`'s own cascade, `doomed_subagent_descendants`) and
    // drop them (the session itself stays, marked done).
    let roots: HashSet<&str> = std::iter::once(id).collect();
    let doomed = doomed_subagent_descendants(&s_file.sessions, &roots);
    s_file.sessions.retain(|s| !doomed.contains(&s.session_id));
    if s_file.schema_version.is_empty() {
        s_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error(cmd, e);
    }

    // Mirror the terminal state into hooks.json so the merged live phase agrees.
    // Reuses the SAME `now` the ledger write above stamped as this session's
    // `endedAt` — one instant for the whole roster-exit, not two clock reads.
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    upsert_hook(&mut h_file.hooks, id, "done", &now);
    if h_file.schema_version.is_empty() {
        h_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&hooks_path(), &h_file) {
        return stage_error(cmd, e);
    }

    let mut changed = vec![
        format!("session {id}: state → done"),
        format!("session {id}: phase → done"),
    ];
    match restage_graph() {
        Ok(g) => changed.push(g.to_string_lossy().into_owned()),
        Err(e) => return stage_error(cmd, e),
    }
    Outcome::ok(cmd, format!("ended session `{id}`"))
        .changed(changed)
        .with_data(json!({ "sessionId": id, "file": sessions_path().to_string_lossy() }))
}

/// `session start --id <id> [--agent --cwd --window --parent]` — UPSERT a
/// running session record (idempotent; startedAt preserved on re-start).
///
/// P-D6 graph residency (`docs/architecture/AOIDED.md`'s "L4"): tries the
/// resident daemon's `dispatch` op FIRST — same registered handler, same
/// stage-write bytes, just run in the daemon's process — and falls back to
/// the direct write below byte-identically when nothing answers
/// (`aoide_client::daemon::daemon_dispatch`'s own contract).
pub fn session_start(inv: &Invocation) -> Outcome {
    if let Some(outcome) = aoide_client::daemon::daemon_dispatch(inv) {
        return outcome;
    }
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_start(
        &id,
        inv.flags.get("agent").map(String::as_str),
        inv.flags.get("cwd").map(String::as_str),
        inv.flags.get("window").map(String::as_str),
        inv.flags.get("parent").map(String::as_str),
        None,
        None,
        None,
        None,
    )
}

/// `session phase --id <id> --phase <phase>` — UPSERT the live hook phase.
///
/// P-D6 routing (see [`session_start`]'s own doc for the full contract).
pub fn session_phase(inv: &Invocation) -> Outcome {
    if let Some(outcome) = aoide_client::daemon::daemon_dispatch(inv) {
        return outcome;
    }
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    let phase = match require_flag(inv, "phase") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_phase(&id, &phase)
}

/// `session end --id <id>` — mark the session done (ok no-op if unknown).
///
/// P-D6 routing (see [`session_start`]'s own doc for the full contract).
pub fn session_end(inv: &Invocation) -> Outcome {
    if let Some(outcome) = aoide_client::daemon::daemon_dispatch(inv) {
        return outcome;
    }
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_end(&id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::model::merged_sessions;
    use crate::graph::testutil::*;
    use crate::graph::manage::{project_add, view};
    // The reaper moved to `crate::reap`; its tests still live here (they
    // lean on session-lifecycle fixtures/helpers this module owns).
    use crate::reap::{effective_live_addresses, is_session_dead, reap};

    #[test]
    fn do_subagent_spawn_mints_a_petname_on_create() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("subagent-spawn-petname");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        do_subagent_spawn("sub:t1", "owner", "Task name", "explore", true);

        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "sub:t1").unwrap();
        assert!(rec.petname.is_some(), "a freshly created subagent node must mint a petname");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn iso_utc_formats_and_round_trips_through_the_reader() {
        // The Unix epoch and a known instant, formatted exactly.
        assert_eq!(iso_utc_from_epoch(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc_from_epoch(1_700_000_000), "2023-11-14T22:13:20Z");
        // Whatever we stamp must parse back through conductor's reader (the inverse).
        let stamp = now_iso_utc();
        let epoch = aoide_storage::time::parse_iso_utc(&stamp)
            .expect("a stamp we write is readable by the reader that consumes it");
        // And that epoch re-formats to the very same string (round-trip closed).
        assert_eq!(iso_utc_from_epoch(epoch), stamp);
    }
    #[test]
    fn upsert_session_is_idempotent_and_preserves_started_at() {
        let mut sessions: Vec<SessionRecord> = Vec::new();
        // First start: inserted, idle, agent defaulted, startedAt stamped.
        assert!(upsert_session(
            &mut sessions,
            "s1",
            None,
            Some("/w"),
            None,
            None,
            None,
            None,
            None,
            None,
            "2026-01-01T00:00:00Z"
        ));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].agent, "claude");
        assert_eq!(sessions[0].state, "idle");
        assert_eq!(sessions[0].started_at, "2026-01-01T00:00:00Z");

        // Re-start with a NEW now + agent + conductor fields: no duplicate,
        // fields updated, but startedAt is NEVER clobbered.
        assert!(!upsert_session(
            &mut sessions,
            "s1",
            Some("melete"),
            None,
            Some("0xabc"),
            Some("parent"),
            Some(true),
            Some("/run/user/1000/aoide/session-s1.sock"),
            Some("do the thing"),
            None,
            "2026-02-02T00:00:00Z"
        ));
        assert_eq!(sessions.len(), 1, "re-start never duplicates");
        assert_eq!(sessions[0].agent, "melete");
        assert_eq!(sessions[0].window_address, "0xabc");
        assert_eq!(sessions[0].parent_session_id.as_deref(), Some("parent"));
        assert_eq!(sessions[0].conductable, Some(true));
        assert_eq!(
            sessions[0].socket.as_deref(),
            Some("/run/user/1000/aoide/session-s1.sock")
        );
        assert_eq!(sessions[0].title.as_deref(), Some("do the thing"));
        assert_eq!(
            sessions[0].started_at, "2026-01-01T00:00:00Z",
            "startedAt preserved across re-start"
        );
    }
    #[test]
    fn upsert_hook_keeps_one_bounded_record_per_session() {
        let mut hooks: Vec<HookRecord> = Vec::new();
        upsert_hook(&mut hooks, "s1", "running", "2026-01-01T00:00:01Z");
        upsert_hook(&mut hooks, "s1", "waiting", "2026-01-01T00:00:02Z");
        upsert_hook(&mut hooks, "s2", "running", "2026-01-01T00:00:03Z");
        assert_eq!(hooks.len(), 2, "one record per session id, never appended");
        let s1 = hooks.iter().find(|h| h.session_id == "s1").unwrap();
        assert_eq!(s1.phase, "waiting");
        assert_eq!(s1.updated_at, "2026-01-01T00:00:02Z");
        // merged_sessions tolerates the one-per-session shape: latest phase wins,
        // folded to the canonical vocab (`waiting` → `idle`).
        let sessions = vec![session("s1", "/w", "running", "t", None)];
        let merged = merged_sessions(&sessions, &hooks);
        assert_eq!(merged[0].state, "idle");
    }
    #[test]
    fn registration_evicts_a_same_window_agent_sibling_immediately() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("regi-evict");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A phantom claude registers on a window first (the old, un-ended id).
        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "old"), ("agent", "claude"), ("cwd", "/p"), ("window", "0xWIN")],
        ));
        // A NEW claude registers on the SAME window (the real re-id after a
        // compact/resume) — this must retire "old" immediately, no grace, no
        // waiting on the reaper.
        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "new"), ("agent", "claude"), ("cwd", "/p"), ("window", "0xWIN")],
        ));

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids: Vec<&str> = s.sessions.iter().map(|r| r.session_id.as_str()).collect();
        assert!(ids.contains(&"new"), "the newly-registered session survives");
        assert!(!ids.contains(&"old"), "the same-window sibling was evicted at registration");

        // A conducted SHELL registering onto the SAME window as an agent must
        // NEVER evict it — that is the normal "shell hosts claude" pairing, not a
        // duplicate. Re-seed "old" as a fresh agent, then register a shell.
        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "again", ), ("agent", "claude"), ("cwd", "/p"), ("window", "0xWIN2")],
        ));
        do_session_start(
            "shellhost",
            Some("shell"),
            Some("/p"),
            Some("0xWIN2"),
            None,
            Some(true), // conductable → is_agent_kind() is false for this record
            None,
            None,
            None,
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids2: Vec<&str> = s2.sessions.iter().map(|r| r.session_id.as_str()).collect();
        assert!(ids2.contains(&"again"), "a conducted shell never evicts its hosted agent");
        assert!(ids2.contains(&"shellhost"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn registration_never_evicts_a_conducted_pty_host() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("regi-host");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // The wrapper: `aoide conduct -- kimi` registers its own record —
        // agent name = the child's basename, conductable + socket (the
        // control-socket owner). upsert_session classifies it kind="agent"
        // from that basename; it is the HOST, not a foreground agent.
        do_session_start(
            "conduct-1",
            Some("kimi"),
            Some("/p"),
            Some("0xWIN3"),
            None,
            Some(true),
            Some("/run/aoide/conduct-1.sock"),
            None,
            None,
        );
        // kimi's SessionStart hook fires inside the conducted child:
        // agent-kind, SAME window, parent = the wrapper id (threaded via
        // AOIDE_SESSION_ID). Before the host carve-outs this registration
        // evicted the wrapper — `send --id conduct-1` then failed
        // "unknown session" and the session could never be commanded.
        do_session_start(
            "kimi-hook-1",
            Some("kimi"),
            Some("/p"),
            Some("0xWIN3"),
            Some("conduct-1"),
            None,
            None,
            None,
            None,
        );

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids: Vec<&str> = s.sessions.iter().map(|r| r.session_id.as_str()).collect();
        assert!(
            ids.contains(&"conduct-1"),
            "the conducted PTY host survives its child's SessionStart"
        );
        assert!(
            ids.contains(&"kimi-hook-1"),
            "the hook session registers alongside its host"
        );
        // The record really is the shape that fooled the old
        // published-kind-wins rule: kind="agent" AND conductable.
        let host = s.sessions.iter().find(|r| r.session_id == "conduct-1").unwrap();
        assert_eq!(host.kind.as_deref(), Some("agent"));
        assert_eq!(host.conductable, Some(true));
        assert_eq!(host.state, "idle", "still live, not evicted-done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    /// The exact live topology diagnosed for task #89: a windowed terminal
    /// wrap hosts claude (same window); claude's own shell tool runs `graph
    /// spawn` for kimi with NO `--parent`, launching a nested HEADLESS wrap
    /// whose own hook session must land as claude's CHILD — not, via a stale
    /// `AOIDE_SESSION_ID` env fallback, as the TERMINAL's sibling. All three
    /// User-decided fixes this regression pins at once: (1) kimi is
    /// windowless by construction (never backfilled to the terminal's
    /// window); (3) the nested wrap parents under claude via the `/proc`
    /// ancestry ↔ `hookAncestry` walk, not the terminal; (2) even forced onto
    /// the SAME window as claude (the pre-fix degraded symptom), the widened
    /// lineage carve-out never evicts either side, because they are
    /// grandparent/grandchild through the nested wrap — never unrelated
    /// same-window twins.
    #[test]
    fn nested_headless_lineage_is_windowless_ancestry_parented_and_never_evicted() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("lineage-nested");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Terminal wrap: windowed, conducted (`aoide conduct` on the shell).
        do_session_start(
            "term-wrap", Some("shell"), Some("/w"), Some("0xWIN"), None, Some(true), None, None,
            None,
        );
        // claude's own hook SessionStart: same window (it runs IN that
        // terminal), parented under the wrap.
        do_session_start(
            "claude", Some("claude"), Some("/w"), Some("0xWIN"), Some("term-wrap"), None, None,
            None, None,
        );
        // claude's own `hookAncestry`, stamped as it would be at its real
        // SessionStart: a REAL ancestor pid of THIS test process — the
        // ancestry walk below has no fake `/proc` to read from, so the only
        // way to exercise the real mechanism is to seed it with the test
        // process's own genuine ancestry.
        let my_ancestry = crate::graph::window::pid_ancestry(std::process::id() as i32);
        stamp_hook_ancestry("claude", &[my_ancestry[1]]);

        // Part 3 — automatic parenting: `spawn`'s own re-exec'd
        // `conduct --headless` for kimi carries no explicit `--parent`. The
        // ancestry walk must resolve to claude, not fall through to an env
        // fallback that would carry the TERMINAL's id (the "spawned wraps
        // parent under the terminal as siblings" bug).
        let snapshot = load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions;
        let resolved = crate::graph::window::resolve_registration_parent(None, "kimi-wrap", &snapshot);
        assert_eq!(
            resolved.as_deref(),
            Some("claude"),
            "kimi's nested wrap must parent under claude via ancestry, never the terminal"
        );
        // The nested wrap itself: headless (no window), conducted. Registered
        // the same two-step way the real `session_conduct` command does it —
        // `do_session_start` first, then `stamp_headless` right after (see
        // `conduct.rs`'s own `headless_conduct_registration_stamps_the_
        // permanent_headless_marker`, which exercises the REAL command end to
        // end, discovery gate included; this test reuses the same
        // stage-writer `stamp_headless` calls, not a raw field literal, so
        // it stays honest about what actually gets written).
        do_session_start(
            "kimi-wrap", Some("kimi"), Some("/w"), None, resolved.as_deref(), Some(true), None,
            None, None,
        );
        stamp_headless("kimi-wrap");

        // Part 1 — windowless lineage: kimi-wrap is a conducted wrap with an
        // EMPTY window, so kimi's own hook session (its child) is windowless
        // BY CONSTRUCTION and must never backfill to the enclosing
        // terminal's window.
        let snapshot = load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions;
        assert!(
            crate::graph::window::windowless_by_lineage_from_parent(Some("kimi-wrap"), &snapshot),
            "kimi must be windowless: its own wrap is headless"
        );
        // claude, by contrast, anchors in a WINDOWED wrap directly — its own
        // backfill stays live (today's behavior, unchanged).
        assert!(!crate::graph::window::windowless_by_lineage_from_parent(Some("term-wrap"), &snapshot));

        // Review round 2 — the re-poison scenario: even if window discovery
        // (or the shellbridge listener) somehow still stamped a STRAY window
        // onto kimi-wrap's own record — the exact bug the gate at
        // `conduct.rs:825` and the listener skip now prevent — the
        // PERMANENT `headless` marker keeps kimi's own backfill check
        // windowless regardless. Force the stray value directly on the
        // stage file (bypassing every write path) to prove the marker alone
        // decides, not `windowAddress` emptiness.
        with_stage_lock(|| {
            let mut f: SessionsFile = load_stage(&sessions_path()).unwrap();
            for s in f.sessions.iter_mut() {
                if s.session_id == "kimi-wrap" {
                    s.window_address = "0xWIN".to_string(); // stray/corrupted
                }
            }
            write_stage(&sessions_path(), &f).unwrap();
        });
        let poisoned = load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions;
        assert!(
            crate::graph::window::windowless_by_lineage_from_parent(Some("kimi-wrap"), &poisoned),
            "the headless marker must override even a corrupted, non-empty windowAddress"
        );
        // Restore for the rest of the test — the corruption above was a
        // deliberate, isolated probe, not this test's real topology.
        with_stage_lock(|| {
            let mut f: SessionsFile = load_stage(&sessions_path()).unwrap();
            for s in f.sessions.iter_mut() {
                if s.session_id == "kimi-wrap" {
                    s.window_address = String::new();
                }
            }
            write_stage(&sessions_path(), &f).unwrap();
        });

        // Part 2 — lineage-safe eviction: register kimi's own hook session,
        // deliberately forced (the pre-fix DEGRADED symptom — what actually
        // happened live before part 1 existed) onto the SAME window as
        // claude. The widened carve-out must protect BOTH sides: kimi and
        // claude are grandchild/grandparent through kimi-wrap, never
        // unrelated same-window twins.
        let out = do_session_start(
            "kimi", Some("kimi"), Some("/w"), Some("0xWIN"), Some("kimi-wrap"), None, None, None,
            None,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        for id in ["term-wrap", "claude", "kimi-wrap", "kimi"] {
            let rec = s
                .sessions
                .iter()
                .find(|r| r.session_id == id)
                .unwrap_or_else(|| panic!("{id} missing from sessions.json"));
            assert_ne!(rec.state, "done", "{id} must survive — lineage-safe eviction");
        }

        // The legitimate case, regression-pinned alongside the fix: a
        // genuine compact/resume twin holding the SAME window with NO
        // lineage relation to anything already there must still collapse
        // instantly — the widened carve-out protects only an ACTUAL lineage
        // member, never every same-window occupant.
        let out2 = do_session_start(
            "claude-resumed", Some("claude"), Some("/w"), Some("0xWIN"), None, None, None, None,
            None,
        );
        assert_eq!(out2.status, aoide_protocol::output::Status::Ok);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids2: Vec<&str> = s2.sessions.iter().map(|r| r.session_id.as_str()).collect();
        assert!(ids2.contains(&"claude-resumed"), "the new twin survives");
        assert!(
            !ids2.contains(&"claude"),
            "the old same-window twin with no lineage relation to the new one still collapses (evicted, then pruned)"
        );
        assert!(
            !ids2.contains(&"kimi"),
            "kimi too — same window, no lineage relation to the freshly-registered twin"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn session_start_upserts_restages_and_anchors_under_a_project() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-start");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // The anchor root must now be a REAL absolute dir (project_add
        // rejects anything else), so the project + session cwd live under
        // the per-test stage dir instead of the fictional /home/k/Aoide.
        let proj = stage.join("proj");
        std::fs::create_dir_all(proj.join("sub")).unwrap();
        project_add(&invocation(
            &["project", "add"],
            &["aoide", proj.to_str().unwrap()],
        ));
        let out = session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "s1"), ("cwd", proj.join("sub").to_str().unwrap())],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let s_file: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_file.sessions.len(), 1);
        assert_eq!(s_file.sessions[0].state, "idle");
        let started = s_file.sessions[0].started_at.clone();
        assert!(!started.is_empty());

        // Every mutation re-stages: graph.json carries the session node + the
        // project-anchored edge, and equals exactly what `view` computes.
        let staged: Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("graph.json")).unwrap())
                .unwrap();
        assert!(staged["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == "session:s1"));
        assert!(staged["edges"].as_array().unwrap().iter().any(|e| {
            e["from"] == "project:aoide" && e["to"] == "session:s1" && e["kind"] == "anchors"
        }));
        let view = view(&invocation(&["graph"], &[]));
        assert_eq!(&staged, view.data.as_ref().unwrap());

        // Re-start updates the agent but preserves startedAt and never dupes.
        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "s1"), ("agent", "melete")],
        ));
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions.len(), 1);
        assert_eq!(s2.sessions[0].agent, "melete");
        assert_eq!(s2.sessions[0].started_at, started);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn session_start_refuses_a_cyclic_parent() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-cycle");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        session_start(&flag_invocation(&["session", "start"], &[("id", "a")]));
        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "b"), ("parent", "a")],
        ));
        // a parented under b would close b→a→…: refused (exit 1), no mutation.
        let out = session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "a"), ("parent", "b")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "cycle");
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions.iter().find(|x| x.session_id == "a").unwrap().parent_session_id.is_none());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn session_end_unknown_id_is_ok_noop() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-end-unknown");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = session_end(&flag_invocation(
            &["session", "end"],
            &[("id", "ghost")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert!(out.changed.is_empty(), "unknown id → no change");
        // No session file was written (nothing to end).
        assert!(!sessions_path().exists());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn session_end_appends_exactly_one_ledger_line() {
        // P-D8: the `do_session_end` half of "clean end and reap each
        // produce one ledger line, never two" — `reap`'s own half lives in
        // `reap.rs`'s test suite; both route through the SAME
        // `ledger_session_exit` (`doc.rs`).
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR"]);
        let stage = unique_stage("sess-end-ledger");
        let state = stage.join("state");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);

        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "end-ledger-1"), ("agent", "claude"), ("cwd", "/w")],
        ));
        let out = session_end(&flag_invocation(
            &["session", "end"],
            &[("id", "end-ledger-1")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);

        let lines = aoide_storage::ledger::read_ledger().unwrap();
        let mine: Vec<_> = lines.iter().filter(|l| l.session_id == "end-ledger-1").collect();
        assert_eq!(mine.len(), 1, "exactly one ledger line, never two: {lines:?}");
        assert_eq!(mine[0].agent, "claude");
        assert_eq!(mine[0].cwd, "/w");
        assert!(!mine[0].ended_at.is_empty());

        // Ending it again (a repeat/idempotent call) must NOT append a
        // second line — the record is already gone from the LIVE (not-done)
        // set the write loop iterates, so the second call is a genuine no-op
        // for the ledger, same as it already is for sessions.json.
        let _ = session_end(&flag_invocation(
            &["session", "end"],
            &[("id", "end-ledger-1")],
        ));
        let lines2 = aoide_storage::ledger::read_ledger().unwrap();
        let mine2: usize = lines2.iter().filter(|l| l.session_id == "end-ledger-1").count();
        assert_eq!(mine2, 1, "a repeat `session end` must not double-append");

        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn session_end_closes_its_own_tunnels_and_spares_another_sessions() {
        // The ssh-transport lane's P-S5 fast path: a clean `session end`
        // closes every tunnel THIS session opened
        // (`aoide_client::tunnel::close_all_for_session`) without touching a
        // different session's — the reaper's `sweep_orphan_tunnels` is only
        // the backstop for the session that never gets to run this path.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR"]);
        let stage = unique_stage("sess-end-tunnels");
        let state = stage.join("state");
        let runtime = stage.join("runtime");
        std::fs::create_dir_all(runtime.join("aoide")).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &runtime);

        session_start(&flag_invocation(
            &["session", "start"],
            &[("id", "end-tunnel-1"), ("agent", "claude"), ("cwd", "/w")],
        ));

        let tunnel_record = |session_id: &str, key: &str| aoide_storage::tunnel::TunnelRecord {
            schema_version: aoide_storage::tunnel::TUNNEL_VERSION.to_string(),
            session_id: session_id.to_string(),
            key: key.to_string(),
            ssh_target: "ssh://user@host".to_string(),
            local_port: 40010,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8710,
            // A pid nothing on the box holds — `close`'s guarded kill is
            // then a fast no-op, exactly like a genuinely dead forward.
            pid: 999_999_999,
            opened_at: aoide_storage::time::now_iso_utc(),
        };
        aoide_storage::tunnel::save(&tunnel_record("end-tunnel-1", "peer-a")).unwrap();
        aoide_storage::tunnel::save(&tunnel_record("other-session", "peer-b")).unwrap();

        let out = session_end(&flag_invocation(
            &["session", "end"],
            &[("id", "end-tunnel-1")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);

        assert!(
            aoide_storage::tunnel::load("end-tunnel-1", "peer-a").is_none(),
            "the ended session's own tunnel record is closed",
        );
        assert!(
            aoide_storage::tunnel::load("other-session", "peer-b").is_some(),
            "another session's tunnel record is untouched",
        );

        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn set_session_log_path_is_change_only_and_noops_on_an_unknown_id() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-log-path");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        session_start(&flag_invocation(&["session", "start"], &[("id", "s")]));

        set_session_log_path("s", "/home/khoa/Aoide/state/sessions/s.log");
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|x| x.session_id == "s").unwrap().log_path.as_deref(),
            Some("/home/khoa/Aoide/state/sessions/s.log")
        );
        let mtime_after_first = std::fs::metadata(sessions_path()).unwrap().modified().unwrap();

        // A second call with the SAME path is change-only: no rewrite, so the
        // file's mtime does not advance.
        std::thread::sleep(std::time::Duration::from_millis(10));
        set_session_log_path("s", "/home/khoa/Aoide/state/sessions/s.log");
        let mtime_after_second = std::fs::metadata(sessions_path()).unwrap().modified().unwrap();
        assert_eq!(
            mtime_after_first, mtime_after_second,
            "an identical logPath must not rewrite the stage file"
        );

        // An unknown id is a safe no-op (never panics, never inserts a record).
        set_session_log_path("ghost", "/nope.log");
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions.len(), 1);
        assert!(!s2.sessions.iter().any(|x| x.session_id == "ghost"));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn session_start_requires_the_id_flag() {
        // P-D6: `session_start` now tries the daemon FIRST — this test does
        // no stage/env setup of its own, but still needs `env_lock`'s own
        // one-time `AOIDE_DAEMON_SOCKET` isolation stamp (`lib.rs`'s own
        // doc) so a real resident daemon on this box is never reached.
        let _guard = crate::env_lock().lock().unwrap();
        let out = session_start(&flag_invocation(&["session", "start"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
    }
    #[test]
    fn is_session_dead_combines_signals_and_never_false_reaps() {
        let live: HashSet<String> = ["aaa", "bbb"].iter().map(|s| s.to_string()).collect();
        let alive = |_p: u32| true; // /proc/<pid> exists
        let dead_proc = |_p: u32| false; // /proc/<pid> is gone
        let rec = |window: &str, pid: Option<u32>| SessionRecord {
            window_address: window.into(),
            pid,
            ..Default::default()
        };
        // These assertions are about the window/pid signals only; pin the third
        // (stale hook-only) signal off by reporting "just seen right now" for
        // every record, regardless of state.
        let now = 0_i64;
        let fresh = |_: &SessionRecord| Some(now);

        // Window-gone (the SUPER+Q kill): a non-empty window absent from the live
        // set is dead even when the pid is alive. The match is 0x/case-tolerant.
        assert!(is_session_dead(
            &rec("0xCCC", None),
            Some(&live),
            None,
            alive,
            now,
            fresh
        ));
        assert!(is_session_dead(
            &rec("0xCCC", Some(9)),
            Some(&live),
            None,
            alive,
            now,
            fresh
        ));
        // A live window (normalised match) with a live pid → NOT dead.
        assert!(!is_session_dead(
            &rec("0xAAA", Some(9)),
            Some(&live),
            None,
            alive,
            now,
            fresh
        ));

        // Process-gone: a pid whose /proc vanished is dead regardless of window
        // (here the window IS live, so ONLY the pid signal fires).
        assert!(is_session_dead(
            &rec("0xAAA", Some(9)),
            Some(&live),
            None,
            dead_proc,
            now,
            fresh
        ));

        // NEVER-FALSE-REAP #1 — neither signal (no window, no pid), and the third
        // signal reports "just seen": left alone.
        assert!(!is_session_dead(
            &rec("", None),
            Some(&live),
            None,
            dead_proc,
            now,
            fresh
        ));

        // NEVER-FALSE-REAP #2 — compositor NOT queried (None): the window signal
        // is suppressed, so a windowed session we could not SEE is never reaped;
        // only the authoritative pid signal remains.
        assert!(!is_session_dead(
            &rec("0xCCC", None),
            None,
            None,
            alive,
            now,
            fresh
        ));
        assert!(!is_session_dead(
            &rec("0xCCC", Some(9)),
            None,
            None,
            alive,
            now,
            fresh
        )); // pid alive → alive
        assert!(is_session_dead(
            &rec("0xCCC", Some(9)),
            None,
            None,
            dead_proc,
            now,
            fresh
        )); // pid gone → dead
    }
    #[test]
    fn reap_drops_killed_sessions_but_spares_the_living() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        // Force pid-only liveness: with no compositor the window signal is
        // suppressed, so the reap decision rests purely on /proc/<pid> — fully
        // deterministic in a test (no hyprctl, no real windows).
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let stage = unique_stage("reap");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A pid that can NEVER exist (above every Linux pid_max) is the killed
        // session; this very process's pid is the living one; and a hook-only
        // session carries NEITHER the window NOR the pid signal and must be
        // spared — AS LONG AS it is fresh. It is stamped with the real "now"
        // (not the fixed 2026-01-01 the other two use) so the reaper's new
        // stale-hook-only-at-rest signal (which reads the real wall clock) does
        // not fire on it: this test is about the window/pid signals, not
        // staleness (that has its own coverage in `reap.rs`'s unit tests).
        let dead_pid = u32::MAX;
        let now = "2026-01-01T00:00:00Z";
        let fresh_now = now_iso_utc();
        let mut sessions = Vec::new();
        // `live` is stamped with the real "now" for the same reason `hookonly`
        // below is: every reaper signal that reads the wall clock must find it
        // current. The pre-boot signal is the second of those — a record whose
        // every timestamp predates the machine's boot is condemned however
        // alive its pid looks, precisely because a pid outliving a reboot is a
        // recycled one. A fixed 2026-01-01 birth date beside a live pid is a
        // state the world cannot produce.
        upsert_session(
            &mut sessions, "live", None, Some("/w"), None, None, None, None, None,
            Some(std::process::id()), &fresh_now,
        );
        upsert_session(
            &mut sessions, "killed", None, Some("/w"), None, None, None, None, None,
            Some(dead_pid), now,
        );
        upsert_session(
            &mut sessions, "hookonly", None, Some("/w"), None, None, None, None, None,
            None, &fresh_now,
        );
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();
        let mut hooks = Vec::new();
        upsert_hook(&mut hooks, "killed", "running", now);
        write_stage(
            &hooks_path(),
            &HooksFile { schema_version: "0".into(), hooks },
        )
        .unwrap();

        let out = reap(&invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["reaped"], json!(["killed"]));
        assert_eq!(data["hyprctlAvailable"], json!(false)); // pid-only fallback

        // The killed session AND its hook are gone; live + hook-only survive.
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids: Vec<&str> = s2.sessions.iter().map(|s| s.session_id.as_str()).collect();
        assert!(ids.contains(&"live"), "a live session is never reaped");
        assert!(ids.contains(&"hookonly"), "a signal-less session is never reaped");
        assert!(!ids.contains(&"killed"), "the killed session was reaped");
        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        assert!(h2.hooks.iter().all(|h| h.session_id != "killed"));

        // graph.json was re-staged and no longer carries the reaped node.
        let g: Value =
            serde_json::from_str(&std::fs::read_to_string(stage.join("graph.json")).unwrap())
                .unwrap();
        assert!(g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["id"] != "session:killed"));

        // Idempotent + never non-zero: a second sweep finds nothing to reap.
        let again = reap(&invocation(&["session", "reap"], &[]));
        assert_eq!(again.status, aoide_protocol::output::Status::Ok);
        assert_eq!(again.data.unwrap()["reaped"], json!([]));

        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn reap_cascades_an_orphaned_subagent_when_its_top_level_parent_is_reaped() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only liveness
        let stage = unique_stage("reap-subagent-cascade");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // A pid that cannot possibly be alive → the pid-dead signal fires for `top`.
        let dead_pid = u32::MAX;
        let now = "2026-01-01T00:00:00Z";
        let mut sessions = Vec::new();
        upsert_session(
            &mut sessions, "top", None, Some("/w"), None, None, None, None, None,
            Some(dead_pid), now,
        );
        // The orphaned Task node — no window, no pid, kind:"subagent" — exactly
        // the shape of the two live ghosts this fix targets.
        sessions.push(SessionRecord {
            session_id: "sub:orphan".into(),
            agent: "general-purpose".into(),
            state: "working".into(),
            started_at: now.into(),
            parent_session_id: Some("top".into()),
            kind: Some("subagent".into()),
            ..Default::default()
        });
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();
        let mut hooks = Vec::new();
        upsert_hook(&mut hooks, "top", "running", now);
        write_stage(
            &hooks_path(),
            &HooksFile { schema_version: "0".into(), hooks },
        )
        .unwrap();

        let out = reap(&invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);

        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let ids: Vec<&str> = s2.sessions.iter().map(|s| s.session_id.as_str()).collect();
        assert!(!ids.contains(&"top"), "the pid-dead top-level session was reaped");
        assert!(
            !ids.contains(&"sub:orphan"),
            "its orphaned subagent child cascades away with it — the gap this test guards"
        );

        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn reap_spares_a_live_but_hook_silent_session() {
        // The regression this whole fix pins: the reaper reaps by REAL liveness
        // (window / pid), NEVER by hook silence. A session whose pid is alive but
        // that has emitted NO hook — its hook stream went quiet across a
        // reload/restart window — must survive the sweep. (hooks.json is left
        // absent, so the session is maximally hook-silent.)
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"); // pid-only liveness
        let stage = unique_stage("reap-hooksilent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // The real "now", not a fixed date: this record must survive every
        // signal that reads the wall clock, and the pre-boot one condemns a
        // record whose whole timeline predates the machine's boot — a live pid
        // on a session born before the last reboot is a recycled pid, which is
        // exactly the ghost that signal exists for.
        let now = now_iso_utc();
        let mut sessions = Vec::new();
        upsert_session(
            &mut sessions, "quiet", None, Some("/w"), Some("0xdead"), None, None, None, None,
            Some(std::process::id()), &now,
        );
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();

        let out = reap(&invocation(&["session", "reap"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(
            out.data.unwrap()["reaped"],
            json!([]),
            "a live-but-hook-silent session is never reaped"
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s2.sessions.iter().any(|s| s.session_id == "quiet"),
            "the hook-silent session survives the reaper pass"
        );

        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn reaper_grace_ignores_a_degenerate_empty_clients_snapshot() {
        // A momentary empty `hyprctl clients` read during a reload window must not
        // mass-reap the windowed roster: the grace downgrades it to pid-only.
        let windowed = vec![SessionRecord {
            window_address: "0xabc".into(),
            state: "running".into(),
            ..Default::default()
        }];
        // Empty gathered set + a windowed live session → degrade to None (pid-only).
        assert!(effective_live_addresses(Some(HashSet::new()), &windowed).is_none());

        // A NON-empty set is trusted as gathered (the normal path).
        let set: HashSet<String> = ["0xabc".to_string()].into_iter().collect();
        assert_eq!(
            effective_live_addresses(Some(set.clone()), &windowed),
            Some(set)
        );

        // Empty set but nothing windowed to protect (a genuinely empty desktop, or
        // an all-`done` roster) → the empty set passes through; pid signal governs.
        let done_only = vec![SessionRecord {
            window_address: "0xabc".into(),
            state: "done".into(),
            ..Default::default()
        }];
        assert_eq!(
            effective_live_addresses(Some(HashSet::new()), &done_only),
            Some(HashSet::new())
        );

        // No compositor at all stays None (unchanged).
        assert!(effective_live_addresses(None, &windowed).is_none());
    }

    #[test]
    fn stamp_resumed_from_lands_the_field_and_renders_a_resumed_edge() {
        // P-D8: the mechanical half of "resurrect mints a new id with
        // resumedFrom set" — no spawn involved, just the stage-write + the
        // graph.json projection it triggers (unlike `stamp_harness_session_id`,
        // this one DOES restage).
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("stamp-resumed-from");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        do_session_start("new-1", Some("claude"), Some("/w"), None, None, None, None, None, None);
        stamp_resumed_from("new-1", "old-1");

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "new-1").unwrap();
        assert_eq!(rec.resumed_from.as_deref(), Some("old-1"));

        let g: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(stage.join("graph.json")).unwrap(),
        )
        .unwrap();
        let edges = g["edges"].as_array().unwrap();
        assert!(
            edges.iter().any(|e| e["from"] == "session:old-1"
                && e["to"] == "session:new-1"
                && e["kind"] == "resumed"),
            "graph.json must be re-staged with the resumed edge: {edges:?}"
        );

        // A second stamp with the SAME value is change-only (no-op) —
        // proven indirectly: an unknown id is a silent no-op and never
        // panics or errors.
        stamp_resumed_from("no-such-session", "old-2");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn stamp_origin_lands_the_field_and_never_restages_graph_json() {
        // P-P3: `stamp_origin` is `graph.json`-invisible, like
        // `hookAncestry`/`headless` — unlike `stamp_resumed_from`, which
        // DOES restage.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("stamp-origin");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        do_session_start("peer-spawned-1", Some("claude"), Some("/w"), None, None, None, None, None, None);
        stamp_origin("peer-spawned-1", "peer:yomi-strix");

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "peer-spawned-1").unwrap();
        assert_eq!(rec.origin.as_deref(), Some("peer:yomi-strix"));

        // A local (non-peer) registration never gets an origin at all.
        do_session_start("local-1", Some("claude"), Some("/w"), None, None, None, None, None, None);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let local = s2.sessions.iter().find(|r| r.session_id == "local-1").unwrap();
        assert_eq!(local.origin, None);

        // An empty origin string is a no-op, same as an unknown id.
        stamp_origin("local-1", "");
        stamp_origin("no-such-session", "peer:ghost");
        let s3: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s3.sessions.iter().find(|r| r.session_id == "local-1").unwrap().origin, None);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn stamp_seal_lands_the_field_and_never_restages_graph_json() {
        // LANE IDENTITY P-ID1: `stamp_seal` is `graph.json`-invisible, the
        // same shape `stamp_origin`'s own sibling test just above proves.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("stamp-seal");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        do_session_start("sealed-1", Some("claude"), Some("/w"), None, None, None, None, None, None);
        stamp_seal("sealed-1", "deadbeefcafe", 1_700_000_000);

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "sealed-1").unwrap();
        assert_eq!(rec.seal.as_deref(), Some("deadbeefcafe"));
        assert_eq!(rec.sealed_issued_at, Some(1_700_000_000));

        // A registration nobody sealed never gets a `seal` at all.
        do_session_start("unsealed-1", Some("claude"), Some("/w"), None, None, None, None, None, None);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        let unsealed = s2.sessions.iter().find(|r| r.session_id == "unsealed-1").unwrap();
        assert_eq!(unsealed.seal, None);
        assert_eq!(unsealed.sealed_issued_at, None);

        // An empty seal is a no-op, same as an unknown id.
        stamp_seal("unsealed-1", "", 1_700_000_000);
        stamp_seal("no-such-session", "deadbeef", 1_700_000_000);
        let s3: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s3.sessions.iter().find(|r| r.session_id == "unsealed-1").unwrap().seal, None);

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
}
