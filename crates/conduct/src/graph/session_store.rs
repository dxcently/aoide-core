//! The session write door: session-registration verbs (`session start/phase/
//! end/wrap`), transcript "say"/title/model extraction, and the sub-agent
//! node lifecycle (`do_subagent_*`). shellbridge only ever SEEDS empty
//! sessions.json/hooks.json (its socket accept loop is future work), so
//! nothing else registers a live session — a session harness (or a Claude
//! Code hook) upserts its own record here, and every mutation re-stages
//! graph.json so the read path lights up immediately.

use super::common::{require_flag, stage_error};
use super::doc::{prune_done, restage_graph, would_cycle};
use super::model::{
    canonical_state, hooks_path, load_stage, sessions_path, write_stage, HooksFile,
    SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
#[cfg(test)]
use super::model::HookRecord;
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::fs::with_stage_lock;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;

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

/// Core of `graph session start`: cycle-check a parent, UPSERT, re-stage.
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
    let cmd = "graph.session.start";
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
    let new_rec = file.sessions.iter().find(|s| s.session_id == id).cloned();
    let evicted: Vec<String> = match &new_rec {
        Some(rec) if crate::reap::is_agent_kind(rec) && !rec.window_address.is_empty() => file
            .sessions
            .iter()
            .filter(|s| {
                s.session_id != id
                    && s.state != "done"
                    && s.window_address == rec.window_address
                    && crate::reap::is_agent_kind(s)
            })
            .map(|s| s.session_id.clone())
            .collect(),
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
        for s in file.sessions.iter_mut() {
            if s.session_id == owner {
                s.state = canon.to_string();
                s.activity = activity.filter(|a| !a.is_empty()).map(str::to_string);
            }
        }
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        let _ = write_stage(&sessions_path(), &file);
        let _ = restage_graph();
    });
}

// ── Transcript "say" — the agent's latest words, straight off its JSONL ──────
//
// Claude Code writes a per-session JSONL transcript at
// `~/.claude/projects/<munge(cwd)>/<session_id>.jsonl` (also handed to every
// hook as `transcript_path`). It is clean, structured, on-disk, and updated live
// by claude itself — a far better "agent output" source than scraping conduct's
// PTY (which for a live `claude` is the rendered TUI). The bridge tail-reads it
// at hook boundaries to publish `say` (distinct from `activity` = current tool).

/// Munge a cwd into Claude Code's project-dir name: every `/` and `.` → `-`
/// (`/home/khoa/Aoide` → `-home-khoa-Aoide`). Mirrors the CLI's on-disk layout
/// so the bridge can locate a transcript from data it already holds.
fn munge_project_dir(cwd: &str) -> String {
    cwd.chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

/// Resolve a session's transcript path: prefer the hook-supplied `transcript_path`
/// when it names a real file, else derive the canonical
/// `$HOME/.claude/projects/<munge(cwd)>/<session_id>.jsonl`. None when neither
/// resolves to an existing file.
pub(crate) fn transcript_path_for(
    session_id: &str,
    cwd: Option<&str>,
    hinted: Option<&str>,
) -> Option<PathBuf> {
    if let Some(h) = hinted.filter(|s| !s.is_empty()) {
        let p = PathBuf::from(h);
        if p.is_file() {
            return Some(p);
        }
    }
    let home = std::env::var_os("HOME")?;
    let cwd = cwd.filter(|s| !s.is_empty())?;
    let p = PathBuf::from(home)
        .join(".claude/projects")
        .join(munge_project_dir(cwd))
        .join(format!("{session_id}.jsonl"));
    p.is_file().then_some(p)
}

/// Collapse a possibly-multiline string to one whitespace-normalised line,
/// truncated at a char boundary to `max` chars with a trailing ellipsis.
fn one_line_clip(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let mut out: String = flat.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Read the last ~32 KiB of the transcript as whole JSONL lines (a leading
/// partial line dropped). Empty on any read error. Transcripts grow unbounded, so
/// only the tail is scanned — enough for the freshest `say` + `custom-title`.
fn transcript_tail(path: &std::path::Path) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 32 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return Vec::new();
    };
    let start = len.saturating_sub(TAIL);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // the seek likely split a line — drop the partial head
    }
    lines
}

/// The agent's latest words: the last matching assistant `text` block in the
/// tail, cleaned to a single line (≤160 chars). None when there is no such text.
///
/// `skip_sidechain`: a top-level session's own transcript never actually embeds
/// sidechain lines inline (ground-truthed: a Task's turns live in a wholly
/// separate `subagents/agent-<id>.jsonl` file, never inline in the parent), so
/// this is defensive/forward-compat there — pass `true`. A sub-agent's OWN
/// dedicated transcript file, by contrast, marks EVERY line `isSidechain:true`
/// (it's sidechain from the top file's perspective) — pass `false` there, or
/// every line would be skipped and `say` would always be `None`.
fn extract_say(lines: &[String], skip_sidechain: bool) -> Option<String> {
    const SAY_MAX: usize = 160;
    let mut found: Option<String> = None;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        if skip_sidechain && v.get("isSidechain").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(content) = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        // The LAST text block in the turn is the agent's freshest prose (prose
        // precedes the tool_use blocks it narrates).
        for block in content.iter().rev() {
            if block.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(t) = block.get("text").and_then(Value::as_str) {
                    let t = t.trim();
                    if !t.is_empty() {
                        found = Some(one_line_clip(t, SAY_MAX));
                        break;
                    }
                }
            }
        }
    }
    found
}

/// The session's NAME: the last `custom-title` record's `customTitle` in the tail
/// (Claude Code's own session title, e.g. "Aoide Dev"). None when never titled.
fn extract_custom_title(lines: &[String]) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) == Some("custom-title") {
            if let Some(t) = v.get("customTitle").and_then(Value::as_str) {
                let t = t.trim();
                if !t.is_empty() {
                    found = Some(one_line_clip(t, 48));
                }
            }
        }
    }
    found
}

/// The session's currently-active model: the last `type:"assistant"` line's
/// `message.model` string in the tail (e.g. `claude-sonnet-5`). None when the
/// tail holds no assistant turn yet. Sits at the same nesting level as the text
/// blocks `extract_say` reads, so it shares the one tail scan. `skip_sidechain`
/// mirrors `extract_say`: `true` for a top-level session's own transcript,
/// `false` for a sub-agent's own (all-sidechain) transcript file.
fn extract_model(lines: &[String], skip_sidechain: bool) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        if skip_sidechain && v.get("isSidechain").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(m) = v
            .get("message")
            .and_then(|m| m.get("model"))
            .and_then(Value::as_str)
        {
            let m = m.trim();
            if !m.is_empty() {
                found = Some(m.to_string());
            }
        }
    }
    found
}

/// The session's context-window fill at its LAST request: `input_tokens +
/// cache_creation_input_tokens + cache_read_input_tokens` off the freshest
/// `type:"assistant"` line's `message.usage` in the tail, e.g.
/// `"usage":{"input_tokens":2,"cache_creation_input_tokens":11803,
/// "cache_read_input_tokens":349611,"output_tokens":459}` → `Some(361_416)`.
/// Deliberately excludes `output_tokens` — that is what the turn just
/// produced, not what sat in the context window when the request was made.
/// Sits at the same nesting level `extract_model` reads, over the same
/// freshest-assistant-line scan, so it shares the one tail read
/// `refresh_transcript_fields` already does. Top-level-session transcripts
/// only (mirrors `extract_model`'s `skip_sidechain=true` case — a sub-agent's
/// own dedicated transcript file is never the tail this function sees). `None`
/// when the tail holds no assistant turn yet, or that freshest turn carries no
/// `usage` block.
fn transcript_context_tokens(lines: &[String]) -> Option<u64> {
    let mut found: Option<u64> = None;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        if v.get("isSidechain").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if let Some(usage) = v.get("message").and_then(|m| m.get("usage")) {
            let input = usage
                .get("input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let cache_creation = usage
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let cache_read = usage
                .get("cache_read_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            found = Some(input + cache_creation + cache_read);
        }
    }
    found
}

/// Best-effort: refresh a session's transcript-derived fields at a hook boundary —
/// its `say` (the agent's latest words) and, set-once, its `title` (the session
/// NAME, from `custom-title`). Change-only; never touches state/activity/pid;
/// re-stages only when something moved. Silent no-op when the transcript can't be
/// located or read. One tail read serves both fields.
pub(in crate::graph) fn refresh_transcript_fields(
    session_id: &str,
    cwd: Option<&str>,
    transcript_hint: Option<&str>,
) {
    let Some(path) = transcript_path_for(session_id, cwd, transcript_hint) else {
        return;
    };
    let lines = transcript_tail(&path);
    if lines.is_empty() {
        return;
    }
    let say = extract_say(&lines, true);
    let name = extract_custom_title(&lines);
    let model = extract_model(&lines, true);
    let context_tokens = transcript_context_tokens(&lines);
    if say.is_none() && name.is_none() && model.is_none() && context_tokens.is_none() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
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
    });
}

/// The directory of a session's sub-agent transcripts, if it exists:
/// `…/projects/<munge(cwd)>/<session_id>/subagents/` (a Task writes its own
/// `agent-<agent_id>.jsonl` here, beside an `agent-<agent_id>.meta.json`).
fn subagents_dir(session_id: &str, cwd: Option<&str>) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let cwd = cwd.filter(|s| !s.is_empty())?;
    let dir = PathBuf::from(home)
        .join(".claude/projects")
        .join(munge_project_dir(cwd))
        .join(session_id)
        .join("subagents");
    dir.is_dir().then_some(dir)
}

/// Find the sub-agent transcript in `dir` for a `sub:<tuid>` node key. Two
/// keying regimes reach here (see `do_subagent_spawn`'s doc comment):
///
/// - `sub:<agent_id>` — an async `Agent`-tool node PostToolUse has re-keyed
///   from its tool_use_id to its agent id; the transcript file is literally
///   named `agent-<agent_id>.jsonl`, so try that direct path FIRST (cheap,
///   unambiguous — no need to open every `.meta.json` in the directory).
/// - `sub:<tool_use_id>` — the classic keying, not yet (or never) re-keyed;
///   fall back to scanning `*.meta.json` files for one whose `toolUseId ==
///   tuid`, returning its sibling `agent-<id>.jsonl`.
fn find_subagent_transcript(dir: &std::path::Path, tuid: &str) -> Option<PathBuf> {
    let direct = dir.join(format!("agent-{tuid}.jsonl"));
    if direct.is_file() {
        return Some(direct);
    }
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".meta.json") {
            continue;
        }
        let Ok(txt) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&txt) else {
            continue;
        };
        if v.get("toolUseId").and_then(Value::as_str) == Some(tuid) {
            let base = name.trim_end_matches(".meta.json");
            let jsonl = dir.join(format!("{base}.jsonl"));
            if jsonl.is_file() {
                return Some(jsonl);
            }
        }
    }
    None
}

/// Best-effort: refresh the `say` of a session's ACTIVE sub-agent nodes from their
/// own transcript files. Runs on each of the PARENT session's hooks, so a
/// background Task (which outlives the turn) shows its latest words on its beamed
/// child row; a synchronous Task blocks the parent and is too transient to catch.
/// Change-only and bounded to the currently-live sub-nodes (depth-1).
pub(in crate::graph) fn refresh_subagent_says(session_id: &str, cwd: Option<&str>) {
    let subs: Vec<String> = match load_stage::<SessionsFile>(&sessions_path()) {
        Ok(file) => file
            .sessions
            .iter()
            .filter(|s| s.kind.as_deref() == Some("subagent"))
            .filter(|s| s.parent_session_id.as_deref() == Some(session_id))
            .map(|s| s.session_id.clone())
            .collect(),
        Err(_) => return,
    };
    if subs.is_empty() {
        return;
    }
    let Some(dir) = subagents_dir(session_id, cwd) else {
        return;
    };
    // (sub_id, say, model) — either of say/model may be None for a given sub.
    let mut updates: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    for sub_id in &subs {
        let Some(tuid) = sub_id.strip_prefix("sub:") else {
            continue;
        };
        let Some(file) = find_subagent_transcript(&dir, tuid) else {
            continue;
        };
        // A sub-agent's OWN dedicated transcript marks every line isSidechain —
        // don't skip them here (see `extract_say`'s doc). Its model is its OWN
        // (subagents can run a different model than their parent).
        let lines = transcript_tail(&file);
        let say = extract_say(&lines, false);
        let model = extract_model(&lines, false);
        if say.is_some() || model.is_some() {
            updates.push((sub_id.clone(), say, model));
        }
    }
    if updates.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut changed = false;
        for (sub_id, say, model) in &updates {
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
                if let Some(model) = model {
                    if s.model.as_deref() != Some(model.as_str()) {
                        s.model = Some(model.clone());
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
    });
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

/// Core of `graph session phase`: UPSERT the hook record (audit), land the
/// canonical live state on sessions.json (the widget file), re-stage. The whole
/// load-modify-write is serialised against every other stage writer by the
/// stage lock (its inner helpers stay lock-free — the lock is not re-entrant).
pub(in crate::graph) fn do_session_phase(id: &str, phase: &str) -> Outcome {
    with_stage_lock(|| do_session_phase_inner(id, phase))
}
fn do_session_phase_inner(id: &str, phase: &str) -> Outcome {
    let cmd = "graph.session.phase";
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
    let cmd = "graph.session.phase";
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

/// Core of `graph session end`: mark the session `done` (and its hook phase
/// `done`), re-stage. An unknown id is an ok no-op (matching `project remove`).
pub(in crate::graph) fn do_session_end(id: &str) -> Outcome {
    with_stage_lock(|| do_session_end_inner(id))
}
fn do_session_end_inner(id: &str) -> Outcome {
    let cmd = "graph.session.end";
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
    for s in s_file.sessions.iter_mut() {
        if s.session_id == id {
            s.state = "done".to_string();
        }
    }
    // Cascade: remove the session's sub-agent subtree. Task nodes carry no pid or
    // window, so the liveness reaper can never clean them — the owning session's
    // end IS their lifecycle end. Collect the transitive `subagent` descendants
    // and drop them (the session itself stays, marked done).
    let mut doomed: HashSet<String> = HashSet::new();
    doomed.insert(id.to_string());
    loop {
        let mut grew = false;
        for s in &s_file.sessions {
            if s.kind.as_deref() == Some("subagent") && !doomed.contains(&s.session_id) {
                if let Some(p) = &s.parent_session_id {
                    if doomed.contains(p) {
                        doomed.insert(s.session_id.clone());
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    s_file
        .sessions
        .retain(|s| s.session_id == id || !doomed.contains(&s.session_id));
    if s_file.schema_version.is_empty() {
        s_file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if let Err(e) = write_stage(&sessions_path(), &s_file) {
        return stage_error(cmd, e);
    }

    // Mirror the terminal state into hooks.json so the merged live phase agrees.
    let mut h_file: HooksFile = match load_stage(&hooks_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let now = now_iso_utc();
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

/// `graph session start --id <id> [--agent --cwd --window --parent]` — UPSERT a
/// running session record (idempotent; startedAt preserved on re-start).
pub fn session_start(inv: &Invocation) -> Outcome {
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

/// `graph session phase --id <id> --phase <phase>` — UPSERT the live hook phase.
pub fn session_phase(inv: &Invocation) -> Outcome {
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

/// `graph session end --id <id>` — mark the session done (ok no-op if unknown).
pub fn session_end(inv: &Invocation) -> Outcome {
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    do_session_end(&id)
}

/// `graph wrap [--agent --parent --id] -- <command…>` — run ANY agent command
/// as a registered session. The universal door for hookless agents: spawn with
/// INHERITED stdio (a wrapped TUI runs undisturbed), register the session
/// running, wait, and mark it done whatever happened — a crashed agent still
/// resolves instead of haunting the roster. The child sees AOIDE_SESSION_ID,
/// so anything hookable inside it can self-report richer phases through
/// `graph session phase --id "$AOIDE_SESSION_ID" --phase blocked`.
///
/// Ordering: spawn FIRST, register second — a failed exec must never register
/// a ghost session. Exit mirrors the child (Ok on success, Error otherwise)
/// with the real code in data.exitCode; the process code stays canonical.
pub fn session_wrap(inv: &Invocation) -> Outcome {
    let cmd = "graph.wrap";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph wrap [--agent <name>] [--parent <sessionId>] [--id <id>] -- <command …>",
        );
    }
    let program = &inv.args[0];
    let agent = inv.flags.get("agent").cloned().unwrap_or_else(|| {
        std::path::Path::new(program)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| program.clone())
    });
    let id = inv.flags.get("id").cloned().unwrap_or_else(|| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("wrap-{}-{ts}", std::process::id())
    });
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    let mut child = match std::process::Command::new(program)
        .args(&inv.args[1..])
        .env("AOIDE_SESSION_ID", &id)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::error(cmd, format!("failed to spawn `{program}`: {e}")),
    };

    let _ = do_session_start(
        &id,
        Some(&agent),
        cwd.as_deref(),
        None,
        inv.flags.get("parent").map(String::as_str),
        None,
        None,
        None,
        // The lifecycle-OWNING pid is THIS wrap process, not `child`: while wrap
        // lives it always runs the `do_session_end` below (even on a child crash),
        // so only wrap's OWN death — a SIGKILL it cannot catch — orphans the
        // record, and that is precisely the pid the reaper should watch.
        Some(std::process::id()),
    );

    let status = child.wait();
    let _ = do_session_end(&id);

    match status {
        Ok(st) if st.success() => {
            Outcome::ok(cmd, format!("`{agent}` finished (session `{id}`)"))
                .changed(vec![format!("session {id}: running → done")])
                .with_data(json!({ "sessionId": id, "agent": agent, "exitCode": 0 }))
        }
        Ok(st) => {
            let code = st.code().unwrap_or(-1); // -1: killed by signal
            Outcome::error(cmd, format!("`{agent}` exited {code} (session `{id}`)"))
                .changed(vec![format!("session {id}: running → done")])
                .with_data(json!({ "sessionId": id, "agent": agent, "exitCode": code }))
        }
        Err(e) => Outcome::error(cmd, format!("wait on `{agent}` failed: {e} (session `{id}`)"))
            .with_data(json!({ "sessionId": id, "agent": agent })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::model::merged_sessions;
    use crate::graph::testutil::*;
    use crate::graph::verbs::{project_add, view};
    // The reaper moved to `crate::reap`; its tests still live here (they
    // lean on session-lifecycle fixtures/helpers this module owns).
    use crate::reap::{effective_live_addresses, is_session_dead, reap};

    #[test]
    fn munge_project_dir_matches_claude_layout() {
        assert_eq!(munge_project_dir("/home/khoa/Aoide"), "-home-khoa-Aoide");
        // A path with a dot component (worktree under `.claude/`): every `/`
        // AND every `.` folds to `-`, matching the CLI's real dir names.
        assert_eq!(
            munge_project_dir("/home/khoa/Aoide/.claude/worktrees/x"),
            "-home-khoa-Aoide--claude-worktrees-x"
        );
    }
    #[test]
    fn latest_say_reads_last_nonsidechain_assistant_text() {
        let path = std::env::temp_dir().join(format!("aoide_say_{}.jsonl", std::process::id()));
        let body = [
            r#"{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}"#,
            r#"{"type":"assistant","isSidechain":false,"message":{"content":[{"type":"text","text":"first words"}]}}"#,
            // A Task sub-agent's line in the SAME file must be ignored.
            r#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"text","text":"SUBAGENT ignore me"}]}}"#,
            // Freshest turn: thinking + multiline text + a tool_use. We take the
            // LAST text block, whitespace-normalised.
            r#"{"type":"assistant","isSidechain":false,"message":{"content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"  the  latest\nline  "},{"type":"tool_use","name":"Bash","input":{}}]}}"#,
        ]
        .join("\n");
        std::fs::write(&path, &body).unwrap();
        let say = extract_say(&transcript_tail(&path), true);
        let _ = std::fs::remove_file(&path);
        assert_eq!(say.as_deref(), Some("the latest line"));
    }
    #[test]
    fn latest_say_is_none_without_agent_text() {
        let path = std::env::temp_dir().join(format!("aoide_say_none_{}.jsonl", std::process::id()));
        let body = [
            r#"{"type":"user","message":{"content":[{"type":"text","text":"only a prompt"}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{}}]}}"#,
        ]
        .join("\n");
        std::fs::write(&path, &body).unwrap();
        let say = extract_say(&transcript_tail(&path), true);
        let _ = std::fs::remove_file(&path);
        assert_eq!(say, None);
    }
    #[test]
    fn extract_model_reads_last_assistant_model() {
        let path = std::env::temp_dir().join(format!("aoide_model_{}.jsonl", std::process::id()));
        let body = [
            r#"{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}"#,
            r#"{"type":"assistant","isSidechain":false,"message":{"model":"claude-opus-4-8","content":[{"type":"text","text":"first"}]}}"#,
            // A same-file sidechain line's model must be ignored when skipping.
            r#"{"type":"assistant","isSidechain":true,"message":{"model":"claude-haiku-4-5","content":[{"type":"text","text":"sub"}]}}"#,
            r#"{"type":"assistant","isSidechain":false,"message":{"model":"claude-sonnet-5","content":[{"type":"text","text":"latest"}]}}"#,
        ]
        .join("\n");
        std::fs::write(&path, &body).unwrap();
        let model = extract_model(&transcript_tail(&path), true);
        let _ = std::fs::remove_file(&path);
        assert_eq!(model.as_deref(), Some("claude-sonnet-5"));
    }
    #[test]
    fn extract_model_is_none_without_assistant_turn() {
        let lines: Vec<String> =
            vec![r#"{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}"#.to_string()];
        assert_eq!(extract_model(&lines, true), None);
    }
    #[test]
    fn context_tokens_sums_input_side_of_freshest_assistant_usage() {
        let path =
            std::env::temp_dir().join(format!("aoide_ctx_{}.jsonl", std::process::id()));
        let body = [
            r#"{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}"#,
            // An earlier assistant turn's usage must be superseded by the freshest.
            r#"{"type":"assistant","isSidechain":false,"message":{"model":"claude-sonnet-5","usage":{"input_tokens":2,"cache_creation_input_tokens":100,"cache_read_input_tokens":200,"output_tokens":50}}}"#,
            // A same-file sidechain line's usage must be ignored (a Task's own turn).
            r#"{"type":"assistant","isSidechain":true,"message":{"usage":{"input_tokens":999999,"cache_creation_input_tokens":999999,"cache_read_input_tokens":999999,"output_tokens":1}}}"#,
            // The freshest non-sidechain turn — output_tokens (459) must NOT be
            // folded into the sum (2 + 11803 + 349611 = 361416, not +459).
            r#"{"type":"assistant","isSidechain":false,"message":{"model":"claude-sonnet-5","usage":{"input_tokens":2,"cache_creation_input_tokens":11803,"cache_read_input_tokens":349611,"output_tokens":459}}}"#,
        ]
        .join("\n");
        std::fs::write(&path, &body).unwrap();
        let tokens = transcript_context_tokens(&transcript_tail(&path));
        let _ = std::fs::remove_file(&path);
        assert_eq!(tokens, Some(361_416));
    }
    #[test]
    fn context_tokens_is_none_without_assistant_usage() {
        // No assistant line at all.
        let no_assistant: Vec<String> =
            vec![r#"{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}"#.to_string()];
        assert_eq!(transcript_context_tokens(&no_assistant), None);

        // An assistant line present, but its message carries no `usage` block
        // (e.g. a stream fragment) — still None, not a false Some(0).
        let no_usage: Vec<String> = vec![
            r#"{"type":"assistant","isSidechain":false,"message":{"model":"claude-sonnet-5","content":[{"type":"text","text":"hi"}]}}"#.to_string(),
        ];
        assert_eq!(transcript_context_tokens(&no_usage), None);
    }
    #[test]
    fn extract_custom_title_takes_the_last_session_title() {
        let lines: Vec<String> = [
            r#"{"type":"custom-title","customTitle":"Old Name","sessionId":"s"}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}"#,
            r#"{"type":"custom-title","customTitle":"  Aoide Dev  ","sessionId":"s"}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(extract_custom_title(&lines).as_deref(), Some("Aoide Dev"));
        // No custom-title record → None (the session is unnamed).
        let bare: Vec<String> =
            vec![r#"{"type":"assistant","message":{"content":[]}}"#.to_string()];
        assert_eq!(extract_custom_title(&bare), None);
    }
    #[test]
    fn find_subagent_transcript_matches_by_tool_use_id() {
        let dir = std::env::temp_dir().join(format!("aoide_subs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Two sub-agent transcripts, each with its own meta.json — mirrors the
        // real `agent-<agent_id>.jsonl` + `.meta.json` layout under
        // `<session>/subagents/`.
        std::fs::write(
            dir.join("agent-aaa111.meta.json"),
            r#"{"agentType":"Explore","description":"x","toolUseId":"toolu_A","spawnDepth":1}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("agent-aaa111.jsonl"),
            r#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"text","text":"from A"}]}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("agent-bbb222.meta.json"),
            r#"{"agentType":"Explore","description":"y","toolUseId":"toolu_B","spawnDepth":1}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("agent-bbb222.jsonl"),
            r#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"text","text":"from B"}]}}"#,
        )
        .unwrap();

        let found = find_subagent_transcript(&dir, "toolu_B").unwrap();
        assert_eq!(found.file_name().unwrap().to_str().unwrap(), "agent-bbb222.jsonl");
        let say = extract_say(&transcript_tail(&found), false);
        assert_eq!(say.as_deref(), Some("from B"));

        // An unknown tool_use_id (no matching Task) finds nothing.
        assert!(find_subagent_transcript(&dir, "toolu_nope").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn find_subagent_transcript_matches_by_agent_id_filename() {
        // The async Agent-tool path: PostToolUse re-keys the graph node from
        // `sub:<tool_use_id>` to `sub:<agent_id>`, so lookups arrive keyed by
        // agent id — which never equals any `meta.json`'s `toolUseId`. The
        // transcript must still resolve via the direct `agent-<agent_id>.jsonl`
        // filename, even though its meta.json's `toolUseId` is a DIFFERENT,
        // unrelated tool_use_id value (the id of the Task call that originally
        // spawned it, before the re-key).
        let dir = std::env::temp_dir().join(format!("aoide_subs_aid_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let agent_id = "a2e15372d23f6f70d";
        std::fs::write(
            dir.join(format!("agent-{agent_id}.meta.json")),
            r#"{"agentType":"Explore","description":"z","toolUseId":"toolu_UNRELATED","model":"fable"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("agent-{agent_id}.jsonl")),
            [
                r#"{"type":"assistant","isSidechain":true,"message":{"model":"claude-fable-5","content":[{"type":"text","text":"first"}]}}"#,
                r#"{"type":"assistant","isSidechain":true,"message":{"model":"claude-fable-5","content":[{"type":"text","text":"from agent id"}]}}"#,
            ]
            .join("\n"),
        )
        .unwrap();

        // Looked up by agent id (the re-keyed `sub:<agent_id>` case) — resolves
        // via the direct filename, NOT the meta scan (whose toolUseId doesn't
        // match).
        let found = find_subagent_transcript(&dir, agent_id).unwrap();
        assert_eq!(
            found.file_name().unwrap().to_str().unwrap(),
            format!("agent-{agent_id}.jsonl")
        );
        let lines = transcript_tail(&found);
        assert_eq!(extract_say(&lines, false).as_deref(), Some("from agent id"));
        assert_eq!(extract_model(&lines, false).as_deref(), Some("claude-fable-5"));

        // The pre-existing tool-use-id-keyed path still works via the meta scan.
        let found2 = find_subagent_transcript(&dir, "toolu_UNRELATED").unwrap();
        assert_eq!(
            found2.file_name().unwrap().to_str().unwrap(),
            format!("agent-{agent_id}.jsonl")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn one_line_clip_flattens_and_truncates() {
        assert_eq!(one_line_clip("a  b\n c", 80), "a b c");
        let long = "x".repeat(200);
        let clipped = one_line_clip(&long, 10);
        assert_eq!(clipped.chars().count(), 10);
        assert!(clipped.ends_with('…'));
    }
    #[test]
    fn wrap_registers_resolves_and_mirrors_the_child() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("wrap");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Success: the child asserts AOIDE_SESSION_ID is present in its env.
        let out = session_wrap(&wrap_invocation(
            &["sh", "-c", "test -n \"$AOIDE_SESSION_ID\""],
            &[("id", "wrap-ok")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 0);
        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == "wrap-ok").unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.agent, "sh"); // basename default

        // Failure: exit code mirrored in data, session still resolves done.
        let out = session_wrap(&wrap_invocation(
            &["sh", "-c", "exit 7"],
            &[("id", "wrap-fail"), ("agent", "sevens")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["exitCode"], 7);
        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        let rec = s
            .sessions
            .iter()
            .find(|r| r.session_id == "wrap-fail")
            .unwrap();
        assert_eq!(rec.state, "done");
        assert_eq!(rec.agent, "sevens");

        // Spawn failure: error outcome, and NO session registered.
        let out = session_wrap(&wrap_invocation(
            &["/nonexistent-aoide-wrap-test"],
            &[("id", "wrap-ghost")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        let s: SessionsFile =
            serde_json::from_str(&std::fs::read_to_string(stage.join("sessions.json")).unwrap())
                .unwrap();
        assert!(s.sessions.iter().all(|r| r.session_id != "wrap-ghost"));

        // No command at all → usage.
        let out = session_wrap(&wrap_invocation(&[], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);

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
            &["graph", "session", "start"],
            &[("id", "old"), ("agent", "claude"), ("cwd", "/p"), ("window", "0xWIN")],
        ));
        // A NEW claude registers on the SAME window (the real re-id after a
        // compact/resume) — this must retire "old" immediately, no grace, no
        // waiting on the reaper.
        session_start(&flag_invocation(
            &["graph", "session", "start"],
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
            &["graph", "session", "start"],
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
    fn session_start_upserts_restages_and_anchors_under_a_project() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-start");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        project_add(&invocation(
            &["graph", "project", "add"],
            &["aoide", "/home/k/Aoide"],
        ));
        let out = session_start(&flag_invocation(
            &["graph", "session", "start"],
            &[("id", "s1"), ("cwd", "/home/k/Aoide/sub")],
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
        let view = view(&invocation(&["graph", "view"], &[]));
        assert_eq!(&staged, view.data.as_ref().unwrap());

        // Re-start updates the agent but preserves startedAt and never dupes.
        session_start(&flag_invocation(
            &["graph", "session", "start"],
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

        session_start(&flag_invocation(&["graph", "session", "start"], &[("id", "a")]));
        session_start(&flag_invocation(
            &["graph", "session", "start"],
            &[("id", "b"), ("parent", "a")],
        ));
        // a parented under b would close b→a→…: refused (exit 1), no mutation.
        let out = session_start(&flag_invocation(
            &["graph", "session", "start"],
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
            &["graph", "session", "end"],
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
    fn session_start_requires_the_id_flag() {
        let out = session_start(&flag_invocation(&["graph", "session", "start"], &[]));
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
        assert!(is_session_dead(&rec("0xCCC", None), Some(&live), alive, now, fresh));
        assert!(is_session_dead(
            &rec("0xCCC", Some(9)),
            Some(&live),
            alive,
            now,
            fresh
        ));
        // A live window (normalised match) with a live pid → NOT dead.
        assert!(!is_session_dead(
            &rec("0xAAA", Some(9)),
            Some(&live),
            alive,
            now,
            fresh
        ));

        // Process-gone: a pid whose /proc vanished is dead regardless of window
        // (here the window IS live, so ONLY the pid signal fires).
        assert!(is_session_dead(
            &rec("0xAAA", Some(9)),
            Some(&live),
            dead_proc,
            now,
            fresh
        ));

        // NEVER-FALSE-REAP #1 — neither signal (no window, no pid), and the third
        // signal reports "just seen": left alone.
        assert!(!is_session_dead(
            &rec("", None),
            Some(&live),
            dead_proc,
            now,
            fresh
        ));

        // NEVER-FALSE-REAP #2 — compositor NOT queried (None): the window signal
        // is suppressed, so a windowed session we could not SEE is never reaped;
        // only the authoritative pid signal remains.
        assert!(!is_session_dead(&rec("0xCCC", None), None, alive, now, fresh));
        assert!(!is_session_dead(
            &rec("0xCCC", Some(9)),
            None,
            alive,
            now,
            fresh
        )); // pid alive → alive
        assert!(is_session_dead(
            &rec("0xCCC", Some(9)),
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
        upsert_session(
            &mut sessions, "live", None, Some("/w"), None, None, None, None, None,
            Some(std::process::id()), now,
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

        let out = reap(&invocation(&["graph", "reap"], &[]));
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
        let again = reap(&invocation(&["graph", "reap"], &[]));
        assert_eq!(again.status, aoide_protocol::output::Status::Ok);
        assert_eq!(again.data.unwrap()["reaped"], json!([]));

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

        let now = "2026-01-01T00:00:00Z";
        let mut sessions = Vec::new();
        upsert_session(
            &mut sessions, "quiet", None, Some("/w"), Some("0xdead"), None, None, None, None,
            Some(std::process::id()), now,
        );
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions },
        )
        .unwrap();

        let out = reap(&invocation(&["graph", "reap"], &[]));
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
}
