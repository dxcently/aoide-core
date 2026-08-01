//! Stage-file record shapes, stage I/O, and the pure DAG-shaping derivations
//! every other `graph` submodule builds on (CONTRACTS.md §4 shapes).

use crate::shellbridge::{atomic_write, stage_dir};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

/// graph.json / projects.json stage-file format version (CONTRACTS.md §4).
pub const STAGE_GRAPH_VERSION: &str = "0";

// ── Stage-file records (CONTRACTS.md §4 shapes) ─────────────────────────────

/// One registered project anchor root (`song/stage/projects.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Project {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub path: String,
}

/// One session record (`song/stage/sessions.json`, written by shellbridge).
/// `parentSessionId` is the optional additive spawned-by edge; `extra`
/// round-trips any fields this version does not know about.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionRecord {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub agent: String,
    #[serde(rename = "windowAddress", default)]
    pub window_address: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub state: String,
    #[serde(rename = "startedAt", default)]
    pub started_at: String,
    #[serde(
        rename = "parentSessionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_session_id: Option<String>,
    /// Conductor-channel additive fields (v0-safe; absent on a legacy record).
    /// `conductable` marks a session spawned under `aoide conduct` (it owns a
    /// PTY + control socket); `socket` is that per-session injection socket
    /// (`$XDG_RUNTIME_DIR/aoide/session-<id>.sock`); `title` is the auto-renamed
    /// one-line task the last delivered `graph send` wrote onto the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conductable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The lifecycle-OWNING process's pid (the `conduct`/`wrap` process itself,
    /// NOT the wrapped child) — the liveness anchor for the reaper. While this
    /// process lives, normal-exit cleanup (`do_session_end`) is guaranteed; when
    /// it is SIGKILLed (SUPER+Q kills the whole terminal process tree,
    /// uncatchably) the record orphans `running` and `/proc/<pid>` vanishes,
    /// which is exactly the signal `is_session_dead` reaps on. Additive/v0-safe:
    /// absent on a legacy record and on hook-only sessions that never had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The Hyprland workspace id this session's window currently lives on,
    /// stamped by the `socket2` window-event listener alongside `windowAddress`
    /// (and re-stamped when the window moves between workspaces). Additive and
    /// v0-safe: absent on a legacy record and whenever the window/workspace
    /// could not be resolved (off-Hyprland, or the window not yet open). The
    /// gadget-dock roster reads it to preview-highlight the bar's WorkspaceRow
    /// on hover (concepts/Terminal-Commander) — a pure-data bridge, no dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<i64>,
    /// The live "current command / current tool" for this session: for a
    /// conducted SHELL it is the foreground command (`cargo test`, `vim …`),
    /// captured by conduct's PTY tick and cleared at the bare prompt; for an
    /// AGENT it is the tool currently running (set from the PreToolUse hook,
    /// cleared when the turn settles). Additive/v0-safe — absent when there is
    /// nothing running. The roster shows it so a row reads as what it is *doing*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<String>,
    /// What KIND of thing this record is, published so the widgets never infer
    /// it from the agent string: `agent` (a Claude/agent session), `shell` (a
    /// conducted terminal), `subagent` (a Task the agent spawned — a leaf of
    /// the conductor tree), or `a2a` (CONTRACTS.md §6 — an external A2A agent
    /// folded into the session DAG, client side, via `aoide a2a agent add`).
    /// Additive/v0-safe (absent on a legacy record; readers fall back to
    /// agent!="shell").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The agent's latest *words* — a one-line tail of the session's Claude Code
    /// transcript (the last non-sidechain assistant `text` block), distinct from
    /// `activity` (the current *tool*). Read straight off the on-disk JSONL
    /// transcript at hook boundaries (Stop / PostToolUse / Notification), so the
    /// conductor can show what the agent is *saying*, not just what it is running.
    /// Additive/v0-safe — absent for shells and for an agent that has not spoken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub say: Option<String>,
    /// The Claude model this session is currently running, taken straight from
    /// the freshest `type:"assistant"` line's `message.model` in the on-disk
    /// JSONL transcript (e.g. `claude-sonnet-5`, `claude-opus-4-8`), refreshed
    /// at the same hook boundaries as `say`. For a subagent it is that
    /// subagent's OWN model (from its own transcript) — genuinely able to differ
    /// from its parent's. Additive/v0-safe — absent for shells and until the
    /// session has produced at least one assistant turn. The bar shows it as the
    /// clock's subtext; widgets read the raw id and map it to a short label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The context-window fill of this session's LAST request: `input_tokens +
    /// cache_creation_input_tokens + cache_read_input_tokens` off the freshest
    /// `type:"assistant"` line's `message.usage` in the on-disk JSONL transcript
    /// (deliberately excludes `output_tokens` — that's what the turn just
    /// produced, not what sat in the window when the request was made).
    /// Refreshed at the same hook boundaries as `say`/`model`. Additive/v0-safe
    /// — absent for shells and until the session has produced at least one
    /// assistant turn (same lifecycle as `model`). The dock maps the raw count
    /// to a context-window meter, computing its own ceiling from `model`
    /// client-side (a 200k/1M split, with a heuristic bump for the cases where
    /// the transcript's model id doesn't spell out its long-context tier).
    #[serde(
        rename = "contextTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_tokens: Option<u64>,
    /// True while this conducted SHELL is blocked at a `sudo` password prompt
    /// — detected by conduct's PTY tick (the foreground process is `sudo`, or
    /// the `[sudo] password for` text was just seen crossing master→stdout)
    /// and force-published alongside `state:"awaiting"`. Additive/v0-safe:
    /// absent on a legacy record and cleared back to `None` (never written as
    /// `Some(false)`) the moment the prompt clears — so the key disappears
    /// rather than lingering false. Agents are hook-driven and never set this.
    /// The dock reads it to show a lock badge + ping distinct from an
    /// ordinary permission-prompt `awaiting` — "it's YOUR password", not the
    /// agent's.
    #[serde(rename = "needsSudo", default, skip_serializing_if = "Option::is_none")]
    pub needs_sudo: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One hook record (`song/stage/hooks.json`, written by shellbridge).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookRecord {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub phase: String,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `projects.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectsFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub projects: Vec<Project>,
}

/// `sessions.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionsFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
}

/// `hooks.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HooksFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub hooks: Vec<HookRecord>,
}

// ── Stage-file I/O (missing file → empty registry; writes atomic) ──────────

pub(in crate::graph) fn projects_path() -> PathBuf {
    stage_dir().join("projects.json")
}
pub(crate) fn sessions_path() -> PathBuf {
    stage_dir().join("sessions.json")
}
pub(crate) fn hooks_path() -> PathBuf {
    stage_dir().join("hooks.json")
}
pub(in crate::graph) fn graph_path() -> PathBuf {
    stage_dir().join("graph.json")
}

/// Load one stage file; a missing file is an empty registry (tolerated), a
/// corrupt one is a structured error string.
pub(crate) fn load_stage<T: serde::de::DeserializeOwned + Default>(
    path: &std::path::Path,
) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| format!("{}: unreadable stage file: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Atomic write of one stage file (write-temp-then-rename, CONTRACTS.md §4).
pub(crate) fn write_stage<T: Serialize>(path: &std::path::Path, value: &T) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| format!("{}: serialize: {e}", path.display()))?;
    atomic_write(path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

// ── The DAG computation (pure; shared by view / emit / render) ──────────────

/// Is `cwd` inside the project rooted at `root`? (path-component-aware).
fn cwd_under(cwd: &str, root: &str) -> bool {
    let root = if root.len() > 1 {
        root.trim_end_matches('/')
    } else {
        root
    };
    cwd == root || cwd.starts_with(&format!("{}/", root))
}

/// The anchoring project for a cwd: longest matching root wins, so nested
/// projects anchor correctly. Returns an index into `projects`.
pub fn anchor_for(cwd: &str, projects: &[Project]) -> Option<usize> {
    projects
        .iter()
        .enumerate()
        .filter(|(_, p)| cwd_under(cwd, &p.path))
        .max_by_key(|(_, p)| p.path.trim_end_matches('/').len())
        .map(|(i, _)| i)
}

/// Sessions with their live state merged in: the latest hook phase (by
/// `updatedAt`; ties → the later record wins) overrides the roster state.
pub fn merged_sessions(sessions: &[SessionRecord], hooks: &[HookRecord]) -> Vec<SessionRecord> {
    let mut latest: BTreeMap<&str, (&str, &str)> = BTreeMap::new(); // id → (updatedAt, phase)
    for h in hooks {
        match latest.get(h.session_id.as_str()) {
            Some((at, _)) if h.updated_at.as_str() < *at => {}
            _ => {
                latest.insert(&h.session_id, (&h.updated_at, &h.phase));
            }
        }
    }
    let mut merged: Vec<SessionRecord> = sessions.to_vec();
    for s in &mut merged {
        if let Some((_, phase)) = latest.get(s.session_id.as_str()) {
            if !phase.is_empty() {
                s.state = (*phase).to_string();
            }
        }
    }
    // Every producer's vocab is folded to the ONE canonical set the desktop
    // renders — so graph.json (conductor) and sessions.json (widgets) agree even for
    // an un-migrated legacy record.
    for s in &mut merged {
        s.state = canonical_state(&s.state).to_string();
    }
    // Deterministic ordering everywhere downstream: (startedAt, sessionId).
    merged.sort_by(|a, b| {
        (a.started_at.as_str(), a.session_id.as_str())
            .cmp(&(b.started_at.as_str(), b.session_id.as_str()))
    });
    merged
}

/// The canonical session-state vocabulary the desktop renders VERBATIM — no
/// widget-side regex derivation (that split-brain is what this replaces). Every
/// producer (hooks, `conduct`, the reaper) writes one of these onto
/// `sessions.json`; this shim also folds the legacy / hook-phase vocab
/// (`running`/`waiting`/`blocked`) onto it, so an old record is migrated the
/// first time any writer touches the file — no rollout dance.
///
///   working  — in a turn / running a tool (or a shell running a foreground cmd)
///   awaiting — needs the user (a permission prompt or the idle-input ping); the
///              dock peeks on this and only this (`needsInput ⇔ awaiting`)
///   stopped  — the turn ENDED and the agent is sitting at the prompt, RECENTLY.
///              Alive and warm: the natural face of a session you just finished
///              talking to. Ages out to `idle` after
///              [`crate::reap::STOPPED_IDLE_AFTER_SECS`] in the reaper pass.
///   idle     — at rest and COLD: stopped for more than an hour, or freshly
///              created / resumed and not yet active (a bare shell prompt too)
///   done     — the session ENDED (SessionEnd / a reap). Never `stopped`.
///
/// `stop`/`stopped` map to `stopped`, NOT `done`: the only producer that ever
/// writes either token is a Stop-hook adapter (`graph session phase --phase
/// stop`, the shape `entities/Agent-Hooking` documents for a foreign harness),
/// and the Stop hook means "the turn ended", not "the process exited". Real
/// termination arrives as `SessionEnd` (→ `do_session_end`, which writes `done`
/// directly and never routes through this shim) or as the explicit
/// `exit`/`finished`/`complete` vocabulary below.
pub fn canonical_state(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "working" | "running" | "active" | "busy" | "tool" | "trace" => "working",
        "awaiting" | "blocked" | "await" => "awaiting",
        "stopped" | "stop" => "stopped",
        "idle" | "waiting" | "ready" | "sleep" => "idle",
        "done" | "exit" | "finished" | "complete" => "done",
        // Empty/unknown → at rest (never invent a working/awaiting signal).
        _ => "idle",
    }
}

pub(in crate::graph) fn sorted_projects(projects: &[Project]) -> Vec<Project> {
    let mut p = projects.to_vec();
    p.sort_by(|a, b| a.name.cmp(&b.name));
    p
}

/// Does the child's parent resolve to a registered session? (a dangling
/// `parentSessionId` falls back to project anchoring).
pub(in crate::graph) fn resolved_parent<'a>(
    s: &SessionRecord,
    ids: &HashSet<&'a str>,
) -> Option<String> {
    s.parent_session_id
        .as_deref()
        .filter(|p| ids.contains(p))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;

    #[test]
    fn anchoring_longest_prefix_wins() {
        let p = sorted_projects(&fixture_projects()); // [aoide, nested]
                                                      // Inside the nested project → the deeper root wins.
        assert_eq!(
            anchor_for("/home/k/Aoide/sub/x", &p).map(|i| p[i].name.as_str()),
            Some("nested")
        );
        // At the outer root → the outer project.
        assert_eq!(
            anchor_for("/home/k/Aoide", &p).map(|i| p[i].name.as_str()),
            Some("aoide")
        );
        // Component-aware: /home/k/Aoide-extra is NOT under /home/k/Aoide.
        assert_eq!(anchor_for("/home/k/Aoide-extra", &p), None);
        assert_eq!(anchor_for("/tmp/elsewhere", &p), None);
    }
    #[test]
    fn session_record_workspace_round_trips_and_stays_absent_when_unset() {
        // serde: `workspace` serialises as an integer when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.workspace = Some(2);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"workspace\":2"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workspace, Some(2));

        // A record without a workspace omits the key entirely (no null noise) and
        // a legacy record with no `workspace` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("workspace"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.workspace, None);
    }
    #[test]
    fn session_record_needs_sudo_round_trips_and_stays_absent_when_unset() {
        // serde: `needsSudo` serialises as a bool when Some(true), and is
        // skipped (skip_serializing_if) when None — additive/v0-safe on the
        // wire, matching the `workspace` field's contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.needs_sudo = Some(true);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"needsSudo\":true"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.needs_sudo, Some(true));

        // A record with no needsSudo omits the key entirely (no null/false
        // noise) and a legacy record with no `needsSudo` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("needsSudo"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.needs_sudo, None);
    }
    #[test]
    fn session_record_context_tokens_round_trips_and_stays_absent_when_unset() {
        // serde: `contextTokens` serialises as an integer when Some, and is
        // skipped (skip_serializing_if) when None — additive/v0-safe on the
        // wire, matching the `needsSudo`/`workspace` fields' contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.context_tokens = Some(361_416);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"contextTokens\":361416"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.context_tokens, Some(361_416));

        // A record with no contextTokens omits the key entirely (no null
        // noise) and a legacy record with no `contextTokens` field parses to
        // None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("contextTokens"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.context_tokens, None);
    }
    #[test]
    fn canonical_state_folds_every_producer_onto_the_five_state_vocabulary() {
        // The five canonical outputs, each reached by its own name.
        assert_eq!(canonical_state("working"), "working");
        assert_eq!(canonical_state("awaiting"), "awaiting");
        assert_eq!(canonical_state("stopped"), "stopped");
        assert_eq!(canonical_state("idle"), "idle");
        assert_eq!(canonical_state("done"), "done");

        // `stopped` is FIRST-CLASS, not an alias of `done`: the Stop hook ends a
        // TURN. Both spellings a Stop-hook adapter might write land there.
        assert_eq!(canonical_state("stopped"), "stopped");
        assert_eq!(canonical_state("stop"), "stopped");
        assert_eq!(canonical_state(" Stopped "), "stopped");
        assert_ne!(canonical_state("stopped"), "done");

        // Real termination keeps its own vocabulary.
        for ended in ["done", "exit", "finished", "complete"] {
            assert_eq!(canonical_state(ended), "done", "{ended}");
        }
        // Legacy vocab still migrates in passing.
        assert_eq!(canonical_state("running"), "working");
        assert_eq!(canonical_state("blocked"), "awaiting");
        assert_eq!(canonical_state("waiting"), "idle");
        // Empty/unknown never invents a signal — it rests, cold.
        assert_eq!(canonical_state(""), "idle");
        assert_eq!(canonical_state("mystery"), "idle");
    }
    #[test]
    fn session_records_round_trip_unknown_fields() {
        // shellbridge may grow fields this version does not know; a graph
        // rewrite (link/prune) must not drop them.
        let raw = r#"{ "sessionId": "s", "agent": "claude", "windowAddress": "0x1",
                       "cwd": "/x", "state": "running", "startedAt": "t",
                       "futureField": 42 }"#;
        let rec: SessionRecord = serde_json::from_str(raw).unwrap();
        let back = serde_json::to_value(&rec).unwrap();
        assert_eq!(back["futureField"], 42);
        assert!(back.get("parentSessionId").is_none());
        // A record with no pid serialises WITHOUT the key (additive/v0-safe).
        assert!(back.get("pid").is_none());
    }
}
