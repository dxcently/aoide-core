//! Stage-file record shapes (CONTRACTS.md §4 shapes).
//!
//! Moved from `graph/model.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::graph::{Project, SessionRecord, …}` caller is untouched.
//! The pure DAG-shaping derivations (`cwd_under`, `anchor_for`,
//! `merged_sessions`, `sorted_projects`, `resolved_parent`) stay in root
//! `graph/model.rs` — they're conduct's charter and move in Phase 3b.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// graph.json / projects.json stage-file format version (CONTRACTS.md §4).
pub const STAGE_GRAPH_VERSION: &str = "0";

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
    /// The agent's latest TOOL CALL as a one-line label (`Bash: cargo test`),
    /// read off the same transcript tail as `say` at the same refresh points.
    /// Deliberately not `activity`: that field is the tool running RIGHT NOW
    /// (hook-set, cleared the moment the turn settles), so a card between tools
    /// shows nothing; this one is the transcript's record of what the agent last
    /// reached for and stays put until it reaches for something else.
    /// Additive/v0-safe — absent for shells and until the first tool call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
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
    /// assistant turn (same lifecycle as `model`). The dock reads the published
    /// `context_ceiling` field (below) to turn this raw count into a meter,
    /// rather than computing its own ceiling from `model` client-side.
    #[serde(
        rename = "contextTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_tokens: Option<u64>,
    /// The context-window ceiling (tokens) for this session's current `model`,
    /// computed at refresh time by `aoide_protocol::context_ceiling_for_model`
    /// and published so the dock renders the fill meter without reimplementing the
    /// 200k/1M split (the widget-side guessing this replaces). Re-derived whenever
    /// `model` changes, so a mid-session model switch re-caps automatically.
    /// Additive/v0-safe — absent for shells and until the first assistant turn
    /// lands (same lifecycle as `model`/`contextTokens`); a legacy record without
    /// it falls back to 200k client-side.
    #[serde(
        rename = "contextCeiling",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_ceiling: Option<u64>,
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
    /// Absolute path to the pty-master transcript of a HEADLESS `aoide conduct`
    /// session (`state/sessions/<sessionId>.log`, CONTRACTS.md §4) — raw bytes,
    /// append-only, unrotated. Stamped right after `do_session_start` by
    /// `set_session_log_path`, once the log file is open. Additive/v0-safe:
    /// absent on a legacy record and on every INTERACTIVE session (conduct
    /// never sets it when a real controlling tty is attached).
    #[serde(rename = "logPath", default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// A human-readable `adjective-noun` DISPLAY handle, minted once (see
    /// `petname::mint_for`) — never a lookup key and never encoding machine
    /// or role (those are derived at render time, `display::session_label`).
    /// `sessionId` stays the sole canonical identity everywhere: JSON
    /// payloads, sockets, CONTRACTS keys, `Node::session_id`. Additive/
    /// v0-safe: absent on a legacy record and never backfilled onto one —
    /// same "field this version doesn't know about round-trips, an absent
    /// one stays absent" discipline as `logPath` above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub petname: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn session_record_context_ceiling_round_trips_and_stays_absent_when_unset() {
        // serde: `contextCeiling` serialises as an integer when Some, and is
        // skipped (skip_serializing_if) when None — same additive/v0-safe wire
        // contract as `contextTokens` above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.context_ceiling = Some(1_000_000);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"contextCeiling\":1000000"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.context_ceiling, Some(1_000_000));

        // A record with no contextCeiling omits the key entirely (no null
        // noise) and a legacy record with no `contextCeiling` field parses to
        // None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("contextCeiling"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.context_ceiling, None);
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
    #[test]
    fn session_record_log_path_round_trips_and_stays_absent_when_unset() {
        // serde: `logPath` serialises as a string when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire,
        // matching the `needsSudo`/`workspace` fields' contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.log_path = Some("/home/khoa/Aoide/state/sessions/s.log".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            json.contains("\"logPath\":\"/home/khoa/Aoide/state/sessions/s.log\""),
            "serialised: {json}"
        );
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.log_path, rec.log_path);

        // A record with no logPath omits the key entirely (no null noise) and
        // a legacy record with no `logPath` field parses to None — a record
        // WITHOUT the key serialises byte-identical to before this field
        // existed.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("logPath"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.log_path, None);
    }
    #[test]
    fn session_record_petname_round_trips_and_stays_absent_when_unset() {
        // serde: `petname` serialises as a string when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire,
        // matching the `logPath`/`needsSudo`/`workspace` fields' contract
        // above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.petname = Some("brave-otter".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"petname\":\"brave-otter\""), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.petname, rec.petname);

        // A record with no petname omits the key entirely (no null noise) and
        // a legacy record with no `petname` field parses to None — never
        // backfilled just by round-tripping.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("petname"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.petname, None);
    }
}
