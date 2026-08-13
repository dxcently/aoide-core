//! `graph send` — the gated injection door — and the hook door (`graph
//! session hook`) that maps Claude-Code hook payloads onto the session/
//! sub-agent verbs. The one place untrusted agent-bound text and untrusted
//! hook JSON both land, so every outcome is audited and a hook payload never
//! propagates as anything but data.

use super::common::{require_flag, stage_error};
use super::doc::restage_graph;
use super::model::{load_stage, sessions_path, write_stage, SessionsFile, STAGE_GRAPH_VERSION};
use super::session_store::{
    do_session_end, do_session_phase, do_session_phase_if, do_session_start, do_subagent_end,
    do_subagent_rekey, do_subagent_spawn, now_iso_utc, refresh_subagent_says,
    refresh_transcript_fields, set_owner_activity,
};
use super::window::{discover_window, ensure_session_window};
use aoide_protocol::agents::{agent_profile, known_agents, AgentProfile, HookClass, CLAUDE_PROFILE};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::fs::{stage_dir, with_stage_lock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

// ── `graph send`: the gated injection door ──────────────────────────────────

/// A pending (unapproved) injection, staged for the conductor to surface for a
/// one-key approve/deny. Written atomically to `song/stage/pending.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingSend {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub submit: bool,
    #[serde(rename = "queuedAt", default)]
    pub queued_at: String,
}

/// `pending.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub pending: Vec<PendingSend>,
}

fn pending_path() -> PathBuf {
    stage_dir().join("pending.json")
}

/// The gate decision for a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendGate {
    /// Explicit `--yes` on this send.
    Yes,
    /// The global orchestration-mode switch authorised it (no human in the loop).
    Autogate,
    /// The sender is the target's parent — an orchestrator freely commanding a
    /// child it spawned (the "freely orchestrated" default). No human in the loop.
    AutogateParent,
    /// No authorisation — held pending for approval.
    Pending,
}
impl SendGate {
    fn delivers(self) -> bool {
        !matches!(self, SendGate::Pending)
    }
    fn label(self) -> &'static str {
        match self {
            SendGate::Yes => "yes",
            SendGate::Autogate => "autogate",
            SendGate::AutogateParent => "autogate-parent",
            SendGate::Pending => "pending",
        }
    }
}

/// Global autogate switch: `AOIDE_CONDUCT_AUTOGATE` in {1,true,yes,all} declares
/// an orchestration-mode where every send delivers without a human (still
/// audited) — the box-wide "freely orchestrated" toggle.
fn autogate_env() -> bool {
    matches!(
        std::env::var("AOIDE_CONDUCT_AUTOGATE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("all")
    )
}

/// The parent-autogate rule (pure, unit-tested): the sender may freely command a
/// child it spawned. True when the target session's `parentSessionId` equals the
/// SENDER's own `AOIDE_SESSION_ID` — both present and non-empty. A cross-tree or
/// unrelated send (no id, empty id, or a mismatch) is NOT autogated and stays
/// pending. This is what lets an orchestrator steer the children it conducted
/// without a prompt while every other send remains gated.
fn sender_is_parent(sender_session: Option<&str>, target_parent: Option<&str>) -> bool {
    match (sender_session, target_parent) {
        (Some(s), Some(p)) => !s.is_empty() && s == p,
        _ => false,
    }
}

/// Resolve the gate: `--yes`, then the global autogate switch, then the
/// parent-of-target rule, else pending.
fn send_gate(yes: bool, sender_is_parent: bool) -> SendGate {
    if yes {
        SendGate::Yes
    } else if autogate_env() {
        SendGate::Autogate
    } else if sender_is_parent {
        SendGate::AutogateParent
    } else {
        SendGate::Pending
    }
}

/// A one-line, length-bounded form of the injected text — the auto-rename title.
fn one_line_title(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    const MAX: usize = 60;
    if first.chars().count() > MAX {
        let mut t: String = first.chars().take(MAX - 1).collect();
        t.push('…');
        t
    } else {
        first.to_string()
    }
}

fn record_pending(id: &str, text: &str, submit: bool) -> Result<(), String> {
    let mut file: PendingFile = load_stage(&pending_path())?;
    file.schema_version = STAGE_GRAPH_VERSION.to_string();
    file.pending.push(PendingSend {
        session_id: id.to_string(),
        text: text.to_string(),
        submit,
        queued_at: now_iso_utc(),
    });
    write_stage(&pending_path(), &file)
}

/// Auto-rename: write `title` onto the session record and re-stage the graph so
/// the node relabels. A missing id is a silent no-op (the send still succeeded).
fn set_session_title(id: &str, title: &str) -> Result<(), String> {
    let mut file: SessionsFile = load_stage(&sessions_path())?;
    let mut found = false;
    for s in file.sessions.iter_mut() {
        if s.session_id == id {
            s.title = Some(title.to_string());
            found = true;
        }
    }
    if !found {
        return Ok(());
    }
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    write_stage(&sessions_path(), &file)?;
    restage_graph().map(|_| ())
}

/// Name a session from its FIRST user prompt — set the `title` slot only when it
/// is still empty, so the opening prompt names the session and later prompts do
/// not rename it (a deliberate `graph send` steer still overwrites via
/// [`set_session_title`] — that IS a rename). Under the stage lock (this runs on
/// every UserPromptSubmit hook, concurrent with conduct ticks). No-op for an
/// unregistered id. Re-stages only when it wrote.
fn set_session_name_if_unset(id: &str, name: &str) {
    if name.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut changed = false;
        for s in file.sessions.iter_mut() {
            if s.session_id == id && s.title.as_deref().unwrap_or("").is_empty() {
                s.title = Some(name.to_string());
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

/// One audit line per send outcome, through aoided's audit path. The injected
/// text rides as `untrusted_data` (never the message) — forwarded agent-bound
/// text is data, never re-interpreted as a command (the house rule).
fn audit_send(inv: &Invocation, status: &str, message: &str, text: &str) {
    let log = inv
        .flags
        .get("audit-log")
        .map(PathBuf::from)
        .unwrap_or_else(aoide_protocol::default_audit_log);
    let _ = aoide_protocol::append_audit(
        &log,
        &aoide_protocol::AuditRecord {
            ts: super::conduct::unix_ts(),
            door: inv.door,
            class: aoide_protocol::EventClass::Audit,
            command: "graph.send".to_string(),
            status: status.to_string(),
            message: message.to_string(),
            untrusted_data: Some(text.to_string()),
        },
    );
}

/// `aoide graph send --id <id> [--submit] [--yes] -- <text …>` — the one
/// injection door. Resolves the target's control socket from sessions.json;
/// errors cleanly (exit 1) if the id is unknown or not conductable. Gate: WITHOUT
/// `--yes` and no autogate, the send is recorded PENDING (atomic stage write) and
/// NOT delivered; WITH `--yes` (or an autogate match) it connects to the socket,
/// writes `<text>` (+ `\n` on `--submit`), auto-renames the node to a one-line
/// form of the text, and returns delivered. Every outcome writes an audit line.
pub fn session_send(inv: &Invocation) -> Outcome {
    let cmd = "graph.send";
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph send --id <id> [--submit] [--yes] -- <text …>",
        );
    }
    let text = inv.args.join(" ");
    let submit = inv.flag_present("submit");
    let yes = inv.flag_present("yes");

    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        let out = Outcome::error(cmd, format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    };
    let is_conductable = rec.conductable == Some(true);
    let socket = rec.socket.clone().filter(|s| !s.is_empty());
    let target_parent = rec.parent_session_id.clone();
    if !is_conductable || socket.is_none() {
        let out = Outcome::error(
            cmd,
            format!("session `{id}` is not conductable (no control socket)"),
        )
        .with_data(json!({ "reason": "not-conductable", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    }
    let socket = socket.unwrap();

    // The gate. The sender's own session id (from the env `aoide conduct` exports)
    // vs the target's parent decides the parent-autogate rule.
    let sender = std::env::var("AOIDE_SESSION_ID").ok();
    let is_parent = sender_is_parent(sender.as_deref(), target_parent.as_deref());
    let gate = send_gate(yes, is_parent);
    if !gate.delivers() {
        if let Err(e) = record_pending(&id, &text, submit) {
            return stage_error(cmd, e);
        }
        let out = Outcome::ok(
            cmd,
            format!("send to `{id}` held pending approval (no --yes / autogate)"),
        )
        .changed(vec![format!("pending send queued for {id}")])
        .with_data(json!({
            "id": id,
            "state": "pending",
            "delivered": false,
            "submit": submit,
            "gate": gate.label(),
        }));
        audit_send(inv, "pending", &out.message, &text);
        return out;
    }

    // Deliver: connect + write the payload (+ newline on --submit).
    let mut payload = text.clone();
    if submit {
        payload.push('\n');
    }
    match UnixStream::connect(&socket) {
        Ok(mut stream) => {
            use std::io::Write as _;
            if let Err(e) = stream
                .write_all(payload.as_bytes())
                .and_then(|_| stream.flush())
            {
                let out = Outcome::error(cmd, format!("failed to inject into `{id}`: {e}"))
                    .with_data(json!({ "reason": "socket-write-failed", "id": id, "socket": socket }));
                audit_send(inv, "error", &out.message, &text);
                return out;
            }
        }
        Err(e) => {
            let out = Outcome::error(cmd, format!("control socket for `{id}` unreachable: {e}"))
                .with_data(json!({ "reason": "socket-unreachable", "id": id, "socket": socket }));
            audit_send(inv, "error", &out.message, &text);
            return out;
        }
    }

    // Auto-rename the node to a one-line form of the delivered task.
    let title = one_line_title(&text);
    let mut changed = vec![format!("injected {} byte(s) into {id}", payload.len())];
    match set_session_title(&id, &title) {
        Ok(()) => changed.push(format!("session {id}: title → {title}")),
        Err(e) => changed.push(format!("(title update failed: {e})")), // delivery already happened.
    }

    let out = Outcome::ok(cmd, format!("delivered to `{id}` ({})", gate.label()))
        .changed(changed)
        .with_data(json!({
            "id": id,
            "state": "delivered",
            "delivered": true,
            "submit": submit,
            "title": title,
            "gate": gate.label(),
        }));
    audit_send(inv, "delivered", &out.message, &text);
    out
}

/// A Task sub-agent to create: its node id (`sub:<tool_use_id>`), a human name
/// (the Task description or subagent type), and the subagent type.
#[derive(Debug)]
struct SubSpawn {
    sub_id: String,
    name: String,
    agent_type: String,
}

/// The action a Claude-Code hook payload maps to (or nothing, for events we
/// deliberately ignore — the door is a no-op for everything unmapped).
#[derive(Debug)]
enum HookAction {
    Start { id: String, cwd: Option<String> },
    /// Set the live phase; `name` carries the first user prompt on
    /// UserPromptSubmit (used to name the session set-once), `None` otherwise.
    Phase {
        id: String,
        phase: String,
        name: Option<String>,
    },
    /// A tool started (PreToolUse). `owner` is the session, or `sub:<parent_
    /// tool_use_id>` when the tool ran inside a Task sub-agent (so a sub-agent's
    /// tool churn updates the sub-node, not its parent). `spawn` is Some when the
    /// tool IS a Task — create that child node.
    ToolStart {
        session: String,
        owner: String,
        activity: Option<String>,
        spawn: Option<SubSpawn>,
    },
    /// A tool finished (PostToolUse). `end_sub` closes the Task's child node.
    ToolEnd {
        session: String,
        owner: String,
        end_sub: Option<String>,
    },
    /// PostToolUse for an ASYNC `Agent` dispatch (`tool_response.isAsync == true`):
    /// the launch returned in single-digit ms but the background sub-agent runs
    /// on. Do NOT tear the node down; RE-KEY it from `sub:<tool_use_id>` to
    /// `sub:<agent_id>` (the only id the later SubagentStart/Stop carry) and clear
    /// the owner's foreground activity like a normal tool boundary.
    SubRekey {
        session: String,
        owner: String,
        from_sub_id: String,
        to_sub_id: String,
    },
    /// SubagentStart backstop: ensure the child node exists. `create` is true for
    /// the classic path (keyed by the Task's tool_use_id via `parent_tool_use_id`)
    /// so a missed PreToolUse(Task) is still recovered; it is false for the async
    /// `Agent` fallback (keyed by `agent_id`), which only confirms the re-keyed
    /// node and must never create a duplicate.
    SubEnsure {
        sub_id: String,
        session: String,
        agent_type: String,
        create: bool,
    },
    /// SubagentStop backstop: close the child node.
    SubEnd {
        sub_id: String,
    },
    /// Conditional phase: set `phase` ONLY if the session is still `working`,
    /// else a no-op. Guards the ambiguous idle Notification — a "waiting for your
    /// input" ping only means `awaiting` when the turn is still mid-flight (an
    /// unanswered AskUserQuestion); a settled `idle`/`done` session must not be
    /// flipped by the ~60s idle heartbeat.
    PhaseIfRunning { id: String, phase: String },
    End { id: String },
}

/// Map ONE hook payload (`session_id`, `hook_event_name`, optional `cwd`) to a
/// session-registration action, or `None` when the event is unknown/missing or
/// the `session_id` is absent/empty. Pure over the decoded JSON so the mapping
/// is unit-testable without touching stdin or the stage. The event vocabulary
/// itself lives in the agent's profile (`hook_event_map`); this collapses the
/// semantic classes onto the session verbs.
fn map_hook(profile: &AgentProfile, payload: &Value) -> Option<HookAction> {
    let id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let event = payload.get("hook_event_name").and_then(Value::as_str)?;
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // Is `tool` a sub-agent-dispatch tool for this harness (claude: Task/Agent)?
    let is_subagent_tool = |tool: &str| profile.subagent_tools.contains(&tool);
    match (profile.hook_event_map)(event) {
        HookClass::SessionStart => Some(HookAction::Start { id: id.to_string(), cwd }),
        // A new prompt: the turn is live → `working`, and the prompt text names
        // the session (set-once, downstream).
        HookClass::PromptSubmit => {
            let name = payload
                .get("user_prompt")
                .and_then(Value::as_str)
                .map(one_line_title)
                .filter(|s| !s.is_empty());
            Some(HookAction::Phase {
                id: id.to_string(),
                phase: "working".to_string(),
                name,
            })
        }
        // A tool call. Route it to its OWNER — the session, or the sub-node
        // `sub:<parent_tool_use_id>` when the tool ran inside a Task sub-agent
        // (nesting + activity routing). The Task tool itself spawns/closes a
        // child node; any other tool sets the owner working with the tool as its
        // current `activity`. Both are part of the awaiting-clearing set.
        HookClass::PreToolUse => {
            let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
            let tuid = payload.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
            let owner = match payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                Some(p) => format!("sub:{p}"),
                None => id.to_string(),
            };
            if is_subagent_tool(tool) && !tuid.is_empty() {
                let input = payload.get("tool_input");
                let field = |k: &str| {
                    input
                        .and_then(|i| i.get(k))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                };
                let stype = field("subagent_type");
                let desc = field("description");
                let name = one_line_title(if desc.is_empty() { stype } else { desc });
                Some(HookAction::ToolStart {
                    session: id.to_string(),
                    owner,
                    activity: if name.is_empty() { None } else { Some(name.clone()) },
                    spawn: Some(SubSpawn {
                        sub_id: format!("sub:{tuid}"),
                        name,
                        agent_type: stype.to_string(),
                    }),
                })
            } else {
                Some(HookAction::ToolStart {
                    session: id.to_string(),
                    owner,
                    activity: if tool.is_empty() { None } else { Some(tool.to_string()) },
                    spawn: None,
                })
            }
        }
        HookClass::PostToolUse => {
            let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
            let tuid = payload.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
            let owner = match payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                Some(p) => format!("sub:{p}"),
                None => id.to_string(),
            };
            // Async `Agent` dispatch: PostToolUse fires the instant the LAUNCH
            // returns (`tool_response.isAsync == true`), NOT when the background
            // agent finishes — so tearing the node down here would kill it within
            // ~4ms of creating it. Instead re-key `sub:<tuid>` → `sub:<agentId>`
            // (this payload's own `tool_response.agentId`, the only place both ids
            // co-occur) so the later SubagentStop can find it. A classic Task (or a
            // synchronous Agent with no `isAsync`) really IS done here — end it.
            let resp = payload.get("tool_response");
            let async_agent_id = if is_subagent_tool(tool)
                && !tuid.is_empty()
                && resp
                    .and_then(|r| r.get("isAsync"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                resp.and_then(|r| r.get("agentId"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            } else {
                None
            };
            if let Some(aid) = async_agent_id {
                Some(HookAction::SubRekey {
                    session: id.to_string(),
                    owner,
                    from_sub_id: format!("sub:{tuid}"),
                    to_sub_id: format!("sub:{aid}"),
                })
            } else {
                let end_sub = if is_subagent_tool(tool) && !tuid.is_empty() {
                    Some(format!("sub:{tuid}"))
                } else {
                    None
                };
                Some(HookAction::ToolEnd {
                    session: id.to_string(),
                    owner,
                    end_sub,
                })
            }
        }
        // The turn ended and it is the user's move again — but a finished turn is
        // NOT "needs input" (that would make the anxious state the resting face of
        // the whole roster). `awaiting` is reserved strictly for the Notification
        // signals below, so Stop settles to `stopped`: alive, at the prompt, and
        // RECENTLY so. It is not `done` (the session did not end — only the turn),
        // and not `idle` (that is the COLD rest a `stopped` session decays into an
        // hour later, in the reaper's `decay_stopped_sessions` pass).
        HookClass::Stop => Some(HookAction::Phase {
            id: id.to_string(),
            phase: "stopped".to_string(),
            name: None,
        }),
        // The needs-input signal. Prefer the structured `notification_type`
        // (idle_prompt / permission_prompt, confirmed present in the CLI); fall
        // back to the brittle English `message` for older payloads. A permission
        // prompt is an unambiguous mid-turn blocker → `awaiting` at once. The ~60s
        // idle ping is ambiguous — only a still-`working` turn (an unseen
        // AskUserQuestion) becomes `awaiting`; a settled idle/done session is left
        // untouched. Anything else is a no-op. The vocabulary lives in the
        // profile; the unconditional permission tier wins across BOTH sources.
        HookClass::Notification => {
            let ntype = payload
                .get("notification_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let msg = payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let by_type = (profile.hook_event_map)(&format!("ntype:{ntype}"));
            let by_msg = (profile.hook_event_map)(&format!("msg:{msg}"));
            if matches!(by_type, HookClass::Awaiting) || matches!(by_msg, HookClass::Awaiting) {
                Some(HookAction::Phase {
                    id: id.to_string(),
                    phase: "awaiting".to_string(),
                    name: None,
                })
            } else if matches!(by_type, HookClass::AwaitingIfRunning)
                || matches!(by_msg, HookClass::AwaitingIfRunning)
            {
                Some(HookAction::PhaseIfRunning {
                    id: id.to_string(),
                    phase: "awaiting".to_string(),
                })
            } else {
                None
            }
        }
        // Sub-agent lifecycle backstops. The classic path keys on the spawning
        // Task's tool_use_id (carried as `parent_tool_use_id`) — it converges on
        // the same node the PreToolUse/PostToolUse(Task) path manages, whichever
        // fires. This harness's async `Agent` dispatch carries NEITHER
        // tool_use_id NOR parent_tool_use_id here — only `agent_id` — so we fall
        // back to it, keyed `sub:<agent_id>`, which is exactly what the async
        // PostToolUse re-keyed the node to. The classic path may create a node
        // (backstop for a missed PreToolUse); the agent_id fallback only confirms
        // the re-keyed node (never creates a duplicate).
        HookClass::SubagentStart => {
            let via_parent = payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let key = via_parent.or_else(|| {
                payload
                    .get("agent_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            });
            key.map(|k| HookAction::SubEnsure {
                sub_id: format!("sub:{k}"),
                session: id.to_string(),
                agent_type: payload
                    .get("agent_type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                create: via_parent.is_some(),
            })
        }
        HookClass::SubagentStop => {
            let key = payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    payload
                        .get("agent_id")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                });
            key.map(|k| HookAction::SubEnd {
                sub_id: format!("sub:{k}"),
            })
        }
        HookClass::SessionEnd => Some(HookAction::End { id: id.to_string() }),
        // A DEDICATED needs-input event (kimi: `PermissionRequest`) — the same
        // unconditional `awaiting` a permission Notification yields. Claude's
        // map can never produce this class at the top level (its Awaiting only
        // answers prefixed notification-detail queries), so claude is unchanged.
        HookClass::Awaiting => Some(HookAction::Phase {
            id: id.to_string(),
            phase: "awaiting".to_string(),
            name: None,
        }),
        // Unknown events (and the conditional idle class, which only the
        // Notification arm acts on) map to nothing.
        _ => None,
    }
}

/// Drive one hook payload (already read as a string) through the claude
/// profile — the test-facing wrapper (production resolves the profile from
/// `--agent` via [`hook_profile_for`] and calls [`hook_for_profile`]).
#[cfg(test)]
fn hook_from_str(buf: &str) -> Outcome {
    let profile = agent_profile(CLAUDE_PROFILE.name).expect("the claude profile is registered");
    hook_for_profile(profile, buf)
}

/// The profile-parametrized core of [`hook_from_str`].
///
/// Split from `session_hook` so the whole path — parse, map, execute — is
/// testable without a real stdin. Empty/malformed input or an unmapped event is
/// an ok no-op; a mapped action runs the matching core but its outcome is ALWAYS
/// folded into an ok envelope: this door runs inside interactive-session hooks
/// and must never exit non-zero (a stage hiccup must not break the session).
/// Self-heal for the hook door: a live session whose store record was ended
/// or pruned mid-process (an errant SessionEnd payload, a conversation switch
/// that fired End, a store reset, a reap during a hook-silent restart window)
/// re-registers on its NEXT real event — harnesses fire SessionStart only at
/// launch, so without this the session is permanently invisible to the graph
/// until the harness restarts. Mirror of the `Start` arm's registration
/// (window discovery + `AOIDE_SESSION_ID` env-parent threading), inserting a
/// fresh idle record; no-op when the id already exists. `sub:` ids are never
/// implicit-started — they exist only as children of a registered parent.
fn hook_ensure_session(profile: &AgentProfile, payload: &Value, id: &str) {
    if id.starts_with("sub:") {
        return;
    }
    let exists = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions.iter().any(|s| s.session_id == id))
        .unwrap_or(false);
    if exists {
        return;
    }
    let cwd = payload.get("cwd").and_then(Value::as_str).map(str::to_string);
    let (window, pid) = match discover_window() {
        Some((addr, pid, _workspace)) => (Some(addr), Some(pid)),
        None => (None, None),
    };
    let env_parent = std::env::var("AOIDE_SESSION_ID")
        .ok()
        .filter(|p| !p.is_empty() && *p != id);
    let _ = do_session_start(
        &id,
        Some(profile.name),
        cwd.as_deref(),
        window.as_deref(),
        env_parent.as_deref(),
        None,
        None,
        None,
        pid,
    );
}

fn hook_for_profile(profile: &'static AgentProfile, buf: &str) -> Outcome {
    let cmd = "graph.session.hook";
    let noop = |reason: &str| {
        Outcome::ok(cmd, format!("no-op ({reason})"))
            .with_data(json!({ "action": "none", "reason": reason }))
    };
    let mut payload: Value = match serde_json::from_str(buf.trim()) {
        Ok(v) => v,
        Err(_) => return noop("empty-or-malformed-stdin"),
    };
    // Map harness-native field names onto the canonical contract before
    // mapping (identity for claude; kimi's prompt array, tool_call_id, and
    // agent_name land on user_prompt / tool_use_id / agent_type).
    (profile.normalize_payload)(&mut payload);
    let Some(action) = map_hook(profile, &payload) else {
        return noop("unmapped-or-missing-event");
    };
    let inner = match action {
        HookAction::Start { id, cwd } => {
            // Best-effort: the hook is a subprocess of the agent's terminal, so
            // discover that window (+ its owning pid) now and register it — this
            // is what makes a hook-only Claude session `graph focus`-jumpable.
            // Workspace is stamped later by the shellbridge window-event listener
            // (resolve_pending_session_windows), which is authoritative and keeps
            // it fresh across moves — do_session_start carries only window + pid.
            let (window, pid) = match discover_window() {
                Some((addr, pid, _workspace)) => (Some(addr), Some(pid)),
                None => (None, None),
            };
            // A claude launched INSIDE a conducted session inherits its parent's
            // `AOIDE_SESSION_ID` in the hook process env — thread it as the
            // parent so a claude-conducting-claude (or a claude-in-a-shell) nests
            // in the graph. The hook door inherits the launcher's env.
            let env_parent = std::env::var("AOIDE_SESSION_ID")
                .ok()
                .filter(|p| !p.is_empty() && *p != id);
            let out = do_session_start(
                &id,
                Some(profile.name),
                cwd.as_deref(),
                window.as_deref(),
                env_parent.as_deref(),
                None,
                None,
                None,
                pid,
            );
            // A FRESH id is inserted `idle` by `upsert_session`. A RESUME (same id,
            // SessionStart source=resume/compact/clear) deliberately preserves the
            // stored state — a working/awaiting session must not be reset — but a
            // session resumed out of `stopped` is by definition "not yet active"
            // again, which is `idle`. Fold exactly that one case, conditionally, so
            // both stage files agree (hooks.json still holds the Stop phase, and
            // `merged_sessions` overlays it — leaving it would resurrect `stopped`).
            do_session_phase_if(&id, "idle", "stopped");
            out
        }
        HookAction::Phase { id, phase, name } => {
            // Self-heal: a live session whose store record was ended or pruned
            // mid-process (an errant SessionEnd payload, a conversation switch,
            // a store reset, a reap during a hook-silent restart window) comes
            // back on its NEXT event — harnesses fire SessionStart only at
            // launch, so without this the session is permanently invisible until
            // the harness restarts. Same registration path as Start (window +
            // env-parent threading), fresh idle.
            hook_ensure_session(profile, &payload, &id);
            // Backfill a still-empty windowAddress on any later hook — covers a
            // session that registered before the window mapped (or before this
            // discovery shipped), so it becomes jumpable without a restart.
            ensure_session_window(&id);
            let out = do_session_phase(&id, &phase);
            // The first user prompt names the session (set-once).
            if let Some(n) = name {
                set_session_name_if_unset(&id, &n);
            }
            out
        }
        HookAction::PhaseIfRunning { id, phase } => {
            hook_ensure_session(profile, &payload, &id);
            ensure_session_window(&id);
            do_session_phase_if(&id, &phase, "working")
        }
        HookAction::ToolStart {
            session,
            owner,
            activity,
            spawn,
        } => {
            hook_ensure_session(profile, &payload, &session);
            ensure_session_window(&session);
            // Spawn the child FIRST so it exists before its parent's activity
            // points at it, then mark the owner working + its current activity.
            if let Some(sp) = spawn {
                do_subagent_spawn(&sp.sub_id, &owner, &sp.name, &sp.agent_type, true);
            }
            set_owner_activity(&owner, "working", activity.as_deref());
            Outcome::ok("graph.session.hook", format!("tool start → {owner}"))
        }
        HookAction::ToolEnd {
            session,
            owner,
            end_sub,
        } => {
            hook_ensure_session(profile, &payload, &session);
            ensure_session_window(&session);
            if let Some(sub) = end_sub {
                do_subagent_end(&sub);
            }
            // The tool finished; the owner is still in its turn (working) but no
            // longer running that tool — clear its `activity`.
            set_owner_activity(&owner, "working", None);
            Outcome::ok("graph.session.hook", format!("tool end → {owner}"))
        }
        HookAction::SubRekey {
            session,
            owner,
            from_sub_id,
            to_sub_id,
        } => {
            hook_ensure_session(profile, &payload, &session);
            ensure_session_window(&session);
            do_subagent_rekey(&from_sub_id, &to_sub_id);
            // The launch returned; the parent is no longer running that tool in
            // the foreground (its sub-agent runs on in the background) — clear the
            // activity, exactly as a normal tool boundary would.
            set_owner_activity(&owner, "working", None);
            Outcome::ok(
                "graph.session.hook",
                format!("subagent rekey {from_sub_id} → {to_sub_id}"),
            )
        }
        HookAction::SubEnsure {
            sub_id,
            session,
            agent_type,
            create,
        } => {
            hook_ensure_session(profile, &payload, &session);
            do_subagent_spawn(&sub_id, &session, &agent_type, &agent_type, create);
            Outcome::ok("graph.session.hook", format!("subagent {sub_id}"))
        }
        HookAction::SubEnd { sub_id } => {
            do_subagent_end(&sub_id);
            Outcome::ok("graph.session.hook", format!("subagent end {sub_id}"))
        }
        HookAction::End { id } => do_session_end(&id),
    };
    // After applying the action, refresh the session's transcript `say` at the
    // boundaries where fresh prose has just landed: the turn end (Stop), a tool
    // boundary (PostToolUse), a new prompt (UserPromptSubmit), or an input-needed
    // ping (Notification). Skips the high-frequency PreToolUse (its prose is
    // captured at the matching PostToolUse) and the lifecycle-only events. Only
    // the TOP-LEVEL session speaks — a sub-agent tool call carries
    // `parent_tool_use_id`, and must not overwrite its parent's say.
    if let (Some(sid), Some(evt)) = (
        payload
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty()),
        payload.get("hook_event_name").and_then(Value::as_str),
    ) {
        let is_sub = payload
            .get("parent_tool_use_id")
            .and_then(Value::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let cwd = payload.get("cwd").and_then(Value::as_str);
        let say_boundary = matches!(
            (profile.hook_event_map)(evt),
            HookClass::Stop | HookClass::PostToolUse | HookClass::PromptSubmit | HookClass::Notification
        );
        if !is_sub && say_boundary {
            refresh_transcript_fields(
                profile,
                sid,
                cwd,
                payload.get("transcript_path").and_then(Value::as_str),
            );
        }
        // A background Task keeps running after the parent's turn settles, so
        // catch its words on every one of the parent's own hooks (not just the
        // set above) — cheap: a no-op unless the session currently has a live
        // sub-node. Deferred/direct children only (see `refresh_subagent_says`).
        if !is_sub {
            refresh_subagent_says(profile, sid, cwd);
        }
    }
    // Fold the inner outcome into an ok envelope — exit 0, no matter what.
    Outcome::ok(cmd, inner.message)
        .changed(inner.changed)
        .with_data(json!({
            "action": "applied",
            "innerStatus": format!("{:?}", inner.status),
            "innerData": inner.data,
        }))
}

/// Resolve the agent profile for a hook invocation: `--agent <name>` selects
/// it (default claude, until harnesses self-report); an unknown name is a
/// structured error naming the registered agents.
fn hook_profile_for(inv: &Invocation) -> Result<&'static AgentProfile, Outcome> {
    let name = inv
        .flags
        .get("agent")
        .map(String::as_str)
        .unwrap_or(CLAUDE_PROFILE.name);
    agent_profile(name).ok_or_else(|| {
        Outcome::error(
            "graph.session.hook",
            format!("unknown agent `{name}` (known: {})", known_agents().join(", ")),
        )
        .with_data(json!({ "reason": "unknown-agent", "agent": name, "known": known_agents() }))
    })
}

/// `graph session hook [--agent <name>]` — the hook door for agent harnesses.
/// Reads ONE JSON object from stdin and maps it (through the selected agent
/// profile) to the session verbs. Never exits non-zero for a payload problem
/// (see [`hook_for_profile`]); a bogus `--agent` is a plain CLI error.
pub fn session_hook(inv: &Invocation) -> Outcome {
    use std::io::Read;
    let profile = match hook_profile_for(inv) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let mut buf = String::new();
    let _ = std::io::stdin().lock().read_to_string(&mut buf);
    hook_for_profile(profile, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::common::load_inputs;
    use crate::graph::conduct::conduct_socket_path;
    use crate::graph::doc::prune_done;
    use crate::graph::model::{hooks_path, merged_sessions, HooksFile};
    use crate::graph::testutil::*;

    #[test]
    fn parent_autogate_decision_is_exact_and_guarded() {
        // The sender IS the target's parent → autogated (freely orchestrated).
        assert!(sender_is_parent(Some("orch"), Some("orch")));
        // Mismatched ids (cross-tree / unrelated) → NOT autogated.
        assert!(!sender_is_parent(Some("orch"), Some("other")));
        // A missing sender or a parentless target → NOT autogated.
        assert!(!sender_is_parent(None, Some("orch")));
        assert!(!sender_is_parent(Some("orch"), None));
        // Empty ids never match (a blank env var is not a parent claim).
        assert!(!sender_is_parent(Some(""), Some("")));
        assert!(!sender_is_parent(Some(""), Some("orch")));

        // The gate resolves in priority order: --yes ▸ global env ▸ parent ▸ pending.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_CONDUCT_AUTOGATE"]);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        assert_eq!(send_gate(true, false), SendGate::Yes); // --yes wins outright
        assert_eq!(send_gate(false, true), SendGate::AutogateParent);
        assert_eq!(send_gate(false, false), SendGate::Pending);
        assert!(SendGate::AutogateParent.delivers());
        assert_eq!(SendGate::AutogateParent.label(), "autogate-parent");
        std::env::set_var("AOIDE_CONDUCT_AUTOGATE", "1");
        // The global switch outranks the parent rule (both deliver; label differs).
        assert_eq!(send_gate(false, true), SendGate::Autogate);
        assert_eq!(send_gate(false, false), SendGate::Autogate);
    }
    #[test]
    fn send_yes_delivers_and_autorenames_the_title() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);

        let root = unique_stage("send-yes");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no standing autogate.

        let id = "send-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // A stand-in listener plays the conducted process.
        let listener = UnixListener::bind(&socket).unwrap();

        // Register a conductable session pointing at that socket.
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // Accept + read the injected payload to EOF in a thread.
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["hello", "world"],
            &[("id", id), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "yes");
        // --submit appended a newline.
        assert_eq!(String::from_utf8(got).unwrap(), "hello world\n");

        // Title auto-renamed on the record + restaged graph node.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|r| r.session_id == id).unwrap().title.as_deref(),
            Some("hello world")
        );

        // An audit line for the delivery was written.
        let log = std::fs::read_to_string(root.join("log")).unwrap_or_default();
        assert!(
            log.contains("graph.send") && log.contains("delivered"),
            "audit log carries the delivered send: {log}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_without_yes_is_held_pending_not_delivered() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);

        let root = unique_stage("send-pending");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");

        let id = "pend-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap(); // so we can assert nothing connected.

        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        let out = session_send(&send_invocation(&["do", "a", "thing"], &[("id", id)]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        // Nothing connected to the listener.
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a held-pending send delivers nothing"
        );

        // Recorded in pending.json.
        let pf: PendingFile = load_stage(&pending_path()).unwrap();
        assert!(
            pf.pending
                .iter()
                .any(|p| p.session_id == id && p.text == "do a thing"),
            "the send is recorded pending"
        );

        // Title NOT changed (delivery never happened).
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions.iter().find(|r| r.session_id == id).unwrap().title.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_delivers_when_sender_is_the_targets_parent() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-parent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no global autogate.
        // The SENDER is the orchestrator session `orch`.
        std::env::set_var("AOIDE_SESSION_ID", "orch");

        let id = "child-of-orch";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        // Register a conductable CHILD whose parent is the sender (`orch`).
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"),
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        // No --yes: delivery is authorised purely by the parent relationship.
        let out = session_send(&send_invocation(&["go"], &[("id", id), ("submit", "true")]));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "autogate-parent");
        assert_eq!(String::from_utf8(got).unwrap(), "go\n");

        // An UNRELATED sender (different session) to the same child stays pending.
        std::env::set_var("AOIDE_SESSION_ID", "stranger");
        let out = session_send(&send_invocation(&["hi"], &[("id", id)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_unknown_or_unconductable_is_a_clean_error() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("send-err");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        // Unknown id.
        let out = session_send(&send_invocation(&["hi"], &[("id", "ghost"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "session-not-found");

        // Registered but not conductable (a plain wrap/hook session).
        do_session_start("plain", Some("claude"), None, None, None, None, None, None, None);
        let out = session_send(&send_invocation(&["hi"], &[("id", "plain"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-conductable");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn hook_event_mapping_covers_the_lifecycle_and_ignores_the_rest() {
        let start = map_hook(
            &CLAUDE_PROFILE,
            &json!({ "session_id": "s", "hook_event_name": "SessionStart", "cwd": "/w" }),
        )
        .unwrap();
        assert!(matches!(start, HookAction::Start { cwd: Some(_), .. }));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "UserPromptSubmit" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "working"
        ));
        // A non-Task tool → ToolStart on the session (owner), tool as activity.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash" }))
                .unwrap(),
            HookAction::ToolStart { ref owner, ref activity, spawn: None, .. }
                if owner == "s" && activity.as_deref() == Some("Bash")
        ));
        // PostToolUse → ToolEnd on the same owner (part of the awaiting-clearing set).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Bash" }))
                .unwrap(),
            HookAction::ToolEnd { ref owner, end_sub: None, .. } if owner == "s"
        ));
        // A Task tool → ToolStart carrying a SubSpawn (the child node to create),
        // keyed by its tool_use_id, named from the description.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Task",
                "tool_use_id": "tuABC",
                "tool_input": { "description": "explore the auth module", "subagent_type": "Explore" }
            })).unwrap(),
            HookAction::ToolStart { spawn: Some(ref sp), .. }
                if sp.sub_id == "sub:tuABC" && sp.name == "explore the auth module" && sp.agent_type == "Explore"
        ));
        // A tool fired INSIDE a sub-agent (parent_tool_use_id present) routes to
        // the sub-node, not the session — the nesting/activity-routing rule.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Grep",
                "parent_tool_use_id": "tuABC"
            })).unwrap(),
            HookAction::ToolStart { ref owner, .. } if owner == "sub:tuABC"
        ));
        // PostToolUse(Task) closes the child; SubagentStop is the backstop.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Task",
                "tool_use_id": "tuABC"
            })).unwrap(),
            HookAction::ToolEnd { end_sub: Some(ref e), .. } if e == "sub:tuABC"
        ));
        // This harness's own dispatch tool is named `Agent`, not `Task`. It must
        // spawn/close the sub-node identically — same tool_input field names
        // (`description`, `subagent_type`), so the child is named the same way.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                "tool_use_id": "tuAG",
                "tool_input": { "description": "explore the auth module", "subagent_type": "Explore" }
            })).unwrap(),
            HookAction::ToolStart { spawn: Some(ref sp), .. }
                if sp.sub_id == "sub:tuAG" && sp.name == "explore the auth module" && sp.agent_type == "Explore"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                "tool_use_id": "tuAG"
            })).unwrap(),
            HookAction::ToolEnd { end_sub: Some(ref e), .. } if e == "sub:tuAG"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStop", "parent_tool_use_id": "tuABC"
            })).unwrap(),
            HookAction::SubEnd { ref sub_id } if sub_id == "sub:tuABC"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStart",
                "parent_tool_use_id": "tuABC", "agent_type": "Explore"
            })).unwrap(),
            HookAction::SubEnsure { ref sub_id, ref agent_type, create, .. }
                if sub_id == "sub:tuABC" && agent_type == "Explore" && create
        ));
        // ASYNC `Agent` dispatch: its PostToolUse fires at LAUNCH
        // (`tool_response.isAsync == true`), NOT at completion. It must NOT end the
        // node — it re-keys `sub:<tool_use_id>` → `sub:<agentId>` (the only place
        // both ids co-occur) so the later SubagentStop can find it.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                "tool_use_id": "tuAsync",
                "tool_response": { "isAsync": true, "status": "async_launched", "agentId": "agz1" }
            })).unwrap(),
            HookAction::SubRekey { ref from_sub_id, ref to_sub_id, .. }
                if from_sub_id == "sub:tuAsync" && to_sub_id == "sub:agz1"
        ));
        // The async lifecycle events carry ONLY `agent_id` (no parent_tool_use_id):
        // SubagentStart falls back to it as an enrich-only ensure (create=false);
        // SubagentStop falls back to it to close the re-keyed node.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStart",
                "agent_id": "agz1", "agent_type": "general-purpose"
            })).unwrap(),
            HookAction::SubEnsure { ref sub_id, create, .. }
                if sub_id == "sub:agz1" && !create
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStop", "agent_id": "agz1"
            })).unwrap(),
            HookAction::SubEnd { ref sub_id } if sub_id == "sub:agz1"
        ));
        // Stop settles the turn to `stopped` — a finished turn is not "needs
        // input" (not `awaiting`), not a finished SESSION (not `done`), and not
        // yet cold (`idle` is where the reaper ages it an hour later).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "Stop" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "stopped"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "SessionEnd" })).unwrap(),
            HookAction::End { .. }
        ));
        // Notification with a permission message → an unconditional `awaiting`.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "Claude needs your permission to use Bash"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "awaiting"
        ));
        // The structured notification_type is honoured too (permission_prompt).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "notification_type": "permission_prompt"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "awaiting"
        ));
        // The ambiguous idle ping → the CONDITIONAL variant (guarded downstream).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "Claude is waiting for your input"
            }))
            .unwrap(),
            HookAction::PhaseIfRunning { ref phase, .. } if phase == "awaiting"
        ));
        // …and via notification_type idle_prompt.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "notification_type": "idle_prompt"
            }))
            .unwrap(),
            HookAction::PhaseIfRunning { ref phase, .. } if phase == "awaiting"
        ));
        // "permission" match is case-insensitive.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "PERMISSION required"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "awaiting"
        ));
        // A Notification with an unrecognised or absent message → no action.
        assert!(map_hook(
            &CLAUDE_PROFILE,
            &json!({ "session_id": "s", "hook_event_name": "Notification", "message": "hello" })
        )
        .is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "Notification" })).is_none());
        // Unknown event, missing event, and empty/absent session_id → no action.
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "Zzz" })).is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s" })).is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "hook_event_name": "SessionStart" })).is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "", "hook_event_name": "SessionStart" })).is_none());
    }
    #[test]
    fn hook_garbage_stdin_is_an_ok_noop_never_nonzero() {
        // Every one of these is empty/garbage/unmapped: an ok no-op that touches
        // no stage file (so the live stage is safe even without an override).
        for bad in [
            "",
            "   ",
            "not json at all",
            "{",
            "[]",
            "42",
            "\"a string\"",
            r#"{ "session_id": "x" }"#,                       // no event
            r#"{ "hook_event_name": "SessionStart" }"#,        // no id
            r#"{ "session_id": "x", "hook_event_name": "Zzz" }"#, // unmapped
        ] {
            let out = hook_from_str(bad);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "input: {bad:?}");
            assert_eq!(out.render(false).1, aoide_protocol::output::exit::OK);
            assert_eq!(out.data.unwrap()["action"], "none", "input: {bad:?}");
        }
    }
    #[test]
    fn hook_lifecycle_start_running_waiting_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // SessionStart registers the session (agent claude, cwd from payload).
        let out = hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "extra": 9 }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "claude");
        assert_eq!(s.sessions[0].cwd, "/proj");

        // A FRESH registration is at rest and cold: `idle`, never `stopped`.
        assert_eq!(s.sessions[0].state, "idle");

        // PreToolUse → working, Stop → stopped (latest hook phase wins). The
        // canonical live state now lands on sessions.json too (the widget file).
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "PreToolUse" }"#);
        let s_working: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_working.sessions[0].state, "working");
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "Stop" }"#);
        let (_, ss, hh) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss.sessions, &hh.hooks)[0].state, "stopped");
        let s_stopped: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_stopped.sessions[0].state, "stopped");

        // A RESUME (SessionStart on the SAME id) folds that `stopped` back to
        // `idle` — resumed and not yet active — in BOTH files, so the merge agrees.
        hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "source": "resume" }"#,
        );
        let s_resumed: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_resumed.sessions.len(), 1, "a resume never duplicates");
        assert_eq!(s_resumed.sessions[0].state, "idle");
        let (_, ss_r, hh_r) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss_r.sessions, &hh_r.hooks)[0].state, "idle");

        // A resume must still NOT reset a live turn: back to working, resume again.
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "PreToolUse" }"#);
        hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "source": "resume" }"#,
        );
        let s_live: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_live.sessions[0].state, "working");
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "Stop" }"#);

        // SessionEnd → done in both files.
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "SessionEnd" }"#);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions[0].state, "done");
        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        assert_eq!(h2.hooks.iter().find(|h| h.session_id == "h1").unwrap().phase, "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn hook_notification_blocks_and_the_clearing_set_lifts_it() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-blocked");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let live_phase = |id: &str| -> String {
            let h: HooksFile = load_stage(&hooks_path()).unwrap();
            h.hooks
                .iter()
                .find(|r| r.session_id == id)
                .map(|r| r.phase.clone())
                .unwrap_or_default()
        };

        // Register, then drive to a live turn.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "PreToolUse" }"#);
        assert_eq!(live_phase("b1"), "working");

        // A permission Notification → awaiting, unconditionally.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude needs your permission to use Bash" }"#,
        );
        assert_eq!(live_phase("b1"), "awaiting");

        // PostToolUse (the approval → tool-ran edge) lifts the fermata → working.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "PostToolUse" }"#);
        assert_eq!(live_phase("b1"), "working");

        // The ambiguous idle ping, mid-turn (working), is a real mid-turn
        // question → awaiting.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude is waiting for your input" }"#,
        );
        assert_eq!(live_phase("b1"), "awaiting");

        // Stop settles the turn → stopped.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_phase("b1"), "stopped");

        // The SAME idle ping on a SETTLED (stopped) session is a no-op — the ~60s
        // heartbeat must NOT flip a quietly-finished turn to awaiting.
        let out = hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude is waiting for your input" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(live_phase("b1"), "stopped");

        // A garbage/absent-message Notification is an ok no-op (action:none), and
        // never touches the phase.
        let noop = hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification", "message": "hi" }"#,
        );
        assert_eq!(noop.data.unwrap()["action"], "none");
        assert_eq!(live_phase("b1"), "stopped");

        // awaiting flows through the merge opaquely as the node state.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "permission needed" }"#,
        );
        let (_, ss, hh) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss.sessions, &hh.hooks)[0].state, "awaiting");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn first_user_prompt_names_the_session_set_once() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("name");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        hook_from_str(r#"{ "session_id": "n1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        // First prompt names the session.
        hook_from_str(
            r#"{ "session_id": "n1", "hook_event_name": "UserPromptSubmit",
                 "prompt": "fix the flaky auth test\nand rerun CI" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].title.as_deref(), Some("fix the flaky auth test"));

        // A LATER prompt must NOT rename it (set-once).
        hook_from_str(
            r#"{ "session_id": "n1", "hook_event_name": "UserPromptSubmit",
                 "prompt": "now do something else entirely" }"#,
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s2.sessions[0].title.as_deref(),
            Some("fix the flaky auth test"),
            "the first prompt names the session; later prompts don't rename it"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn subagent_task_builds_nests_and_collapses_the_tree() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("subagent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        // A claude session runs, then spawns a Task sub-agent.
        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "UserPromptSubmit", "prompt": "audit the repo" }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Task",
                 "tool_use_id": "t1",
                 "tool_input": { "description": "map the bridge", "subagent_type": "Explore" } }"#,
        );
        let ss = load();
        let sub = find(&ss, "sub:t1").expect("the Task sub-node is created");
        assert_eq!(sub.parent_session_id.as_deref(), Some("a"));
        assert_eq!(sub.kind.as_deref(), Some("subagent"));
        assert_eq!(sub.state, "working");
        assert_eq!(sub.title.as_deref(), Some("map the bridge"));
        assert_eq!(sub.agent, "Explore");
        // The parent's activity reflects what its child is doing.
        assert_eq!(find(&ss, "a").unwrap().activity.as_deref(), Some("map the bridge"));

        // A tool fired INSIDE the sub-agent routes to the sub-node, not the session.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Grep",
                 "parent_tool_use_id": "t1" }"#,
        );
        assert_eq!(find(&load(), "sub:t1").unwrap().activity.as_deref(), Some("Grep"));

        // The Task returns → the sub-node is removed (the tree collapses).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Task",
                 "tool_use_id": "t1" }"#,
        );
        assert!(
            find(&load(), "sub:t1").is_none(),
            "the sub-node is removed when its Task returns"
        );

        // SessionEnd cascades: a still-open sub-node is cleaned with its session.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Task",
                 "tool_use_id": "t2", "tool_input": { "subagent_type": "Plan" } }"#,
        );
        assert!(find(&load(), "sub:t2").is_some());
        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionEnd" }"#);
        let end = load();
        assert!(
            find(&end, "sub:t2").is_none(),
            "SessionEnd removes the sub-agent subtree"
        );
        assert_eq!(find(&end, "a").unwrap().state, "done");

        // The `Agent` tool (this harness's dispatch name) drives the tree the
        // same way `Task` does: spawn a sub-node on PreToolUse, collapse it on
        // PostToolUse — identical tool_input field names.
        hook_from_str(r#"{ "session_id": "b", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(
            r#"{ "session_id": "b", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "g1",
                 "tool_input": { "description": "map the bridge", "subagent_type": "Explore" } }"#,
        );
        let ss = load();
        let sub = find(&ss, "sub:g1").expect("the Agent sub-node is created");
        assert_eq!(sub.parent_session_id.as_deref(), Some("b"));
        assert_eq!(sub.kind.as_deref(), Some("subagent"));
        assert_eq!(sub.state, "working");
        assert_eq!(sub.title.as_deref(), Some("map the bridge"));
        assert_eq!(sub.agent, "Explore");
        assert_eq!(find(&ss, "b").unwrap().activity.as_deref(), Some("map the bridge"));
        hook_from_str(
            r#"{ "session_id": "b", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "g1" }"#,
        );
        assert!(
            find(&load(), "sub:g1").is_none(),
            "the sub-node is removed when its Agent dispatch returns"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn async_agent_dispatch_survives_launch_and_dies_on_subagent_stop() {
        // The live-captured async `Agent` lifecycle (the reason the earlier fix
        // did nothing on the box): PreToolUse spawns `sub:<tool_use_id>`, but the
        // Agent's PostToolUse fires ~4ms later at LAUNCH (isAsync), NOT at
        // completion — so it must NOT tear the node down. It re-keys the node to
        // `sub:<agentId>`, and only the much-later SubagentStop (agent_id only)
        // ends it.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("async-agent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionStart", "cwd": "/p" }"#);

        // 1) PreToolUse → the node is born under the tool_use_id.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "toolu_X",
                 "tool_input": { "description": "diagnostic probe", "subagent_type": "general-purpose" } }"#,
        );
        let sub = find(&load(), "sub:toolu_X").expect("PreToolUse spawns the node under tool_use_id");
        assert_eq!(sub.parent_session_id.as_deref(), Some("a"));
        assert_eq!(sub.title.as_deref(), Some("diagnostic probe"));

        // 2) SubagentStart (agent_id only, fires BEFORE PostToolUse) is enrich-only:
        // the re-key has not landed, so it is a harmless no-op — it must NOT create
        // a second, bare `sub:<agentId>` node.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStart",
                 "agent_id": "agentX", "agent_type": "general-purpose" }"#,
        );
        assert!(
            find(&load(), "sub:agentX").is_none(),
            "SubagentStart must not create a node before the re-key lands"
        );
        assert!(find(&load(), "sub:toolu_X").is_some(), "the original node still stands");

        // 3) PostToolUse (isAsync) re-keys in place: same node, new id, every field
        // preserved. It must NOT be removed (the ~4ms teardown bug).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "toolu_X",
                 "tool_response": { "isAsync": true, "status": "async_launched", "agentId": "agentX" } }"#,
        );
        let ss = load();
        assert!(
            find(&ss, "sub:toolu_X").is_none(),
            "the tool_use_id key is gone (renamed, not removed)"
        );
        let renamed = find(&ss, "sub:agentX").expect("the node is now reachable by agent_id");
        assert_eq!(renamed.parent_session_id.as_deref(), Some("a"), "parent preserved");
        assert_eq!(renamed.title.as_deref(), Some("diagnostic probe"), "title preserved");
        assert_eq!(renamed.kind.as_deref(), Some("subagent"), "kind preserved");
        assert_eq!(renamed.state, "working", "state preserved (NOT torn down)");

        // 4) A late SubagentStart on the re-keyed node just confirms it (no dup).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStart",
                 "agent_id": "agentX", "agent_type": "general-purpose" }"#,
        );
        assert_eq!(
            load().sessions.iter().filter(|s| s.session_id == "sub:agentX").count(),
            1,
            "the confirming SubagentStart never duplicates the node"
        );

        // 5) SubagentStop (agent_id only, the REAL completion) closes the node.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStop", "agent_id": "agentX" }"#,
        );
        assert!(
            find(&load(), "sub:agentX").is_none(),
            "SubagentStop ends the re-keyed node — the tree collapses at real completion"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn two_concurrent_async_agents_never_cross_attribute() {
        // Two Agent dispatches in ONE turn (parallel). They share a prompt_id, so
        // it is NOT a reliable correlator — the tool_use_id ↔ agent_id link is
        // established per-dispatch by each call's OWN PostToolUse. Prove each node
        // re-keys to its own agent_id with zero cross-contamination, and each
        // SubagentStop ends only its own node.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("async-concurrent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionStart", "cwd": "/p" }"#);

        // Both PreToolUse events (same prompt_id, distinct tool_use_ids).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidA", "prompt_id": "P",
                 "tool_input": { "description": "task A", "subagent_type": "Explore" } }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidB", "prompt_id": "P",
                 "tool_input": { "description": "task B", "subagent_type": "Plan" } }"#,
        );
        assert!(find(&load(), "sub:tuidA").is_some());
        assert!(find(&load(), "sub:tuidB").is_some());

        // Each PostToolUse pairs its OWN tool_use_id with its OWN agentId. Deliver
        // them interleaved with the SubagentStarts to stress the ordering.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStart",
                 "agent_id": "aidA", "agent_type": "Explore" }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidB",
                 "tool_response": { "isAsync": true, "agentId": "aidB" } }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidA",
                 "tool_response": { "isAsync": true, "agentId": "aidA" } }"#,
        );

        // Each node re-keyed to ITS OWN agent_id, carrying ITS OWN title — no swap.
        let ss = load();
        assert!(find(&ss, "sub:tuidA").is_none() && find(&ss, "sub:tuidB").is_none());
        let a = find(&ss, "sub:aidA").expect("dispatch A reachable by aidA");
        let b = find(&ss, "sub:aidB").expect("dispatch B reachable by aidB");
        assert_eq!(a.title.as_deref(), Some("task A"), "A kept its own title");
        assert_eq!(b.title.as_deref(), Some("task B"), "B kept its own title");
        assert_eq!(a.agent, "Explore");
        assert_eq!(b.agent, "Plan");

        // SubagentStop for A ends ONLY A; B survives until its own stop.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStop", "agent_id": "aidA" }"#,
        );
        let ss = load();
        assert!(find(&ss, "sub:aidA").is_none(), "A's stop removes A");
        assert!(find(&ss, "sub:aidB").is_some(), "B is untouched by A's stop");
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStop", "agent_id": "aidB" }"#,
        );
        assert!(find(&load(), "sub:aidB").is_none(), "B's stop removes B");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn kimi_hook_lifecycle_start_prompt_permission_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("kimi-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let live_state = || -> String {
            let s: SessionsFile = load_stage(&sessions_path()).unwrap();
            s.sessions[0].state.clone()
        };

        // SessionStart registers the session — agent recorded as kimi.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "SessionStart", "cwd": "/proj" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "kimi");
        assert_eq!(s.sessions[0].cwd, "/proj");
        assert_eq!(s.sessions[0].state, "idle");

        // UserPromptSubmit → working.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "UserPromptSubmit", "user_prompt": "do the thing" }"#,
        );
        assert_eq!(live_state(), "working");

        // PermissionRequest → awaiting (kimi's dedicated needs-input event).
        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "PermissionRequest" }"#);
        assert_eq!(live_state(), "awaiting");

        // Kimi-only observational events are ok no-ops that never move the phase.
        for evt in ["Interrupt", "PreCompact", "PostCompact", "PermissionResult", "StopFailure", "PostToolUseFailure"] {
            let out = hook_for_profile(
                kimi,
                &format!(r#"{{ "session_id": "k1", "hook_event_name": "{evt}" }}"#),
            );
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "event: {evt}");
            assert_eq!(out.data.unwrap()["action"], "none", "event: {evt}");
        }
        assert_eq!(live_state(), "awaiting", "observational events never move the phase");

        // A kimi Notification carries background-task status, NOT a permission
        // prompt — no vocab, no awaiting.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "Notification", "notification_type": "task.completed" }"#,
        );
        assert_eq!(out.data.unwrap()["action"], "none");
        assert_eq!(live_state(), "awaiting");

        // Stop settles the turn; SessionEnd ends the session.
        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_state(), "stopped");
        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "SessionEnd" }"#);
        assert_eq!(live_state(), "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn kimi_hook_normalizes_native_fields_and_drives_the_subagent_lifecycle() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("kimi-norm");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);

        // UserPromptSubmit with kimi's content-block ARRAY names the session
        // (set-once) and moves it to working.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "UserPromptSubmit",
                 "prompt": [{"type":"text","text":"fix the flaky auth test"}] }"#,
        );
        let s = load();
        assert_eq!(s.sessions[0].title.as_deref(), Some("fix the flaky auth test"));
        assert_eq!(s.sessions[0].state, "working");
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "UserPromptSubmit",
                 "prompt": [{"type":"text","text":"renamed? no"}] }"#,
        );
        assert_eq!(
            load().sessions[0].title.as_deref(),
            Some("fix the flaky auth test"),
            "set-once survives normalization"
        );

        // PreToolUse(Agent) with kimi's tool_call_id spawns the child node —
        // this is kimi's ONLY sub-spawn path (its SubagentStart carries no ids).
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "PreToolUse",
                 "tool_name": "Agent", "tool_call_id": "tool_VvbM0",
                 "tool_input": { "description": "probe the repo", "prompt": "…" } }"#,
        );
        let s = load();
        let sub = find(&s, "sub:tool_VvbM0").expect("PreToolUse(Agent) spawns sub:<tool_call_id>");
        assert_eq!(sub.title.as_deref(), Some("probe the repo"));

        // Kimi's SubagentStart (agent_name only, no tool/agent id) is an ok
        // no-op: it must neither error nor mint a second node.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "SubagentStart",
                 "agent_name": "coder", "prompt": "do the child thing" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.unwrap()["action"], "none");
        assert_eq!(
            load().sessions.iter().filter(|x| x.session_id.starts_with("sub:")).count(),
            1,
            "no id-less SubagentStart duplicate"
        );

        // PostToolUse(Agent) closes the node: kimi's Agent is SYNCHRONOUS
        // (status: completed in tool_output) and 0.31.1's SubagentStop is
        // unreliable/never fired — the tool boundary IS the close path.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "PostToolUse",
                 "tool_name": "Agent", "tool_call_id": "tool_VvbM0",
                 "tool_input": { "description": "probe the repo", "prompt": "…" },
                 "tool_output": "agent_id: agent-0\nstatus: completed\n\n[summary]\ndone" }"#,
        );
        assert!(find(&load(), "sub:tool_VvbM0").is_none(), "PostToolUse(Agent) closed the sub node");
        assert_eq!(load().sessions[0].state, "working", "the parent's turn runs on");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn pi_hook_lifecycle_start_prompt_tools_stop_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("pi-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let pi = agent_profile("pi").unwrap();
        let live_state = || -> String {
            let s: SessionsFile = load_stage(&sessions_path()).unwrap();
            s.sessions[0].state.clone()
        };

        // SessionStart registers the session — agent recorded as pi, idle.
        let out = hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "SessionStart", "cwd": "/proj" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "pi");
        assert_eq!(s.sessions[0].cwd, "/proj");
        assert_eq!(s.sessions[0].state, "idle");

        // UserPromptSubmit names the session (set-once) and → working.
        hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "UserPromptSubmit", "user_prompt": "do the thing" }"#,
        );
        assert_eq!(live_state(), "working");
        assert_eq!(
            load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions[0].title.as_deref(),
            Some("do the thing")
        );

        // PreToolUse sets the tool as activity; PostToolUse clears it — with
        // pi's empty subagent_tools, no sub-node is ever spawned.
        hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "PreToolUse", "tool_name": "bash", "tool_use_id": "call_1" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].activity.as_deref(), Some("bash"));
        assert_eq!(
            s.sessions.iter().filter(|x| x.session_id.starts_with("sub:")).count(),
            0,
            "pi never spawns sub-nodes"
        );
        assert_eq!(live_state(), "working");
        hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "PostToolUse", "tool_name": "bash", "tool_use_id": "call_1" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions[0].activity.is_none(), "activity cleared at the tool end");
        assert_eq!(live_state(), "working");

        // pi events with no pi vocabulary are ok no-ops (never an error).
        for evt in ["Notification", "SubagentStart", "SubagentStop", "PermissionRequest"] {
            let out = hook_for_profile(
                pi,
                &format!(r#"{{ "session_id": "p1", "hook_event_name": "{evt}" }}"#),
            );
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "event: {evt}");
            assert_eq!(out.data.unwrap()["action"], "none", "event: {evt}");
        }
        assert_eq!(live_state(), "working", "no-op events never move the phase");

        // Stop settles the turn; SessionEnd ends the session.
        hook_for_profile(pi, r#"{ "session_id": "p1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_state(), "stopped");
        hook_for_profile(pi, r#"{ "session_id": "p1", "hook_event_name": "SessionEnd" }"#);
        assert_eq!(live_state(), "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn hook_self_heals_a_pruned_session_on_its_next_event() {
        // The kimi regression: a live session got a SessionEnd payload (the
        // process never exited), was pruned as `done`, and no further event
        // could ever re-register it — SessionStart fires only at harness
        // launch. The door must treat the first event for an unknown id as an
        // implicit start.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("hook-heal");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let pay = |name: &str, extra: serde_json::Value| {
            let mut m = serde_json::Map::new();
            m.insert("hook_event_name".into(), name.into());
            m.insert("session_id".into(), "ghost-1".into());
            m.insert("cwd".into(), "/proj".into());
            for (k, v) in extra.as_object().unwrap() {
                m.insert(k.clone(), v.clone());
            }
            serde_json::Value::Object(m).to_string()
        };

        // SessionStart -> SessionEnd -> prune: the store record is GONE.
        hook_for_profile(kimi, &pay("SessionStart", json!({})));
        hook_for_profile(kimi, &pay("SessionEnd", json!({})));
        let mut f: SessionsFile = load_stage(&sessions_path()).unwrap();
        let mut h: HooksFile = load_stage(&hooks_path()).unwrap();
        let (kept, kept_h, _removed, _cleared) = prune_done(f.sessions, h.hooks);
        f.sessions = kept;
        h.hooks = kept_h;
        write_stage(&sessions_path(), &f).unwrap();
        write_stage(&hooks_path(), &h).unwrap();
        assert!(
            load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions.is_empty(),
            "precondition: the session record is gone"
        );

        // The next real event (a prompt) re-registers it, working + named.
        let out =
            hook_for_profile(kimi, &pay("UserPromptSubmit", json!({ "user_prompt": "revive" })));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "kimi");
        assert_eq!(s.sessions[0].state, "working");
        assert_eq!(s.sessions[0].title.as_deref(), Some("revive"));
        assert_eq!(s.sessions[0].cwd, "/proj");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn hook_end_for_an_unknown_session_stays_a_noop() {
        // SessionEnd must NOT create a session — ending something that never
        // existed is a no-op, not an implicit start.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("hook-end-noop");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let payload = json!({
            "hook_event_name": "SessionEnd",
            "session_id": "ghost-2",
            "cwd": "/proj",
        })
        .to_string();
        let out = hook_for_profile(kimi, &payload);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s.sessions.is_empty(),
            "SessionEnd for an unknown id never creates a session"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn hook_agent_flag_selects_the_profile_or_errors() {
        // No flag → the claude default.
        let inv = flag_invocation(&["graph", "session", "hook"], &[]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "claude");
        // --agent kimi → the kimi profile.
        let inv = flag_invocation(&["graph", "session", "hook"], &[("agent", "kimi")]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "kimi");
        // --agent pi → the pi profile.
        let inv = flag_invocation(&["graph", "session", "hook"], &[("agent", "pi")]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "pi");
        // --agent bogus → a structured error (exit 1, reason + the known list).
        let inv = flag_invocation(&["graph", "session", "hook"], &[("agent", "bogus")]);
        let out = match hook_profile_for(&inv) {
            Err(o) => o,
            Ok(p) => panic!("bogus agent resolved to {}", p.name),
        };
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        let data = out.data.unwrap();
        assert_eq!(data["reason"], "unknown-agent");
        assert_eq!(data["agent"], "bogus");
        assert_eq!(data["known"], json!(["claude", "kimi", "pi"]));
    }
}
