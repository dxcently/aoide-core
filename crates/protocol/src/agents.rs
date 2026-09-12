//! The agent-profile seam: every piece of agent-harness-specific knowledge
//! (hook event vocabulary, permission phrasing, sub-agent tool names, model
//! context ceilings, the on-disk transcript layout, the hook-settings file)
//! behind ONE lookup table, so a second harness lands as a new entry rather
//! than a scatter of conditionals. The table is open (`agent_profile` returns
//! `Option`); it holds `claude` (the first harness, moved here verbatim from
//! `conduct`'s hook door and transcript readers), `kimi`, `pi`, and
//! `eidolon` (a harness with no hook file at all — see [`EIDOLON_PROFILE`]'s
//! own doc for what that leaves absent).

use serde_json::Value;
use std::path::{Path, PathBuf};

/// The semantic class a hook event maps to — what the door's dispatch
/// actually collapses to, with the harness's event NAMES kept inside the
/// profile's `hook_event_map`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookClass {
    SessionStart,
    /// A new user prompt (claude: `UserPromptSubmit`).
    PromptSubmit,
    PreToolUse,
    PostToolUse,
    /// The turn ended (claude: `Stop`).
    Stop,
    /// A notification ping; its awaiting semantics are classified by a
    /// second `hook_event_map` query on the detail (see below).
    Notification,
    SubagentStart,
    SubagentStop,
    SessionEnd,
    /// Needs input NOW (a permission prompt) — an unconditional `awaiting`.
    Awaiting,
    /// Maybe needs input (an idle ping) — `awaiting` only when the turn is
    /// still mid-flight.
    AwaitingIfRunning,
    /// Unmapped: the door is a no-op for it.
    Unknown,
}

/// Locator + extractors for an agent's on-disk transcript (claude: the
/// per-session JSONL Claude Code writes under `~/.claude/projects/`).
pub struct TranscriptSpec {
    /// Resolve a session's transcript path: prefer the hook-supplied
    /// `transcript_path` hint when it names a real file, else derive the
    /// canonical location. None when neither resolves to an existing file.
    pub locate: fn(session_id: &str, cwd: Option<&str>, hinted: Option<&str>) -> Option<PathBuf>,
    /// Read the tail of the transcript as whole JSONL lines (a leading
    /// partial line dropped). Empty on any read error.
    pub tail: fn(path: &Path) -> Vec<String>,
    /// The agent's latest words off the tail lines. `skip_sidechain` is true
    /// for a top-level session's own transcript, false for a sub-agent's own
    /// (all-sidechain) file.
    pub say: fn(lines: &[String], skip_sidechain: bool) -> Option<String>,
    /// The agent's latest TOOL CALL off the tail lines, as a one-line label
    /// (`Bash: cargo test`) — see [`tool_label`]. Distinct from the hook-set
    /// `activity`: that is only ever the tool running RIGHT NOW and is cleared
    /// when the turn settles, while this is read from the transcript and so
    /// survives as "the last thing it did". `skip_sidechain` as `say`.
    pub tool: fn(lines: &[String], skip_sidechain: bool) -> Option<String>,
    /// The session's NAME (claude: the last `custom-title` record).
    pub title: fn(lines: &[String]) -> Option<String>,
    /// The session's currently-active model id (`skip_sidechain` as `say`).
    pub model: fn(lines: &[String], skip_sidechain: bool) -> Option<String>,
    /// The context-window fill at the last request.
    pub context_tokens: fn(lines: &[String]) -> Option<u64>,
    /// The directory of a session's sub-agent transcripts, if it exists.
    pub subagents_dir: fn(session_id: &str, cwd: Option<&str>) -> Option<PathBuf>,
    /// Find the sub-agent transcript in `dir` for a `sub:<tuid>` node key.
    pub find_subagent: fn(dir: &Path, tuid: &str) -> Option<PathBuf>,
}

/// The on-disk format of an agent's hook-settings file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsFormat {
    Json,
    Toml,
    /// The harness's hook wiring is a DECLARATIVE file, not a settings file
    /// the installer writes. pi's extension (`~/.pi/agent/extensions/`) is
    /// managed by the NixOS dendrite, so `hooks install` short-circuits with a
    /// clear message instead of writing a file the harness never reads.
    Declarative,
}

/// The keystrokes that answer a harness's INTERACTIVE permission prompt, for
/// the one consumer that needs them: the herald's permission summons
/// (`aoide graph permit`), which types the human's verdict back into the
/// conducted session's pty.
///
/// These are the prompt's own hotkeys, verified by READING the live prompt on
/// screen — never guessed. Claude Code renders a numbered select
/// (`❯ 1. Yes / 2. Yes, allow all … / 3. No`), so its answers are the bare
/// digits `1` and `3` and no Enter is needed.
///
/// Deliberately printable digits rather than control keys: if the summons is
/// answered a moment after the prompt already resolved elsewhere, a stray
/// digit lands harmlessly (and visibly) in the composer, where an Escape
/// would have interrupted a live turn.
pub struct PermissionKeys {
    pub approve: &'static str,
    pub deny: &'static str,
}

/// Where an agent's hook settings live (a later installer command writes them;
/// today this is declarative only).
pub struct SettingsSpec {
    /// Path relative to `$HOME` (claude: `.claude/settings.json`).
    pub relative_path: &'static str,
    pub format: SettingsFormat,
}

/// One agent harness's whole profile — the seam every agent-aware consumer
/// dispatches through.
pub struct AgentProfile {
    pub name: &'static str,
    /// Map a hook event name to its semantic class. Also classifies a
    /// Notification's detail when queried with a prefixed key, so the three
    /// input kinds can never cross-classify:
    /// `ntype:<raw notification_type>` (exact) → `Awaiting`/`AwaitingIfRunning`;
    /// `msg:<lowercased message>` (substring, the brittle English fallback for
    /// older payloads) → `Awaiting`/`AwaitingIfRunning`. Anything else →
    /// `Unknown`.
    pub hook_event_map: fn(&str) -> HookClass,
    /// Message substrings (matched against the lowercased notification
    /// `message`) that force `awaiting` unconditionally.
    pub permission_vocab: &'static [&'static str],
    /// Tool names that dispatch a sub-agent (spawn/manage a child node).
    pub subagent_tools: &'static [&'static str],
    /// How to answer this harness's interactive permission prompt from the
    /// herald summons, or `None` when its prompt shape has not been verified
    /// on a live screen — in which case `graph permit` refuses to raise a
    /// summons at all rather than typing a guess into someone's session.
    pub permission_keys: Option<PermissionKeys>,
    /// The keystroke that SUBMITS a composed line in this harness's own
    /// input — what `graph send --submit` appends to the payload after the
    /// text, resolved per-target from the DELIVERED session's own agent
    /// profile (never a fixed byte at the call site). Every registered
    /// profile names one; there is no absent case, only the unregistered-
    /// agent fallback to claude's `\n` every other profile lookup already
    /// takes.
    pub submit_key: &'static str,
    /// Normalize a raw hook payload onto the canonical field names the hook
    /// door reads (`user_prompt`, `tool_use_id`, `agent_type`, …), in place,
    /// before `map_hook` runs. Identity for a harness whose payloads already
    /// speak the contract (pi, via its own extension).
    pub normalize_payload: fn(&mut Value),
    /// The context-window ceiling for a model id (see `model.rs`).
    pub model_ceiling: fn(Option<&str>) -> u64,
    pub transcript: TranscriptSpec,
    pub hook_settings: SettingsSpec,
    /// Where this harness discovers installable skills — a directory of
    /// `<skill-name>/SKILL.md` packages — relative to `$HOME` (claude:
    /// `.claude/skills`). `None` for a harness with no skills-directory
    /// concept (or none verified): `hooks install` then skips its skill
    /// link with a taught message instead of guessing a path.
    pub skills_dir: Option<&'static str>,
    /// argv that launches this harness fresh (claude: `&["claude"]`) — the
    /// program name plus any args every invocation needs, BEFORE a caller's
    /// own extra args (e.g. `--resume` or a task prompt) are appended.
    pub launch: &'static [&'static str],
    /// argv that resumes a prior session of this harness by ITS OWN id
    /// (claude: `["claude", "--resume", <id>]`). `None` means the harness's
    /// resume flag has not been verified against real CLI/extension
    /// material — never a guessed flag — so `graph resurrect` (P-D8) skips
    /// it with a taught message rather than typing a wrong invocation.
    pub resume_args: Option<fn(harness_session_id: &str) -> Vec<String>>,
    /// argv that delivers a message to a live session of this harness
    /// WITHOUT going through its pty composer at all — for a harness whose
    /// own native inter-session transport exists (eidolon: `eidolon send`).
    /// Shaped like [`resume_args`] but for a different id space: `to` names
    /// the RECIPIENT (not necessarily the caller's own session), and the
    /// returned argv is everything AFTER the executable — the caller
    /// resolves which literal binary is "this harness" itself (e.g. via
    /// `/proc/<pid>/exe` — PATH does not name a stable program for every
    /// harness). `None` for every harness with no such transport: its only
    /// input surface is the pty composer a keystroke path already reaches.
    /// Two contract halves a caller MUST honour, named here because both are
    /// easy to get wrong from the argv shape alone:
    /// - the message TEXT is never an argv word — the caller writes it to
    ///   the spawned child's STDIN instead (see [`eidolon_native_send`]'s
    ///   own doc for why: the child re-joins multiple text args with
    ///   spaces, silently losing newlines);
    /// - the child's exit 0 means the message was ACCEPTED (queued or
    ///   delivered), never that the recipient has processed or even seen
    ///   it — there is no synchronous "consumed" signal on this transport.
    pub native_send: Option<fn(to: &str) -> Vec<String>>,
}

// ── claude ──────────────────────────────────────────────────────────────────

/// Claude Code's hook event map (event names confirmed present in the CLI).
/// The notification detail keys: the structured `notification_type`
/// (`permission_prompt` / `idle_prompt`) and, for older payloads, the brittle
/// English `message` — the permission tier wins inside one string, matching
/// the door's precedence.
fn claude_hook_event(name: &str) -> HookClass {
    match name {
        "SessionStart" => HookClass::SessionStart,
        "UserPromptSubmit" => HookClass::PromptSubmit,
        "PreToolUse" => HookClass::PreToolUse,
        "PostToolUse" => HookClass::PostToolUse,
        "Stop" => HookClass::Stop,
        "Notification" => HookClass::Notification,
        "SubagentStart" => HookClass::SubagentStart,
        "SubagentStop" => HookClass::SubagentStop,
        "SessionEnd" => HookClass::SessionEnd,
        // The structured `notification_type` detail.
        "ntype:permission_prompt" => HookClass::Awaiting,
        "ntype:idle_prompt" => HookClass::AwaitingIfRunning,
        // The lowercased `message` fallback: a permission phrase is an
        // unambiguous mid-turn blocker; the ~60s "waiting for your input"
        // idle ping is ambiguous (conditional).
        other => match other.strip_prefix("msg:") {
            Some(msg) if CLAUDE_PROFILE.permission_vocab.iter().any(|t| msg.contains(t)) => {
                HookClass::Awaiting
            }
            Some(msg) if msg.contains("waiting for your input") => HookClass::AwaitingIfRunning,
            _ => HookClass::Unknown,
        },
    }
}

// Claude Code writes a per-session JSONL transcript at
// `~/.claude/projects/<munge(cwd)>/<session_id>.jsonl` (also handed to every
// hook as `transcript_path`). It is clean, structured, on-disk, and updated
// live by claude itself — a far better "agent output" source than scraping
// conduct's PTY (which for a live `claude` is the rendered TUI). The bridge
// tail-reads it at hook boundaries to publish `say` (distinct from
// `activity` = current tool).

/// Munge a cwd into Claude Code's project-dir name: every `/` and `.` → `-`
/// (`/home/khoa/Aoide` → `-home-khoa-Aoide`). Mirrors the CLI's on-disk layout
/// so the bridge can locate a transcript from data it already holds.
fn munge_project_dir(cwd: &str) -> String {
    cwd.chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

/// Resolve a session's transcript path: prefer the hook-supplied
/// `transcript_path` when it names a real file, else derive the canonical
/// `$HOME/.claude/projects/<munge(cwd)>/<session_id>.jsonl`. None when neither
/// resolves to an existing file.
fn transcript_path_for(
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
    let projects = PathBuf::from(home).join(".claude/projects");
    let file = format!("{session_id}.jsonl");
    if let Some(cwd) = cwd.filter(|s| !s.is_empty()) {
        let p = projects.join(munge_project_dir(cwd)).join(&file);
        if p.is_file() {
            return Some(p);
        }
    }
    // The cwd derivation MISSES whenever the session has moved: Claude Code
    // fixes its project bucket at launch, while the roster's `cwd` tracks the
    // session's current directory — a session launched in `~/Aoide` but working
    // in `~/Aoide/pkgs/aoide` derives a bucket that does not exist. The hook
    // path never noticed (its payload carries `transcript_path`); the reaper's
    // refresh, which has no hint, saw every such session as transcript-less and
    // silently skipped it. So: fall back to asking each project bucket whether
    // it holds this session id. A direct `is_file` per bucket — one readdir of
    // `projects/` and a handful of stats, no directory contents walked.
    for e in std::fs::read_dir(&projects).ok()?.flatten() {
        let p = e.path().join(&file);
        if p.is_file() {
            return Some(p);
        }
    }
    None
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
/// partial line dropped). Empty on any read error. Transcripts grow unbounded,
/// so only the tail is scanned — enough for the freshest `say` +
/// `custom-title`.
fn transcript_tail(path: &Path) -> Vec<String> {
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
/// tail, cleaned to a single line (≤160 chars). None when there is no such
/// text.
///
/// `skip_sidechain`: a top-level session's own transcript never actually
/// embeds sidechain lines inline (ground-truthed: a Task's turns live in a
/// wholly separate `subagents/agent-<id>.jsonl` file, never inline in the
/// parent), so this is defensive/forward-compat there — pass `true`. A
/// sub-agent's OWN dedicated transcript file, by contrast, marks EVERY line
/// `isSidechain:true` (it's sidechain from the top file's perspective) — pass
/// `false` there, or every line would be skipped and `say` would always be
/// `None`.
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

/// One line of tool call: the tool's NAME, plus the first argument that says
/// WHAT it is acting on (`Bash: cargo test --workspace`, `Edit: reap.rs`).
///
/// Harness-neutral on purpose — claude's `tool_use`, pi's `toolCall` and kimi's
/// `tool.call` carry different envelopes but the same two facts, so all three
/// extractors funnel through here and a card reads identically whichever agent
/// filled it. An unrecognised argument shape degrades to the bare name rather
/// than to nothing: the tool that ran is worth showing even when its subject
/// isn't legible.
fn tool_label(name: &str, args: Option<&Value>) -> Option<String> {
    const TOOL_MAX: usize = 120;
    /// Argument keys that name a tool's SUBJECT, most specific first. Every
    /// harness's file/search/shell tools use one of these.
    const SUBJECT_KEYS: [&str; 8] = [
        "command",
        "file_path",
        "path",
        "pattern",
        "query",
        "url",
        "description",
        "prompt",
    ];
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let subject = args
        .and_then(|a| {
            SUBJECT_KEYS
                .iter()
                .find_map(|k| a.get(*k).and_then(Value::as_str))
        })
        .map(str::trim)
        .filter(|s| !s.is_empty());
    Some(match subject {
        Some(s) => one_line_clip(&format!("{name}: {s}"), TOOL_MAX),
        None => one_line_clip(name, TOOL_MAX),
    })
}

/// The agent's latest tool call: the last `tool_use` block of the freshest
/// matching `type:"assistant"` line in the tail. `skip_sidechain` mirrors
/// [`extract_say`]. None when the tail holds no tool call — a session that has
/// only talked shows no tool row rather than a stale one.
fn extract_tool(lines: &[String], skip_sidechain: bool) -> Option<String> {
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
        for block in content.iter().rev() {
            if block.get("type").and_then(Value::as_str) != Some("tool_use") {
                continue;
            }
            let Some(name) = block.get("name").and_then(Value::as_str) else {
                continue;
            };
            if let Some(label) = tool_label(name, block.get("input")) {
                found = Some(label);
                break;
            }
        }
    }
    found
}

/// The session's NAME: the last `custom-title` record's `customTitle` in the
/// tail (Claude Code's own session title, e.g. "Aoide Dev"). None when never
/// titled.
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
/// tail holds no assistant turn yet. Sits at the same nesting level as the
/// text blocks `extract_say` reads, so it shares the one tail scan.
/// `skip_sidechain` mirrors `extract_say`: `true` for a top-level session's
/// own transcript, `false` for a sub-agent's own (all-sidechain) transcript
/// file.
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
fn find_subagent_transcript(dir: &Path, tuid: &str) -> Option<PathBuf> {
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

/// Identity normalizer for a harness whose payloads already speak the
/// canonical field names — currently just pi (see [`PI_PROFILE`]'s doc).
fn normalize_identity(_: &mut Value) {}

/// Normalize a claude hook payload onto the canonical (aoide-internal) field
/// name, in place. Copy-only, same shape as [`kimi_normalize_payload`] below.
/// Ground-truthed against the installed Claude Code binary's own
/// hook-payload-construction JS: `UserPromptSubmit` sends the prompt text as
/// `prompt` (a plain string) — NOT `user_prompt`, despite `user_prompt` being
/// this door's own canonical/internal name for it (the name `map_hook` reads
/// downstream). Gated to `UserPromptSubmit` so a same-named `prompt` field
/// possibly carried by some other event never misreads as a turn-naming
/// user prompt (mirrors kimi's own guard against the same hazard, there done
/// by content-shape instead of by event).
fn claude_normalize_payload(p: &mut Value) {
    let Some(obj) = p.as_object_mut() else {
        return;
    };
    if obj.get("hook_event_name").and_then(Value::as_str) != Some("UserPromptSubmit") {
        return;
    }
    if !obj.contains_key("user_prompt") {
        let text = obj.get("prompt").and_then(Value::as_str).map(str::to_string);
        if let Some(text) = text.filter(|t| !t.trim().is_empty()) {
            obj.insert("user_prompt".to_string(), Value::String(text));
        }
    }
}

/// The Claude Code profile — every claude-specific fact the bridge knows,
/// in one place.
pub static CLAUDE_PROFILE: AgentProfile = AgentProfile {
    name: "claude",
    hook_event_map: claude_hook_event,
    permission_vocab: &["permission"],
    // Claude Code's classic dispatch tool is `Task`; this harness's own tool
    // is named `Agent` instead — both spawn/manage a background sub-agent the
    // same way from the hook's point of view, so both gate sub-agent node
    // creation/teardown identically.
    subagent_tools: &["Task", "Agent"],
    // Read off the live prompt: "❯ 1. Yes / 2. Yes, allow all edits during
    // this session / 3. No". Option 2 is deliberately NOT the approve key —
    // a summons approves THIS request, never the rest of the session.
    permission_keys: Some(PermissionKeys {
        approve: "1",
        deny: "3",
    }),
    // A terminal's Enter key sends CR (`\r`); Claude Code binds LF (ctrl-J /
    // shift-enter) to "insert newline" in the composer, not submit. Observed
    // on the installed Claude Code 2.1.263 on two independent hosts: root's
    // Osaka fixture and the yomi doorbell rig both found a bare `\n` only
    // inserts a newline, leaving the turn unsubmitted until a bare `\r`
    // follows.
    submit_key: "\r",
    normalize_payload: claude_normalize_payload,
    model_ceiling: crate::model::context_ceiling_for_model,
    transcript: TranscriptSpec {
        locate: transcript_path_for,
        tail: transcript_tail,
        say: extract_say,
        tool: extract_tool,
        title: extract_custom_title,
        model: extract_model,
        context_tokens: transcript_context_tokens,
        subagents_dir,
        find_subagent: find_subagent_transcript,
    },
    hook_settings: SettingsSpec {
        relative_path: ".claude/settings.json",
        format: SettingsFormat::Json,
    },
    // Claude Code loads personal skills from `~/.claude/skills/<name>/SKILL.md`.
    skills_dir: Some(".claude/skills"),
    launch: &["claude"],
    // `claude --resume <id>` is documented/well-known CLI behaviour, named
    // verbatim in this field's own doc comment in `docs/architecture/
    // AOIDED.md`'s L5 section — the design authority for this table, not a
    // guess made here.
    resume_args: Some(claude_resume_args),
    // Claude Code's only input surface is the pty composer every existing
    // keystroke path already reaches — no separate native transport.
    native_send: None,
};

/// `claude --resume <harness_session_id>` — resume a prior claude session by
/// its own id.
fn claude_resume_args(harness_session_id: &str) -> Vec<String> {
    vec![
        "claude".to_string(),
        "--resume".to_string(),
        harness_session_id.to_string(),
    ]
}

// ── kimi ────────────────────────────────────────────────────────────────────

/// Kimi Code's hook event map (same stdin-JSON transport and base fields as
/// claude's). The core events are 1:1 with claude's semantics; kimi signals
/// needs-input with a DEDICATED `PermissionRequest` event, so there is no
/// notification_type/message vocabulary to classify (a kimi `Notification`
/// carries background-task status, never a permission prompt — its detail
/// queries fall through to `Unknown`, and `permission_vocab` is empty).
///
/// Kimi-only observational events (`PermissionResult`, `PreCompact`,
/// `PostCompact`, `StopFailure`, `PostToolUseFailure`) map to `Unknown` — an
/// ok no-op, never an error. So does `Interrupt`: kimi's `Stop` does NOT fire
/// on Esc, so an interrupted turn leaves the session looking `working` until
/// the next hook — flagged here, deliberately not yet handled.
fn kimi_hook_event(name: &str) -> HookClass {
    match name {
        "SessionStart" => HookClass::SessionStart,
        "UserPromptSubmit" => HookClass::PromptSubmit,
        "PreToolUse" => HookClass::PreToolUse,
        "PostToolUse" => HookClass::PostToolUse,
        "Stop" => HookClass::Stop,
        "Notification" => HookClass::Notification,
        "SubagentStart" => HookClass::SubagentStart,
        "SubagentStop" => HookClass::SubagentStop,
        "SessionEnd" => HookClass::SessionEnd,
        // THE awaiting signal: fired just before waiting for user approval.
        "PermissionRequest" => HookClass::Awaiting,
        _ => HookClass::Unknown,
    }
}

/// The context-window ceiling, in tokens, for a kimi model id — the same
/// publish-on-the-record discipline as claude's (`model.rs`). `k3` is natively
/// 1M-context (`k3` exact, or `k3-1m`-style variants); the 256k tiers are
/// `k3-256k`, `kimi-for-coding`, and `kimi-for-coding-highspeed`. On-disk ids
/// arrive PROVIDER-PREFIXED (`kimi-code/kimi-for-coding` — the wire's
/// `usage.record.model` / `llm.request.modelAlias`), so the match runs on the
/// basename after the last `/`. An absent or unrecognised id takes the
/// conservative 200k default.
fn kimi_context_ceiling(model: Option<&str>) -> u64 {
    const K200: u64 = 200_000;
    const K256: u64 = 256_000;
    const M1: u64 = 1_000_000;
    let Some(raw) = model else { return K200 };
    let id = raw.rsplit('/').next().unwrap_or(raw).to_ascii_lowercase();
    if id == "k3" || id.starts_with("k3-1m") {
        M1
    } else if matches!(
        id.as_str(),
        "k3-256k" | "kimi-for-coding" | "kimi-for-coding-highspeed"
    ) {
        K256
    } else {
        K200
    }
}

/// Normalize a kimi hook payload onto the canonical (claude-contract) field
/// names, in place. Copy-only — the kimi-native fields are left intact.
/// Ground-truthed against captured 0.31.1 payloads:
/// - `UserPromptSubmit.prompt` is an ARRAY of content blocks → join its text
///   blocks into the contract's `user_prompt` string (session naming).
/// - Tool events carry `tool_call_id` → the contract's `tool_use_id` (the
///   sub-agent spawn/close bookkeeping keys on it).
/// - `SubagentStart`/`SubagentStop` name the child `agent_name` → the
///   contract's `agent_type`. (0.31.1 carries NO tool/agent id on these
///   events, so the door's ensure/stop arms stay no-ops for kimi: the
///   PreToolUse(Agent) spawn and the synchronous PostToolUse(Agent) close are
///   kimi's real sub-agent path — its Agent tool returns `status: completed`
///   in `tool_output`, and SubagentStop is unreliable/never fired.)
fn kimi_normalize_payload(p: &mut Value) {
    let Some(obj) = p.as_object_mut() else {
        return;
    };
    if !obj.contains_key("user_prompt") {
        let joined = obj.get("prompt").and_then(Value::as_array).map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        });
        if let Some(text) = joined.filter(|t| !t.trim().is_empty()) {
            obj.insert("user_prompt".to_string(), Value::String(text));
        }
    }
    if !obj.contains_key("tool_use_id") {
        let id = obj
            .get("tool_call_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(id) = id {
            obj.insert("tool_use_id".to_string(), Value::String(id));
        }
    }
    if !obj.contains_key("agent_type") {
        let name = obj
            .get("agent_name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(name) = name {
            obj.insert("agent_type".to_string(), Value::String(name));
        }
    }
}

// ── kimi transcript layout ───────────────────────────────────────────────────
//
// Kimi Code writes a per-session DIRECTORY at
// `<kimi-home>/sessions/wd_<dirname>_<hash>/<session_id>/` (`<kimi-home>` =
// $KIMI_CODE_HOME, default `~/.kimi-code`):
//   state.json                 — {"title","isCustomTitle","workDir","agents":{…}}
//   agents/main/wire.jsonl     — the main agent's typed event log (transcript)
//   agents/agent-<N>/wire.jsonl — each sub-agent's own log
// The `wd_` hash algorithm is opaque — the locator globs `*/<session_id>`
// under the sessions root instead (few dirs, cheap). Ground-truthed record
// types: `turn.prompt` (user prompt), `context.append_loop_event` with
// `event.type:"content.part"` (the assistant's think/text stream),
// `usage.record` (per-turn model + token counts), `llm.request`
// (model/modelAlias), `config.update`.

/// The kimi sessions root: `$KIMI_CODE_HOME/sessions` when set, else
/// `~/.kimi-code/sessions`.
fn kimi_sessions_root() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("KIMI_CODE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(home).join("sessions"));
    }
    Some(PathBuf::from(std::env::var_os("HOME")?).join(".kimi-code/sessions"))
}

/// Resolve a session's directory: the `<session_id>` child of any `wd_*`
/// bucket under the sessions root.
fn kimi_session_dir(session_id: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(kimi_sessions_root()?).ok()?.flatten() {
        let cand = e.path().join(session_id);
        if cand.is_dir() {
            return Some(cand);
        }
    }
    None
}

/// Resolve a session's transcript: prefer the hook-supplied hint when it
/// names a real file (parity with claude — kimi 0.31.1 hooks carry no
/// `transcript_path`, so this is defensive), else the globbed
/// `<session>/agents/main/wire.jsonl`. `cwd` is unused: the `wd_` bucket hash
/// is opaque, so the glob — not a path derivation — does the locating.
fn kimi_transcript_locate(
    session_id: &str,
    _: Option<&str>,
    hinted: Option<&str>,
) -> Option<PathBuf> {
    if let Some(h) = hinted.filter(|s| !s.is_empty()) {
        let p = PathBuf::from(h);
        if p.is_file() {
            return Some(p);
        }
    }
    let p = kimi_session_dir(session_id)?.join("agents/main/wire.jsonl");
    p.is_file().then_some(p)
}

/// Kimi's tail: the generic 32 KiB tail of `wire.jsonl` (shared with claude),
/// PLUS the session's `state.json` minified and appended as a final "line" —
/// the spec's `title` extractor takes only tail lines, but kimi's custom
/// title lives in state.json BESIDE the wire log, never inside it.
fn kimi_wire_tail(path: &Path) -> Vec<String> {
    let mut lines = transcript_tail(path);
    // <session>/agents/<name>/wire.jsonl → <session>/state.json
    let state = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|session_dir| session_dir.join("state.json"));
    if let Some(sp) = state {
        if let Ok(txt) = std::fs::read_to_string(sp) {
            if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                lines.push(v.to_string());
            }
        }
    }
    lines
}

/// The agent's latest words off a `wire.jsonl` tail: the last
/// `context.append_loop_event` whose event is a `content.part` of type `text`
/// (the assistant's prose stream; `think` parts are chain-of-thought, not
/// words). `skip_sidechain` is a claude-ism — kimi sub-agents live in their
/// own `agents/agent-<N>/` files, never inline — so it is accepted and
/// ignored.
fn kimi_extract_say(lines: &[String], _: bool) -> Option<String> {
    const SAY_MAX: usize = 160;
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("context.append_loop_event") {
            continue;
        }
        let Some(part) = v.get("event").and_then(|e| e.get("part")) else {
            continue;
        };
        if part.get("type").and_then(Value::as_str) != Some("text") {
            continue;
        }
        if let Some(t) = part.get("text").and_then(Value::as_str) {
            let t = t.trim();
            if !t.is_empty() {
                found = Some(one_line_clip(t, SAY_MAX));
            }
        }
    }
    found
}

/// The agent's latest tool call off a `wire.jsonl` tail: the last
/// `context.append_loop_event` whose event is a `tool.call` — its `name` plus
/// its `args` (the same object kimi's own `display` renders from).
/// `skip_sidechain` is a claude-ism, accepted and ignored (as `kimi_extract_say`).
fn kimi_extract_tool(lines: &[String], _: bool) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("context.append_loop_event") {
            continue;
        }
        let Some(event) = v.get("event") else {
            continue;
        };
        if event.get("type").and_then(Value::as_str) != Some("tool.call") {
            continue;
        }
        let Some(name) = event.get("name").and_then(Value::as_str) else {
            continue;
        };
        if let Some(label) = tool_label(name, event.get("args")) {
            found = Some(label);
        }
    }
    found
}

/// The session's NAME: kimi's `state.json` `title`, ONLY when `isCustomTitle`
/// is true (a derived placeholder is not a name — mirrors claude's
/// custom-title semantics). Reaches here as the minified state line
/// `kimi_wire_tail` appends; None when never custom-titled.
fn kimi_extract_title(lines: &[String]) -> Option<String> {
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("isCustomTitle").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if let Some(t) = v.get("title").and_then(Value::as_str) {
            let t = t.trim();
            if !t.is_empty() {
                return Some(one_line_clip(t, 48));
            }
        }
    }
    None
}

/// The session's active model: the freshest `usage.record.model` or
/// `llm.request.modelAlias` in the tail (both are written per turn; last
/// wins). `skip_sidechain` ignored, as `kimi_extract_say`.
fn kimi_extract_model(lines: &[String], _: bool) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let m = match v.get("type").and_then(Value::as_str) {
            Some("usage.record") => v.get("model"),
            Some("llm.request") => v.get("modelAlias"),
            _ => None,
        };
        if let Some(m) = m.and_then(Value::as_str) {
            let m = m.trim();
            if !m.is_empty() {
                found = Some(m.to_string());
            }
        }
    }
    found
}

/// The context-window fill at the last turn: the freshest `usage.record`'s
/// input side — `inputOther + inputCacheRead + inputCacheCreation` (mirrors
/// claude's input + cache fields; `output` is what the turn produced, not
/// what sat in the window).
fn kimi_context_tokens(lines: &[String]) -> Option<u64> {
    let mut found: Option<u64> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("usage.record") {
            continue;
        }
        let Some(u) = v.get("usage") else {
            continue;
        };
        let sum = ["inputOther", "inputCacheRead", "inputCacheCreation"]
            .iter()
            .map(|k| u.get(k).and_then(Value::as_u64).unwrap_or(0))
            .sum();
        found = Some(sum);
    }
    found
}

/// The directory of a session's agent logs (`agents/`, holding `main/` and
/// one `agent-<N>/` per sub-agent), if the session resolves on disk.
fn kimi_subagents_dir(session_id: &str, _: Option<&str>) -> Option<PathBuf> {
    let dir = kimi_session_dir(session_id)?.join("agents");
    dir.is_dir().then_some(dir)
}

/// Find a sub-agent's `wire.jsonl` for a `sub:<tuid>` node key. Kimi 0.31.1
/// writes NO on-disk correlator between a hook's `tool_call_id` and its
/// `agent-<N>` dir (state.json's agents map carries only
/// homedir/type/parentAgentId), so only the direct `agent-<tuid>/wire.jsonl`
/// path resolves — forwards-compat should a future version key dirs by call
/// id; anything else is None (a kimi sub-node simply has no transcript probe,
/// like a claude sub-agent whose file is absent).
fn kimi_find_subagent(dir: &Path, tuid: &str) -> Option<PathBuf> {
    let p = dir.join(format!("agent-{tuid}")).join("wire.jsonl");
    p.is_file().then_some(p)
}

/// The Kimi Code profile.
pub static KIMI_PROFILE: AgentProfile = AgentProfile {
    name: "kimi",
    hook_event_map: kimi_hook_event,
    // Kimi signals awaiting via the dedicated `PermissionRequest` event, so
    // there is no message-substring vocabulary (the Notification detail
    // queries never match).
    permission_vocab: &[],
    // Kimi's dispatch tool IS `Agent` — confirmed in captured 0.31.1 hook
    // payloads (`tool_name:"Agent"`); this harness has no `Task` alias.
    subagent_tools: &["Agent"],
    // Read off the live prompt (2026-08-20 probe, headless conducted kimi,
    // pty log at a real shell-permission prompt): "▶ Run this command? / ...
    // / ▶ 1. Approve once / 2. Approve for this session / 3. Reject /
    // 4. Reject with feedback / ↑/↓ select · 1/2/3/4 choose · ↵ confirm".
    // Injecting the single byte "1" (no trailing \r) fired approval
    // immediately and the command executed — the digit alone chooses AND
    // confirms, no trailing submit byte needed (same as claude's digits).
    // Option 2 is deliberately NOT the approve key — it is the
    // session-wide allow-all, and a summons approves THIS request only.
    // Option 4 is reject-with-feedback, not the bare deny.
    permission_keys: Some(PermissionKeys {
        approve: "1",
        deny: "3",
    }),
    // Kimi's TUI submits a composed line on `\r`, NOT `\n` — read off the
    // live screen (Conductor-Channel.md's `graph send` entry): against a
    // kimi target, a plain `\n` types the line without submitting it.
    submit_key: "\r",
    normalize_payload: kimi_normalize_payload,
    model_ceiling: kimi_context_ceiling,
    transcript: TranscriptSpec {
        locate: kimi_transcript_locate,
        tail: kimi_wire_tail,
        say: kimi_extract_say,
        tool: kimi_extract_tool,
        title: kimi_extract_title,
        model: kimi_extract_model,
        context_tokens: kimi_context_tokens,
        subagents_dir: kimi_subagents_dir,
        find_subagent: kimi_find_subagent,
    },
    hook_settings: SettingsSpec {
        relative_path: ".kimi-code/config.toml",
        format: SettingsFormat::Toml,
    },
    // No skills-directory concept verified for Kimi Code — never a guessed
    // path; `hooks install` skips the skill link with a taught message.
    skills_dir: None,
    launch: &["kimi"],
    // Verified 2026-08-25 against the real installed `kimi` binary — the
    // exact 0.31.1 build `pkgs/kimi-code/default.nix` pins (`kimi --version`
    // matches the pinned version byte for byte) — via `kimi --help`:
    // `-S, --session [id]  Resume a session. With ID: resume that session.
    // Without ID: interactively pick.` Passing an id resumes THAT session
    // (not a guess — the flag's own help text names the id-resume case
    // explicitly, and the id kimi expects is the same `<session_id>` this
    // profile's transcript locator already keys `kimi_session_dir` on).
    resume_args: Some(kimi_resume_args),
    // Kimi's only input surface is the pty composer every existing
    // keystroke path already reaches — no separate native transport.
    native_send: None,
};

/// `kimi --session <harness_session_id>` — resume a prior kimi session by
/// its own id (see [`KIMI_PROFILE`]'s doc comment for the verification).
fn kimi_resume_args(harness_session_id: &str) -> Vec<String> {
    vec![
        "kimi".to_string(),
        "--session".to_string(),
        harness_session_id.to_string(),
    ]
}

// ── pi ─────────────────────────────────────────────────────────────────────

/// The Pi hook event map — exactly the events the aoide-pi-session extension
/// emits (SessionStart/UserPromptSubmit/PreToolUse/PostToolUse/Stop/SessionEnd,
/// canonical claude-shaped payloads). pi has no notification or sub-agent
/// vocabulary visible to its extension API, so those classes never arise and
/// every other name is an ok no-op.
fn pi_hook_event(name: &str) -> HookClass {
    match name {
        "SessionStart" => HookClass::SessionStart,
        "UserPromptSubmit" => HookClass::PromptSubmit,
        "PreToolUse" => HookClass::PreToolUse,
        "PostToolUse" => HookClass::PostToolUse,
        "Stop" => HookClass::Stop,
        "SessionEnd" => HookClass::SessionEnd,
        _ => HookClass::Unknown,
    }
}

// ── pi transcript layout ────────────────────────────────────────────────────
//
// pi writes one JSONL per session at
// `~/.pi/agent/sessions/--<bucket(cwd)>--/<ISO-timestamp>_<session-uuid>.jsonl`
// (or under the session root pi itself resolves — precedence: `--session-dir`
// flag, `$PI_CODING_AGENT_SESSION_DIR`, then settings.json's `sessionDir`;
// the locator honors only the env var, so a sessionDir-only config is a known
// miss class). The uuid in the filename IS the session id (the file's header
// `id` field).
// Ground-truthed record types: `session` (header: id/cwd), `model_change`
// (provider/modelId — the active model), `message` (user/assistant/toolResult;
// an assistant message carries `provider` + `model` + `usage`), `session_info`
// (name — pi's /rename), `thinking_level_change`.

/// The pi sessions root: `$PI_CODING_AGENT_SESSION_DIR` when set, else
/// `~/.pi/agent/sessions`.
fn pi_sessions_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("PI_CODING_AGENT_SESSION_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    Some(PathBuf::from(std::env::var_os("HOME")?).join(".pi/agent/sessions"))
}

/// pi's own cwd bucket derivation (session-manager.js: strip a single leading
/// `/` (or `\`), map `/`, `\`, `:` to `-` — dots and everything else
/// preserved — then wrap in `--…--`). `/home/khoa/Aoide` →
/// `--home-khoa-Aoide--`; `/home/khoa/.dotfiles` → `--home-khoa-.dotfiles--`.
/// The claude munge is deliberately NOT reused: it also maps dots, which pi
/// does not.
fn pi_bucket(cwd: &str) -> String {
    let stripped = cwd
        .strip_prefix('/')
        .or_else(|| cwd.strip_prefix('\\'))
        .unwrap_or(cwd);
    let mapped: String = stripped
        .chars()
        .map(|c| if c == '/' || c == '\\' || c == ':' { '-' } else { c })
        .collect();
    format!("--{mapped}--")
}

/// Resolve a session's transcript: prefer the hook-supplied hint when it names
/// a real file (the pi extension hands over `getSessionFile()`), else the
/// `<ts>_<session_id>.jsonl` file under the session's cwd bucket
/// ([`pi_bucket`]).
fn pi_transcript_locate(
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
    let cwd = cwd.filter(|s| !s.is_empty())?;
    let dir = pi_sessions_root()?.join(pi_bucket(cwd));
    let suffix = format!("_{session_id}.jsonl");
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.ends_with(&suffix) && e.path().is_file() {
            return Some(e.path());
        }
    }
    None
}

/// The agent's latest words off a pi jsonl tail: the last `message` line whose
/// `role` is `assistant`, taking its LAST `text` content block (the freshest
/// prose; `thinking`/`toolCall` blocks are not words). `skip_sidechain` is a
/// claude-ism — pi has no sidechain concept — so it is accepted and ignored.
fn pi_extract_say(lines: &[String], _: bool) -> Option<String> {
    const SAY_MAX: usize = 160;
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let m = v.get("message");
        if m.and_then(|m| m.get("role")).and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(content) = m.and_then(|m| m.get("content")).and_then(Value::as_array) else {
            continue;
        };
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

/// The agent's latest tool call off a pi jsonl tail: the last `toolCall`
/// content block of the freshest assistant `message` line — its `name` plus its
/// `arguments`. `skip_sidechain` is a claude-ism, accepted and ignored (as
/// `pi_extract_say`).
fn pi_extract_tool(lines: &[String], _: bool) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let m = v.get("message");
        if m.and_then(|m| m.get("role")).and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(content) = m.and_then(|m| m.get("content")).and_then(Value::as_array) else {
            continue;
        };
        for block in content.iter().rev() {
            if block.get("type").and_then(Value::as_str) != Some("toolCall") {
                continue;
            }
            let Some(name) = block.get("name").and_then(Value::as_str) else {
                continue;
            };
            if let Some(label) = tool_label(name, block.get("arguments")) {
                found = Some(label);
                break;
            }
        }
    }
    found
}

/// The session's NAME: the last `session_info` entry's `name` in the tail
/// (pi's /rename — the session selector's display name). None when never
/// renamed (the graph names the session from the first prompt instead).
fn pi_extract_title(lines: &[String]) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("session_info") {
            continue;
        }
        if let Some(n) = v.get("name").and_then(Value::as_str) {
            let n = n.trim();
            if !n.is_empty() {
                found = Some(one_line_clip(n, 48));
            }
        }
    }
    found
}

/// The session's active model: the freshest `model_change` (provider/modelId)
/// or assistant `message` (provider/model) — both written per model/turn, last
/// wins. The provider prefix mirrors kimi's provider-prefixed on-disk ids: pi
/// can run ANY provider, so the bare model id alone is ambiguous.
fn pi_extract_model(lines: &[String], _: bool) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let (provider, model) = match v.get("type").and_then(Value::as_str) {
            Some("model_change") => (v.get("provider"), v.get("modelId")),
            Some("message") => {
                let m = v.get("message");
                if m.and_then(|m| m.get("role")).and_then(Value::as_str) != Some("assistant") {
                    continue;
                }
                (m.and_then(|m| m.get("provider")), m.and_then(|m| m.get("model")))
            }
            _ => continue,
        };
        let (Some(p), Some(m)) = (provider.and_then(Value::as_str), model.and_then(Value::as_str))
        else {
            continue;
        };
        let p = p.trim();
        let m = m.trim();
        if p.is_empty() || m.is_empty() {
            continue;
        }
        found = Some(format!("{p}/{m}"));
    }
    found
}

/// The context-window fill at the last request: the freshest assistant
/// `message`'s input-side `usage` — `input + cacheRead + cacheWrite` (mirrors
/// claude's input + cache-creation + cache-read; output and reasoning are what
/// the turn produced, not what sat in the window).
///
/// `None` when the tail holds no assistant turn with a usage block.
fn pi_context_tokens(lines: &[String]) -> Option<u64> {
    let mut found: Option<u64> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if v.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let m = v.get("message");
        if m.and_then(|m| m.get("role")).and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(usage) = m.and_then(|m| m.get("usage")) else {
            continue;
        };
        let sum = ["input", "cacheRead", "cacheWrite"]
            .iter()
            .map(|k| usage.get(k).and_then(Value::as_u64).unwrap_or(0))
            .sum();
        found = Some(sum);
    }
    found
}

/// pi has no sub-agent transcripts: its children (pi-subagents) are separate
/// pi processes, excluded from tracking on the extension side (non-tui) —
/// never a `sub:` node. Always None.
fn pi_subagents_dir(_: &str, _: Option<&str>) -> Option<PathBuf> {
    None
}

/// Unreachable for pi (no sub-agent dir); mirrors the seam's signature.
fn pi_find_subagent(_: &Path, _: &str) -> Option<PathBuf> {
    None
}

/// The Pi profile. The aoide-pi-session extension emits Aoide's own
/// canonical field names directly (it's aoide-owned code, not a foreign
/// harness to translate), so normalize is identity. Its sub-agent children
/// run non-interactively (never reach the graph) and its permissions are
/// invisible to the extension API, so both vocabularies are empty. The model
/// ceiling reuses the shared logic (claude-family ids resolve to their real
/// tiers; the deepseek-v4 line resolves to 1M; kimi/other ids take the
/// conservative 200k default).
pub static PI_PROFILE: AgentProfile = AgentProfile {
    name: "pi",
    hook_event_map: pi_hook_event,
    permission_vocab: &[],
    subagent_tools: &[],
    // pi's permissions are invisible to the extension API (see above), so
    // there is no prompt for a summons to answer.
    permission_keys: None,
    // pi's extension is a claude-shaped input surface; Enter submits.
    // Unverified against a live pi — this byte mirrors claude's old
    // (pre-fix) value and has not been re-checked now that claude's own
    // profile turned out to need `\r` instead.
    submit_key: "\n",
    normalize_payload: normalize_identity,
    model_ceiling: crate::model::context_ceiling_for_model,
    transcript: TranscriptSpec {
        locate: pi_transcript_locate,
        tail: transcript_tail,
        say: pi_extract_say,
        tool: pi_extract_tool,
        title: pi_extract_title,
        model: pi_extract_model,
        context_tokens: pi_context_tokens,
        subagents_dir: pi_subagents_dir,
        find_subagent: pi_find_subagent,
    },
    hook_settings: SettingsSpec {
        relative_path: ".pi/agent/extensions/aoide-pi-session.ts",
        format: SettingsFormat::Declarative,
    },
    // pi's extension surface is declarative (see `hook_settings`); it has no
    // skills directory.
    skills_dir: None,
    launch: &["pi"],
    // Verified 2026-08-25 by ACTUALLY RESUMING a session with the real
    // installed `pi` binary (the `pi-coding-agent` package
    // `modules/dendrites/pi-coding-agent.nix` installs) — not read off
    // `--help` alone, since pi's help text names THREE candidate flags
    // (`--resume`/`-r` "Select a session to resume" — no id argument, an
    // interactive picker; `--session <path|id>` — "Use specific session
    // file or partial UUID", ambiguous open-vs-continue; `--session-id
    // <id>` — "Use exact project session ID, creating it if missing") and
    // only live behaviour disambiguates them. Ran `pi --session-id
    // probe-1 -p "hello"` (created a new transcript, id `probe-1`, one
    // exchange logged), then ran `pi --session-id probe-1 -p "what did I
    // say before?"` again: NO new transcript file was created (same
    // `<ts>_probe-1.jsonl`, line count grew), and the reply correctly
    // recalled "hello" as the first message — proof the second call loaded
    // and continued the SAME session rather than starting a fresh one.
    // `--resume`/`-r` and `--session <path|id>` were not chosen: neither
    // takes a bare id + unambiguous continue semantics the way
    // `--session-id` demonstrably does.
    resume_args: Some(pi_resume_args),
    // pi's own sub-agent children aside, its only input surface is the pty
    // composer every existing keystroke path already reaches — no separate
    // native transport.
    native_send: None,
};

/// `pi --session-id <harness_session_id>` — resume a prior pi session by its
/// own id (see [`PI_PROFILE`]'s doc comment for the live verification).
fn pi_resume_args(harness_session_id: &str) -> Vec<String> {
    vec![
        "pi".to_string(),
        "--session-id".to_string(),
        harness_session_id.to_string(),
    ]
}

// ── eidolon ─────────────────────────────────────────────────────────────────

/// Eidolon fires no hook event at all — its `event.rs` bus
/// (`ToolCallStarted`/`AskUser`/`PolicyVerdict`/`ContextSize`/`TurnSettled`/
/// `Cancelled`) is `tokio::sync::broadcast`, in-process only, and never
/// reaches the door (P-EIDOLON brief §2, `core/src/event.rs:1-8`). Always
/// `Unknown`; this exists only because `AgentProfile.hook_event_map` is not
/// itself `Option`, and nothing calls it for a harness whose `hook_settings`
/// is `Declarative` with no aoide-authored file underneath (see
/// [`EIDOLON_PROFILE`]'s own doc).
fn eidolon_hook_event(_: &str) -> HookClass {
    HookClass::Unknown
}

// ── eidolon presence layout ─────────────────────────────────────────────────
//
// Eidolon has no hook transcript at all: its durable turn log
// (`~/.local/share/eidolon/sessions/<epoch-ms>.eid`) is a bitcode-framed
// binary journal (`core/src/session/log.rs:1-38`) — opened read-write by the
// harness's own `log` subcommand, which repairs a torn tail in place, and
// unparseable without eidolon's own decoder, so it is not a safe read
// target here. What IS safe, small, and already JSON is the swarm presence
// file every launch registers:
// `$XDG_RUNTIME_DIR/eidolon/<id>/meta.json` — a single flat object
// (id/pid/log/cwd/repo/model/started_ms/title/busy, `presence.rs:33-53`,
// `swarm/src/lib.rs:16-31`). The id is deterministic from `(cwd, log)`
// (`presence.rs:399-421`), never a timestamp, and that id IS this profile's
// `session_id` — so `locate` below needs no search, no cwd bucket, no
// directory scan: the id names its own file directly.

/// Resolve an eidolon session's presence file directly:
/// `$XDG_RUNTIME_DIR/eidolon/<session_id>/meta.json`, falling back to
/// `std::env::temp_dir()` exactly as eidolon's own `Presence::root()` does
/// (`presence.rs:104-110`) — a caller that only ever consulted
/// `XDG_RUNTIME_DIR` directly would silently miss every presence dir
/// eidolon itself would have written under the temp-dir fallback (e.g. a
/// session started outside a login/systemd context where the var is
/// unset). The session id here already IS the native presence id (see the
/// layout note above), so there is nothing to search for and nothing to
/// disambiguate by `cwd` — two live sessions sharing one cwd still resolve
/// to two distinct files, one per session id, never a collision, and never
/// widened to match on `cwd` the way claude/pi's locators do. `hinted` is
/// accepted for signature parity with every other profile's locator, but it
/// is honoured only when it already names this exact same file: the id
/// alone derives the ONE path this session can mean, so a hint that agreed
/// would change nothing and a hint that disagreed would be pointing at some
/// OTHER session's file — never followed either way. `cwd` is accepted and
/// unused for the same reason. `None` when the file does not exist (a stale
/// or torn-down presence dir looks the same as one that never existed).
fn eidolon_transcript_locate(
    session_id: &str,
    _cwd: Option<&str>,
    _hinted: Option<&str>,
) -> Option<PathBuf> {
    let root = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = root.join("eidolon").join(session_id).join("meta.json");
    path.is_file().then_some(path)
}

/// Read eidolon's presence `meta.json`, capped at 4 KiB, parse it as ONE
/// JSON value, and hand it back re-serialized as exactly ONE compact
/// "line" — not `.lines()`-split like every other profile's `tail`.
/// `meta.json` is a single flat object written temp-then-rename with
/// `serde_json::to_vec_pretty` (`presence.rs:227-233`): it is MULTI-LINE
/// JSON on disk, so a line-splitting tail would hand every extractor below
/// a fragment (`"{"` on one "line", `"title": "…"` on the next) that parses
/// as nothing. Parsing once here, at the tail boundary, and recompacting is
/// what lets `eidolon_extract_title`/`eidolon_extract_model` stay identical
/// in shape to every other profile's per-line `serde_json::from_str`
/// extractor. 4 KiB is generous headroom over every real recording (the
/// longest fields are a home-relative log path and a title, both well under
/// a hundred bytes, and pretty-printing only adds whitespace) while still
/// bounding a corrupt or pathological file instead of reading it whole.
/// Empty on ANY read error, non-UTF-8 content, or a JSON parse failure
/// (including a file truncated by the byte cap) — never a partial or
/// best-effort line, matching the brief's "never infer from a missing or
/// partial tail" discipline.
fn eidolon_transcript_tail(path: &Path) -> Vec<String> {
    use std::io::Read;
    const CAP: u64 = 4096;
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    if f.take(CAP).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(&buf) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    vec![value.to_string()]
}

/// Always `None`: `meta.json` carries no turn content, and the journal that
/// does (`.eid`) is unsafe to read directly (see the layout note above) and
/// unparseable without eidolon's own bitcode decoder. Unsupported until the
/// producer's `--jsonl` export lands (P-EIDOLON brief §3, slice E5) — named,
/// not silently guessed absent.
fn eidolon_extract_say(_lines: &[String], _skip_sidechain: bool) -> Option<String> {
    None
}

/// Always `None`, same reason as [`eidolon_extract_say`]: no tool-call
/// record exists in `meta.json`, and the journal that has one needs the
/// slice-E5 producer export to read safely.
fn eidolon_extract_tool(_lines: &[String], _skip_sidechain: bool) -> Option<String> {
    None
}

/// The session's NAME: `meta.json.title`, eidolon's own session title field
/// (set at launch, and by the TUI's rename). `None` when absent or blank.
fn eidolon_extract_title(lines: &[String]) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if let Some(t) = v.get("title").and_then(Value::as_str) {
            let t = t.trim();
            if !t.is_empty() {
                found = Some(one_line_clip(t, 48));
            }
        }
    }
    found
}

/// The session's active model: `meta.json.model`, provider-prefixed with a
/// COLON as eidolon itself writes it (live-verified: `"claude-cli:opus"`).
/// Returned verbatim, unstripped — `model_ceiling` below feeds this same
/// string straight into the shared lookup with no prefix surgery, so the
/// display value and the ceiling lookup's input are the same string.
/// `skip_sidechain` is a claude-ism eidolon has no concept of (P5: no
/// sub-agent transcripts — swarm peers are independent top-level
/// processes); accepted and ignored, matching pi/kimi's own precedent.
fn eidolon_extract_model(lines: &[String], _skip_sidechain: bool) -> Option<String> {
    let mut found: Option<String> = None;
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if let Some(m) = v.get("model").and_then(Value::as_str) {
            let m = m.trim();
            if !m.is_empty() {
                found = Some(m.to_string());
            }
        }
    }
    found
}

/// Always `None`: `meta.json` carries no usage/token data at all.
fn eidolon_context_tokens(_lines: &[String]) -> Option<u64> {
    None
}

/// Eidolon has no sub-agent transcripts: swarm peers are independent
/// top-level processes, each with its own presence dir and `.eid` file,
/// never a child the way claude's Task or pi's Agent tool spawns one (P5,
/// `swarm/src/lib.rs:16-31`) — always `None`, mirroring pi's own precedent
/// ([`pi_subagents_dir`]).
fn eidolon_subagents_dir(_session_id: &str, _cwd: Option<&str>) -> Option<PathBuf> {
    None
}

/// Unreachable for eidolon (no sub-agent dir); mirrors the seam's signature,
/// same as [`pi_find_subagent`].
fn eidolon_find_subagent(_dir: &Path, _tuid: &str) -> Option<PathBuf> {
    None
}

/// `eidolon send --from aoide --wake <to> -` — deliver a message to another
/// live eidolon session by its native presence id, WITHOUT typing into any
/// pty composer at all (`main.rs:155-176`, impl `:506-546`,
/// `swarm::api::send_external` `api.rs:154-205`). `to` is the recipient's
/// exact presence id (never the `channel` fan-out keyword — Aoide always
/// names one session). The returned argv is everything AFTER the
/// executable, per [`AgentProfile::native_send`]'s own contract:
/// - `--from aoide` and `--wake` are passed explicitly rather than riding
///   on eidolon's own defaults (`--from` defaults to `"cli"`, a direct
///   message defaults to `wake: true`) — a default is free to change
///   upstream; an explicit flag is not.
/// - the trailing bare `-` is the payload sentinel: eidolon reads the
///   message text from STDIN when the text arg is exactly `-`
///   (`main.rs:519-525`); every other shape re-joins multiple text args
///   with single spaces (`main.rs:518`), silently collapsing newlines. The
///   caller MUST write the message to the spawned child's stdin — never
///   append it as another argv word.
/// - success is `exit 0` with one line on stdout: `delivered to <id>` (the
///   doorbell answered) or `written to <id>'s inbox, but it is not
///   answering; it will read it on recovery` (`api.rs:199-204`) — both are
///   ACCEPTED, neither is a read receipt; there is no id to correlate a
///   later reply against (`inbox.rs:15-40`'s `Envelope` carries none).
fn eidolon_native_send(to: &str) -> Vec<String> {
    vec![
        "send".to_string(),
        "--from".to_string(),
        "aoide".to_string(),
        "--wake".to_string(),
        to.to_string(),
        "-".to_string(),
    ]
}

/// The Eidolon profile (P-EIDOLON brief rev 3, slice E1a) — bounded
/// metadata only. Eidolon has no hook file and fires no event that reaches
/// the door ([`eidolon_hook_event`] below is `Unknown` for everything, and
/// `normalize_payload` is the identity no-op — both moot rather than
/// absent, since nothing ever calls them for a harness `hook_settings`
/// never wires a real file for), so this profile fills far less than
/// claude/kimi/pi's own: everything it CAN report comes from the swarm
/// presence file (`meta.json`), and every field it cannot fill is a taught
/// refusal, not a guess:
/// - `permission_vocab: &[]`, `subagent_tools: &[]` — no notification
///   vocabulary and no sub-agent-spawning tool exist to name.
/// - `permission_keys: None` — the interactive permission prompt is the
///   TUI's own script-rebindable Rune `confirm` table
///   (`tui/ui/default.rn:515-519`), invisible to Aoide; there is no
///   verified prompt shape to answer, so `graph permit` refuses a summons
///   rather than typing a guess.
/// - `skills_dir: None` — eidolon's tools are Rune scripts and MCP, not
///   `<name>/SKILL.md` packages; there is no directory for `hooks install`
///   to link into.
/// - `hook_settings.format: Declarative` — see its own field comment below;
///   `hooks install eidolon` gets the existing Declarative short-circuit
///   for free, same door as pi's own entry.
/// - `launch: &["eidolon"]` — the bare program name; no subcommand launches
///   the TUI (`main.rs:313-320`), same shape as every other profile's fresh
///   launch.
/// - `resume_args: None` — `eidolon resume <SESSION:PathBuf>` and
///   `eidolon tui --session <SESSION:PathBuf>` both take a LOG PATH
///   (`main.rs:115-131`, `:242-256`), never the session id `resume_args`'s
///   own `fn(harness_session_id: &str)` is typed to take, and `LedgerEntry`
///   carries no log path today (P-EIDOLON brief §7, ruling R1's default
///   (a)). The id-to-log-path mapping is slice E4's job, not "unsupported
///   forever" — `graph resurrect` skips it with the existing taught
///   message meanwhile, same as any other `None` here. A live TUI's own
///   `:resume` is separately unsupported until eidolon's own P4 lands (the
///   presence id derives from the log path at launch, and adopting a
///   different session in place never refreshes it — the record would go
///   on describing the OLD log).
/// - `native_send: Some(eidolon_native_send)` — see its own doc: the one
///   profile where a message never needs the pty composer at all.
/// - `transcript.say`/`tool`/`context_tokens`: always `None` — eidolon's
///   turn content lives in the bitcode-framed `.eid` journal
///   (`core/src/session/log.rs:1-38`), not in `meta.json`, and reading that
///   journal safely needs the producer's own `--jsonl` export (P-EIDOLON
///   brief §3's "producer export"), unimplemented until slice E5.
/// - state `awaiting`/`error`/`cancel` are UNOBSERVABLE by this profile, not
///   merely unfilled: eidolon's `AskUser`/`PolicyVerdict`/`Cancelled`
///   events never leave its in-process bus (`core/src/event.rs:1-8`), so no
///   slice built on this profile alone can ever assert them — a fact for
///   the reconciler that consumes this profile, not something this file
///   can fix.
pub static EIDOLON_PROFILE: AgentProfile = AgentProfile {
    name: "eidolon",
    hook_event_map: eidolon_hook_event,
    permission_vocab: &[],
    subagent_tools: &[],
    // No verified prompt shape to answer — see the profile doc above.
    permission_keys: None,
    // `ret` submits in eidolon's TUI, both normal and insert mode
    // (`default.rn:771,1084`); never consulted in this slice — the native
    // `send` transport (`native_send` below) never reaches the pty at all,
    // and this slice's own transcript reading doesn't type anything either.
    submit_key: "\r",
    normalize_payload: normalize_identity,
    model_ceiling: crate::model::context_ceiling_for_model,
    transcript: TranscriptSpec {
        locate: eidolon_transcript_locate,
        tail: eidolon_transcript_tail,
        say: eidolon_extract_say,
        tool: eidolon_extract_tool,
        title: eidolon_extract_title,
        model: eidolon_extract_model,
        context_tokens: eidolon_context_tokens,
        subagents_dir: eidolon_subagents_dir,
        find_subagent: eidolon_find_subagent,
    },
    // Eidolon has no hook file at all — its config is Nix-owned and
    // read-only to the harness (`~/eidolon/AGENTS.md`: "Configuration is
    // read-only to the harness... Do not add another config writer"). This
    // names that nix-generated config path only so `hooks install`'s
    // existing Declarative short-circuit message has something concrete and
    // true to cite; the FORMAT is what actually matters here — `hooks
    // install eidolon` never reads or writes this path, unlike pi's own
    // Declarative entry, which names a real aoide-authored extension file.
    hook_settings: SettingsSpec {
        relative_path: ".config/eidolon/config.toml",
        format: SettingsFormat::Declarative,
    },
    // No SKILL.md concept — see the profile doc above.
    skills_dir: None,
    launch: &["eidolon"],
    // No `resume_args` — see the profile doc above (ruling R1, default (a)).
    resume_args: None,
    // The one profile with a native inter-session transport — see
    // `eidolon_native_send`'s own doc for the two contract halves a caller
    // must honour (stdin payload, accepted-not-consumed exit code).
    native_send: Some(eidolon_native_send),
};

/// The profile table. New harnesses land here as another entry.
static PROFILES: &[&AgentProfile] =
    &[&CLAUDE_PROFILE, &KIMI_PROFILE, &PI_PROFILE, &EIDOLON_PROFILE];

/// Look up an agent harness's profile by name (`claude`, `kimi`, …). `None`
/// for a harness the bridge has no profile for.
pub fn agent_profile(name: &str) -> Option<&'static AgentProfile> {
    PROFILES.iter().copied().find(|p| p.name == name)
}

/// Every agent name with a registered profile.
pub fn known_agents() -> &'static [&'static str] {
    &["claude", "kimi", "pi", "eidolon"]
}

/// Is this profile's launch program discoverable on `PATH`? Onboard's own
/// harness preselection (ONBOARD.md decision 7: the multi-select picker
/// preselects every harness already on `PATH`) — the `AgentProfile`-shaped
/// wrapper over `bin::on_path`. A profile with an empty `launch` slice is
/// never on `PATH` by definition.
pub fn on_path(profile: &AgentProfile) -> bool {
    profile.launch.first().is_some_and(|program| crate::bin::on_path(program))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the seam itself: dispatch pins ─────────────────────────────────────

    #[test]
    fn on_path_reflects_the_profiles_launch_program_via_the_bin_probe() {
        // Shares `bin`'s own PATH-mutation lock -- `on_path` delegates
        // straight into `bin::on_path`, so a bin.rs test running
        // concurrently would race the same real `PATH` env var otherwise.
        let _guard = crate::bin::path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_agents_on_path_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pi"), "").unwrap();
        std::env::set_var("PATH", &dir);

        assert!(on_path(&PI_PROFILE), "pi's launch program sits on the scoped PATH");

        std::fs::remove_file(dir.join("pi")).unwrap();
        assert!(!on_path(&PI_PROFILE), "pi's launch program no longer sits on PATH");

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_profile_resolves_registered_agents_and_rejects_the_unknown() {
        let p = agent_profile("claude").expect("claude is registered");
        assert_eq!(p.name, "claude");
        assert_eq!(agent_profile("kimi").expect("kimi is registered").name, "kimi");
        assert_eq!(agent_profile("pi").expect("pi is registered").name, "pi");
        assert_eq!(
            agent_profile("eidolon").expect("eidolon is registered").name,
            "eidolon"
        );
        assert!(agent_profile("nope").is_none());
        assert!(agent_profile("").is_none());
        assert_eq!(known_agents(), &["claude", "kimi", "pi", "eidolon"]);
    }

    #[test]
    fn submit_key_is_pinned_per_profile() {
        // Enter sends CR (`\r`), not LF — claude and kimi's TUIs both submit
        // on `\r` (claude: observed on the installed Claude Code 2.1.263 on
        // two independent hosts, root's Osaka fixture and the yomi doorbell
        // rig, where a bare `\n` only inserted a newline; kimi: ground-
        // truthed on a live screen, see Conductor-Channel.md's `graph send`
        // entry). pi's `\n` is unverified against a live pi, carried over
        // from claude's old (pre-fix) value. A wrong byte here types the
        // line without submitting it.
        assert_eq!(CLAUDE_PROFILE.submit_key, "\r");
        assert_eq!(KIMI_PROFILE.submit_key, "\r");
        assert_eq!(PI_PROFILE.submit_key, "\n");
    }

    #[test]
    fn every_profile_names_a_nonempty_launch_argv() {
        // A new harness is a table entry — this is the one field EVERY
        // registered profile must fill (P-D7), unlike `resume_args`, which
        // is legitimately `None` for a harness whose resume flag is
        // unverified.
        for p in [&CLAUDE_PROFILE, &KIMI_PROFILE, &PI_PROFILE] {
            assert!(!p.launch.is_empty(), "{} has an empty launch argv", p.name);
        }
        assert_eq!(CLAUDE_PROFILE.launch, &["claude"]);
        assert_eq!(KIMI_PROFILE.launch, &["kimi"]);
        assert_eq!(PI_PROFILE.launch, &["pi"]);
    }

    #[test]
    fn resume_args_produce_the_exact_verified_argv() {
        // claude: named verbatim in `docs/architecture/AOIDED.md`'s L5
        // section (the design authority for this table).
        let claude = CLAUDE_PROFILE.resume_args.expect("claude resumes");
        assert_eq!(claude("sess-123"), vec!["claude", "--resume", "sess-123"]);

        // kimi: verified against `kimi --help`'s own text on the exact
        // pinned 0.31.1 binary (`-S, --session [id]  Resume a session. With
        // ID: resume that session.`).
        let kimi = KIMI_PROFILE.resume_args.expect("kimi resumes");
        assert_eq!(kimi("sess-456"), vec!["kimi", "--session", "sess-456"]);

        // pi: verified LIVE — `pi --session-id <id>` run twice against the
        // same id continued the same on-disk transcript (no new file, and
        // the second run recalled the first run's own prompt), rather than
        // starting a fresh session.
        let pi = PI_PROFILE.resume_args.expect("pi resumes");
        assert_eq!(pi("sess-789"), vec!["pi", "--session-id", "sess-789"]);
    }

    #[test]
    fn claude_hook_event_map_covers_the_lifecycle() {
        let map = CLAUDE_PROFILE.hook_event_map;
        assert_eq!(map("SessionStart"), HookClass::SessionStart);
        assert_eq!(map("UserPromptSubmit"), HookClass::PromptSubmit);
        assert_eq!(map("PreToolUse"), HookClass::PreToolUse);
        assert_eq!(map("PostToolUse"), HookClass::PostToolUse);
        assert_eq!(map("Stop"), HookClass::Stop);
        assert_eq!(map("Notification"), HookClass::Notification);
        assert_eq!(map("SubagentStart"), HookClass::SubagentStart);
        assert_eq!(map("SubagentStop"), HookClass::SubagentStop);
        assert_eq!(map("SessionEnd"), HookClass::SessionEnd);
        assert_eq!(map("Zzz"), HookClass::Unknown);
        assert_eq!(map(""), HookClass::Unknown);
    }

    #[test]
    fn claude_notification_detail_classification_keeps_the_tiers() {
        let map = CLAUDE_PROFILE.hook_event_map;
        // The structured notification_type (exact).
        assert_eq!(map("ntype:permission_prompt"), HookClass::Awaiting);
        assert_eq!(map("ntype:idle_prompt"), HookClass::AwaitingIfRunning);
        assert_eq!(map("ntype:foo"), HookClass::Unknown);
        assert_eq!(map("ntype:"), HookClass::Unknown);
        // The brittle English message fallback (substring, lowercased upstream).
        assert_eq!(
            map("msg:claude needs your permission to use bash"),
            HookClass::Awaiting
        );
        assert_eq!(map("msg:permission required"), HookClass::Awaiting);
        assert_eq!(
            map("msg:claude is waiting for your input"),
            HookClass::AwaitingIfRunning
        );
        assert_eq!(map("msg:hello"), HookClass::Unknown);
        assert_eq!(map("msg:"), HookClass::Unknown);
        // The permission tier wins inside one string.
        assert_eq!(
            map("msg:permission granted, waiting for your input"),
            HookClass::Awaiting
        );
        // The input kinds never cross-classify: a bare message without the
        // prefix is not a detail query, and a detail key is not an event.
        assert_eq!(map("permission"), HookClass::Unknown);
        assert_eq!(map("waiting for your input"), HookClass::Unknown);
    }

    #[test]
    fn claude_profile_pins_the_vocab_tools_ceiling_and_settings() {
        assert_eq!(CLAUDE_PROFILE.permission_vocab, &["permission"]);
        assert!(CLAUDE_PROFILE.subagent_tools.contains(&"Task"));
        assert!(CLAUDE_PROFILE.subagent_tools.contains(&"Agent"));
        assert!(!CLAUDE_PROFILE.subagent_tools.contains(&"Bash"));
        // The ceiling dispatch is model.rs's logic, through the profile.
        assert_eq!(
            (CLAUDE_PROFILE.model_ceiling)(Some("claude-sonnet-5")),
            1_000_000
        );
        assert_eq!((CLAUDE_PROFILE.model_ceiling)(Some("claude-haiku-4-5")), 200_000);
        assert_eq!((CLAUDE_PROFILE.model_ceiling)(None), 200_000);
        assert_eq!(CLAUDE_PROFILE.hook_settings.relative_path, ".claude/settings.json");
        assert_eq!(CLAUDE_PROFILE.hook_settings.format, SettingsFormat::Json);
        assert_eq!(CLAUDE_PROFILE.skills_dir, Some(".claude/skills"));
    }

    // ── the kimi profile ───────────────────────────────────────────────────

    #[test]
    fn kimi_hook_event_map_covers_core_events_and_the_dedicated_awaiting() {
        let map = KIMI_PROFILE.hook_event_map;
        // The core events are 1:1 with claude's classes.
        assert_eq!(map("SessionStart"), HookClass::SessionStart);
        assert_eq!(map("UserPromptSubmit"), HookClass::PromptSubmit);
        assert_eq!(map("PreToolUse"), HookClass::PreToolUse);
        assert_eq!(map("PostToolUse"), HookClass::PostToolUse);
        assert_eq!(map("Stop"), HookClass::Stop);
        assert_eq!(map("Notification"), HookClass::Notification);
        assert_eq!(map("SubagentStart"), HookClass::SubagentStart);
        assert_eq!(map("SubagentStop"), HookClass::SubagentStop);
        assert_eq!(map("SessionEnd"), HookClass::SessionEnd);
        // PermissionRequest is THE needs-input signal.
        assert_eq!(map("PermissionRequest"), HookClass::Awaiting);
        // Kimi-only observational events (and Interrupt) are ok no-ops.
        for evt in [
            "PermissionResult",
            "Interrupt",
            "PreCompact",
            "PostCompact",
            "StopFailure",
            "PostToolUseFailure",
        ] {
            assert_eq!(map(evt), HookClass::Unknown, "event: {evt}");
        }
        // A kimi Notification's detail never classifies as awaiting (no vocab).
        assert_eq!(map("ntype:task.completed"), HookClass::Unknown);
        assert_eq!(map("msg:permission needed"), HookClass::Unknown);
        assert_eq!(map("Zzz"), HookClass::Unknown);
    }

    #[test]
    fn kimi_profile_pins_vocab_tools_ceilings_and_settings() {
        assert!(KIMI_PROFILE.permission_vocab.is_empty());
        // Kimi's dispatch tool is `Agent` (captured 0.31.1 payloads) — no Task.
        assert_eq!(KIMI_PROFILE.subagent_tools, &["Agent"]);
        // Ceilings: k3 = 1M, the 256k tiers, garbage/None = the 200k default.
        let ceil = KIMI_PROFILE.model_ceiling;
        assert_eq!(ceil(Some("k3")), 1_000_000);
        assert_eq!(ceil(Some("K3")), 1_000_000);
        assert_eq!(ceil(Some("k3-1m")), 1_000_000);
        assert_eq!(ceil(Some("k3-256k")), 256_000);
        assert_eq!(ceil(Some("kimi-for-coding")), 256_000);
        assert_eq!(ceil(Some("kimi-for-coding-highspeed")), 256_000);
        // On-disk ids are provider-prefixed (the wire's real values).
        assert_eq!(ceil(Some("kimi-code/kimi-for-coding")), 256_000);
        assert_eq!(ceil(Some("kimi-code/k3-256k")), 256_000);
        assert_eq!(ceil(Some("kimi-code/k3")), 1_000_000);
        assert_eq!(ceil(Some("garbage")), 200_000);
        assert_eq!(ceil(Some("")), 200_000);
        assert_eq!(ceil(None), 200_000);
        assert_eq!(KIMI_PROFILE.hook_settings.relative_path, ".kimi-code/config.toml");
        assert_eq!(KIMI_PROFILE.hook_settings.format, SettingsFormat::Toml);
        // No skills dir verified for kimi — a guessed path would make
        // `hooks install` mint a directory the harness never reads.
        assert_eq!(KIMI_PROFILE.skills_dir, None);
    }

    #[test]
    fn kimi_normalize_maps_native_fields_onto_the_contract() {
        let norm = KIMI_PROFILE.normalize_payload;
        // UserPromptSubmit: the prompt ARRAY of content blocks joins into
        // `user_prompt` (non-text blocks skipped), kimi's field kept intact.
        let mut p = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s",
            "prompt": [
                {"type": "text", "text": "line one"},
                {"type": "image", "data": "…"},
                {"type": "text", "text": "line two"}
            ]
        });
        norm(&mut p);
        assert_eq!(p["user_prompt"], "line one\nline two");
        assert!(p["prompt"].is_array(), "the kimi-native field is preserved");
        // Tool events: tool_call_id → tool_use_id.
        let mut t = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "tool_name": "Agent",
            "tool_call_id": "tool_ABC",
            "tool_input": {"description": "d", "prompt": "p"}
        });
        norm(&mut t);
        assert_eq!(t["tool_use_id"], "tool_ABC");
        assert_eq!(t["tool_call_id"], "tool_ABC", "copy, not rename");
        // SubagentStart: agent_name → agent_type. A STRING `prompt` here is
        // the child's task, NOT a user prompt — it must not name the session.
        let mut sub = serde_json::json!({
            "hook_event_name": "SubagentStart",
            "session_id": "s",
            "agent_name": "coder",
            "prompt": "do the child thing"
        });
        norm(&mut sub);
        assert_eq!(sub["agent_type"], "coder");
        assert!(sub.get("user_prompt").is_none(), "a string prompt is not user_prompt");
    }

    #[test]
    fn claude_normalize_maps_the_real_prompt_field_onto_the_contract() {
        let norm = CLAUDE_PROFILE.normalize_payload;
        // Ground-truthed: claude's UserPromptSubmit sends the text as `prompt`
        // (a plain string), not `user_prompt` — map it onto the contract.
        let mut p = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s",
            "prompt": "fix the flaky auth test"
        });
        norm(&mut p);
        assert_eq!(p["user_prompt"], "fix the flaky auth test");
        assert_eq!(p["prompt"], "fix the flaky auth test", "the native field is preserved");

        // An already-canonical payload is left alone (copy, never clobber).
        let mut c = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "user_prompt": "canonical wins",
            "prompt": "native loses",
            "tool_use_id": "tu"
        });
        norm(&mut c);
        assert_eq!(c["user_prompt"], "canonical wins");

        // Gated to UserPromptSubmit: a `prompt` field on any other event (e.g.
        // a sub-agent dispatch's task text) must never misread as the user's
        // turn-naming prompt — same hazard kimi guards against on SubagentStart.
        let mut other = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "session_id": "s",
            "prompt": "not a user prompt"
        });
        norm(&mut other);
        assert!(other.get("user_prompt").is_none(), "non-UserPromptSubmit prompt is not user_prompt");

        // Garbage payloads and empty/missing prompt text don't panic or insert.
        let mut garbage = serde_json::json!(["not", "an", "object"]);
        norm(&mut garbage);
        let mut empty = serde_json::json!({ "hook_event_name": "UserPromptSubmit", "prompt": "   " });
        norm(&mut empty);
        assert!(empty.get("user_prompt").is_none(), "blank prompt text is not inserted");
        let mut missing = serde_json::json!({ "hook_event_name": "UserPromptSubmit" });
        norm(&mut missing);
        assert!(missing.get("user_prompt").is_none(), "no prompt field at all is a no-op");
    }

    #[test]
    fn kimi_normalize_never_clobbers_canonical_fields() {
        let norm = KIMI_PROFILE.normalize_payload;
        let mut p = serde_json::json!({
            "user_prompt": "canonical wins",
            "prompt": [{"type": "text", "text": "native"}],
            "tool_use_id": "tu_canon",
            "tool_call_id": "tool_native",
            "agent_type": "explore",
            "agent_name": "coder"
        });
        norm(&mut p);
        assert_eq!(p["user_prompt"], "canonical wins");
        assert_eq!(p["tool_use_id"], "tu_canon");
        assert_eq!(p["agent_type"], "explore");
        // Garbage payloads don't panic: non-object, empty text blocks, empty ids.
        let mut garbage = serde_json::json!(["not", "an", "object"]);
        norm(&mut garbage);
        let mut empty = serde_json::json!({
            "prompt": [{"type": "text", "text": "  "}],
            "tool_call_id": "",
            "agent_name": ""
        });
        norm(&mut empty);
        assert!(empty.get("user_prompt").is_none());
        assert!(empty.get("tool_use_id").is_none());
        assert!(empty.get("agent_type").is_none());
    }

    #[test]
    fn kimi_wire_extractors_read_the_typed_event_log() {
        // Fixture mirrors the real wire.jsonl record shapes (session_de940cb0
        // captures): prompt, think + text content parts, usage, llm.request,
        // config.update — plus the minified state.json line kimi_wire_tail
        // appends.
        let lines: Vec<String> = [
            r#"{"type":"metadata","protocol_version":"1.4","created_at":1}"#,
            r#"{"type":"config.update","modelAlias":"kimi-code/kimi-for-coding","thinkingEffort":"on"}"#,
            r#"{"type":"turn.prompt","input":[{"type":"text","text":"do the thing"}]}"#,
            r#"{"type":"llm.request","model":"kimi-for-coding","modelAlias":"kimi-code/kimi-for-coding"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"think","think":"hmm, thinking"}}}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"first words"}}}"#,
            r#"{"type":"usage.record","model":"kimi-code/kimi-for-coding","usage":{"inputOther":100,"output":9,"inputCacheRead":20,"inputCacheCreation":3},"usageScope":"turn"}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"step.end","usage":{"inputOther":1}}}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"  the  latest\nwords  "}}}"#,
            r#"{"type":"usage.record","model":"kimi-code/k3","usage":{"inputOther":500,"output":50,"inputCacheRead":40,"inputCacheCreation":7},"usageScope":"turn"}"#,
            r#"{"title":"My Custom Name","isCustomTitle":true,"workDir":"/p"}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let spec = &KIMI_PROFILE.transcript;
        // say: the LAST text part (whitespace-normalised); think parts skipped.
        assert_eq!((spec.say)(&lines, true).as_deref(), Some("the latest words"));
        // model: last of usage.record.model / llm.request.modelAlias.
        assert_eq!((spec.model)(&lines, true).as_deref(), Some("kimi-code/k3"));
        // context: freshest usage.record's input side only (500+40+7; output
        // excluded).
        assert_eq!((spec.context_tokens)(&lines), Some(547));
        // title: only when isCustomTitle.
        assert_eq!((spec.title)(&lines).as_deref(), Some("My Custom Name"));
        let derived: Vec<String> =
            vec![r#"{"title":"derived placeholder","isCustomTitle":false}"#.to_string()];
        assert_eq!((spec.title)(&derived), None);
        // Empty tails yield nothing.
        let bare: Vec<String> = vec!["garbage".to_string(), r#"{"type":"turn.prompt","input":[]}"#.to_string()];
        assert!((spec.say)(&bare, true).is_none());
        assert!((spec.model)(&bare, true).is_none());
        assert!((spec.context_tokens)(&bare).is_none());
        assert!((spec.title)(&bare).is_none());
    }

    #[test]
    fn kimi_transcript_locate_globs_and_the_tail_carries_state_json() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let saved = std::env::var_os("KIMI_CODE_HOME");
        let root = std::env::temp_dir().join(format!("aoide_kimi_home_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // The real on-disk shape: sessions/wd_<dirname>_<hash>/<session_id>/
        // with agents/main/wire.jsonl, agents/agent-0/wire.jsonl, state.json.
        let session = root.join("sessions/wd_proj_0123456789ab/session_abc123");
        std::fs::create_dir_all(session.join("agents/main")).unwrap();
        std::fs::create_dir_all(session.join("agents/agent-0")).unwrap();
        std::fs::write(
            session.join("agents/main/wire.jsonl"),
            concat!(
                "{\"type\":\"context.append_loop_event\",\"event\":{\"type\":\"content.part\",\"part\":{\"type\":\"text\",\"text\":\"main says hi\"}}}\n",
                "{\"type\":\"usage.record\",\"model\":\"kimi-code/kimi-for-coding\",\"usage\":{\"inputOther\":10,\"output\":1,\"inputCacheRead\":2,\"inputCacheCreation\":3}}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            session.join("state.json"),
            "{\n  \"title\": \"Renamed By Hand\",\n  \"isCustomTitle\": true\n}\n",
        )
        .unwrap();
        std::fs::write(session.join("agents/agent-0/wire.jsonl"), "{}\n").unwrap();
        std::env::set_var("KIMI_CODE_HOME", &root);

        let spec = &KIMI_PROFILE.transcript;
        // locate: the glob finds the session under any wd_* bucket; the cwd is
        // irrelevant (the bucket hash is opaque).
        let found = (spec.locate)("session_abc123", Some("/irrelevant"), None).unwrap();
        assert!(found.ends_with("agents/main/wire.jsonl"));
        assert!((spec.locate)("session_nope", Some("/x"), None).is_none());
        // A real hinted file wins (parity with claude).
        assert_eq!(
            (spec.locate)("session_nope", None, Some(found.to_str().unwrap())),
            Some(found.clone())
        );
        // The tail appends minified state.json, so title + say + model +
        // context all resolve off the ONE read.
        let lines = (spec.tail)(&found);
        assert_eq!((spec.say)(&lines, true).as_deref(), Some("main says hi"));
        assert_eq!(
            (spec.model)(&lines, true).as_deref(),
            Some("kimi-code/kimi-for-coding")
        );
        assert_eq!((spec.context_tokens)(&lines), Some(15));
        assert_eq!((spec.title)(&lines).as_deref(), Some("Renamed By Hand"));
        // subagents_dir/find_subagent: the agents dir resolves; only a direct
        // agent-<tuid>/wire.jsonl hit finds a sub transcript (0.31.1 has no
        // tool_call_id ↔ agent-N correlator).
        let subs = (spec.subagents_dir)("session_abc123", None).unwrap();
        assert!(subs.ends_with("agents"));
        assert!((spec.find_subagent)(&subs, "0").unwrap().ends_with("agent-0/wire.jsonl"));
        assert!((spec.find_subagent)(&subs, "tool_VvbM0U7").is_none());
        assert!((spec.subagents_dir)("session_nope", None).is_none());

        match saved {
            Some(v) => std::env::set_var("KIMI_CODE_HOME", v),
            None => std::env::remove_var("KIMI_CODE_HOME"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── the pi profile ────────────────────────────────────────────────────

    #[test]
    fn pi_hook_event_map_covers_the_lifecycle_only() {
        let map = PI_PROFILE.hook_event_map;
        assert_eq!(map("SessionStart"), HookClass::SessionStart);
        assert_eq!(map("UserPromptSubmit"), HookClass::PromptSubmit);
        assert_eq!(map("PreToolUse"), HookClass::PreToolUse);
        assert_eq!(map("PostToolUse"), HookClass::PostToolUse);
        assert_eq!(map("Stop"), HookClass::Stop);
        assert_eq!(map("SessionEnd"), HookClass::SessionEnd);
        // pi has no notification/sub-agent vocabulary — those are ok no-ops.
        for evt in ["Notification", "SubagentStart", "SubagentStop", "Zzz", ""] {
            assert_eq!(map(evt), HookClass::Unknown, "event: {evt}");
        }
    }

    #[test]
    fn pi_profile_pins_vocab_tools_ceiling_and_settings() {
        assert!(PI_PROFILE.permission_vocab.is_empty());
        assert!(PI_PROFILE.subagent_tools.is_empty());
        // The shared ceiling logic: claude-family ids resolve, the deepseek-v4
        // line resolves to 1M, everything else (kimi ids, garbage, None) takes
        // the conservative default.
        let ceil = PI_PROFILE.model_ceiling;
        assert_eq!(ceil(Some("claude-sonnet-5")), 1_000_000);
        assert_eq!(ceil(Some("deepseek/deepseek-v4-flash")), 1_000_000);
        assert_eq!(ceil(Some("deepseek/deepseek-v4-pro")), 1_000_000);
        assert_eq!(ceil(Some("kimi-code/k3")), 200_000);
        assert_eq!(ceil(None), 200_000);
        assert_eq!(
            PI_PROFILE.hook_settings.relative_path,
            ".pi/agent/extensions/aoide-pi-session.ts"
        );
        assert_eq!(PI_PROFILE.hook_settings.format, SettingsFormat::Declarative);
        assert_eq!(PI_PROFILE.skills_dir, None);
    }

    #[test]
    fn pi_transcript_extractors_read_the_jsonl_layout() {
        // Fixture mirrors the real pi jsonl record shapes (session
        // 019ff466-… capture): header, model_change, user/assistant messages
        // with provider/model/usage, session_info naming, thinking + toolCall
        // content blocks.
        let lines: Vec<String> = [
            r#"{"type":"session","version":3,"id":"s1","cwd":"/p"}"#,
            r#"{"type":"model_change","provider":"deepseek","modelId":"deepseek-v4-flash"}"#,
            r#"{"type":"message","message":{"role":"user","content":[{"type":"text","text":"do it"}]}}"#,
            r#"{"type":"message","message":{"role":"assistant","content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"first words"},{"type":"toolCall","id":"c1","name":"bash","arguments":{}}]}}"#,
            r#"{"type":"message","message":{"role":"assistant","content":[{"type":"text","text":"  the  latest\nwords  "}],"provider":"deepseek","model":"deepseek-v4-flash","usage":{"input":100,"output":9,"cacheRead":20,"cacheWrite":3,"reasoning":5}}}"#,
            r#"{"type":"session_info","name":"Refactor Module"}"#,
            r#"{"type":"message","message":{"role":"toolResult","toolCallId":"c1","toolName":"bash","content":[]}}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let spec = &PI_PROFILE.transcript;
        // say: the LAST text block of the freshest assistant message;
        // thinking/toolCall blocks are not words, toolResult/user are not
        // assistant.
        assert_eq!((spec.say)(&lines, true).as_deref(), Some("the latest words"));
        // model: freshest provider/model (deepseek/deepseek-v4-flash), last
        // wins over the earlier model_change.
        assert_eq!(
            (spec.model)(&lines, true).as_deref(),
            Some("deepseek/deepseek-v4-flash")
        );
        // context: freshest assistant usage's input side only (100+20+3;
        // output/reasoning excluded).
        assert_eq!((spec.context_tokens)(&lines), Some(123));
        // title: last session_info name; a never-renamed session has none.
        assert_eq!((spec.title)(&lines).as_deref(), Some("Refactor Module"));
        let bare: Vec<String> =
            vec![r#"{"type":"session","id":"s1"}"#.to_string()];
        assert_eq!((spec.title)(&bare), None);
        assert!((spec.say)(&bare, true).is_none());
        assert!((spec.model)(&bare, true).is_none());
        assert!((spec.context_tokens)(&bare).is_none());
    }

    #[test]
    fn pi_transcript_locate_finds_the_cwd_bucket_file() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let saved = std::env::var_os("PI_CODING_AGENT_SESSION_DIR");
        let root = std::env::temp_dir().join(format!("aoide_pi_home_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // The real on-disk shape: --<bucket(cwd)>--/<ts>_<session_id>.jsonl,
        // with the header id matching the filename uuid.
        let bucket = root.join("--home-khoa-Aoide--");
        std::fs::create_dir_all(&bucket).unwrap();
        std::fs::write(
            bucket.join("2026-08-12T05-16-56-318Z_s1.jsonl"),
            concat!(
                "{\"type\":\"session\",\"version\":3,\"id\":\"s1\"}\n",
                "{\"type\":\"message\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"provider\":\"deepseek\",\"model\":\"deepseek-v4-flash\"}}\n"
            ),
        )
        .unwrap();
        std::env::set_var("PI_CODING_AGENT_SESSION_DIR", &root);

        let spec = &PI_PROFILE.transcript;
        // locate: the cwd bucket + filename uuid resolve; the hint wins over
        // any derivation; a wrong bucket or unknown id is None.
        let found = (spec.locate)("s1", Some("/home/khoa/Aoide"), None).unwrap();
        assert!(found.ends_with("2026-08-12T05-16-56-318Z_s1.jsonl"));
        assert_eq!(
            (spec.locate)("s2", None, Some(found.to_str().unwrap())),
            Some(found.clone())
        );
        assert!((spec.locate)("s1", Some("/elsewhere"), None).is_none());
        assert!((spec.locate)("s2", Some("/home/khoa/Aoide"), None).is_none());
        // Dots are PRESERVED in pi's buckets (unlike claude's munge):
        // /home/khoa/.dotfiles → --home-khoa-.dotfiles--, never
        // --home-khoa--dotfiles--. Pin the divergence.
        let dotbucket = root.join("--home-khoa-.dotfiles--");
        std::fs::create_dir_all(&dotbucket).unwrap();
        std::fs::write(dotbucket.join("2026-08-12T05-16-56-318Z_s3.jsonl"), "\n").unwrap();
        assert!(
            (spec.locate)("s3", Some("/home/khoa/.dotfiles"), None)
                .unwrap()
                .ends_with("2026-08-12T05-16-56-318Z_s3.jsonl")
        );
        assert!((spec.locate)("s3", Some("/home/khoa/Aoide"), None).is_none());
        // The tail + extractors work end-to-end through the spec.
        let lines = (spec.tail)(&found);
        assert_eq!((spec.say)(&lines, true).as_deref(), Some("hi"));
        assert_eq!(
            (spec.model)(&lines, true).as_deref(),
            Some("deepseek/deepseek-v4-flash")
        );
        // No sub-agent machinery for pi.
        assert!((spec.subagents_dir)("s1", None).is_none());
        assert!((spec.subagents_dir)("s_nope", None).is_none());

        match saved {
            Some(v) => std::env::set_var("PI_CODING_AGENT_SESSION_DIR", v),
            None => std::env::remove_var("PI_CODING_AGENT_SESSION_DIR"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_transcript_spec_dispatches_locate_and_extract() {
        let spec = &CLAUDE_PROFILE.transcript;
        // A nonexistent transcript locates to nothing; the extractors read
        // real lines through the spec exactly as through the plain fns.
        assert!((spec.locate)("no-such-session", Some("/definitely/not/here"), None).is_none());
        let lines = vec![
            r#"{"type":"assistant","isSidechain":false,"message":{"model":"claude-sonnet-5","content":[{"type":"text","text":"hello there"}],"usage":{"input_tokens":1,"cache_creation_input_tokens":2,"cache_read_input_tokens":3,"output_tokens":9}}}"#
                .to_string(),
            r#"{"type":"custom-title","customTitle":"Spec Title","sessionId":"s"}"#.to_string(),
        ];
        assert_eq!((spec.say)(&lines, true).as_deref(), Some("hello there"));
        assert_eq!((spec.title)(&lines).as_deref(), Some("Spec Title"));
        assert_eq!((spec.model)(&lines, true).as_deref(), Some("claude-sonnet-5"));
        assert_eq!((spec.context_tokens)(&lines), Some(6));
    }

    // ── the claude transcript readers (moved verbatim from
    //    conduct/src/graph/session_store.rs with their tests) ────────────────

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
    fn every_harness_extracts_its_latest_tool_call_into_one_label() {
        // claude: `tool_use` blocks inside an assistant message's content.
        let claude: Vec<String> = [
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"file_path":"/p/reap.rs"}}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"now the build"},{"type":"tool_use","name":"Bash","input":{"command":"cargo  test\n--workspace"}}]}}"#,
            r#"{"type":"assistant","isSidechain":true,"message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"fn reap"}}]}}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let spec = &CLAUDE_PROFILE.transcript;
        // The freshest NON-sidechain tool call wins, flattened to one line.
        assert_eq!(
            (spec.tool)(&claude, true).as_deref(),
            Some("Bash: cargo test --workspace")
        );
        // A sub-agent's own file is all-sidechain — read it with skip off.
        assert_eq!((spec.tool)(&claude, false).as_deref(), Some("Grep: fn reap"));

        // pi: `toolCall` blocks with `arguments`.
        let pi: Vec<String> = [
            r#"{"type":"message","message":{"role":"user","content":[{"type":"text","text":"go"}]}}"#,
            r#"{"type":"message","message":{"role":"assistant","content":[{"type":"toolCall","id":"c1","name":"bash","arguments":{"command":"git status"}}]}}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            (PI_PROFILE.transcript.tool)(&pi, true).as_deref(),
            Some("bash: git status")
        );

        // kimi: a `tool.call` loop event with `args`.
        let kimi: Vec<String> = [
            r#"{"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"hi"}}}"#,
            r#"{"type":"context.append_loop_event","event":{"type":"tool.call","name":"Bash","args":{"command":"nix build"}}}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            (KIMI_PROFILE.transcript.tool)(&kimi, true).as_deref(),
            Some("Bash: nix build")
        );

        // No tool call in the tail → nothing (never a stale or invented label).
        let quiet: Vec<String> =
            vec![r#"{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}"#.to_string()];
        assert!((spec.tool)(&quiet, true).is_none());
    }

    #[test]
    fn tool_label_falls_back_to_the_bare_name_and_clips() {
        // An argument shape with no recognised subject key still names the tool.
        assert_eq!(
            tool_label("TodoWrite", Some(&serde_json::json!({ "todos": [] }))).as_deref(),
            Some("TodoWrite")
        );
        assert_eq!(tool_label("Bash", None).as_deref(), Some("Bash"));
        // An empty subject is no subject.
        assert_eq!(
            tool_label("Bash", Some(&serde_json::json!({ "command": "   " }))).as_deref(),
            Some("Bash")
        );
        // A nameless call is not a tool call.
        assert_eq!(tool_label("  ", None), None);
        // Long subjects are clipped to one bounded line.
        let long = tool_label(
            "Bash",
            Some(&serde_json::json!({ "command": "x".repeat(400) })),
        )
        .unwrap();
        assert_eq!(long.chars().count(), 120);
        assert!(long.starts_with("Bash: x") && long.ends_with('…'));
    }

    #[test]
    fn one_line_clip_flattens_and_truncates() {
        assert_eq!(one_line_clip("a  b\n c", 80), "a b c");
        let long = "x".repeat(200);
        let clipped = one_line_clip(&long, 10);
        assert_eq!(clipped.chars().count(), 10);
        assert!(clipped.ends_with('…'));
    }

    // ── the eidolon profile ─────────────────────────────────────────────────

    #[test]
    fn eidolon_hook_event_map_has_no_vocabulary() {
        let map = EIDOLON_PROFILE.hook_event_map;
        // No hook file, no event vocabulary at all -- every input is
        // Unknown, including every lifecycle name the other three profiles
        // map.
        for evt in [
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "Stop",
            "Notification",
            "SubagentStart",
            "SubagentStop",
            "SessionEnd",
            "Zzz",
            "",
        ] {
            assert_eq!(map(evt), HookClass::Unknown, "event: {evt}");
        }
    }

    #[test]
    fn eidolon_profile_pins_the_absent_fields_and_declarative_settings() {
        assert!(EIDOLON_PROFILE.permission_vocab.is_empty());
        assert!(EIDOLON_PROFILE.subagent_tools.is_empty());
        assert!(EIDOLON_PROFILE.permission_keys.is_none());
        assert_eq!(EIDOLON_PROFILE.submit_key, "\r");
        assert_eq!(EIDOLON_PROFILE.skills_dir, None);
        assert!(EIDOLON_PROFILE.resume_args.is_none());
        assert_eq!(EIDOLON_PROFILE.launch, &["eidolon"]);
        assert_eq!(
            EIDOLON_PROFILE.hook_settings.relative_path,
            ".config/eidolon/config.toml"
        );
        assert_eq!(EIDOLON_PROFILE.hook_settings.format, SettingsFormat::Declarative);

        // No stripper: `context_ceiling_for_model` matches its family
        // tokens as a SUBSTRING search, so the "claude-cli:" prefix is
        // already inert. "claude-cli:opus" carries no version digits after
        // "opus", so it falls through to the conservative 200k default
        // (same as any other unrecognised id) -- a real versioned family
        // id embedded in the same prefixed shape resolves exactly as it
        // would bare.
        let ceil = EIDOLON_PROFILE.model_ceiling;
        assert_eq!(ceil(Some("claude-cli:opus")), 200_000);
        assert_eq!(ceil(Some("claude-cli:claude-sonnet-5")), 1_000_000);
        assert_eq!(ceil(Some("claude-cli:claude-haiku-4-5")), 200_000);
        assert_eq!(ceil(None), 200_000);

        // The one profile with a native inter-session transport; the three
        // existing profiles carry none (their only input surface is the
        // pty composer).
        assert!(EIDOLON_PROFILE.native_send.is_some());
        assert!(CLAUDE_PROFILE.native_send.is_none());
        assert!(KIMI_PROFILE.native_send.is_none());
        assert!(PI_PROFILE.native_send.is_none());
        let send = EIDOLON_PROFILE.native_send.expect("eidolon has a native transport");
        assert_eq!(
            send("fixture-target-1"),
            vec!["send", "--from", "aoide", "--wake", "fixture-target-1", "-"]
        );
    }

    #[test]
    fn eidolon_transcript_tail_and_extractors_fill_only_name_and_model() {
        let path =
            std::env::temp_dir().join(format!("aoide_eidolon_meta_{}.json", std::process::id()));
        // Synthetic fixture, PRETTY-PRINTED (multi-line) -- eidolon writes
        // meta.json via `serde_json::to_vec_pretty` (presence.rs:227-233),
        // so the on-disk file is never one compact line; `tail` must parse
        // it as one JSON value and re-emit it as a single compact line.
        // Shape matches the live-verified meta.json (id/pid/log/cwd/repo/
        // model/started_ms/title/busy); every value is synthetic, never
        // a real session.
        std::fs::write(
            &path,
            "{\n  \"id\": \"fixture-a1a1\",\n  \"pid\": 424242,\n  \"log\": \"/tmp/fixture/eidolon/session-a.eid\",\n  \"cwd\": \"/tmp/fixture-cwd\",\n  \"repo\": null,\n  \"model\": \"claude-cli:opus\",\n  \"started_ms\": 1000000000000,\n  \"title\": \"demo session\",\n  \"busy\": false\n}\n",
        )
        .unwrap();

        let spec = &EIDOLON_PROFILE.transcript;
        let lines = (spec.tail)(&path);
        assert_eq!(lines.len(), 1, "the pretty-printed value recompacts to exactly one line");
        assert!(!lines[0].contains('\n'), "the returned line is compact, not pretty-printed");

        // name/model fill from title/model...
        assert_eq!((spec.title)(&lines).as_deref(), Some("demo session"));
        assert_eq!((spec.model)(&lines, true).as_deref(), Some("claude-cli:opus"));
        // ...say/tool/contextTokens stay absent -- meta.json carries none of it.
        assert!((spec.say)(&lines, true).is_none());
        assert!((spec.tool)(&lines, true).is_none());
        assert!((spec.context_tokens)(&lines).is_none());
        // No sub-agent machinery for eidolon.
        assert!((spec.subagents_dir)("fixture-a1a1", None).is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn eidolon_transcript_tail_returns_empty_on_a_read_or_parse_error() {
        let spec = &EIDOLON_PROFILE.transcript;

        // No such file -- a read error, not a panic.
        let missing = std::env::temp_dir()
            .join(format!("aoide_eidolon_meta_missing_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        assert_eq!((spec.tail)(&missing), Vec::<String>::new());

        // A file that exists but is not valid JSON -- a parse error, not a
        // panic and not a best-effort partial line.
        let malformed = std::env::temp_dir()
            .join(format!("aoide_eidolon_meta_malformed_{}.json", std::process::id()));
        std::fs::write(&malformed, "{ not json").unwrap();
        assert_eq!((spec.tail)(&malformed), Vec::<String>::new());

        let _ = std::fs::remove_file(&malformed);
    }

    #[test]
    fn eidolon_transcript_locate_keys_on_the_native_presence_id_not_cwd() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let saved = std::env::var_os("XDG_RUNTIME_DIR");
        let root =
            std::env::temp_dir().join(format!("aoide_eidolon_runtime_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // Two LIVE presence dirs sharing one cwd -- the id, not the cwd,
        // must be what disambiguates them.
        let dir_a = root.join("eidolon").join("fixture-aaa1");
        let dir_b = root.join("eidolon").join("fixture-bbb2");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::write(
            dir_a.join("meta.json"),
            r#"{"id":"fixture-aaa1","pid":111,"log":"/tmp/fixture/a.eid","cwd":"/tmp/shared-cwd","repo":null,"model":"claude-cli:opus","started_ms":1,"title":"a","busy":false}"#,
        )
        .unwrap();
        std::fs::write(
            dir_b.join("meta.json"),
            r#"{"id":"fixture-bbb2","pid":222,"log":"/tmp/fixture/b.eid","cwd":"/tmp/shared-cwd","repo":null,"model":"claude-cli:opus","started_ms":2,"title":"b","busy":true}"#,
        )
        .unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let spec = &EIDOLON_PROFILE.transcript;
        // Same cwd argument passed for both lookups -- the id alone must
        // disambiguate, never the cwd.
        let found_a = (spec.locate)("fixture-aaa1", Some("/tmp/shared-cwd"), None).unwrap();
        let found_b = (spec.locate)("fixture-bbb2", Some("/tmp/shared-cwd"), None).unwrap();
        assert_ne!(found_a, found_b);
        assert_eq!(found_a, dir_a.join("meta.json"));
        assert_eq!(found_b, dir_b.join("meta.json"));

        // A hinted path that does NOT name this session's own file is never
        // followed -- it does not redirect session a's lookup to b's file.
        let wrong_hint = dir_b.join("meta.json");
        assert_eq!(
            (spec.locate)("fixture-aaa1", None, Some(wrong_hint.to_str().unwrap())),
            Some(dir_a.join("meta.json"))
        );
        // A hinted path that DOES name this exact file is (trivially)
        // honoured -- it agrees with the id-derived path, so nothing
        // changes.
        let right_hint = dir_a.join("meta.json");
        assert_eq!(
            (spec.locate)("fixture-aaa1", None, Some(right_hint.to_str().unwrap())),
            Some(dir_a.join("meta.json"))
        );

        // An unregistered id resolves to nothing.
        assert!((spec.locate)("fixture-nope", Some("/tmp/shared-cwd"), None).is_none());

        // XDG_RUNTIME_DIR unset falls back to `std::env::temp_dir()`,
        // exactly like eidolon's own `Presence::root()` (presence.rs:
        // 104-110) -- a session outside a systemd/login runtime dir (a
        // bare `sh`, a container with no XDG env) still resolves.
        std::env::remove_var("XDG_RUNTIME_DIR");
        let fallback_id = format!("fixture-fallback-{}", std::process::id());
        let fallback_dir = std::env::temp_dir().join("eidolon").join(&fallback_id);
        let _ = std::fs::remove_dir_all(&fallback_dir);
        std::fs::create_dir_all(&fallback_dir).unwrap();
        std::fs::write(
            fallback_dir.join("meta.json"),
            r#"{"id":"fixture-fallback","pid":333,"log":"/tmp/fixture/c.eid","cwd":"/tmp/shared-cwd","repo":null,"model":"claude-cli:opus","started_ms":3,"title":"c","busy":false}"#,
        )
        .unwrap();
        assert_eq!(
            (spec.locate)(&fallback_id, None, None),
            Some(fallback_dir.join("meta.json"))
        );
        let _ = std::fs::remove_dir_all(&fallback_dir);

        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn on_path_reflects_eidolons_launch_program_via_the_bin_probe() {
        // Same pattern as the shared `on_path_reflects_the_profiles_
        // launch_program_via_the_bin_probe` test above, run against
        // eidolon's own `launch` entry -- `command -v eidolon` may resolve
        // to a different binary from the one a live session runs (nix
        // store vs `~/.local/bin`), so this only proves "an `eidolon`
        // exists on PATH", never "this session's binary" (dispatch's own
        // live-facts caveat).
        let _guard = crate::bin::path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir()
            .join(format!("aoide_agents_on_path_eidolon_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("eidolon"), "").unwrap();
        std::env::set_var("PATH", &dir);

        assert!(on_path(&EIDOLON_PROFILE), "eidolon's launch program sits on the scoped PATH");

        std::fs::remove_file(dir.join("eidolon")).unwrap();
        assert!(!on_path(&EIDOLON_PROFILE), "eidolon's launch program no longer sits on PATH");

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
