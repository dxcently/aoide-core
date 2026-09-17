//! `session trace <id> [--tail N] [--follow] [--json]` — the run, step by
//! step, off the TRACE one harness mirrors beside its journal
//! (`docs/architecture/EIDOLON-TRACE.md`: read side Aoide, write side
//! eidolon).
//!
//! Every other harness's on-disk turn log is its TRANSCRIPT, and Aoide reads
//! it to fill `say`/`tool`/`contextTokens` — a handful of fields, never a
//! stream a caller can watch. eidolon mirrors its journal as ONE JSON RECORD
//! PER LINE and names that file from its own presence metadata, so the whole
//! run is readable in order: `AssistantMessage` (thinking, text, tool calls),
//! `ToolResult`, `TurnSettled`, `TurnBudget`/`TurnDeadline`, `AskUser`,
//! `ExternalMessage`, `Cancelled`. This module renders that stream and
//! nothing else — the contract (line shape, the state rule) is eidolon's and
//! is stated once in that design doc.
//!
//! **Nothing here is a second parser or a second resolver.**
//! `aoide_protocol::agents::eidolon_trace_record` turns one line into a
//! [`TraceRecord`] (the SAME function `eidolon_state_from_trace` folds
//! state from), the harness CAPABILITY is
//! `TranscriptSpec::trace` (never `if agent == "eidolon"` — see
//! `aoide-protocol`'s `AGENTS.md`), the trace PATH comes from
//! `TranscriptSpec::locate` (the same locator the reaper's transcript
//! refresh calls, so there is one answer to "which file is this session's"),
//! and `<id>` resolves through `aoide_storage::addr::resolve` — the exact
//! resolver `send --to` and bare `session`'s filter use. This module owns
//! only the RENDERING (`render_line`) and the `--follow` loop.
//!
//! **Read-only, no stage write, no daemon.** Nothing here mutates any file:
//! it loads `sessions.json`, derives a name for the session, reads the trace
//! and prints. It therefore takes no stage lock and never routes through
//! `aoide_client::daemon::daemon_dispatch` — unlike every session-WRITE
//! handler in this crate (P-D6's L4 family).
//!
//! **`--follow` blocks until Ctrl-C** and is CLI-only, the same shape
//! `events tail`/`secrets watch` hold: a follow-style command makes no sense
//! over MCP/A2A, where one connection would be parked until a human at the
//! other end gave up. `--json` in follow mode prints each NEW record line
//! verbatim (the line already IS the wire shape) rather than an envelope per
//! tick.
//!
//! **A session with no trace is a TAUGHT error, never an empty listing** —
//! three separate reasons, each named: the harness keeps no trace at all
//! (`TranscriptSpec::trace` is `None`), the presence metadata names none or
//! the file is gone (`locate` fell back to `meta.json`, which the trace
//! reader refuses), or the agent has no registered profile here.

use super::common::{require_args, stage_error};
use super::model::{load_stage, resolved_parent, sessions_path, SessionRecord, SessionsFile};
use aoide_protocol::agents::{agent_profile, eidolon_trace_record, TraceRecord};
use aoide_protocol::output::Outcome;
use aoide_protocol::Door;
use aoide_protocol::Invocation;
use aoide_storage::addr::{self, LocalCandidate, Resolution};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Records shown when `--tail` is absent — enough to see the last few turns
/// without a whole session's history scrolling past.
const DEFAULT_TAIL: usize = 50;
/// How long `--follow` waits between re-reads of the trace.
const FOLLOW_POLL: Duration = Duration::from_millis(500);
/// An `AssistantMessage`'s thinking block, clipped.
const THINKING_MAX: usize = 80;
/// An `AssistantMessage`'s text block, and every other one-line field, clipped.
const TEXT_MAX: usize = 120;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_signum: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// One whitespace-flattened line, clipped at a char boundary with a trailing
/// ellipsis. A local copy of the same three-line helper every renderer in
/// this crate carries (`protocol/src/agents.rs`, `graph/codex_capture.rs`) —
/// the SHARED copy is private to `protocol/agents`, and this is display-only
/// text, not a second reading of any record.
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

/// Clip to `max` chars at a char boundary with a trailing ellipsis, KEEPING
/// the text's own internal whitespace — the tool-result first line, where a
/// tab or a column of spaces is part of what the result printed.
fn clip_keep_ws(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// One record's own timestamp as `hh:mm:ss` in LOCAL time — libc's
/// `localtime_r` over `ts_ms / 1000` (eidolon's clock at append, epoch
/// milliseconds). A record with no readable `ts_ms`, or a timestamp
/// `localtime_r` refuses, renders `--:--:--` rather than a guess. Local, not
/// UTC: the reader is a human comparing this against their own clock.
fn hh_mm_ss_local(ts_ms: Option<i64>) -> String {
    const UNKNOWN: &str = "--:--:--";
    let Some(ms) = ts_ms else {
        return UNKNOWN.to_string();
    };
    let secs = ms.div_euclid(1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return UNKNOWN.to_string();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// The content blocks of an `AssistantMessage`/`UserMessage` payload; an
/// absent or non-array `content` reads as no blocks.
fn content_blocks(payload: Option<&Value>) -> &[Value] {
    const NONE: &[Value] = &[];
    payload
        .and_then(|p| p.get("content"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(NONE)
}

/// A payload string field, one-lined and clipped; empty when absent/blank.
fn field(payload: Option<&Value>, key: &str, max: usize) -> String {
    payload
        .and_then(|p| p.get(key))
        .and_then(Value::as_str)
        .map(|s| one_line_clip(s, max))
        .unwrap_or_default()
}

/// `AssistantMessage`: thinking cut to [`THINKING_MAX`] and (on a terminal)
/// dimmed, then text cut to [`TEXT_MAX`], then `→ <tool name>` per `tool_use`
/// — every block in the record's own order, joined. An empty block
/// contributes nothing (never an empty dim wrapper).
///
/// `dim` is passed in rather than probed here so the render is a pure
/// function of the record and one boolean — the caller decides, and a test
/// pins both spellings.
fn assistant_summary(payload: Option<&Value>, dim: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    for block in content_blocks(payload) {
        match block.get("type").and_then(Value::as_str) {
            Some("thinking") => {
                let t = field(Some(block), "thinking", THINKING_MAX);
                if !t.is_empty() {
                    parts.push(if dim { format!("\u{1b}[2m{t}\u{1b}[0m") } else { t });
                }
            }
            Some("text") => {
                let t = field(Some(block), "text", TEXT_MAX);
                if !t.is_empty() {
                    parts.push(t);
                }
            }
            Some("tool_use") => {
                let name = field(Some(block), "name", TEXT_MAX);
                if !name.is_empty() {
                    parts.push(format!("→ {name}"));
                }
            }
            _ => {}
        }
    }
    parts.join("  ")
}

/// `ToolResult`: the result's FIRST line cut to [`TEXT_MAX`], prefixed `!`
/// when `is_error`. `content` is a string in eidolon's own sample shape; an
/// array of blocks (a shape nothing forbids) falls back to its first `text`.
fn tool_result_summary(payload: Option<&Value>, prefix: &str) -> String {
    let Some(p) = payload else {
        return String::new();
    };
    let raw = match p.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(_)) => content_blocks(Some(p))
            .iter()
            .find_map(|b| b.get("text").and_then(Value::as_str))
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    };
    let first = raw.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        return String::new();
    }
    format!("{prefix}{}", clip_keep_ws(first, TEXT_MAX))
}

/// `TurnSettled`: the stop reason and the turn's input/output tokens, each
/// omitted when the record does not carry it.
fn settled_summary(payload: Option<&Value>) -> String {
    let stop = field(payload, "stop_reason", TEXT_MAX);
    let usage = payload.and_then(|p| p.get("usage"));
    let num = |key: &str| {
        usage
            .and_then(|u| u.get(key))
            .and_then(Value::as_i64)
            .map(|n| n.to_string())
    };
    let mut parts: Vec<String> = Vec::new();
    if !stop.is_empty() {
        parts.push(stop);
    }
    if let (Some(i), Some(o)) = (num("input_tokens"), num("output_tokens")) {
        parts.push(format!("in {i} out {o}"));
    } else if let Some(i) = num("input_tokens") {
        parts.push(format!("in {i}"));
    } else if let Some(o) = num("output_tokens") {
        parts.push(format!("out {o}"));
    }
    parts.join(" · ")
}

/// `AskUser`: the prompt, plus whether it is still open (`answer: null`) or
/// was answered — the one salient field the state rule also reads.
fn ask_summary(payload: Option<&Value>) -> String {
    let prompt = field(payload, "prompt", TEXT_MAX);
    let answered = payload
        .and_then(|p| p.get("answer"))
        .map(|a| !a.is_null())
        .unwrap_or(false);
    let verdict = if answered { "(answered)" } else { "(open)" };
    if prompt.is_empty() {
        verdict.to_string()
    } else {
        format!("{prompt} {verdict}")
    }
}

/// `ExternalMessage`: who steered it and what they said.
fn external_summary(payload: Option<&Value>) -> String {
    let from = field(payload, "from", TEXT_MAX);
    let text = field(payload, "text", TEXT_MAX);
    match (from.is_empty(), text.is_empty()) {
        (false, false) => format!("{from}: {text}"),
        (false, true) => from,
        (true, false) => text,
        (true, true) => String::new(),
    }
}

/// A `UserMessage`'s first text block — the first thing asked.
fn user_summary(payload: Option<&Value>) -> String {
    content_blocks(payload)
        .iter()
        .find(|b| b.get("type").and_then(Value::as_str) == Some("text"))
        .and_then(|b| b.get("text").and_then(Value::as_str))
        .map(|t| one_line_clip(t, TEXT_MAX))
        .unwrap_or_default()
}

/// The one-line summary a record renders after its kind. Kinds the design
/// doc names get their own arm; everything else (a `UserMessage`, a
/// `SessionStart`, a newer eidolon's variant Aoide has never heard of)
/// degrades to its own salient field where one is known and to the compact
/// payload otherwise — never to nothing, so an unfamiliar record is still
/// visible rather than silently blank.
fn summary(record: &TraceRecord, dim: bool) -> String {
    let p = record.payload.as_ref();
    match record.kind.as_str() {
        "AssistantMessage" => assistant_summary(p, dim),
        // `Cancelled`/`TurnDeadline` ride the same arm shape as the rest:
        // a unit variant carries no payload, so it renders the kind alone.
        "ToolResult" => {
            let is_error = p
                .and_then(|p| p.get("is_error"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            tool_result_summary(p, if is_error { "! " } else { "" })
        }
        "TurnSettled" => settled_summary(p),
        "AskUser" => ask_summary(p),
        "ExternalMessage" => external_summary(p),
        "TurnBudget" => numeric_field(p, "calls_left"),
        "TurnDeadline" => numeric_field(p, "secs_left"),
        "ContextSize" => numeric_field(p, "tokens"),
        "PolicyVerdict" => field(p, "outcome", TEXT_MAX),
        "SessionStart" | "ModelChanged" => prefixed_field(p, "model", "model=", TEXT_MAX),
        "UserMessage" => user_summary(p),
        _ => p.map(|p| one_line_clip(&p.to_string(), TEXT_MAX)).unwrap_or_default(),
    }
}

/// `key=value` for one payload field, whichever of the two spellings the
/// journal used — the sample contract writes numbers, and nothing about the
/// shape promises it stays one. Empty (the whole column omitted) when the
/// record carries no such field.
fn numeric_field(payload: Option<&Value>, key: &str) -> String {
    let Some(v) = payload.and_then(|p| p.get(key)) else {
        return String::new();
    };
    match v {
        Value::Number(n) => format!("{key}={n}"),
        Value::String(s) if !s.trim().is_empty() => format!("{key}={}", one_line_clip(s, TEXT_MAX)),
        _ => String::new(),
    }
}

/// `prefix<value>` for one payload string field, the whole column omitted
/// when the field is absent or blank — never a dangling `model=`.
fn prefixed_field(payload: Option<&Value>, key: &str, prefix: &str, max: usize) -> String {
    let v = field(payload, key, max);
    if v.is_empty() {
        String::new()
    } else {
        format!("{prefix}{v}")
    }
}

/// One record as the human line the design doc fixes:
/// `#<id>  <hh:mm:ss>  <kind>  <summary>` — the summary omitted (never a
/// trailing blank column) when the record has nothing to say.
fn render_line(record: &TraceRecord, dim: bool) -> String {
    let mut line = format!(
        "#{}  {}  {}",
        record.id,
        hh_mm_ss_local(record.ts_ms),
        record.kind
    );
    let s = summary(record, dim);
    if !s.is_empty() {
        line.push_str("  ");
        line.push_str(&s);
    }
    line
}

/// A tail line that is NOT a readable record — a torn write, a hand-edit, a
/// line from a newer eidolon whose shape Aoide cannot name — still gets a
/// line, flagged `?`, rather than being dropped silently.
fn render_unparsed(line: &str) -> String {
    format!("#?  --:--:--  ?  {}", one_line_clip(line, TEXT_MAX))
}

/// Render one line: the parsed record's own rendering, or the `?` line.
fn render_any(line: &str, dim: bool) -> String {
    match eidolon_trace_record(line) {
        Some(record) => render_line(&record, dim),
        None => render_unparsed(line),
    }
}

/// The last `tail` lines of a trace, in file order — the render window.
fn last_lines<'a>(lines: &'a [String], tail: usize) -> Vec<&'a String> {
    lines.iter().rev().take(tail).rev().collect()
}

/// `--tail N` — a positive integer, or the default. A value the flag did not
/// carry (`--tail` with no token, which the parser stores as `"true"`) or a
/// `0` is a taught usage error, never a silently empty listing.
fn parse_tail(inv: &Invocation) -> Result<usize, Outcome> {
    let Some(raw) = inv.flags.get("tail") else {
        return Ok(DEFAULT_TAIL);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(DEFAULT_TAIL);
    }
    match raw.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(Outcome::usage(
            "session.trace",
            format!(
                "`{raw}` is not a record count — --tail takes a positive integer (e.g. --tail 20); \
                 omit it for the last {DEFAULT_TAIL} records"
            ),
        )
        .with_data(json!({ "reason": "bad-tail", "tail": raw }))),
    }
}

/// The session's name for the message line, through the canonical display
/// grammar — the same render `session pending list` gives a target, falling
/// back to the raw id when no record carries it.
fn label(id: &str, records: &[SessionRecord], ids: &HashSet<&str>, host: &str) -> String {
    match records.iter().find(|r| r.session_id == id) {
        Some(rec) => {
            let role = if resolved_parent(rec, ids).is_some() { "child" } else { "root" };
            aoide_storage::display::session_label(rec, host, role)
        }
        None => id.to_string(),
    }
}

/// Is stdout a terminal? Dimming an `AssistantMessage`'s thinking is a
/// display nicety; a redirected/piped read gets plain text, the same
/// discipline `aoide_protocol::pick` holds for its own ANSI.
fn stdout_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// `session trace <id> [--tail N] [--follow] [--json]` — see the module doc.
pub fn session_trace(inv: &Invocation) -> Outcome {
    let cmd = "session.trace";
    let args = match require_args(inv, &["id"]) {
        Ok(a) => a,
        Err(o) => return o,
    };
    let target = args[0].trim().to_string();
    let tail = match parse_tail(inv) {
        Ok(n) => n,
        Err(o) => return o,
    };
    let json_mode = inv.flag_present("json");
    let follow = inv.flag_present("follow");
    if follow && inv.door != Door::Cli {
        return Outcome::usage(
            cmd,
            "--follow blocks until Ctrl-C; run it from a terminal (not over this door)",
        );
    }

    // `<id>` resolves exactly like `send --to`: the ONE
    // `aoide_storage::addr::resolve`, over this box's live roster plus its
    // registered node names, with the same ambiguity/not-found
    // refusals. No hub preference here — that is a ROUTING rule for `send`
    // (P-D5), not a rule for reading a file that lives on THIS box.
    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let host = aoide_storage::display::local_host_name();
    let ids: HashSet<&str> = file.sessions.iter().map(|s| s.session_id.as_str()).collect();
    let candidates: Vec<LocalCandidate<'_>> = file
        .sessions
        .iter()
        .map(|s| {
            let role = if resolved_parent(s, &ids).is_some() { "child" } else { "root" };
            LocalCandidate { session_id: &s.session_id, petname: s.petname.as_deref(), role }
        })
        .collect();
    let nodes = aoide_storage::node_store::load_nodes();
    let node_names: Vec<&str> = nodes.iter().map(|p| p.name.as_str()).collect();

    let id = match addr::resolve(&target, &host, &candidates, &node_names) {
        Resolution::Local(id) => id,
        Resolution::Remote { node, .. } => {
            return Outcome::error(
                cmd,
                format!(
                    "`{target}` resolves to a session on node `{node}` — a trace is a file on the \
                     node that wrote it, so run `session trace` there"
                ),
            )
            .with_data(json!({ "reason": "remote-target", "node": node, "target": target }));
        }
        Resolution::Ambiguous(found) => {
            return Outcome::error(
                cmd,
                format!(
                    "`{target}` is ambiguous — {} local session(s) match: {}",
                    found.len(),
                    found.join(", ")
                ),
            )
            .with_data(json!({ "reason": "ambiguous", "target": target, "candidates": found }));
        }
        Resolution::NotFound => {
            let hint = if !target.contains('/') && node_names.contains(&target.as_str()) {
                format!(
                    " (`{target}` names a known node, not a local session — did you mean `{target}/<session>`?)"
                )
            } else {
                String::new()
            };
            return Outcome::error(cmd, format!("no session matches `{target}`{hint}"))
                .with_data(json!({ "reason": "not-found", "target": target }));
        }
    };

    // The trace is a HARNESS CAPABILITY, never a name check: a profile whose
    // `TranscriptSpec::trace` is `None` keeps no trace file at all, and
    // saying so is the honest answer (the capability test is why no consumer
    // here writes `if agent == "eidolon"`).
    let name = label(&id, &file.sessions, &ids, &host);
    let agent = file
        .sessions
        .iter()
        .find(|r| r.session_id == id)
        .map(|r| r.agent.clone())
        .unwrap_or_default();
    let Some(profile) = agent_profile(&agent) else {
        return Outcome::error(
            cmd,
            format!("`{name}` runs `{agent}`, which has no registered agent profile here — no trace reader to reach"),
        )
        .with_data(json!({ "reason": "unknown-agent", "sessionId": id, "agent": agent }));
    };
    let Some(read_trace) = profile.transcript.trace else {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` runs `{agent}`, which keeps no trace — a trace is a file a harness \
                 mirrors its journal into, one JSON record per line, and names from its own \
                 presence metadata; `eidolon` is the one harness that does today \
                 (docs/architecture/EIDOLON-TRACE.md)"
            ),
        )
        .with_data(json!({
            "reason": "no-trace-capability",
            "sessionId": id,
            "agent": agent,
        }));
    };

    // The PATH is the same locator every other transcript reader uses: it
    // prefers the file the presence metadata names, and falls back to the
    // metadata itself when there is none.
    let cwd = file
        .sessions
        .iter()
        .find(|r| r.session_id == id)
        .map(|r| r.cwd.clone())
        .unwrap_or_default();
    let Some(path) = (profile.transcript.locate)(&id, Some(&cwd), None) else {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` has no readable presence metadata — looked for \
                 $XDG_RUNTIME_DIR/eidolon/{id}/meta.json (a torn-down or never-registered presence)"
            ),
        )
        .with_data(json!({ "reason": "no-presence", "sessionId": id }));
    };
    let Some(lines) = read_trace(&path) else {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` has no trace at {} — its presence metadata names no `trace` file \
                 (an older eidolon, or a session that never wrote one), and a file that is not \
                 a `.jsonl` trace is not one",
                path.display()
            ),
        )
        .with_data(json!({
            "reason": "no-trace",
            "sessionId": id,
            "presence": path.to_string_lossy(),
        }));
    };

    if follow {
        return follow_trace(cmd, &id, &name, &path, read_trace, tail, json_mode);
    }

    let shown = last_lines(&lines, tail);
    let dim = stdout_is_terminal();
    let raw: Vec<String> = shown.iter().map(|l| (*l).clone()).collect();
    let body: Vec<String> = shown.iter().map(|l| render_any(l, dim)).collect();
    let mut message = format!("{} record(s) · {name}", body.len());
    if !json_mode && !body.is_empty() {
        message.push('\n');
        message.push_str(&body.join("\n"));
    }
    Outcome::ok(cmd, message)
        .with_data(json!({
            "sessionId": id,
            "trace": path.to_string_lossy(),
            "tail": tail,
            "records": body.len(),
            "lines": raw,
        }))
}

/// `--follow`: print the current window, then re-read the trace every
/// [`FOLLOW_POLL`] and print whatever grew, until Ctrl-C. Re-reading the
/// tail each tick (rather than holding a delta reader open) keeps this on
/// the SAME reader as the one-shot path — the file is a bounded 1 MiB window,
/// and a trace that was rotated or truncated simply yields a shorter list,
/// which this loop notices by count rather than replaying history.
fn follow_trace(
    cmd: &str,
    id: &str,
    name: &str,
    path: &Path,
    read_trace: fn(&Path) -> Option<Vec<String>>,
    tail: usize,
    json_mode: bool,
) -> Outcome {
    use std::io::Write;
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
    let dim = stdout_is_terminal();
    let emit = |line: &str| {
        if json_mode {
            println!("{line}");
        } else {
            println!("{}", render_any(line, dim));
        }
        let _ = std::io::stdout().flush();
    };

    let mut seen = 0usize;
    let mut printed = 0usize;
    if let Some(lines) = read_trace(path) {
        let window = last_lines(&lines, tail);
        seen = lines.len();
        for line in window {
            emit(line);
            printed += 1;
        }
    }
    while !INTERRUPTED.load(Ordering::SeqCst) {
        std::thread::sleep(FOLLOW_POLL);
        if INTERRUPTED.load(Ordering::SeqCst) {
            break;
        }
        let Some(lines) = read_trace(path) else {
            continue; // the file is momentarily not there — keep waiting
        };
        if lines.len() < seen {
            // Rotated, truncated, or replaced: start counting from the new tail.
            seen = lines.len();
            continue;
        }
        for line in lines.iter().skip(seen) {
            emit(line);
            printed += 1;
        }
        seen = lines.len();
    }
    Outcome::ok(cmd, format!("followed {printed} record(s) · {name}"))
        .with_data(json!({
            "sessionId": id,
            "trace": path.to_string_lossy(),
            "followed": true,
            "printed": printed,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::{unique_stage, EnvVars};
    use aoide_protocol::output::Status;
    use std::collections::BTreeMap;

    // The design doc's own sample lines, verbatim (EIDOLON-TRACE.md's "Line"
    // block) — the same fixtures `protocol/agents.rs` and `graph/eidolon.rs`
    // pin their own halves against.
    const START: &str = r#"{"id":0,"parent":null,"ts_ms":1789603005561,"kind":{"SessionStart":{"model":"ollama:deepseek-v4.1-flash","cwd":"/home/khoa/Aoide","system":null}}}"#;
    const USER: &str = r##"{"id":1,"parent":0,"ts_ms":1789603005570,"kind":{"UserMessage":{"role":"user","content":[{"type":"text","text":"# Brief A: …"}]}}}"##;
    const ASSISTANT: &str = r#"{"id":2,"parent":1,"ts_ms":1789603009102,"kind":{"AssistantMessage":{"role":"assistant","content":[{"type":"thinking","thinking":"I should read the slot catalog first, and then compare it against the facets directory to see which surfaces each song claims for itself.","signature":"…"},{"type":"text","text":"Let me read the slot catalog first."},{"type":"tool_use","id":"call_8vr43zri","name":"read","input":{"path":"modules/facets/quickshell/qml/slots.md"}}]}}}"#;
    const RESULT: &str = r#"{"id":3,"parent":2,"ts_ms":1789603009140,"kind":{"ToolResult":{"tool_use_id":"call_8vr43zri","content":"     1\t# Per-song widget slots\n     2\tcatalog\n","is_error":false}}}"#;
    const RESULT_ERR: &str = r#"{"id":4,"parent":3,"ts_ms":1789603009200,"kind":{"ToolResult":{"tool_use_id":"call_9","content":"ENOENT: no such file\nmore","is_error":true}}}"#;
    const SETTLED: &str = r#"{"id":131,"parent":130,"ts_ms":1789606421000,"kind":{"TurnSettled":{"stop_reason":"end_turn","usage":{"input_tokens":9570000,"output_tokens":71900,"cache_creation_input_tokens":0,"cache_read_input_tokens":9430000}}}}"#;
    const CANCELLED: &str = r#"{"id":77,"parent":76,"ts_ms":1789626990000,"kind":"Cancelled"}"#;
    const ASK: &str = r#"{"id":40,"parent":39,"ts_ms":1789626500000,"kind":{"AskUser":{"call_id":"call_x","prompt":"Overwrite?","answer":null}}}"#;
    const BUDGET: &str = r#"{"id":120,"parent":119,"ts_ms":1789606380000,"kind":{"TurnBudget":{"calls_left":8}}}"#;
    const EXTERNAL: &str = r#"{"id":55,"parent":54,"ts_ms":1789626700000,"kind":{"ExternalMessage":{"from":"orchestrator","channel":null,"text":"STOP: write the report now"}}}"#;

    fn trace_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["session".into(), "trace".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
            door: Door::Cli,
        }
    }

    /// A fake eidolon presence + trace on disk, plus the roster record that
    /// makes `session trace` find it: the locator resolves
    /// `$XDG_RUNTIME_DIR/eidolon/<id>/meta.json`, and that file names the
    /// trace. Returns the root the caller removes.
    fn fixture(tag: &str, id: &str, agent: &str, lines: &[&str], with_trace_key: bool) -> std::path::PathBuf {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let trace = sessions.join(format!("{id}.jsonl"));
        // An empty slice writes an EMPTY file, not one blank line — the
        // difference between "a trace with no records yet" and "a trace
        // holding an unreadable line".
        let body = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        std::fs::write(&trace, body).unwrap();

        let presence = root.join("eidolon").join(id);
        std::fs::create_dir_all(&presence).unwrap();
        let trace_field = if with_trace_key {
            format!(r#","trace":"{}""#, trace.display())
        } else {
            String::new()
        };
        std::fs::write(
            presence.join("meta.json"),
            format!(
                r#"{{"id":"{id}","pid":4242,"log":"{id}.eid","cwd":"/home/khoa","model":"claude-cli:opus","title":"ng","busy":false{trace_field}}}"#
            ),
        )
        .unwrap();

        std::fs::write(
            stage.join("sessions.json"),
            format!(
                r#"{{"schemaVersion":"0","sessions":[{{"sessionId":"{id}","agent":"{agent}","cwd":"/home/khoa","state":"working","startedAt":"2026-09-12T00:00:00Z","petname":"brave-otter"}}]}}"#
            ),
        )
        .unwrap();
        root
    }

    fn env_keys() -> [&'static str; 5] {
        [
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_HOME",
            "HOME",
        ]
    }

    // ── the render, pure ─────────────────────────────────────────────────

    #[test]
    fn an_assistant_message_renders_thinking_text_and_every_tool_call() {
        let rec = eidolon_trace_record(ASSISTANT).expect("the doc's assistant line is a record");
        let line = render_line(&rec, false);
        assert!(line.starts_with("#2  "), "{line}");
        assert!(line.contains("AssistantMessage"), "{line}");
        assert!(
            line.contains("I should read the slot catalog first"),
            "the thinking block is shown: {line}"
        );
        assert!(line.contains("Let me read the slot catalog first."), "{line}");
        assert!(line.contains("→ read"), "a tool_use renders its name: {line}");
        // 80-char thinking / 120-char text: the doc's own thinking sample is
        // longer than the window, so it is clipped, not dropped.
        assert!(line.contains('…'), "the long thinking block is clipped: {line}");
        assert!(!line.contains('\u{1b}'), "undimmed render carries no escapes: {line}");
    }

    #[test]
    fn thinking_is_dimmed_only_when_the_renderer_is_told_to() {
        let rec = eidolon_trace_record(ASSISTANT).unwrap();
        let dim = render_line(&rec, true);
        assert!(dim.contains("\u{1b}[2m"), "{dim}");
        assert!(dim.contains("\u{1b}[0m"), "{dim}");
        // Everything else is unchanged by the flag.
        assert_eq!(
            dim.replace("\u{1b}[2m", "").replace("\u{1b}[0m", ""),
            render_line(&rec, false)
        );
    }

    #[test]
    fn a_tool_result_shows_its_first_line_and_flags_an_error() {
        let ok = render_line(&eidolon_trace_record(RESULT).unwrap(), false);
        assert!(ok.contains("ToolResult"), "{ok}");
        assert!(ok.contains("# Per-song widget slots"), "{ok}");
        assert!(!ok.contains("catalog"), "only the FIRST line is shown: {ok}");
        assert!(!ok.contains("! "), "{ok}");

        let err = render_line(&eidolon_trace_record(RESULT_ERR).unwrap(), false);
        assert!(err.contains("! ENOENT: no such file"), "{err}");
        assert!(!err.contains("more"), "the second line is cut: {err}");
    }

    #[test]
    fn the_remaining_kinds_each_show_their_one_salient_field() {
        let s = render_line(&eidolon_trace_record(SETTLED).unwrap(), false);
        assert!(s.contains("end_turn"), "{s}");
        assert!(s.contains("in 9570000 out 71900"), "{s}");

        let c = render_line(&eidolon_trace_record(CANCELLED).unwrap(), false);
        assert!(c.contains("Cancelled"), "{c}");
        assert!(c.ends_with("Cancelled"), "a unit variant renders its kind alone: {c}");

        let a = render_line(&eidolon_trace_record(ASK).unwrap(), false);
        assert!(a.contains("Overwrite? (open)"), "{a}");

        let b = render_line(&eidolon_trace_record(BUDGET).unwrap(), false);
        assert!(b.contains("calls_left=8"), "{b}");

        let e = render_line(&eidolon_trace_record(EXTERNAL).unwrap(), false);
        assert!(e.contains("orchestrator: STOP: write the report now"), "{e}");

        let u = render_line(&eidolon_trace_record(USER).unwrap(), false);
        assert!(u.contains("# Brief A: …"), "{u}");

        let st = render_line(&eidolon_trace_record(START).unwrap(), false);
        assert!(st.contains("model=ollama:deepseek-v4.1-flash"), "{st}");
    }

    #[test]
    fn a_kind_aoide_has_never_heard_of_renders_its_payload_never_nothing() {
        let rec = eidolon_trace_record(r#"{"id":9,"ts_ms":1,"kind":{"SomethingNew":{"x":1}}}"#).unwrap();
        let line = render_line(&rec, false);
        assert!(line.contains("SomethingNew"), "{line}");
        assert!(line.contains("\"x\":1"), "an unknown kind still shows its payload: {line}");
    }

    #[test]
    fn an_unreadable_line_renders_as_a_flagged_line_never_dropped() {
        let line = render_any("{ not json", false);
        assert!(line.starts_with("#?  --:--:--  ?"), "{line}");
        assert!(line.contains("not json"), "{line}");
        // A line with no usable ts_ms reads `--:--:--`, never an epoch guess.
        let rec = eidolon_trace_record(r#"{"id":5,"kind":{"ContextSize":{"tokens":134700}}}"#).unwrap();
        assert!(render_line(&rec, false).contains("--:--:--"));
    }

    // ── the command, end to end over a fake presence ──────────────────────

    #[test]
    fn trace_renders_the_last_records_of_a_real_trace_file() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&env_keys());
        let root = fixture(
            "trace-basic",
            "Aoide-7d23",
            "eidolon",
            &[START, USER, ASSISTANT, RESULT, BUDGET, SETTLED],
            true,
        );

        let out = session_trace(&trace_invocation(&["Aoide-7d23"], &[]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        let data = out.data.clone().unwrap();
        assert_eq!(data["sessionId"], "Aoide-7d23");
        assert_eq!(data["records"], 6, "the whole short trace fits under the default tail");
        assert!(data["trace"].as_str().unwrap().ends_with("Aoide-7d23.jsonl"));
        let lines = data["lines"].as_array().unwrap();
        assert_eq!(lines[0].as_str().unwrap(), START, "--json passes the raw lines through verbatim");
        assert!(out.message.contains("6 record(s)"), "{}", out.message);
        // The human body: one line per record, `#id  hh:mm:ss  kind  summary`.
        let body: Vec<&str> = out.message.lines().skip(1).collect();
        assert_eq!(body.len(), 6);
        assert!(body[0].starts_with("#0  ") && body[0].contains("SessionStart"), "{:?}", body[0]);
        assert!(body[2].contains("→ read"), "{:?}", body[2]);
        assert!(body[5].contains("end_turn"), "{:?}", body[5]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tail_narrows_to_the_last_n_records() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&env_keys());
        let root = fixture("trace-tail", "Aoide-tail", "eidolon", &[START, USER, ASSISTANT, SETTLED], true);

        let out = session_trace(&trace_invocation(&["Aoide-tail"], &[("tail", "2")]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.clone().unwrap()["records"], 2);
        let lines = out.data.clone().unwrap()["lines"].as_array().unwrap().clone();
        assert_eq!(lines[0].as_str().unwrap(), ASSISTANT, "the last two, in file order");
        assert_eq!(lines[1].as_str().unwrap(), SETTLED);
        assert!(!out.message.contains("#0  "), "the older records are outside the window: {}", out.message);

        // A non-numeric / zero --tail is a taught usage error, never a silent
        // empty listing.
        for bad in ["nope", "0", "true"] {
            let out = session_trace(&trace_invocation(&["Aoide-tail"], &[("tail", bad)]));
            assert_eq!(out.status, Status::Usage, "--tail {bad}: {}", out.message);
            assert_eq!(out.data.unwrap()["reason"], "bad-tail");
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_name_tail4_or_petname_resolves_through_the_one_resolver() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&env_keys());
        let root = fixture("trace-resolve", "eidolon-abcdef", "eidolon", &[SETTLED], true);

        let tail4 = session_trace(&trace_invocation(&["cdef"], &[]));
        assert_eq!(tail4.status, Status::Ok, "tail4 must resolve: {}", tail4.message);
        assert_eq!(tail4.data.unwrap()["sessionId"], "eidolon-abcdef");

        let petname = session_trace(&trace_invocation(&["brave-otter"], &[]));
        assert_eq!(petname.status, Status::Ok, "petname must resolve: {}", petname.message);
        assert_eq!(petname.data.unwrap()["sessionId"], "eidolon-abcdef");

        let exact = session_trace(&trace_invocation(&["eidolon-abcdef"], &[]));
        assert_eq!(exact.status, Status::Ok);

        // Ambiguity and a miss are the resolver's own refusals, verbatim.
        let miss = session_trace(&trace_invocation(&["nothing-matches-this"], &[]));
        assert_eq!(miss.status, Status::Error);
        assert_eq!(miss.data.unwrap()["reason"], "not-found");
        assert!(miss.message.contains("no session matches"), "{}", miss.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_session_without_a_trace_gets_a_taught_error_naming_why() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&env_keys());

        // 1. The harness keeps no trace at all.
        let root = fixture("trace-notrace", "Aoide-old", "eidolon", &[SETTLED], false);
        let out = session_trace(&trace_invocation(&["Aoide-old"], &[]));
        assert_eq!(out.status, Status::Error, "msg: {}", out.message);
        assert_eq!(out.data.clone().unwrap()["reason"], "no-trace");
        assert!(out.message.contains("names no `trace` file"), "{}", out.message);
        assert!(out.message.contains("older eidolon"), "{}", out.message);
        let _ = std::fs::remove_dir_all(&root);

        // 2. A harness that keeps none by construction (claude's profile has
        //    `transcript.trace == None`).
        let root = fixture("trace-claude", "claude-1", "claude", &[SETTLED], true);
        let out = session_trace(&trace_invocation(&["claude-1"], &[]));
        assert_eq!(out.status, Status::Error, "msg: {}", out.message);
        assert_eq!(out.data.clone().unwrap()["reason"], "no-trace-capability");
        assert!(out.message.contains("keeps no trace"), "{}", out.message);
        let _ = std::fs::remove_dir_all(&root);

        // 3. An eidolon record whose presence is gone entirely.
        let root = fixture("trace-nopresence", "Aoide-gone", "eidolon", &[SETTLED], true);
        std::fs::remove_dir_all(root.join("eidolon")).unwrap();
        let out = session_trace(&trace_invocation(&["Aoide-gone"], &[]));
        assert_eq!(out.status, Status::Error, "msg: {}", out.message);
        assert_eq!(out.data.clone().unwrap()["reason"], "no-presence");
        assert!(out.message.contains("no readable presence metadata"), "{}", out.message);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_empty_trace_is_an_honest_empty_listing_not_a_taught_error() {
        // `eidolon_trace_tail` answers `Some(empty)` for a trace that exists
        // and holds nothing yet — that IS the authority, and the command
        // reports it as zero records rather than claiming no trace exists.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&env_keys());
        let root = fixture("trace-empty", "Aoide-empty", "eidolon", &[], true);

        let out = session_trace(&trace_invocation(&["Aoide-empty"], &[]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.unwrap()["records"], 0);
        assert!(out.message.starts_with("0 record(s)"), "{}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn follow_is_cli_only_and_a_missing_id_is_a_usage_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&env_keys());
        let root = fixture("trace-follow", "Aoide-follow", "eidolon", &[SETTLED], true);

        let mut inv = trace_invocation(&["Aoide-follow"], &[("follow", "true")]);
        inv.door = Door::Mcp;
        let out = session_trace(&inv);
        assert_eq!(out.status, Status::Usage, "msg: {}", out.message);
        assert!(out.message.contains("--follow blocks until Ctrl-C"), "{}", out.message);

        let out = session_trace(&trace_invocation(&[], &[]));
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("missing required argument <id>"), "{}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn session_trace_registers_at_the_expected_path() {
        let mut r = aoide_protocol::registry::Registry::new();
        crate::commands::graph::register(&mut r);
        let cmd = r
            .get(&["session".to_string(), "trace".to_string()])
            .expect("session trace must be registered");
        assert_eq!(cmd.dotted(), "session.trace");
        assert!(cmd.implemented && !cmd.gated);
        assert!(cmd.args.iter().any(|a| a.name == "id" && a.required));
        for f in ["tail", "follow", "json"] {
            assert!(cmd.flags.iter().any(|x| x.name == f), "missing --{f}: {:?}", cmd.flags);
        }
    }
}
