//! Native Codex capture (P-CX-5, the codex-integration follow-on): a PURE
//! fold from a Codex rollout's own JSONL lines into one [`CodexCapture`]
//! ([`fold_rollout`]/[`fold_rollout_from`]), plus the bounded, impure reader
//! over a live rollout ([`capture_for`]) that feeds it. `codex_app.rs`'s
//! `sync_codex_app_threads` is the one caller: it gathers a [`CodexCapture`]
//! per desired thread and merges `say`/`tool`/`activity`/`model`/
//! `context_tokens`/`context_ceiling`/`sources` onto that thread's
//! `kind:"app"` record, change-only. `state`/`parentSessionId`/`title` stay
//! untouched by that merge — later slices' own territory, not this one's.
//!
//! [`fold_rollout`] walks `lines` in order; `ordinal` is the line's own
//! position in the slice, never a value read out of the record itself — the
//! ruling that pins the pointer contract. [`fold_rollout_from`] is the same
//! fold with an explicit starting ordinal, for a caller (namely
//! [`capture_for`]) handing it only the TAIL of a rollout: the lines it
//! folds are a slice, but a pointer must still name the record's TRUE line
//! number in the whole file. A line that fails to parse as JSON, whether
//! truncated by a tail cut or simply malformed, contributes nothing: nothing
//! here ever infers a field from a record it could not read whole. Every
//! value this fold DOES capture carries a `sources` pointer
//! (`<path>#<ordinal>`), so a rendered datum with no pointer is a bug in a
//! caller, never a judgement call made here.
//!
//! [`capture_for`] locates a thread's rollout under a Codex sessions root
//! (`super::codex_app::find_rollout`, the same walk `thread_cwd` already
//! reuses — no second discovery path) and reads at most the last
//! [`TAIL_BYTES`] of it. A cut that lands mid-record leaves a partial line
//! at the front of the tail buffer; it is discarded, never parsed, the same
//! "unreadable whole, contributes nothing" rule the fold itself holds for a
//! truncated line anywhere else. A missing rollout, an unreadable one, or a
//! tail whose only content is one record too large to ever appear whole in
//! the window all yield [`CodexCapture::default`] — every field `None`,
//! which is data absent, never an idle/completion signal on its own and
//! never a reason to touch the roster (capture has no say in enrolment;
//! `codex_app.rs`'s `ThreadScan` stays the only authority for that).
//!
//! Two record shapes are recognised but always contribute nothing: a
//! `response_item`/`reasoning` record (opaque `encrypted_content`, empty
//! `summary`) and an `event_msg`/`item_completed` record whose item is
//! `Reasoning` (`summary_text`/`raw_content`, always empty on disk). A
//! reasoning trace is not on disk in any readable form, and no adjacent
//! record is ever fashioned into one.
//!
//! `state` is derived from the ORDER task-lifecycle events appear in, never
//! from elapsed time: the latest of `task_started`/`task_complete`/
//! `turn_aborted` decides `working`/`idle`. Nothing here ever produces
//! `awaiting` — there is no such event in the app's own records to read.
//!
//! `prompt` — the user's own latest turn, clipped to one line — is captured
//! under D1 (root ruling, codex seq 228: scope is Aoide's existing session
//! surfaces only). That authorization changes nothing about what this pure
//! function does; it folds one more field, sourced and pointed exactly like
//! every other.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

/// One-line clip bounds, matching the shape `aoide-protocol::agents`'s own
/// harness extractors already use (`SAY_MAX`/`TOOL_MAX`) for the same
/// purpose — kept local rather than reached into, since that crate's own
/// helpers are private to it.
const SAY_MAX: usize = 160;
const PROMPT_MAX: usize = 160;
const TOOL_MAX: usize = 120;
const ACTIVITY_MAX: usize = 120;

/// A pure fold of one Codex rollout's own JSONL records — the shape a later
/// slice's I/O wrapper upserts onto a `kind:"app"` `SessionRecord`. Every
/// field starts `None`; [`fold_rollout`] is the only way to produce one with
/// anything filled in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CodexCapture {
    /// `working` while a turn's `task_started` is unclosed, `idle` once a
    /// `task_complete`/`turn_aborted` closes it — never `awaiting`, never
    /// downgraded by elapsed time (this fold never reads a clock).
    pub state: Option<String>,
    /// The tool call in flight: the latest `custom_tool_call`/`function_call`
    /// with no later matching `*_output` for the same `call_id`. Absent when
    /// nothing is in flight.
    pub activity: Option<String>,
    /// The latest completed `CommandExecution`/`McpToolCall`/`FileChange`,
    /// one line, `<kind>: <subject>` — mirrors `tool_label`'s shape.
    pub tool: Option<String>,
    /// The latest agent message, clipped to one line.
    pub say: Option<String>,
    /// The latest user message, clipped to one line (D1 — see the module
    /// doc).
    pub prompt: Option<String>,
    /// The latest turn's model, from `turn_context` — per-turn, never a
    /// configured default for a thread that has not yet taken one.
    pub model: Option<String>,
    /// Occupancy: the latest `token_count`'s `last_token_usage.input_tokens`
    /// alone — never the cumulative `total_token_usage`, never summed with
    /// the `cached_input_tokens` field already inside it.
    pub context_tokens: Option<u64>,
    /// The same record's `model_context_window` — the app's own number.
    pub context_ceiling: Option<u64>,
    /// `session_meta.parent_thread_id`, written once at the thread's birth.
    pub parent_thread_id: Option<String>,
    /// `session_meta.thread_source` — `user`/`subagent`/`guardian_review`.
    pub thread_source: Option<String>,
    /// `session_meta.agent_nickname`.
    pub nickname: Option<String>,
    /// The newest `timestamp` of any record this capture actually used —
    /// an "as of," never a wall-clock read.
    pub captured_at: Option<String>,
    /// Field name → `<path>#<ordinal>` pointer, filled only for a field this
    /// fold actually set. `None` on a rollout that captured nothing at all.
    pub sources: Option<BTreeMap<String, String>>,
}

/// `<path>#<ordinal>` — the one pointer shape every captured field uses.
fn pointer(path: &Path, ordinal: usize) -> String {
    format!("{}#{ordinal}", path.display())
}

/// Note that `field` was captured at `ordinal`, and widen `captured_at` to
/// this record's own `timestamp` when it is newer than what's already held.
/// ISO-8601 UTC timestamps of the app's own fixed format sort correctly as
/// plain strings, so no parse is needed here.
fn record_pointer(
    sources: &mut BTreeMap<String, String>,
    captured_at: &mut Option<String>,
    field: &'static str,
    path: &Path,
    ordinal: usize,
    ts: Option<&str>,
) {
    sources.insert(field.to_string(), pointer(path, ordinal));
    if let Some(ts) = ts {
        if captured_at.as_deref().map(|c| c < ts).unwrap_or(true) {
            *captured_at = Some(ts.to_string());
        }
    }
}

/// Collapse a possibly-multiline string to one whitespace-normalised line,
/// truncated at a char boundary to `max` chars with a trailing ellipsis —
/// the same shape `aoide-protocol::agents`'s own extractors already clip a
/// `say`/`tool` line to.
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

/// Text out of an `AgentMessage`/`UserMessage` item's `content` — either a
/// bare string, or an array of blocks of which only `{"type":"text",
/// "text":…}` ones count (the shape the brief's own inventory cites for
/// `UserMessage`). Every text block found is joined with a space; `None`
/// when there is nothing to say.
fn item_text(content: Option<&Value>) -> Option<String> {
    match content? {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        }
        Value::Array(blocks) => {
            let parts: Vec<String> = blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

/// The `<kind>: <subject>` label for a completed tool item — degrades to the
/// bare kind name when the subject can't be read, mirroring `tool_label`'s
/// own "show the tool that ran even when its subject isn't legible" stance.
fn tool_label_for(kind: &str, item: &Value) -> String {
    let summary = match kind {
        "CommandExecution" => command_execution_summary(item),
        "McpToolCall" => mcp_tool_call_summary(item),
        "FileChange" => file_change_summary(item),
        _ => None,
    };
    match summary {
        Some(s) => one_line_clip(&format!("{kind}: {s}"), TOOL_MAX),
        None => kind.to_string(),
    }
}

/// `parsed_cmd` is the app's own display-ready form when present; a raw
/// `command` (string, or an argv array) is the fallback.
fn command_execution_summary(item: &Value) -> Option<String> {
    if let Some(s) = item.get("parsed_cmd").and_then(Value::as_str) {
        return Some(s.to_string());
    }
    match item.get("command") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(argv)) => {
            let parts: Vec<&str> = argv.iter().filter_map(Value::as_str).collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

fn mcp_tool_call_summary(item: &Value) -> Option<String> {
    let server = item.get("server").and_then(Value::as_str)?;
    let tool = item.get("tool").and_then(Value::as_str)?;
    Some(format!("{server}/{tool}"))
}

fn file_change_summary(item: &Value) -> Option<String> {
    let changes = item.get("changes")?.as_array()?;
    let parts: Vec<String> = changes
        .iter()
        .filter_map(|c| {
            c.get("path")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| c.as_str().map(str::to_string))
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Fold a Codex rollout's own JSONL lines into one [`CodexCapture`]. `path`
/// names the rollout for the `sources` pointers this produces — this
/// function never opens it; the bounded read is [`capture_for`]'s job. A
/// line that fails to parse, and any record type/shape this fold does not
/// recognise, contributes nothing. Ordinals start at 0 — `lines[0]` is
/// taken to be the rollout's own first line; a caller handing this only a
/// TAIL of the file wants [`fold_rollout_from`] instead.
pub(crate) fn fold_rollout(path: &Path, lines: &[String]) -> CodexCapture {
    fold_rollout_from(path, 0, lines)
}

/// Same fold as [`fold_rollout`], but `lines[0]`'s own true line number in
/// the file is `start_ordinal` rather than 0 — for [`capture_for`], which
/// hands this only a bounded TAIL of a rollout and must still point at each
/// record's real line number, not its position within that tail slice.
pub(crate) fn fold_rollout_from(
    path: &Path,
    start_ordinal: usize,
    lines: &[String],
) -> CodexCapture {
    let mut cap = CodexCapture::default();
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    // `call_id` -> (ordinal, timestamp, one-line label) for a tool call
    // issued but not yet matched by its own `*_output` record.
    let mut in_flight: BTreeMap<String, (usize, Option<String>, String)> = BTreeMap::new();

    for (i, line) in lines.iter().enumerate() {
        let ordinal = start_ordinal + i;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let ts = record.get("timestamp").and_then(Value::as_str);
        let Some(rtype) = record.get("type").and_then(Value::as_str) else {
            continue;
        };
        let payload = record.get("payload");

        match rtype {
            "session_meta" => {
                let Some(payload) = payload else { continue };
                if let Some(v) = payload.get("parent_thread_id").and_then(Value::as_str) {
                    cap.parent_thread_id = Some(v.to_string());
                    record_pointer(
                        &mut sources,
                        &mut cap.captured_at,
                        "parent_thread_id",
                        path,
                        ordinal,
                        ts,
                    );
                }
                if let Some(v) = payload.get("thread_source").and_then(Value::as_str) {
                    cap.thread_source = Some(v.to_string());
                    record_pointer(
                        &mut sources,
                        &mut cap.captured_at,
                        "thread_source",
                        path,
                        ordinal,
                        ts,
                    );
                }
                if let Some(v) = payload.get("agent_nickname").and_then(Value::as_str) {
                    cap.nickname = Some(v.to_string());
                    record_pointer(
                        &mut sources,
                        &mut cap.captured_at,
                        "nickname",
                        path,
                        ordinal,
                        ts,
                    );
                }
            }
            "turn_context" => {
                if let Some(v) = payload.and_then(|p| p.get("model")).and_then(Value::as_str) {
                    cap.model = Some(v.to_string());
                    record_pointer(
                        &mut sources,
                        &mut cap.captured_at,
                        "model",
                        path,
                        ordinal,
                        ts,
                    );
                }
            }
            "event_msg" => {
                let Some(payload) = payload else { continue };
                match payload.get("type").and_then(Value::as_str) {
                    Some("task_started") => {
                        cap.state = Some("working".to_string());
                        record_pointer(
                            &mut sources,
                            &mut cap.captured_at,
                            "state",
                            path,
                            ordinal,
                            ts,
                        );
                    }
                    Some("task_complete") | Some("turn_aborted") => {
                        cap.state = Some("idle".to_string());
                        record_pointer(
                            &mut sources,
                            &mut cap.captured_at,
                            "state",
                            path,
                            ordinal,
                            ts,
                        );
                    }
                    Some("item_completed") => {
                        let Some(item) = payload.get("item") else {
                            continue;
                        };
                        match item.get("type").and_then(Value::as_str) {
                            Some(kind @ ("CommandExecution" | "McpToolCall" | "FileChange")) => {
                                cap.tool = Some(tool_label_for(kind, item));
                                record_pointer(
                                    &mut sources,
                                    &mut cap.captured_at,
                                    "tool",
                                    path,
                                    ordinal,
                                    ts,
                                );
                            }
                            Some("AgentMessage") => {
                                if let Some(text) = item_text(item.get("content")) {
                                    cap.say = Some(one_line_clip(&text, SAY_MAX));
                                    record_pointer(
                                        &mut sources,
                                        &mut cap.captured_at,
                                        "say",
                                        path,
                                        ordinal,
                                        ts,
                                    );
                                }
                            }
                            Some("UserMessage") => {
                                if let Some(text) = item_text(item.get("content")) {
                                    cap.prompt = Some(one_line_clip(&text, PROMPT_MAX));
                                    record_pointer(
                                        &mut sources,
                                        &mut cap.captured_at,
                                        "prompt",
                                        path,
                                        ordinal,
                                        ts,
                                    );
                                }
                            }
                            // Reasoning, SubAgentActivity, and every other
                            // item type contribute nothing at this slice.
                            _ => {}
                        }
                    }
                    Some("token_count") => {
                        let Some(info) = payload.get("info") else {
                            continue;
                        };
                        if let Some(n) = info
                            .get("last_token_usage")
                            .and_then(|u| u.get("input_tokens"))
                            .and_then(Value::as_u64)
                        {
                            cap.context_tokens = Some(n);
                            record_pointer(
                                &mut sources,
                                &mut cap.captured_at,
                                "context_tokens",
                                path,
                                ordinal,
                                ts,
                            );
                        }
                        if let Some(n) = info.get("model_context_window").and_then(Value::as_u64) {
                            cap.context_ceiling = Some(n);
                            record_pointer(
                                &mut sources,
                                &mut cap.captured_at,
                                "context_ceiling",
                                path,
                                ordinal,
                                ts,
                            );
                        }
                    }
                    _ => {}
                }
            }
            "response_item" => {
                let Some(payload) = payload else { continue };
                match payload.get("type").and_then(Value::as_str) {
                    Some("custom_tool_call") | Some("function_call") => {
                        if let Some(call_id) = payload.get("call_id").and_then(Value::as_str) {
                            let name = payload.get("name").and_then(Value::as_str).unwrap_or("");
                            let label = one_line_clip(name, ACTIVITY_MAX);
                            in_flight.insert(
                                call_id.to_string(),
                                (ordinal, ts.map(str::to_string), label),
                            );
                        }
                    }
                    Some("custom_tool_call_output") | Some("function_call_output") => {
                        if let Some(call_id) = payload.get("call_id").and_then(Value::as_str) {
                            in_flight.remove(call_id);
                        }
                    }
                    // "message" carries prompt/response too, but §3's design
                    // sources those exclusively off `item_completed` — never
                    // a second authority for the same datum.
                    _ => {}
                }
            }
            _ => {}
        }
    }

    if let Some((_, (ordinal, ts, label))) = in_flight
        .into_iter()
        .max_by_key(|(_, (ordinal, ..))| *ordinal)
    {
        cap.activity = Some(label);
        record_pointer(
            &mut sources,
            &mut cap.captured_at,
            "activity",
            path,
            ordinal,
            ts.as_deref(),
        );
    }

    cap.sources = (!sources.is_empty()).then_some(sources);
    cap
}

/// The bounded window [`capture_for`] ever reads off the END of a rollout —
/// enough to span many records without loading an entire day's file into
/// memory. A fixture larger than this pins both the truncation and the
/// ordinal arithmetic in a test.
const TAIL_BYTES: u64 = 1024 * 1024;

/// How many whole lines precede byte offset `start` in `path`'s CURRENT
/// contents, and whether `start` itself opens mid-line. `start == 0` is
/// always aligned — the file's own first byte starts line 0. Otherwise,
/// alignment turns on the byte immediately before `start`: landing right
/// after a `\n` means `start` begins a fresh line; anything else means the
/// tail read's first bytes are the back half of a line whose front half
/// this reader never sees, which counts as one more line before the window
/// — a line the tail can only ever read PART of, so [`capture_for`] drops
/// it rather than fold a partial record. A test with a fixture larger than
/// [`TAIL_BYTES`] pins this arithmetic against the file's own true line
/// numbers.
fn tail_alignment(path: &Path, start: u64) -> std::io::Result<(usize, bool)> {
    if start == 0 {
        return Ok((0, false));
    }
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut remaining = start;
    let mut buf = [0u8; 64 * 1024];
    let mut newline_count: usize = 0;
    let mut last_byte: u8 = 0;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        newline_count += buf[..n].iter().filter(|&&b| b == b'\n').count();
        last_byte = buf[n - 1];
        remaining -= n as u64;
    }
    let aligned = last_byte == b'\n';
    Ok((newline_count + usize::from(!aligned), !aligned))
}

/// Locate `thread_id`'s rollout under `codex_home` — [`super::codex_app::
/// find_rollout`]'s own walk, the one discovery path [`thread_cwd`] already
/// uses, never a second one grown here — and fold at most its last
/// [`TAIL_BYTES`]. Every failure mode (no rollout found, the file can't be
/// opened or read, a tail whose only content is one record too large to
/// ever land whole in the window) yields [`CodexCapture::default`]: every
/// field `None`, which a caller must treat as data absent, never as an
/// idle/completion signal and never as grounds to touch a thread's
/// enrolment — capture has no vote there.
pub(crate) fn capture_for(codex_home: &Path, thread_id: &str) -> CodexCapture {
    let Some(path) = super::codex_app::find_rollout(&codex_home.join("sessions"), thread_id) else {
        return CodexCapture::default();
    };
    capture_from_path(&path).unwrap_or_default()
}

/// The fallible core of [`capture_for`], split out so its `?`-heavy I/O
/// stays out of the public, infallible signature.
fn capture_from_path(path: &Path) -> std::io::Result<CodexCapture> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    let (start_ordinal, drop_first) = tail_alignment(path, start)?;
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let mut split: Vec<&str> = text.split('\n').collect();
    // A trailing empty string after the file's own final `\n` is not a line.
    if split.last() == Some(&"") {
        split.pop();
    }
    // The tail's first split element is only the back half of a line whose
    // front half this bounded read never saw — discarded WHOLE, never
    // parsed, per the tail-parser rule (P-CX-5, codex seq 228).
    if drop_first && !split.is_empty() {
        split.remove(0);
    }
    let lines: Vec<String> = split.into_iter().map(str::to_string).collect();
    Ok(fold_rollout_from(path, start_ordinal, &lines))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(
            "/home/khoa/.codex/sessions/2026/09/12/rollout-2026-09-12T09-00-00-00000000-0000-7000-8000-000000000001.jsonl",
        )
    }

    fn task_started(ts: &str, turn_id: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"task_started","turn_id":"{turn_id}","started_at":"{ts}","model_context_window":258400,"collaboration_mode_kind":"default"}}}}"#
        )
    }

    fn task_complete(ts: &str, turn_id: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"task_complete","turn_id":"{turn_id}","last_agent_message":"done","started_at":"{ts}","completed_at":"{ts}","duration_ms":120,"time_to_first_token_ms":40}}}}"#
        )
    }

    fn turn_aborted(ts: &str, turn_id: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"turn_aborted","turn_id":"{turn_id}","reason":"interrupted","started_at":"{ts}","completed_at":"{ts}","duration_ms":90}}}}"#
        )
    }

    fn turn_context(ts: &str, model: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"turn_context","payload":{{"turn_id":"t1","root_turn_id":"t1","cwd":"/home/khoa/Aoide","workspace_roots":["/home/khoa/Aoide"],"model":"{model}","effort":"medium","approval_policy":"on-request","sandbox_policy":"workspace-write","permission_profile":"default","collaboration_mode":"default","realtime_active":false}}}}"#
        )
    }

    fn item_completed_command(ts: &str, turn_id: &str, command: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"CommandExecution","command":"{command}","parsed_cmd":"{command}","cwd":"/home/khoa/Aoide","status":"completed","exit_code":0,"duration":120}},"started_at_ms":0,"completed_at_ms":120}}}}"#
        )
    }

    fn item_completed_agent_message(ts: &str, turn_id: &str, text: &str, phase: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"AgentMessage","content":[{{"type":"text","text":"{text}"}}],"phase":"{phase}"}},"started_at_ms":0,"completed_at_ms":10}}}}"#
        )
    }

    fn item_completed_user_message(ts: &str, turn_id: &str, text: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"UserMessage","content":[{{"type":"text","text":"{text}"}}]}},"started_at_ms":0,"completed_at_ms":10}}}}"#
        )
    }

    fn item_completed_reasoning(ts: &str, turn_id: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"Reasoning","summary_text":"","raw_content":[]}},"started_at_ms":0,"completed_at_ms":5}}}}"#
        )
    }

    fn response_item_reasoning(ts: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"response_item","payload":{{"type":"reasoning","summary":[],"encrypted_content":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"}}}}"#
        )
    }

    fn token_count(
        ts: &str,
        input_tokens: u64,
        cached: u64,
        cumulative_total: u64,
        ceiling: u64,
    ) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"token_count","info":{{"last_token_usage":{{"input_tokens":{input_tokens},"cached_input_tokens":{cached},"output_tokens":50}},"total_token_usage":{{"total_tokens":{cumulative_total}}},"model_context_window":{ceiling}}},"rate_limits":{{}}}}}}"#
        )
    }

    fn tool_call_issued(ts: &str, kind: &str, call_id: &str, name: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"response_item","payload":{{"type":"{kind}","id":"{call_id}","call_id":"{call_id}","name":"{name}","status":"in_progress","arguments":"{{}}"}}}}"#
        )
    }

    fn tool_call_output(ts: &str, kind: &str, call_id: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"response_item","payload":{{"type":"{kind}_output","call_id":"{call_id}","output":"ok"}}}}"#
        )
    }

    fn session_meta(
        ts: &str,
        id: &str,
        parent_thread_id: &str,
        thread_source: &str,
        nickname: &str,
    ) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"session_meta","payload":{{"session_id":"{id}","id":"{id}","parent_thread_id":"{parent_thread_id}","cwd":"/home/khoa/Aoide","originator":"codex_cli","cli_version":"1.0","source":"desktop","thread_source":"{thread_source}","agent_nickname":"{nickname}","agent_path":"","model_provider":"openai","context_window":258400,"git":{{}}}}}}"#
        )
    }

    fn item_completed_command_with_parsed(
        ts: &str,
        turn_id: &str,
        command: &str,
        parsed_cmd: &str,
    ) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"CommandExecution","command":"{command}","parsed_cmd":"{parsed_cmd}","cwd":"/home/khoa/Aoide","status":"completed","exit_code":0,"duration":120}},"started_at_ms":0,"completed_at_ms":120}}}}"#
        )
    }

    fn item_completed_mcp_tool_call(ts: &str, turn_id: &str, server: &str, tool: &str) -> String {
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"McpToolCall","server":"{server}","tool":"{tool}","status":"completed","duration":80}},"started_at_ms":0,"completed_at_ms":80}}}}"#
        )
    }

    fn item_completed_file_change(ts: &str, turn_id: &str, paths: &[&str]) -> String {
        let changes: Vec<String> = paths
            .iter()
            .map(|p| format!(r#"{{"path":"{p}"}}"#))
            .collect();
        format!(
            r#"{{"timestamp":"{ts}","type":"event_msg","payload":{{"type":"item_completed","thread_id":"th1","turn_id":"{turn_id}","item":{{"type":"FileChange","changes":[{}],"status":"completed"}},"started_at_ms":0,"completed_at_ms":40}}}}"#,
            changes.join(",")
        )
    }

    #[test]
    fn an_unclosed_task_started_is_working() {
        let path = fixture_path();
        let lines = vec![task_started("2026-09-12T09:00:00.000Z", "t1")];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.state.as_deref(), Some("working"));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("state")),
            Some(&pointer(&path, 0))
        );
    }

    #[test]
    fn a_task_complete_closes_the_turn_to_idle() {
        let path = fixture_path();
        let lines = vec![
            task_started("2026-09-12T09:00:00.000Z", "t1"),
            task_complete("2026-09-12T09:00:05.000Z", "t1"),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.state.as_deref(), Some("idle"));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("state")),
            Some(&pointer(&path, 1))
        );
    }

    #[test]
    fn a_turn_aborted_closes_it_too() {
        let path = fixture_path();
        let lines = vec![
            task_started("2026-09-12T09:00:00.000Z", "t1"),
            turn_aborted("2026-09-12T09:00:03.000Z", "t1"),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.state.as_deref(), Some("idle"));
    }

    #[test]
    fn a_working_turn_is_never_downgraded_by_elapsed_time() {
        let path = fixture_path();
        // The gap between these two timestamps is far past any plausible
        // "the app went quiet" threshold. This fold reads no clock at all —
        // a long silence must never flip `working` back to `idle` on its
        // own; only a `task_complete`/`turn_aborted` record closes a turn.
        let lines = vec![
            task_started("2026-09-12T09:00:00.000Z", "t1"),
            token_count("2026-09-12T09:26:00.000Z", 1000, 500, 2_000_000, 258_400),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.state.as_deref(), Some("working"));
    }

    #[test]
    fn a_capture_never_yields_awaiting() {
        let path = fixture_path();
        let never_awaiting = |lines: &[String]| {
            let cap = fold_rollout(&path, lines);
            assert_ne!(cap.state.as_deref(), Some("awaiting"));
        };
        never_awaiting(&[]);
        never_awaiting(&[task_started("2026-09-12T09:00:00.000Z", "t1")]);
        never_awaiting(&[
            task_started("2026-09-12T09:00:00.000Z", "t1"),
            task_complete("2026-09-12T09:00:05.000Z", "t1"),
        ]);
        never_awaiting(&[turn_context("2026-09-12T09:00:00.000Z", "gpt-6-astra")]);
    }

    #[test]
    fn a_tool_call_with_no_output_is_the_activity() {
        let path = fixture_path();
        let lines = vec![tool_call_issued(
            "2026-09-12T09:00:00.000Z",
            "function_call",
            "call-1",
            "shell",
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.activity.as_deref(), Some("shell"));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("activity")),
            Some(&pointer(&path, 0))
        );
    }

    #[test]
    fn a_tool_call_with_its_output_leaves_no_activity() {
        let path = fixture_path();
        let lines = vec![
            tool_call_issued(
                "2026-09-12T09:00:00.000Z",
                "function_call",
                "call-1",
                "shell",
            ),
            tool_call_output("2026-09-12T09:00:01.000Z", "function_call", "call-1"),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.activity, None);
        assert!(cap
            .sources
            .as_ref()
            .map(|s| !s.contains_key("activity"))
            .unwrap_or(true));
    }

    #[test]
    fn the_latest_command_execution_is_the_tool_label() {
        let path = fixture_path();
        let lines = vec![
            item_completed_command("2026-09-12T09:00:00.000Z", "t1", "cargo build"),
            item_completed_command(
                "2026-09-12T09:00:05.000Z",
                "t1",
                "cargo test -p aoide-conduct",
            ),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(
            cap.tool.as_deref(),
            Some("CommandExecution: cargo test -p aoide-conduct")
        );
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("tool")),
            Some(&pointer(&path, 1))
        );
    }

    #[test]
    fn the_model_comes_from_the_latest_turn_context() {
        let path = fixture_path();
        let lines = vec![
            turn_context("2026-09-12T09:00:00.000Z", "gpt-6-astra"),
            turn_context("2026-09-12T09:05:00.000Z", "gpt-6-astra-mini"),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.model.as_deref(), Some("gpt-6-astra-mini"));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("model")),
            Some(&pointer(&path, 1))
        );
    }

    #[test]
    fn occupancy_is_last_input_tokens_never_the_cumulative_total() {
        let path = fixture_path();
        let lines = vec![token_count(
            "2026-09-12T09:21:04.305Z",
            231_126,
            230_656,
            25_252_358,
            258_400,
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.context_tokens, Some(231_126));
        assert_ne!(cap.context_tokens, Some(25_252_358));
    }

    #[test]
    fn occupancy_never_adds_the_cached_field_on_top() {
        let path = fixture_path();
        let lines = vec![token_count(
            "2026-09-12T09:21:04.305Z",
            231_126,
            230_656,
            25_252_358,
            258_400,
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.context_tokens, Some(231_126));
        assert_ne!(cap.context_tokens, Some(231_126 + 230_656));
    }

    #[test]
    fn the_ceiling_is_the_apps_own_model_context_window() {
        let path = fixture_path();
        let lines = vec![token_count(
            "2026-09-12T09:21:04.305Z",
            231_126,
            230_656,
            25_252_358,
            258_400,
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.context_ceiling, Some(258_400));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("context_ceiling")),
            Some(&pointer(&path, 0))
        );
    }

    #[test]
    fn a_reasoning_record_contributes_nothing() {
        let path = fixture_path();
        let lines = vec![item_completed_reasoning("2026-09-12T09:00:00.000Z", "t1")];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap, CodexCapture::default());
    }

    #[test]
    fn a_reasoning_record_with_encrypted_content_still_contributes_nothing() {
        let path = fixture_path();
        let lines = vec![response_item_reasoning("2026-09-12T09:00:00.000Z")];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap, CodexCapture::default());
    }

    #[test]
    fn every_captured_field_carries_a_pointer_and_an_uncaptured_one_carries_none() {
        let path = fixture_path();
        let lines = vec![
            turn_context("2026-09-12T09:00:00.000Z", "gpt-6-astra"),
            item_completed_agent_message(
                "2026-09-12T09:00:05.000Z",
                "t1",
                "done with the build",
                "final_answer",
            ),
        ];
        let cap = fold_rollout(&path, &lines);

        assert_eq!(cap.model.as_deref(), Some("gpt-6-astra"));
        assert_eq!(cap.say.as_deref(), Some("done with the build"));

        let sources = cap.sources.expect("captured fields must carry sources");
        assert_eq!(sources.get("model"), Some(&pointer(&path, 0)));
        assert_eq!(sources.get("say"), Some(&pointer(&path, 1)));

        assert_eq!(cap.state, None);
        assert_eq!(cap.activity, None);
        assert_eq!(cap.tool, None);
        assert_eq!(cap.prompt, None);
        assert_eq!(cap.context_tokens, None);
        assert_eq!(cap.context_ceiling, None);
        assert_eq!(cap.parent_thread_id, None);
        assert_eq!(cap.thread_source, None);
        assert_eq!(cap.nickname, None);
        for field in [
            "state",
            "activity",
            "tool",
            "prompt",
            "context_tokens",
            "context_ceiling",
            "parent_thread_id",
            "thread_source",
            "nickname",
        ] {
            assert!(
                !sources.contains_key(field),
                "{field} was never captured and must carry no pointer"
            );
        }
    }

    #[test]
    fn the_latest_user_message_is_the_prompt_and_carries_its_pointer() {
        let path = fixture_path();
        let lines = vec![
            item_completed_user_message("2026-09-12T09:00:00.000Z", "t1", "first question"),
            item_completed_user_message(
                "2026-09-12T09:05:00.000Z",
                "t1",
                "run the fold tests please",
            ),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.prompt.as_deref(), Some("run the fold tests please"));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("prompt")),
            Some(&pointer(&path, 1))
        );
    }

    #[test]
    fn a_session_meta_record_yields_parent_thread_source_and_nickname_with_pointers() {
        let path = fixture_path();
        let lines = vec![session_meta(
            "2026-09-12T09:00:00.000Z",
            "00000000-0000-7000-8000-000000000002",
            "00000000-0000-7000-8000-000000000003",
            "subagent",
            "Laplace",
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(
            cap.parent_thread_id.as_deref(),
            Some("00000000-0000-7000-8000-000000000003")
        );
        assert_eq!(cap.thread_source.as_deref(), Some("subagent"));
        assert_eq!(cap.nickname.as_deref(), Some("Laplace"));

        let sources = cap
            .sources
            .expect("session_meta fields must carry pointers");
        assert_eq!(sources.get("parent_thread_id"), Some(&pointer(&path, 0)));
        assert_eq!(sources.get("thread_source"), Some(&pointer(&path, 0)));
        assert_eq!(sources.get("nickname"), Some(&pointer(&path, 0)));
    }

    #[test]
    fn parsed_cmd_wins_over_a_differing_raw_command() {
        let path = fixture_path();
        let lines = vec![item_completed_command_with_parsed(
            "2026-09-12T09:00:00.000Z",
            "t1",
            "bash -lc 'cargo test -p aoide-conduct'",
            "cargo test -p aoide-conduct",
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(
            cap.tool.as_deref(),
            Some("CommandExecution: cargo test -p aoide-conduct"),
            "parsed_cmd is the app's own display-ready form and must win over the raw command"
        );
    }

    #[test]
    fn an_mcp_tool_call_labels_server_and_tool() {
        let path = fixture_path();
        let lines = vec![item_completed_mcp_tool_call(
            "2026-09-12T09:00:00.000Z",
            "t1",
            "mneme",
            "search_vault",
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.tool.as_deref(), Some("McpToolCall: mneme/search_vault"));
    }

    #[test]
    fn a_file_change_labels_its_changed_paths() {
        let path = fixture_path();
        let lines = vec![item_completed_file_change(
            "2026-09-12T09:00:00.000Z",
            "t1",
            &["src/graph/codex_capture.rs", "README.md"],
        )];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(
            cap.tool.as_deref(),
            Some("FileChange: src/graph/codex_capture.rs, README.md")
        );
    }

    #[test]
    fn an_unparseable_line_contributes_nothing_and_neighbouring_ordinals_stay_correct() {
        let path = fixture_path();
        let lines = vec![
            turn_context("2026-09-12T09:00:00.000Z", "gpt-6-astra"),
            r#"{"timestamp":"2026-09-12T09:00:02.000Z","type":"turn_cont"#.to_string(),
            turn_context("2026-09-12T09:05:00.000Z", "gpt-6-astra-mini"),
        ];
        let cap = fold_rollout(&path, &lines);
        assert_eq!(cap.model.as_deref(), Some("gpt-6-astra-mini"));
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("model")),
            Some(&pointer(&path, 2)),
            "the truncated line at ordinal 1 must contribute nothing and must not shift the following record's ordinal"
        );
    }

    // `capture_for` — the bounded, impure reader over a live rollout.
    // Fixtures are written by these tests themselves under a tempdir shaped
    // like real records (`type`/`payload.type`/field names match the fixture
    // helpers above); never a real rollout, never `~/.codex` (rulings §31).

    fn write_rollout(codex_home: &Path, thread_id: &str, body: &str) -> PathBuf {
        let dir = codex_home.join("sessions");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("rollout-2026-09-12T09-00-00-{thread_id}.jsonl"));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_missing_rollout_yields_every_field_none() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-missing");
        let cap = capture_for(&codex_home, "00000000-0000-7000-8000-00000000000f");
        assert_eq!(cap, CodexCapture::default());
    }

    #[test]
    fn an_unreadable_rollout_yields_every_field_none() {
        // A dangling symlink is unreadable regardless of privilege level
        // (unlike a permission bit, which a root test runner ignores) — the
        // file `find_rollout` locates exists as a directory entry, but
        // opening it always fails.
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-unreadable");
        let dir = codex_home.join("sessions");
        std::fs::create_dir_all(&dir).unwrap();
        let thread_id = "00000000-0000-7000-8000-000000000011";
        let link = dir.join(format!("rollout-2026-09-12T09-00-00-{thread_id}.jsonl"));
        std::os::unix::fs::symlink(dir.join("does-not-exist.jsonl"), &link).unwrap();
        let cap = capture_for(&codex_home, thread_id);
        assert_eq!(cap, CodexCapture::default());
    }

    #[test]
    fn a_tail_shorter_than_one_record_captures_nothing() {
        // One record, alone in the file, whose own serialised length
        // exceeds `TAIL_BYTES` — the bounded read can never see it whole,
        // so it must capture nothing (never a reason to infer state either
        // way; see the module doc's "oversized record" case).
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-tailshort");
        let thread_id = "00000000-0000-7000-8000-000000000012";
        let padding = "a".repeat(TAIL_BYTES as usize + 1000);
        let body = format!(
            r#"{{"timestamp":"2026-09-12T09:00:00.000Z","type":"turn_context","payload":{{"turn_id":"t1","model":"oversized-model","padding":"{padding}"}}}}
"#
        );
        assert!(
            body.len() as u64 > TAIL_BYTES,
            "fixture must exceed the tail window to exercise this case"
        );
        write_rollout(&codex_home, thread_id, &body);
        let cap = capture_for(&codex_home, thread_id);
        assert_eq!(
            cap,
            CodexCapture::default(),
            "a record too large to ever land whole in the tail must capture nothing"
        );
    }

    #[test]
    fn a_partial_leading_line_is_dropped() {
        // `line0` is a single record padded well past `TAIL_BYTES`, so the
        // tail read's cut lands inside it; `line1` is a small, ordinary
        // record placed entirely after the cut. If the dropped fragment of
        // `line0` were ever parsed, `cap.model` would read its
        // "straddle-model"; it must instead read `line1`'s own value.
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-partial");
        let thread_id = "00000000-0000-7000-8000-000000000013";
        let padding = "a".repeat(TAIL_BYTES as usize);
        let line0 = format!(
            r#"{{"timestamp":"2026-09-12T09:00:00.000Z","type":"turn_context","payload":{{"turn_id":"t0","model":"straddle-model","padding":"{padding}"}}}}"#
        );
        let line1 = turn_context("2026-09-12T09:05:00.000Z", "landed-model");
        let body = format!("{line0}\n{line1}\n");
        assert!(body.len() as u64 > TAIL_BYTES);
        let path = write_rollout(&codex_home, thread_id, &body);
        let cap = capture_for(&codex_home, thread_id);
        assert_eq!(
            cap.model.as_deref(),
            Some("landed-model"),
            "the dropped leading fragment must never surface its own value"
        );
        assert_eq!(
            cap.sources.as_ref().and_then(|s| s.get("model")),
            Some(&pointer(&path, 1)),
            "line1 is the file's true second line (0-based ordinal 1)"
        );
    }

    #[test]
    fn an_ordinal_equals_its_line_number_minus_one() {
        // `line0` (decoy, outside the tail window entirely) is followed by
        // a filler line sized so the remaining bytes (filler + real1 +
        // real2, each newline-terminated) total EXACTLY `TAIL_BYTES` — so
        // the tail read's start lands precisely on a line boundary (right
        // after `line0`'s own `\n`), pinning the ALIGNED half of the
        // ordinal arithmetic (the not-aligned half is
        // `a_partial_leading_line_is_dropped`, above).
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-ordinal");
        let thread_id = "00000000-0000-7000-8000-000000000014";

        let line0 = turn_context("2026-09-12T08:00:00.000Z", "decoy-model");
        let real1 = turn_context("2026-09-12T09:00:00.000Z", "gpt-real-1");
        let real2 = item_completed_agent_message(
            "2026-09-12T09:00:05.000Z",
            "t1",
            "hello there",
            "final_answer",
        );

        let want_tail_len = TAIL_BYTES as usize;
        let real_bytes = real1.len() + 1 + real2.len() + 1;
        let filler_prefix =
            r#"{"timestamp":"2026-09-12T08:30:00.000Z","type":"filler","padding":""}"#;
        let overhead = filler_prefix.len() + 1;
        let pad_len = want_tail_len - real_bytes - overhead;
        let padding = "a".repeat(pad_len);
        let filler = format!(
            r#"{{"timestamp":"2026-09-12T08:30:00.000Z","type":"filler","padding":"{padding}"}}"#
        );
        let tail_region = format!("{filler}\n{real1}\n{real2}\n");
        assert_eq!(
            tail_region.len(),
            want_tail_len,
            "tail_region must be exactly TAIL_BYTES so the cut lands right after line0's newline"
        );

        let body = format!("{line0}\n{tail_region}");
        assert_eq!(body.len() as u64, TAIL_BYTES + line0.len() as u64 + 1);
        let path = write_rollout(&codex_home, thread_id, &body);
        let cap = capture_for(&codex_home, thread_id);

        // line0 = ordinal 0 (outside the window, decoy-model must never surface)
        // filler = ordinal 1 (unrecognised type, contributes nothing)
        // real1  = ordinal 2 (turn_context -> model)
        // real2  = ordinal 3 (item_completed AgentMessage -> say)
        assert_eq!(cap.model.as_deref(), Some("gpt-real-1"));
        assert_eq!(cap.say.as_deref(), Some("hello there"));
        let sources = cap.sources.expect("captured fields must carry pointers");
        assert_eq!(sources.get("model"), Some(&pointer(&path, 2)));
        assert_eq!(sources.get("say"), Some(&pointer(&path, 3)));
    }
}
