//! Native Codex capture (P-CX-5, the codex-integration follow-on): a PURE
//! fold from a Codex rollout's own JSONL lines into one [`CodexCapture`]
//! ([`fold_rollout_from`]), plus the bounded, impure reader over a live
//! rollout ([`capture_for`]) that feeds it. `codex_app.rs`'s
//! `sync_codex_app_threads` is the one caller: it gathers a [`CodexCapture`]
//! per desired thread and merges `say`/`tool`/`activity`/`model`/
//! `context_tokens`/`context_ceiling`/`sources` onto that thread's
//! `kind:"app"` record, change-only. `state`/`parentSessionId`/`title` stay
//! untouched by that merge — later slices' own territory, not this one's.
//!
//! [`fold_rollout_from`] walks `lines` in order starting at `start_ordinal`
//! — the ordinal each pointer carries is that starting point plus the
//! line's own position in the slice, never a value read out of the record
//! itself — the ruling that pins the pointer contract. [`capture_for`]
//! hands it only the TAIL of a rollout (via [`fold_tail`]): the lines it
//! folds are a slice, but a pointer must still name the record's TRUE line
//! number in the whole file, hence the explicit starting ordinal rather
//! than an assumed 0. A line that fails to parse as JSON, whether
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
//! Every live thread pays this on every ~1 Hz tick, so `capture_for` keeps a
//! per-thread, process-lifetime memo: an unchanged `(len, mtime)` since the
//! last read returns that read's own [`CodexCapture`] straight back with no
//! file I/O at all, and a rollout that only grew (append-only, `mtime`
//! never moving backwards) reuses the memo's own tail-alignment facts
//! UNCHANGED — no re-scanning the bytes before the tail window a second
//! time — for as long as that window stays within a small bounded slack
//! past [`TAIL_BYTES`]; only once accumulated growth outruns that slack
//! does it pay a fresh alignment scan, same as a cold cache miss. The
//! resolved rollout path is cached the same way and re-walked only once it
//! stops existing. A rollout that shrank or was rewritten in place (not
//! append-only) drops its memo entry outright and recounts from scratch.
//! [`retain_capture_memo`] is `codex_app.rs::sync_codex_app_threads`'s own
//! once-per-tick call to evict a thread's memo entry once it stops
//! appearing among the threads that tick actually observed — a closed
//! window or a released lock never leaves its rollout path and tail facts
//! pinned in memory forever.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
/// field starts `None`; [`fold_rollout_from`] is the only way to produce
/// one with anything filled in.
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
/// recognise, contributes nothing. `lines[0]`'s own true line number in the
/// file is `start_ordinal`, never assumed to be 0: [`capture_for`] hands
/// this only a bounded TAIL of a rollout (via [`fold_tail`]) and must still
/// point at each record's real line number, not its position within that
/// tail slice; a test folding a whole small fixture from the top passes 0.
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

/// How wide [`capture_for`]'s per-thread memo ever lets its read window
/// drift, at most, before it re-anchors: `TAIL_BYTES` for the window itself
/// plus this much slack. A purely append-only tick that stays under the cap
/// reuses its memo's `start`/`start_ordinal`/`drop_first` untouched — the
/// window only grows past the "ideal" `TAIL_BYTES` a little between
/// re-anchors, never past this cap, and never unboundedly.
const MEMO_MAX_WINDOW_BYTES: u64 = 2 * TAIL_BYTES;

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
/// numbers. This is the expensive O(`start`) prefix scan [`capture_for`]'s
/// memo exists to avoid paying on every tick — it runs only on a rollout's
/// first sight, a truncation/rewrite, or a re-anchor past
/// [`MEMO_MAX_WINDOW_BYTES`], never on a plain append-only tick.
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

/// [`capture_for`]'s per-thread memo: the resolved rollout path (so a hit
/// skips `find_rollout`'s own `sessions/**` walk entirely, re-walked only
/// once that path stops existing — the identical "known, unless proven
/// stale" rule `codex_app.rs`'s own thread-cwd cache already holds for the
/// same walk) alongside the `(len, mtime)` and tail-alignment facts that
/// read produced. Process-lifetime only, matching this module's own
/// one-shot audit statics — a restart simply recomputes once, same as a
/// cold miss today.
#[derive(Clone)]
struct CaptureMemo {
    path: PathBuf,
    len: u64,
    mtime: SystemTime,
    start: u64,
    start_ordinal: usize,
    drop_first: bool,
    capture: CodexCapture,
}

/// Keyed by thread id ALONE, not `(codex_home, thread_id)` — a genuinely
/// tighter key, but one this process never needs: a single `aoided` only
/// ever observes one desktop-Codex home (one host, one home), so a thread
/// id is already unambiguous here. Entries are dropped only by
/// [`retain_capture_memo`] — otherwise a thread's memo, and the tail
/// content its `capture` still holds, would sit here forever once that
/// thread stops being live.
static CAPTURE_MEMO: std::sync::Mutex<BTreeMap<String, CaptureMemo>> =
    std::sync::Mutex::new(BTreeMap::new());

/// The pure eviction rule behind [`retain_capture_memo`], split out so a
/// test can exercise it against its own local map instead of the shared
/// [`CAPTURE_MEMO`] static — the static is process-wide, and cargo runs
/// this crate's tests in parallel, so a test that retained *it* directly
/// would evict every other concurrently running test's entries too.
fn retain_memo_in(memo: &mut BTreeMap<String, CaptureMemo>, live: &BTreeSet<String>) {
    memo.retain(|id, _| live.contains(id));
}

/// Drops every memo entry whose thread id is not in `live` — called once
/// per tick by `codex_app.rs::sync_codex_app_threads`, right after it
/// gathers that tick's captures, with the exact thread ids the tick
/// observed. A thread that closes its window or releases its lock stops
/// appearing in `live` on the very next tick, and its rollout path and
/// tail-alignment facts are freed here rather than held onto forever.
pub(crate) fn retain_capture_memo(live: &BTreeSet<String>) {
    let mut memo = CAPTURE_MEMO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retain_memo_in(&mut memo, live);
}

/// Locate `thread_id`'s rollout under `codex_home` — [`super::codex_app::
/// find_rollout`]'s own walk, the one discovery path [`thread_cwd`] already
/// uses, never a second one grown here — and fold at most its last
/// [`TAIL_BYTES`], memoised per thread (see [`CaptureMemo`]) so a live
/// thread's own ~1 Hz callers ([`super::reap`], `window.rs`) don't each pay
/// a fresh prefix scan and a fresh `sessions/**` walk on every tick. Every
/// failure mode (no rollout found, the file can't be opened or read, a tail
/// whose only content is one record too large to ever land whole in the
/// window) yields [`CodexCapture::default`]: every field `None`, which a
/// caller must treat as data absent, never as an idle/completion signal and
/// never as grounds to touch a thread's enrolment — capture has no vote
/// there.
pub(crate) fn capture_for(codex_home: &Path, thread_id: &str) -> CodexCapture {
    let mut memo = CAPTURE_MEMO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let prior = memo.get(thread_id).cloned();

    let path = match prior.as_ref().map(|p| &p.path).filter(|p| p.is_file()) {
        Some(p) => p.clone(),
        None => match super::codex_app::find_rollout(&codex_home.join("sessions"), thread_id) {
            Some(p) => p,
            None => {
                memo.remove(thread_id);
                return CodexCapture::default();
            }
        },
    };

    let Ok(meta) = std::fs::metadata(&path) else {
        memo.remove(thread_id);
        return CodexCapture::default();
    };
    let len = meta.len();
    let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);

    if let Some(entry) = &prior {
        // Nothing changed since the last read: that read's own capture
        // stands, no I/O at all.
        if entry.path == path && entry.len == len && entry.mtime == mtime {
            return entry.capture.clone();
        }
        // Append-only growth: the file only got longer and `mtime` never
        // moved backwards. Extra whole lines before the memo's own
        // `start` are never in play here — this is content AFTER `start`
        // — so the memo's start/start_ordinal/drop_first stay exactly
        // correct for the wider window `[entry.start, len)` as long as
        // that window is still under the slack cap. No newline count, no
        // prefix scan — just the one bounded read the fold needs anyway.
        if entry.path == path
            && len > entry.len
            && mtime >= entry.mtime
            && len - entry.start <= MEMO_MAX_WINDOW_BYTES
        {
            return match fold_tail(&path, entry.start, entry.start_ordinal, entry.drop_first) {
                Ok(cap) => {
                    memo.insert(
                        thread_id.to_string(),
                        CaptureMemo {
                            path,
                            len,
                            mtime,
                            start: entry.start,
                            start_ordinal: entry.start_ordinal,
                            drop_first: entry.drop_first,
                            capture: cap.clone(),
                        },
                    );
                    cap
                }
                Err(_) => {
                    memo.remove(thread_id);
                    CodexCapture::default()
                }
            };
        }
        // Anything else — truncation, mtime moved backwards, a rewrite in
        // place, or growth that has outrun the slack cap — falls through
        // to a full, fresh recompute: a memo that no longer describes an
        // append-only future is never trusted half-way, only replaced.
    }

    match capture_from_path(&path) {
        Ok((cap, start, start_ordinal, drop_first)) => {
            memo.insert(
                thread_id.to_string(),
                CaptureMemo {
                    path,
                    len,
                    mtime,
                    start,
                    start_ordinal,
                    drop_first,
                    capture: cap.clone(),
                },
            );
            cap
        }
        Err(_) => {
            memo.remove(thread_id);
            CodexCapture::default()
        }
    }
}

/// The fallible core of [`capture_for`]'s first sight of a rollout (or a
/// reset once its memo's growth has outrun [`MEMO_MAX_WINDOW_BYTES`]):
/// finds `path`'s tail alignment fresh, then folds it — split out so its
/// `?`-heavy I/O stays out of the public, infallible signature, and so its
/// `(start, start_ordinal, drop_first)` triple is available for
/// [`capture_for`]'s memo to reuse on a later, purely append-only tick.
fn capture_from_path(path: &Path) -> std::io::Result<(CodexCapture, u64, usize, bool)> {
    let len = std::fs::metadata(path)?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    let (start_ordinal, drop_first) = tail_alignment(path, start)?;
    let cap = fold_tail(path, start, start_ordinal, drop_first)?;
    Ok((cap, start, start_ordinal, drop_first))
}

/// Reads `path` from `start` to EOF and folds it at `start_ordinal` — the
/// shared back half of both a fresh [`capture_from_path`] and
/// [`capture_for`]'s own memoised, append-only-growth reuse, which supplies
/// an already-known `start`/`start_ordinal`/`drop_first` instead of paying
/// [`tail_alignment`] again.
fn fold_tail(
    path: &Path,
    start: u64,
    start_ordinal: usize,
    drop_first: bool,
) -> std::io::Result<CodexCapture> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
        assert_eq!(cap.state.as_deref(), Some("working"));
    }

    #[test]
    fn a_capture_never_yields_awaiting() {
        let path = fixture_path();
        let never_awaiting = |lines: &[String]| {
            let cap = fold_rollout_from(&path, 0, lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
        assert_eq!(cap, CodexCapture::default());
    }

    #[test]
    fn a_reasoning_record_with_encrypted_content_still_contributes_nothing() {
        let path = fixture_path();
        let lines = vec![response_item_reasoning("2026-09-12T09:00:00.000Z")];
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);

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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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
        let cap = fold_rollout_from(&path, 0, &lines);
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

    // `capture_for`'s per-thread memo (P-CX-5 S2 review follow-up): an
    // untouched rollout costs no I/O, an append-only tick reuses its
    // cached alignment rather than re-scanning the prefix, a truncation
    // drops the memo outright, and a cached path that has gone missing
    // falls back to a fresh `find_rollout` walk. `CAPTURE_MEMO` is a
    // private module static, but these tests are a child module of
    // `codex_capture` and so may read it directly — the same access every
    // other test here already has to `tail_alignment`/`fold_rollout_from`.

    #[test]
    fn an_unchanged_rollout_returns_the_prior_capture_without_re_reading() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-memo-hit");
        let thread_id = "00000000-0000-7000-8000-000000000015";
        let body = format!(
            "{}\n",
            turn_context("2026-09-12T09:00:00.000Z", "gpt-cached")
        );
        let path = write_rollout(&codex_home, thread_id, &body);

        let first = capture_for(&codex_home, thread_id);
        assert_eq!(first.model.as_deref(), Some("gpt-cached"));

        // The exact (len, mtime) the memo stored — recovered rather than
        // re-derived, so the swap below matches it regardless of this
        // filesystem's own mtime resolution.
        let (memo_len, memo_mtime) = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            let entry = memo
                .get(thread_id)
                .expect("the first capture must have memoised an entry");
            (entry.len, entry.mtime)
        };

        // Swap in DIFFERENT content of the exact same byte length, then
        // force the mtime back to the value the memo holds. A correct
        // memo hit trusts an unchanged (len, mtime) alone and never opens
        // the file again — so it must still hand back the FIRST capture,
        // never see this swapped-in one.
        let lying_body = format!(
            "{}\n",
            turn_context("2026-09-12T09:00:00.000Z", "gpt-tricky")
        );
        assert_eq!(lying_body.len(), body.len(), "the swap must not change len");
        std::fs::write(&path, &lying_body).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(memo_mtime).unwrap();
        drop(file);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), memo_len);

        let second = capture_for(&codex_home, thread_id);
        assert_eq!(
            second.model.as_deref(),
            Some("gpt-cached"),
            "an unchanged (len, mtime) must return the prior capture verbatim, proving no re-read"
        );
    }

    #[test]
    fn an_append_only_growth_reuses_its_memo_alignment_unchanged() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-memo-growth");
        let thread_id = "00000000-0000-7000-8000-000000000016";
        let padding = "a".repeat(TAIL_BYTES as usize);
        let filler = format!(
            r#"{{"timestamp":"2026-09-12T08:00:00.000Z","type":"filler","padding":"{padding}"}}"#
        );
        let real1 = turn_context("2026-09-12T09:00:00.000Z", "gpt-first");
        let body1 = format!("{filler}\n{real1}\n");
        assert!(
            body1.len() as u64 > TAIL_BYTES,
            "fixture must exceed the tail window so the first capture has a real, non-zero start"
        );
        let path = write_rollout(&codex_home, thread_id, &body1);

        let first = capture_for(&codex_home, thread_id);
        assert_eq!(first.model.as_deref(), Some("gpt-first"));

        let before = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            let entry = memo
                .get(thread_id)
                .expect("the first capture must have memoised an entry");
            assert!(
                entry.start > 0,
                "the fixture must force a non-trivial tail start"
            );
            (entry.start, entry.start_ordinal, entry.drop_first)
        };

        // Append-only growth, well inside the slack cap: one more whole
        // record at the end, nothing before `start` disturbed.
        let real2 = turn_context("2026-09-12T09:05:00.000Z", "gpt-second");
        let body2 = format!("{body1}{real2}\n");
        write_rollout(&codex_home, thread_id, &body2);
        let second = capture_for(&codex_home, thread_id);

        let after = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            let entry = memo
                .get(thread_id)
                .expect("growth must still leave a memo entry");
            (entry.start, entry.start_ordinal, entry.drop_first)
        };
        assert_eq!(
            after, before,
            "append-only growth inside the slack cap must reuse the memo's own alignment \
             untouched, never recompute it from a rescanned prefix"
        );

        assert_eq!(second.model.as_deref(), Some("gpt-second"));
        let true_ordinal = body1.lines().count(); // filler=0, real1=1, real2=2
        assert_eq!(true_ordinal, 2);
        let sources = second.sources.expect("captured fields must carry pointers");
        assert_eq!(
            sources.get("model"),
            Some(&pointer(&path, true_ordinal)),
            "the appended record's ordinal must still be its true line number"
        );
    }

    #[test]
    fn a_truncated_rollout_drops_the_memo_and_recounts_from_scratch() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-memo-truncate");
        let thread_id = "00000000-0000-7000-8000-000000000017";
        let padding = "a".repeat(TAIL_BYTES as usize);
        let filler = format!(
            r#"{{"timestamp":"2026-09-12T08:00:00.000Z","type":"filler","padding":"{padding}"}}"#
        );
        let real1 = turn_context("2026-09-12T09:00:00.000Z", "gpt-before-cut");
        let body1 = format!("{filler}\n{real1}\n");
        assert!(body1.len() as u64 > TAIL_BYTES);
        let path = write_rollout(&codex_home, thread_id, &body1);

        let first = capture_for(&codex_home, thread_id);
        assert_eq!(first.model.as_deref(), Some("gpt-before-cut"));
        assert_eq!(
            first.sources.as_ref().and_then(|s| s.get("model")),
            Some(&pointer(&path, 1))
        );

        // Truncation: a much smaller file at the same path — not
        // append-only, so the memo must be dropped rather than reused
        // half-way.
        let body2 = format!(
            "{}\n",
            turn_context("2026-09-12T10:00:00.000Z", "gpt-after-cut")
        );
        assert!((body2.len() as u64) < body1.len() as u64);
        write_rollout(&codex_home, thread_id, &body2);

        let second = capture_for(&codex_home, thread_id);
        assert_eq!(second.model.as_deref(), Some("gpt-after-cut"));
        assert_eq!(
            second.sources.as_ref().and_then(|s| s.get("model")),
            Some(&pointer(&path, 0)),
            "the truncated file's own fresh ordinal must be used, never the stale start_ordinal"
        );

        let entry_start = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            memo.get(thread_id)
                .expect("a truncation still leaves a fresh memo entry")
                .start
        };
        assert_eq!(
            entry_start, 0,
            "the memo must be re-anchored at the truncated file's own start, not the stale one"
        );
    }

    #[test]
    fn a_stale_cached_path_falls_back_to_a_fresh_walk() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-memo-stale-path");
        let thread_id = "00000000-0000-7000-8000-000000000018";
        let body_a = format!(
            "{}\n",
            turn_context("2026-09-12T09:00:00.000Z", "gpt-old-file")
        );
        let path_a = write_rollout(&codex_home, thread_id, &body_a);

        let first = capture_for(&codex_home, thread_id);
        assert_eq!(first.model.as_deref(), Some("gpt-old-file"));

        std::fs::remove_file(&path_a).unwrap();
        let dir = codex_home.join("sessions");
        let path_b = dir.join(format!("rollout-2026-09-13T09-00-00-{thread_id}.jsonl"));
        let body_b = format!(
            "{}\n",
            turn_context("2026-09-13T09:00:00.000Z", "gpt-new-file")
        );
        std::fs::write(&path_b, &body_b).unwrap();

        let second = capture_for(&codex_home, thread_id);
        assert_eq!(
            second.model.as_deref(),
            Some("gpt-new-file"),
            "a cached path that no longer exists must fall back to a fresh find_rollout walk"
        );

        let memo_path = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            memo.get(thread_id)
                .expect("the fresh walk still leaves a memo entry")
                .path
                .clone()
        };
        assert_eq!(
            memo_path, path_b,
            "the memo must now track the newly found path"
        );
    }

    #[test]
    fn a_growth_past_the_slack_cap_reanchors_and_recaptures_the_newest_records() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-memo-reanchor");
        let thread_id = "00000000-0000-7000-8000-000000000019";
        let padding = "a".repeat(TAIL_BYTES as usize);
        let filler = format!(
            r#"{{"timestamp":"2026-09-12T08:00:00.000Z","type":"filler","padding":"{padding}"}}"#
        );
        let real1 = turn_context("2026-09-12T09:00:00.000Z", "gpt-first");
        let body1 = format!("{filler}\n{real1}\n");
        assert!(body1.len() as u64 > TAIL_BYTES);
        let path = write_rollout(&codex_home, thread_id, &body1);

        let first = capture_for(&codex_home, thread_id);
        assert_eq!(first.model.as_deref(), Some("gpt-first"));

        let start_before = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            let entry = memo
                .get(thread_id)
                .expect("the first capture must have memoised an entry");
            assert!(
                entry.start > 0,
                "the fixture must force a non-trivial tail start"
            );
            entry.start
        };

        // Grow well past the slack cap in one tick: a second big filler
        // plus a final, distinguishing record.
        let padding2 = "c".repeat(MEMO_MAX_WINDOW_BYTES as usize);
        let filler2 = format!(
            r#"{{"timestamp":"2026-09-12T09:30:00.000Z","type":"filler2","padding":"{padding2}"}}"#
        );
        let real2 = turn_context("2026-09-12T10:00:00.000Z", "gpt-second");
        let body2 = format!("{body1}{filler2}\n{real2}\n");
        assert!(
            body2.len() as u64 - start_before > MEMO_MAX_WINDOW_BYTES,
            "growth must genuinely outrun the slack cap"
        );
        write_rollout(&codex_home, thread_id, &body2);

        let second = capture_for(&codex_home, thread_id);

        let start_after = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            memo.get(thread_id)
                .expect("a re-anchor still leaves a memo entry")
                .start
        };
        assert_ne!(
            start_after, start_before,
            "growth past the slack cap must re-anchor start, never reuse the old one"
        );
        assert_eq!(
            start_after,
            body2.len() as u64 - TAIL_BYTES,
            "a re-anchor must land at the fresh ideal start, not an arbitrary one"
        );

        assert_eq!(second.model.as_deref(), Some("gpt-second"));
        let true_ordinal = body2.lines().count() - 1; // real2 is the file's last line
        let sources = second.sources.expect("captured fields must carry pointers");
        assert_eq!(
            sources.get("model"),
            Some(&pointer(&path, true_ordinal)),
            "a re-anchored capture's ordinal must still be its true line number"
        );
    }

    #[test]
    fn growth_exactly_at_the_slack_cap_reuses_one_byte_more_reanchors() {
        let codex_home = crate::graph::testutil::unique_stage("codex-capture-memo-boundary");
        let thread_id = "00000000-0000-7000-8000-00000000001a";
        let padding = "a".repeat(TAIL_BYTES as usize);
        let filler = format!(
            r#"{{"timestamp":"2026-09-12T08:00:00.000Z","type":"filler","padding":"{padding}"}}"#
        );
        let real1 = turn_context("2026-09-12T09:00:00.000Z", "gpt-first");
        let body1 = format!("{filler}\n{real1}\n");
        assert!(body1.len() as u64 > TAIL_BYTES);
        write_rollout(&codex_home, thread_id, &body1);

        capture_for(&codex_home, thread_id);
        let start = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            memo.get(thread_id)
                .expect("the first capture must have memoised an entry")
                .start
        };

        // Grow to EXACTLY `start + MEMO_MAX_WINDOW_BYTES` — the gate's own
        // `<=` boundary at codex_capture.rs's `capture_for` — and confirm
        // it still reuses.
        let target_reuse_len = start + MEMO_MAX_WINDOW_BYTES;
        let pad_prefix = r#"{"type":"pad2","p":""}"#;
        let need = target_reuse_len - body1.len() as u64 - 1; // -1 for this line's own trailing \n
        let pad2 = "b".repeat(need as usize - pad_prefix.len());
        let filler2 = format!(r#"{{"type":"pad2","p":"{pad2}"}}"#);
        let body_reuse = format!("{body1}{filler2}\n");
        assert_eq!(body_reuse.len() as u64, target_reuse_len);
        write_rollout(&codex_home, thread_id, &body_reuse);

        capture_for(&codex_home, thread_id);
        let start_at_boundary = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            memo.get(thread_id)
                .expect("the boundary tick still memoises an entry")
                .start
        };
        assert_eq!(
            start_at_boundary, start,
            "growth of exactly MEMO_MAX_WINDOW_BYTES must still reuse the memo's start"
        );

        // One byte more — a single bare newline, still a well-formed
        // (empty) whole line — must re-anchor instead.
        let body_reanchor = format!("{body_reuse}\n");
        assert_eq!(body_reanchor.len() as u64, target_reuse_len + 1);
        write_rollout(&codex_home, thread_id, &body_reanchor);

        capture_for(&codex_home, thread_id);
        let start_past_boundary = {
            let memo = CAPTURE_MEMO.lock().unwrap();
            memo.get(thread_id)
                .expect("a re-anchor still leaves a memo entry")
                .start
        };
        assert_ne!(
            start_past_boundary, start,
            "one byte past MEMO_MAX_WINDOW_BYTES must re-anchor, never reuse the old start"
        );
    }

    // `retain_capture_memo` — the once-per-tick eviction `codex_app.rs`'s
    // `sync_codex_app_threads` calls with the thread ids it actually
    // observed.

    #[test]
    fn retain_capture_memo_drops_an_id_absent_from_live_and_keeps_a_present_one() {
        // Exercises `retain_memo_in` (the pure rule `retain_capture_memo`
        // delegates to) against a local map only. The real `CAPTURE_MEMO`
        // is process-wide and this crate's tests run in parallel, so a
        // test that retained *that* static directly would evict every
        // other concurrently running test's entries too.
        fn synthetic_memo(model: &str) -> CaptureMemo {
            CaptureMemo {
                path: PathBuf::from(format!("/nonexistent/{model}.jsonl")),
                len: 0,
                mtime: std::time::UNIX_EPOCH,
                start: 0,
                start_ordinal: 0,
                drop_first: false,
                capture: CodexCapture::default(),
            }
        }

        let gone_id = "00000000-0000-7000-8000-00000000001b";
        let kept_id = "00000000-0000-7000-8000-00000000001c";
        let mut memo: BTreeMap<String, CaptureMemo> = BTreeMap::new();
        memo.insert(gone_id.to_string(), synthetic_memo("gone"));
        memo.insert(kept_id.to_string(), synthetic_memo("kept"));

        let live: BTreeSet<String> = [kept_id.to_string()].into_iter().collect();
        retain_memo_in(&mut memo, &live);

        assert!(
            !memo.contains_key(gone_id),
            "a thread id absent from `live` must be evicted"
        );
        assert!(
            memo.contains_key(kept_id),
            "a thread id present in `live` must survive"
        );
    }
}
