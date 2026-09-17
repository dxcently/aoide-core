//! The ping-back (P-EIDOLON slice E5b, `docs/architecture/EIDOLON-TRACE.md`
//! "Second slice"): **a parent hears the children it spawned.** Every
//! `agent:"eidolon"` record Aoide enrolled from outside carries a TRACE
//! (`<stem>.jsonl` beside its `.eid`, named by its presence `meta.json`), and
//! this module is the reaper tick's own reader of it: the highest-priority
//! new event on a child since the last pass becomes ONE line, and that line is
//! delivered to the child's `parentSessionId`.
//!
//! **The daemon's own line, never a `send`.** The send door attests the SENDER
//! from the running process's `/proc` ancestry, so inside the resident daemon
//! the attested sender is the daemon — never the child — which is exactly why
//! the reciprocal rule cannot be `sender_is_parent` made symmetric
//! (`conduct/AGENTS.md` forbids threading a peercred pid into `send.rs` for
//! it). This module therefore takes the DOORBELL's path instead
//! (`graph/doorbell.rs`): raw injection into the target's own transport — one
//! write + close over a live Claude Code channel socket, else
//! [`write_delivery`] plus the target's own submit keystroke for a headless
//! wrap — with no gate, no `pending.json` entry, no provenance prefix, no
//! title rename (the line starts with `[`, which
//! [`names_the_node`](super::send::names_the_node) would otherwise read as a
//! task label), and no mailbase receipt. Every other door forwards this exact
//! thing through the daemon instead, because the daemon IS the policy and
//! audit boundary here: [`pingback`] executes only under `Door::Daemon` and
//! returns silently for every other door (the daemon's own tick will do it).
//!
//! **Post-lock, after the eidolon sync.** The reaper holds `.stage.lock`
//! across `reap_inner`; this module runs entirely AFTER that lock is released
//! (`reap.rs`'s post-lock collector block, the same side `sync_codex_app_
//! threads`/`refresh_live_agents` sit on), never inside it — the claim section
//! takes the stage lock briefly for its own read-decide-write, and the socket
//! write that follows happens with no lock held at all. The socket write is
//! bounded ([`super::doorbell::connect_for_ring`]'s own 2s timeout, the one
//! transport-timeout authority in this crate) so a wedged parent can never
//! park the daemon's tick.
//!
//! **At-most-once, by a per-child cursor claimed BEFORE the delivery.**
//! `state/stage/pingback.json` holds, per child session id, the last trace
//! record id examined (`seen`) and the record id a silence line was already
//! sent for (`silentAt`). The claim section reads that file, decides, and
//! writes the ADVANCED cursor with a temp-then-rename write, all inside one
//! short critical section; the delivery happens after. A crash between the two
//! loses a line — the safe direction, since the other direction is a duplicate
//! in a parent's composer. A child whose record is gone drops out of the file
//! on the same pass.
//!
//! **Never a shell parent.** A line submitted into a bare shell would RUN as a
//! command, so a target whose `agent` is `""`/`"shell"` (or names no
//! registered harness profile) is skipped and counted, never injected into.
//! Every child-authored fragment of a line — the quoted say, prompt and stop
//! reason, and the unquoted tool label — is untrusted model output (house
//! rule 4): one line, control characters stripped, clipped to [`SAY_MAX`]
//! with `…`; the quoted ones are never allowed to start with `/` or `!`.

use super::conduct::channel_socket_path;
use super::doorbell::{connect_for_ring, write_channel};
use super::eidolon::{eidolon_state_from_trace, DroppedEidolon};
use super::model::{canonical_state, load_stage, sessions_path, SessionRecord, SessionsFile};
use super::permit::profile_for_agent;
use super::send::{audit_send, write_delivery, SUBMIT_KEYSTROKE_DELAY};
use super::trace::{one_line_clip, tool_result_summary};
use aoide_protocol::agents::{agent_profile, eidolon_trace_record, TraceRecord};
use aoide_protocol::{Door, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// How much of a quoted `say`/prompt reaches the parent's line — one short
/// phrase, never a paragraph in somebody else's composer.
const SAY_MAX: usize = 80;
/// How long a turn may sit with no new record before the child is called
/// silent (the brief's ten minutes).
const SILENCE_MS: i64 = 10 * 60 * 1000;
/// How many `ToolResult{is_error:true}` records IN A ROW it takes to say
/// "failing" — below this, tool errors ride an existing line at most.
const ERROR_RUN: u64 = 3;

/// `state/stage/pingback.json` — the per-child cursor. One map, keyed by the
/// child's own native session id (the eidolon presence id, verbatim).
pub(crate) fn pingback_path() -> PathBuf {
    aoide_storage::fs::conducting_stage_dir().join("pingback.json")
}

/// One child's cursor entry: `seen` is the last trace record id examined
/// (delivered or merely passed over), `silentAt` the record id a silence line
/// was already sent for. `silentAt` is re-armed (absent) by any new record, so
/// a child that speaks and goes quiet again gets its next silence line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CursorEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seen: Option<String>,
    #[serde(rename = "silentAt", default, skip_serializing_if = "Option::is_none")]
    silent_at: Option<String>,
}

/// The whole cursor file. A `BTreeMap` so the file's own key order is stable
/// (a diff of two ticks reads as a diff of children, never of hashing).
type CursorFile = BTreeMap<String, CursorEntry>;

/// What [`pingback`] did this tick — the report the reaper prints from and its
/// own tests assert against. Never folded into the sweep's `changed` vec: a
/// parent being told something must not toast the desktop every twelve
/// seconds (`refresh_live_agents`' own rule, one collector over).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PingbackReport {
    /// `(parent id, the line delivered)` per delivery.
    pub delivered: Vec<(String, String)>,
    /// `(target id, why not)` for every candidate that was claimed but not
    /// delivered — `no-parent-record`, `shell-parent`, `not-conductable`,
    /// `parent-done`, `interactive-composer`, `write-failed`.
    pub skipped: Vec<(String, String)>,
}

/// One child this tick, already gathered: its roster facts plus the trace tail
/// READ OUTSIDE the claim section (a 1 MiB read per child has no business
/// inside the stage lock), so the critical section only reads the cursor,
/// decides, and writes it.
struct Child {
    id: String,
    petname: Option<String>,
    agent: String,
    parent: String,
    /// The trace's own tail lines, or `None` when there is no readable trace
    /// for this child right now (then nothing is examined, and any existing
    /// cursor entry is left exactly as it was).
    lines: Option<Vec<String>>,
    /// `sync_eidolon_sessions` dropped this child's presence record on THIS
    /// tick — the "died mid-turn" row, and the reason its cursor entry leaves
    /// the file on this same pass.
    dropped_mid_turn: bool,
}

/// One decided delivery: which parent, and the one line to write.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChildClaim {
    parent: String,
    line: String,
}

/// The ping-back's whole pass, run from `reap.rs`'s post-lock collector block
/// AFTER `sync_eidolon_sessions()` (so the roster it reads is the one that
/// sync just reconciled) — and only under `Door::Daemon`, the policy and
/// audit boundary for an automated line. Returns the tick's report; the
/// caller folds NOTHING into `outcome.changed`.
pub(crate) fn pingback(inv: &Invocation, dropped: &[DroppedEidolon]) -> PingbackReport {
    let mut report = PingbackReport::default();
    if inv.door != Door::Daemon {
        return report;
    }
    let roster: Vec<SessionRecord> = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions)
        .unwrap_or_default();
    let now_ms = (super::conduct::unix_ts() as i64) * 1000;

    // ── gather (no lock, no socket) ─────────────────────────────────────
    let mut children: Vec<Child> = Vec::new();
    let mut eidolon_ids: HashSet<String> = HashSet::new();
    for rec in roster.iter().filter(|r| r.agent == "eidolon") {
        eidolon_ids.insert(rec.session_id.clone());
        let Some(parent) = rec.parent_session_id.clone().filter(|p| !p.is_empty()) else {
            continue; // top-level: nobody to tell
        };
        children.push(Child {
            id: rec.session_id.clone(),
            petname: rec.petname.clone(),
            agent: rec.agent.clone(),
            parent,
            lines: locate_trace(&rec.agent, &rec.session_id, &rec.cwd, rec.log_path.as_deref()),
            dropped_mid_turn: false,
        });
    }
    for drop in dropped {
        let Some(parent) = drop.parent_session_id.clone().filter(|p| !p.is_empty()) else {
            continue;
        };
        children.push(Child {
            id: drop.session_id.clone(),
            petname: drop.petname.clone(),
            agent: drop.agent.clone(),
            parent,
            lines: drop
                .trace
                .as_deref()
                .and_then(|path| read_trace(&drop.agent, path)),
            dropped_mid_turn: true,
        });
    }

    // ── claim: one short critical section, read → decide → write ────────
    // The advanced cursor is written INSIDE the lock, before it is released:
    // the claim IS the write, so no second tick can decide over the old
    // cursor between this tick's decision and its file.
    let claims = aoide_storage::fs::with_stage_lock(|| {
        let (claims, old_cursor, new_cursor) = claim_locked(&children, &eidolon_ids, now_ms);
        if new_cursor != old_cursor {
            match serde_json::to_string(&new_cursor) {
                Ok(body) => {
                    if let Err(e) = aoide_storage::fs::atomic_write(&pingback_path(), &format!("{body}\n")) {
                        eprintln!("[aoide/reap] ping-back cursor write failed: {e}");
                    }
                }
                Err(e) => eprintln!("[aoide/reap] ping-back cursor encode failed: {e}"),
            }
        }
        claims
    });

    // ── deliver (no lock held) ──────────────────────────────────────────
    for claim in claims {
        match deliver(&claim.line, &claim.parent, &roster, inv) {
            Ok(()) => {
                eprintln!("[aoide/reap] ping-back → {}: {}", claim.parent, claim.line);
                report.delivered.push((claim.parent, claim.line));
            }
            Err(reason) => report.skipped.push((claim.parent, reason)),
        }
    }
    report
}

/// The claim section's whole body — run ONLY inside the stage lock.
///
/// Entry lifetime: an entry survives only while its child is still an
/// `agent:"eidolon"` roster record (so a child whose record is gone — dropped
/// by the sync above, or reaped as stale — leaves the file on this same
/// pass), and a child that yielded nothing to examine keeps whatever it had.
fn claim_locked(
    children: &[Child],
    eidolon_ids: &HashSet<String>,
    now_ms: i64,
) -> (Vec<ChildClaim>, CursorFile, CursorFile) {
    let old = read_cursor();
    let mut next: CursorFile = BTreeMap::new();
    for (id, entry) in &old {
        if eidolon_ids.contains(id) {
            next.insert(id.clone(), entry.clone());
        }
    }

    let mut claims: Vec<ChildClaim> = Vec::new();
    for child in children {
        let entry = next.get(&child.id).cloned().unwrap_or_default();
        let (line, updated) = decide(child, &entry, now_ms);
        if let Some(line) = line {
            claims.push(ChildClaim { parent: child.parent.clone(), line });
        }
        // A child whose record is gone — the `died mid-turn` row, whose only
        // input is the sync's own dropped set — leaves the file on this same
        // pass: an entry naming a session nothing is tracking would only ever
        // re-decide a stale window.
        if updated.seen.is_some() && eidolon_ids.contains(&child.id) {
            next.insert(child.id.clone(), updated);
        }
    }
    (claims, old, next)
}

/// Read the cursor file; any unreadable/unparseable content reads as an EMPTY
/// cursor rather than failing the pass (the file is ours alone, and a torn
/// hand-edit may only ever cost one extra line — never a stuck sweep).
fn read_cursor() -> CursorFile {
    std::fs::read_to_string(pingback_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// One child's whole decision: the line to deliver (or none) and its own next
/// cursor entry. Pure over the already-read tail, so every row of the line
/// grammar is a table test.
fn decide(child: &Child, entry: &CursorEntry, now_ms: i64) -> (Option<String>, CursorEntry) {
    let Some(lines) = &child.lines else {
        return (None, entry.clone());
    };
    let tail: Vec<TraceRecord> = lines.iter().filter_map(|l| eidolon_trace_record(l)).collect();
    let Some(last) = tail.last() else {
        return (None, entry.clone());
    };
    let new = split_new(&tail, entry.seen.as_deref());
    let (line, silent_at) = choose(child, lines, &tail, new, entry.silent_at.as_deref(), now_ms);
    (
        line,
        CursorEntry { seen: Some(last.id.clone()), silent_at },
    )
}

/// The records after `seen` IN THE TAIL — everything in the tail when `seen`
/// is absent or no longer in the window (a tail that scrolled past it, a fresh
/// child): that is treated as new ONCE, and nothing is ever said about what
/// the window lost.
fn split_new<'a>(tail: &'a [TraceRecord], seen: Option<&str>) -> &'a [TraceRecord] {
    let Some(seen) = seen.filter(|s| !s.is_empty() && *s != "?") else {
        return tail;
    };
    match tail.iter().position(|r| r.id == seen) {
        Some(i) => &tail[i + 1..],
        None => tail,
    }
}

/// Choose the highest-priority new event and render its ONE line, returning it
/// beside the silence latch to persist. The table is the design doc's:
///
/// | priority | event | line |
/// |---|---|---|
/// | 1 | `TurnSettled` / `Cancelled` / dropped mid-turn | `settled …` / `cancelled …` / `died mid-turn …` |
/// | 2 | `AskUser{answer:null}` | `asking: "…"` |
/// | 3 | `TurnBudget{calls_left}` / `TurnDeadline{secs_left}` | `wrapping up · <n> calls left` |
/// | 4 | three or more `ToolResult{is_error:true}` in a row, ending the new records | `failing · <k> tool errors in a row · last: <tool label>` |
/// | 5 | no new record, turn open, ten minutes quiet | `silent <M> min · last: …` |
///
/// A `ToolResult{is_error:true}` among the new records rides any priority-1..3
/// line as ` · <k> tool errors`; tool errors alone below three in a row are
/// never a line of their own.
fn choose(
    child: &Child,
    lines: &[String],
    tail: &[TraceRecord],
    new: &[TraceRecord],
    silent_at: Option<&str>,
    now_ms: i64,
) -> (Option<String>, Option<String>) {
    let tag = child_tag(child.petname.as_deref(), &child.id);
    let errors = new.iter().filter(|r| is_error(r)).count() as u64;
    let errors_note = |k: u64| if k == 0 { String::new() } else { format!(" · {k} tool errors") };
    let last_id = tail.last().map(|r| r.id.clone());

    // Priority 1: the turn's own end — settled or cancelled, whichever new
    // record is LAST (the most recent truth wins).
    if let Some(rec) = new.iter().rev().find(|r| r.kind == "TurnSettled" || r.kind == "Cancelled") {
        let head = if rec.kind == "TurnSettled" {
            let stop = str_field(rec.payload.as_ref(), "stop_reason");
            if stop.is_empty() {
                format!("{tag} settled")
            } else {
                format!("{tag} settled {}", quote_inline(&stop))
            }
        } else {
            format!("{tag} cancelled")
        };
        let mut line = head;
        if let Some(calls) = calls_segment(tail) {
            line.push_str(&format!(" · {calls}"));
        }
        if let Some(mins) = mins_segment(tail) {
            line.push_str(&format!(" · {mins}"));
        }
        if let Some(say) = say_of(&child.agent, lines) {
            line.push_str(&format!(" · last: \"{}\"", quote(&say)));
        }
        line.push_str(&errors_note(errors));
        return (Some(line), None);
    }

    // Priority 1, the third shape: the process went away with the turn still
    // open (its trace says so) — the one row that needs the sync's own
    // additive return.
    if child.dropped_mid_turn && turn_open(lines) {
        let mut line = format!("{tag} died mid-turn");
        if let Some(calls) = calls_segment(tail) {
            line.push_str(&format!(" · {calls}"));
        }
        if let Some(say) = say_of(&child.agent, lines) {
            line.push_str(&format!(" · last: \"{}\"", quote(&say)));
        }
        line.push_str(&errors_note(errors));
        return (Some(line), None);
    }

    // Priority 2: a prompt is open and nothing has answered it.
    if let Some(rec) = new
        .iter()
        .rev()
        .find(|r| r.kind == "AskUser" && !answered(r))
    {
        let prompt = str_field(rec.payload.as_ref(), "prompt");
        let mut line = format!("{tag} asking: \"{}\"", quote(&prompt));
        line.push_str(&errors_note(errors));
        return (Some(line), None);
    }

    // Priority 3: the harness told it to wrap up.
    if let Some(rec) = new
        .iter()
        .rev()
        .find(|r| r.kind == "TurnBudget" || r.kind == "TurnDeadline")
    {
        let seg = if rec.kind == "TurnBudget" {
            numeric_field(rec.payload.as_ref(), "calls_left").map(|n| format!("{n} calls left"))
        } else {
            numeric_field(rec.payload.as_ref(), "secs_left").map(|n| format!("{n} s left"))
        };
        let mut line = format!("{tag} wrapping up");
        if let Some(seg) = seg {
            line.push_str(&format!(" · {seg}"));
        }
        line.push_str(&errors_note(errors));
        return (Some(line), None);
    }

    // Priority 4: a run of tool errors, ending the new records.
    let run = trailing_error_run(new);
    if run >= ERROR_RUN {
        let mut line = format!("{tag} failing · {run} tool errors in a row");
        if let Some(label) = last_tool_label(tail) {
            line.push_str(&format!(" · last: {label}"));
        }
        return (Some(line), None);
    }

    // Priority 5: silence on an open turn — latched, one line per silence,
    // re-armed by any new record (every arm above returns `None` for the
    // latch, which IS the re-arm).
    if new.is_empty() && turn_open(lines) {
        if let (Some(last_id), Some(ts)) = (last_id, tail.last().and_then(|r| r.ts_ms)) {
            let quiet_ms = now_ms - ts;
            if quiet_ms >= SILENCE_MS && silent_at != Some(last_id.as_str()) {
                let mins = quiet_ms / 60_000;
                let mut line = format!("{tag} silent {mins} min");
                if let Some(last) = last_tool_or_say(child, tail, lines) {
                    line.push_str(&format!(" · last: {last}"));
                }
                return (Some(line), Some(last_id));
            }
        }
    }

    (None, silent_at.map(str::to_string))
}

// ── gathering ───────────────────────────────────────────────────────────

/// The trace path for a live child, through the harness CAPABILITY
/// (`TranscriptSpec::locate` — the same locator the reaper's transcript
/// refresh and `session trace` call; never `if agent == "eidolon"`), then
/// through `TranscriptSpec::trace`, the ONE trace reader. `None` for a
/// harness that keeps no trace and for a presence naming none. `log_path` is
/// the record's own journal, the locator's hint for a presence that a clean
/// exit already removed.
fn locate_trace(agent: &str, id: &str, cwd: &str, log_path: Option<&str>) -> Option<Vec<String>> {
    let profile = agent_profile(agent)?;
    let path = (profile.transcript.locate)(id, Some(cwd), log_path)?;
    read_trace(agent, &path)
}

/// Read `path` as one harness's trace tail. A trace that is not there, or a
/// path that is not a trace at all, is `None` — never an error that would void
/// this child's whole pass.
fn read_trace(agent: &str, path: &Path) -> Option<Vec<String>> {
    let read = agent_profile(agent)?.transcript.trace?;
    read(path)
}

// ── rendering ───────────────────────────────────────────────────────────

/// `[eidolon <petname>]` — the line's own tag. A record always carries a
/// petname (minted at insert), so the id fallback is for a hand-edited roster,
/// never the ordinary path.
fn child_tag(petname: Option<&str>, id: &str) -> String {
    match petname.filter(|p| !p.trim().is_empty()) {
        Some(name) => format!("[eidolon {name}]"),
        None => format!("[eidolon {id}]"),
    }
}

/// Untrusted child-authored text as ONE safe line (house rule 4): control
/// characters stripped (a `\r` is an Enter at a headless parent's PTY, and
/// whatever follows it would start a fresh composer line), whitespace
/// flattened, clipped to [`SAY_MAX`] with `…`. EVERY fragment the child wrote
/// passes through here — the say, the prompt, the stop reason, and the tool
/// label alike — never only the ones the grammar puts in quotes.
fn clean(s: &str) -> String {
    let stripped: String = s.chars().filter(|c| !c.is_control()).collect();
    one_line_clip(&stripped, SAY_MAX)
}

/// [`clean`] as a quoted phrase: additionally never allowed to start with `/`
/// or `!` (which would read as a command or a shell escape at a parent's
/// prompt) — a leading space is the guard.
fn quote(s: &str) -> String {
    let clipped = clean(s);
    if clipped.starts_with('/') || clipped.starts_with('!') {
        format!(" {clipped}")
    } else {
        clipped
    }
}

/// One field of a record's payload as one clipped line — the stop reason, a
/// prompt: a field READ, never a second formatter for the record.
fn quote_inline(s: &str) -> String {
    quote(s)
}

/// A payload string field, [`clean`]ed; empty when absent/blank.
fn str_field(payload: Option<&Value>, key: &str) -> String {
    payload
        .and_then(|p| p.get(key))
        .and_then(Value::as_str)
        .map(clean)
        .unwrap_or_default()
}

/// A payload numeric field, whichever of the two spellings the journal used
/// (the sample contract writes numbers; nothing promises it stays one).
fn numeric_field(payload: Option<&Value>, key: &str) -> Option<String> {
    match payload?.get(key)? {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.trim().is_empty() => Some(one_line_clip(s, SAY_MAX)),
        _ => None,
    }
}

fn is_error(rec: &TraceRecord) -> bool {
    rec.kind == "ToolResult"
        && rec
            .payload
            .as_ref()
            .and_then(|p| p.get("is_error"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn answered(rec: &TraceRecord) -> bool {
    rec.payload
        .as_ref()
        .and_then(|p| p.get("answer"))
        .map(|a| !a.is_null())
        .unwrap_or(false)
}

fn tool_uses(rec: &TraceRecord) -> u64 {
    rec.payload
        .as_ref()
        .and_then(|p| p.get("content"))
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
                .count() as u64
        })
        .unwrap_or(0)
}

/// The index of the turn's own opening record — the LAST `UserMessage`/
/// `ExternalMessage` in the tail (a steer opens a turn as surely as a first
/// prompt does).
fn turn_open_index(tail: &[TraceRecord]) -> Option<usize> {
    tail.iter()
        .rposition(|r| r.kind == "UserMessage" || r.kind == "ExternalMessage")
}

/// `<N> calls` — `tool_use` blocks since the turn's opening record, when that
/// record is in the tail; `None` (segment omitted) when the window has lost
/// it.
fn calls_segment(tail: &[TraceRecord]) -> Option<String> {
    let start = turn_open_index(tail)?;
    let calls: u64 = tail[start + 1..].iter().map(tool_uses).sum();
    Some(format!("{calls} calls"))
}

/// `<M> min` — whole minutes from that same opening record's `ts_ms` to the
/// tail's last record, when both carry one.
fn mins_segment(tail: &[TraceRecord]) -> Option<String> {
    let start = turn_open_index(tail)?;
    let from = tail.get(start)?.ts_ms?;
    let to = tail.last()?.ts_ms?;
    Some(format!("{} min", (to - from).max(0) / 60_000))
}

/// The turn is still OPEN — the same fold the state rule uses
/// (`eidolon_state_from_trace`, the reconciler's own function): `working` or
/// `awaiting`, never a settled/cancelled end, never "unknown" (no evidence is
/// not evidence of an open turn).
fn turn_open(lines: &[String]) -> bool {
    matches!(eidolon_state_from_trace(lines), Some("working") | Some("awaiting"))
}

/// The child's latest words, through its own harness CAPABILITY
/// (`TranscriptSpec::say` — the very function that fills the roster's `say`
/// field), never a second reader of an assistant record.
fn say_of(agent: &str, lines: &[String]) -> Option<String> {
    let profile = agent_profile(agent)?;
    (profile.transcript.say)(lines, false).filter(|s| !s.trim().is_empty())
}

/// `<tool label>` — the last `ToolResult`'s own rendered line, through
/// `trace.rs`'s `tool_result_summary` (the renderer `session trace` shows for
/// that record; never a second formatter for it), then [`clean`]ed: a tool
/// result's first line is the least trusted text in the trace (a file the
/// child read, a page it fetched).
fn last_tool_label(tail: &[TraceRecord]) -> Option<String> {
    tail.iter()
        .rev()
        .find(|r| r.kind == "ToolResult")
        .map(|r| clean(&tool_result_summary(r.payload.as_ref(), if is_error(r) { "! " } else { "" })))
        .filter(|label| !label.is_empty())
}

/// What the child last DID or SAID — whichever of the two the tail holds most
/// recently, for the silence line.
fn last_tool_or_say(child: &Child, tail: &[TraceRecord], lines: &[String]) -> Option<String> {
    let tool = tail.iter().rposition(|r| r.kind == "ToolResult");
    let spoke = tail.iter().rposition(|r| r.kind == "AssistantMessage");
    match (tool, spoke) {
        (Some(t), Some(s)) if s > t => say_of(&child.agent, lines).map(|s| format!("\"{}\"", quote(&s))),
        (Some(_), _) => last_tool_label(tail),
        (None, Some(_)) => say_of(&child.agent, lines).map(|s| format!("\"{}\"", quote(&s))),
        (None, None) => None,
    }
}

/// How many `ToolResult{is_error:true}` records END the new records.
fn trailing_error_run(new: &[TraceRecord]) -> u64 {
    let mut run = 0;
    for rec in new.iter().rev() {
        if is_error(rec) {
            run += 1;
        } else {
            break;
        }
    }
    run
}

// ── delivery (the doorbell's way) ────────────────────────────────────────

/// Deliver ONE line to `parent`, raw — the doorbell's own transport selection
/// (P-M5c-3): a live Claude Code channel socket outranks the control-socket
/// PTY for ANY wrap and needs no submit keystroke; otherwise a HEADLESS wrap
/// takes [`write_delivery`] plus the wrap's own profile submit key; an
/// interactive wrap with no channel is skipped (`interactive-composer`) — the
/// same ban a ring holds, since this is likewise a raw keystroke with no
/// human's intent behind it. Every rejection is a NAMED skip, counted in the
/// report, never a silent drop.
fn deliver(
    line: &str,
    parent: &str,
    roster: &[SessionRecord],
    inv: &Invocation,
) -> Result<(), String> {
    let Some(rec) = roster.iter().find(|s| s.session_id == parent) else {
        return Err("no-parent-record".to_string());
    };
    // Never a shell parent: a line reaching a bare shell's input is a COMMAND
    // LINE, and it would run. A record naming no registered harness profile is
    // the same shape `profile_for_agent` itself falls back for.
    if matches!(rec.agent.as_str(), "" | "shell") || agent_profile(&rec.agent).is_none() {
        return Err("shell-parent".to_string());
    }
    if !super::doc::is_conductable_now(rec) {
        return Err("not-conductable".to_string());
    }
    if canonical_state(&rec.state) == "done" {
        return Err("parent-done".to_string());
    }

    let payload = format!("{line}\n");
    let channel = connect_for_ring(channel_socket_path(parent))
        .ok()
        .map(|stream| write_channel(stream, payload.as_bytes()));

    let wrote = match channel {
        Some(result) => result,
        None if rec.headless => {
            let socket = rec.socket.as_deref().unwrap_or_default();
            let profile = profile_for_agent(&rec.agent);
            (|| -> std::io::Result<()> {
                let mut stream = connect_for_ring(socket)?;
                write_delivery(
                    &mut stream,
                    payload.as_bytes(),
                    true,
                    profile.submit_key,
                    SUBMIT_KEYSTROKE_DELAY,
                )
            })()
        }
        None => return Err("interactive-composer".to_string()),
    };

    match wrote {
        Ok(()) => {
            // One audit line per delivery, through the SAME helper `send`
            // uses, with this lane's own gate label. The line itself (which
            // carries quoted model output) rides as `untrusted_data`, never as
            // the audit message.
            audit_send(
                inv,
                "delivered",
                &format!("delivered to `{parent}` (autogate-child)"),
                line,
            );
            Ok(())
        }
        Err(_) => Err("write-failed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::conduct::conduct_socket_path;
    use crate::graph::model::{load_stage, sessions_path, write_stage, SessionsFile};
    use crate::graph::session_store::{do_session_start, stamp_headless};
    use crate::graph::testutil::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;

    // The design doc's own sample lines, verbatim (EIDOLON-TRACE.md's "Line"
    // block) — the same fixtures `protocol/agents.rs`, `graph/eidolon.rs` and
    // `graph/trace.rs` pin their own halves against.
    const START: &str = r#"{"id":0,"parent":null,"ts_ms":1789603005561,"kind":{"SessionStart":{"model":"ollama:deepseek-v4.1-flash","cwd":"/home/khoa/Aoide","system":null}}}"#;
    const USER: &str = r##"{"id":1,"parent":0,"ts_ms":1789603005570,"kind":{"UserMessage":{"role":"user","content":[{"type":"text","text":"# Brief A: …"}]}}}"##;
    const ASSISTANT: &str = r#"{"id":2,"parent":1,"ts_ms":1789603009102,"kind":{"AssistantMessage":{"role":"assistant","content":[{"type":"thinking","thinking":"…","signature":"…"},{"type":"text","text":"Let me read the slot catalog first."},{"type":"tool_use","id":"call_8vr43zri","name":"read","input":"{\"path\":\"a\"}"}]}}}"#;
    const RESULT: &str = r#"{"id":3,"parent":2,"ts_ms":1789603009140,"kind":{"ToolResult":{"tool_use_id":"call_8vr43zri","content":"     1\t# Per-song widget slots\nmore","is_error":false}}}"#;
    const RESULT_ERR: &str = r#"{"id":4,"parent":3,"ts_ms":1789603009200,"kind":{"ToolResult":{"tool_use_id":"call_9","content":"ENOENT: no such file\nmore","is_error":true}}}"#;
    const SETTLED: &str = r#"{"id":131,"parent":130,"ts_ms":1789606421000,"kind":{"TurnSettled":{"stop_reason":"end_turn","usage":{"input_tokens":9570000,"output_tokens":71900}}}}"#;
    const CANCELLED: &str = r#"{"id":77,"parent":76,"ts_ms":1789626990000,"kind":"Cancelled"}"#;
    const ASK: &str = r#"{"id":40,"parent":39,"ts_ms":1789626500000,"kind":{"AskUser":{"call_id":"call_x","prompt":"Overwrite?","answer":null}}}"#;
    const BUDGET: &str = r#"{"id":120,"parent":119,"ts_ms":1789606380000,"kind":{"TurnBudget":{"calls_left":8}}}"#;
    const DEADLINE: &str = r#"{"id":121,"parent":120,"ts_ms":1789606380500,"kind":{"TurnDeadline":{"secs_left":30}}}"#;
    const EXTERNAL: &str = r#"{"id":55,"parent":54,"ts_ms":1789626700000,"kind":{"ExternalMessage":{"from":"orchestrator","channel":null,"text":"STOP: write the report now"}}}"#;

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// A child as the gather would hand it over: petname `brave-otter`, agent
    /// `eidolon`, parent `wrap-1`, and the given trace body.
    fn child_of(body: &[&str]) -> Child {
        Child {
            id: "user-0001".to_string(),
            petname: Some("brave-otter".to_string()),
            agent: "eidolon".to_string(),
            parent: "wrap-1".to_string(),
            lines: Some(lines(body)),
            dropped_mid_turn: false,
        }
    }

    /// Decide one body with `seen` already past `seen_id` — the pure seam the
    /// whole line grammar is tested through. "Now" is anchored to the tail's
    /// OWN last record, so the silence row never fires by accident: a test
    /// that wants silence asks for it explicitly through [`plan_at`].
    fn plan(body: &[&str], seen_id: Option<&str>) -> (Option<String>, CursorEntry) {
        plan_at(body, seen_id, last_ts(body))
    }

    fn plan_at(body: &[&str], seen_id: Option<&str>, now: i64) -> (Option<String>, CursorEntry) {
        let child = child_of(body);
        let entry = CursorEntry { seen: seen_id.map(str::to_string), silent_at: None };
        decide(&child, &entry, now)
    }

    /// The tail's own last readable `ts_ms` — the anchor every non-silence
    /// expectation is measured from.
    fn last_ts(body: &[&str]) -> i64 {
        lines(body)
            .iter()
            .filter_map(|l| eidolon_trace_record(l))
            .filter_map(|r| r.ts_ms)
            .next_back()
            .unwrap_or(0)
    }

    fn now_ms() -> i64 {
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()) as i64
    }

    // ── the line grammar, pure ───────────────────────────────────────────

    #[test]
    fn every_row_of_the_table_renders_its_own_one_line() {
        // TurnSettled → settled, with calls/minutes since the opening prompt
        // and the last thing said.
        let (line, entry) = plan(&[USER, ASSISTANT, RESULT, SETTLED], None);
        let line = line.expect("a settled turn is a line");
        assert!(line.starts_with("[eidolon brave-otter] settled end_turn"), "{line}");
        assert!(line.contains("1 calls"), "one tool_use since the prompt: {line}");
        assert!(line.contains("56 min"), "prompt 1789603005570 → settle 1789606421000: {line}");
        assert!(line.contains("last: \"Let me read the slot catalog first.\""), "{line}");
        assert_eq!(entry.seen.as_deref(), Some("131"), "the cursor advances to the tail's last id");
        assert_eq!(entry.silent_at, None);

        // Cancelled → its own line, same trailing segments.
        let (line, _) = plan(&[USER, ASSISTANT, CANCELLED], None);
        let line = line.expect("a cancel is a line");
        assert!(line.starts_with("[eidolon brave-otter] cancelled"), "{line}");
        assert!(line.contains("1 calls"), "{line}");
        assert!(line.contains("last: \"Let me read the slot catalog first.\""), "{line}");

        // AskUser{answer:null} → asking.
        let (line, _) = plan(&[USER, ASK], None);
        assert_eq!(line.unwrap(), "[eidolon brave-otter] asking: \"Overwrite?\"");

        // TurnBudget / TurnDeadline → wrapping up.
        let (line, _) = plan(&[USER, BUDGET], None);
        assert_eq!(line.clone().unwrap(), "[eidolon brave-otter] wrapping up · 8 calls left");
        let (line, _) = plan(&[USER, DEADLINE], None);
        assert_eq!(line.unwrap(), "[eidolon brave-otter] wrapping up · 30 s left");

        // Three errors in a row, ending the new records → failing.
        let (line, _) = plan(&[USER, RESULT_ERR, RESULT_ERR, RESULT_ERR], None);
        let line = line.expect("three in a row is a line");
        assert!(line.starts_with("[eidolon brave-otter] failing · 3 tool errors in a row"), "{line}");
        assert!(line.contains("last: ! ENOENT: no such file"), "the rendered tool result: {line}");

        // Silence on an open turn → silent, with the latch set.
        let now = now_ms();
        let old = format!(
            r#"{{"id":7,"parent":6,"ts_ms":{},"kind":{{"AssistantMessage":{{"content":[{{"type":"text","text":"thinking it over"}}]}}}}}}"#,
            now - 11 * 60 * 1000
        );
        let (line, entry) = plan_at(&[USER, old.as_str()], Some("7"), now);
        let line = line.expect("ten quiet minutes is a line");
        assert!(line.starts_with("[eidolon brave-otter] silent 11 min"), "{line}");
        assert!(line.contains("last: \"thinking it over\""), "{line}");
        assert_eq!(entry.silent_at.as_deref(), Some("7"), "the silence latch is set");
    }

    #[test]
    fn a_dropped_child_with_an_open_turn_reads_died_mid_turn() {
        let mut child = child_of(&[USER, ASSISTANT]);
        child.dropped_mid_turn = true;
        let (line, entry) = decide(&child, &CursorEntry::default(), now_ms());
        let line = line.expect("a death with the turn open is a line");
        assert!(line.starts_with("[eidolon brave-otter] died mid-turn"), "{line}");
        assert!(line.contains("1 calls"), "{line}");
        assert!(line.contains("last: \"Let me read the slot catalog first.\""), "{line}");
        assert_eq!(entry.seen.as_deref(), Some("2"));

        // ...but a child whose trace says the turn ENDED is not "mid-turn",
        // and its new settled record is already the priority-1 line.
        let mut closed = child_of(&[USER, SETTLED]);
        closed.dropped_mid_turn = true;
        let (line, _) = decide(&closed, &CursorEntry::default(), now_ms());
        assert!(line.unwrap().contains("settled"), "a settled death is not a mid-turn death");
        let mut silent_death = child_of(&[SETTLED]);
        silent_death.dropped_mid_turn = true;
        let (line, _) = decide(
            &silent_death,
            &CursorEntry { seen: Some("131".to_string()), silent_at: None },
            now_ms(),
        );
        assert_eq!(line, None, "a closed turn's death is not a line");
    }

    #[test]
    fn the_highest_priority_new_event_wins_and_the_last_of_a_tie() {
        // Several events new at once: settled (1) beats asking (2), wrapping
        // (3), the error run (4) and silence (5).
        let (line, _) = plan(&[USER, BUDGET, ASK, RESULT_ERR, SETTLED], None);
        assert!(line.unwrap().starts_with("[eidolon brave-otter] settled"), "priority 1 wins");

        // asking beats wrapping up.
        let (line, _) = plan(&[USER, ASK, BUDGET], None);
        assert!(line.unwrap().contains("asking: \"Overwrite?\""));

        // wrapped up beats a failing run.
        let (line, _) = plan(&[USER, BUDGET, RESULT_ERR, RESULT_ERR, RESULT_ERR], None);
        assert!(line.unwrap().contains("wrapping up"));

        // Two priority-1 records new in the same tick: the LAST one is the
        // turn's most recent truth.
        let (line, _) = plan(&[USER, CANCELLED, SETTLED], None);
        assert!(line.unwrap().contains("settled"), "the last priority-1 record wins");

        // A turn already seen as settled, then cancelled: the cancel is the
        // new event.
        let (line, _) = plan(&[USER, SETTLED, CANCELLED], Some("131"));
        assert!(line.unwrap().contains("cancelled"));
    }

    #[test]
    fn tool_errors_ride_a_higher_line_and_never_fire_alone_below_three() {
        // One error among the new records rides the settled line.
        let (line, _) = plan(&[USER, ASSISTANT, RESULT_ERR, SETTLED], None);
        assert!(line.unwrap().ends_with(" · 1 tool errors"), "the error rides along");

        // Two errors ride an asking line the same way.
        let (line, _) = plan(&[USER, RESULT, RESULT_ERR, RESULT_ERR, ASK], None);
        let line = line.unwrap();
        assert!(line.contains("asking: \"Overwrite?\""), "{line}");
        assert!(line.ends_with(" · 2 tool errors"), "{line}");

        // Below three in a row, with nothing else new: NOT a line.
        assert_eq!(plan(&[USER, RESULT_ERR, RESULT_ERR, ASSISTANT], Some("2")).0, None);
        assert_eq!(plan(&[USER, RESULT_ERR], Some("1")).0, None, "one error alone is not a line");

        // A run broken by another record is not a run.
        assert_eq!(plan(&[USER, RESULT_ERR, RESULT_ERR, RESULT_ERR, RESULT_ERR, RESULT, ASSISTANT], Some("2")).0, None);
    }

    #[test]
    fn quoted_text_is_one_line_clipped_and_never_starts_a_command() {
        // 200 chars of quoted output clips to SAY_MAX with an ellipsis.
        let long = format!(
            r#"{{"id":5,"parent":4,"ts_ms":1000,"kind":{{"AskUser":{{"prompt":"{}","answer":null}}}}}}"#,
            "x".repeat(200)
        );
        let (line, _) = plan(&[USER, long.as_str()], Some("1"));
        let line = line.unwrap();
        assert!(line.contains('…'), "clipped: {line}");
        let quoted = line.split('"').nth(1).unwrap();
        assert_eq!(quoted.chars().count(), SAY_MAX, "exactly SAY_MAX chars inside the quotes");

        // A leading `/` or `!` is a command/escape at a parent's prompt — the
        // quote is prefixed with a space instead.
        for raw in ["/compact keep only records", "!rm -rf /tmp/x"] {
            let escaped = raw.replace('"', "'");
            let json = format!(
                r#"{{"id":5,"parent":4,"ts_ms":1000,"kind":{{"AskUser":{{"prompt":"{escaped}","answer":null}}}}}}"#
            );
            let (line, _) = plan(&[USER, json.as_str()], Some("1"));
            let line = line.unwrap();
            assert!(line.contains(&format!("\" {raw}\"")), "leading space guards it: {line}");
        }

        // Control characters (an escape sequence an agent printed) never reach
        // the parent's composer.
        let noisy = r#"{"id":5,"parent":4,"ts_ms":1000,"kind":{"AskUser":{"prompt":"a\u001b[31mb\u0007c","answer":null}}}"#;
        let (line, _) = plan(&[USER, noisy], Some("1"));
        let line = line.unwrap();
        assert!(!line.contains('\u{1b}') && !line.contains('\u{7}'), "{line:?}");
        assert!(line.contains("a[31mbc"), "{line:?}");
    }

    #[test]
    fn a_tool_label_is_cleaned_like_every_other_child_authored_fragment() {
        // A tool result's first line is the least trusted text in the trace
        // (a file the child `cat`ed, a page it fetched). On the failing and
        // the silence lines it rides as `last: <label>` — and a `\r` inside
        // it is an Enter at a headless parent's PTY, so `!rm …` after it
        // would be a shell escape at the start of a fresh composer line.
        let poison = r#"{"id":9,"parent":8,"ts_ms":1789603009300,"kind":{"ToolResult":{"tool_use_id":"call_p","content":"ok\r!rm -rf /tmp/x\u0007 boom\u001b[0m","is_error":true}}}"#;
        let (line, _) = plan(&[USER, ASSISTANT, RESULT_ERR, RESULT_ERR, poison], Some("2"));
        let line = line.unwrap();
        assert!(line.contains("failing · 3 tool errors in a row · last: ! ok!rm -rf /tmp/x boom[0m"), "{line:?}");
        assert!(!line.chars().any(char::is_control), "{line:?}");

        // The same label on the silence line.
        let old = format!(
            r#"{{"id":9,"parent":8,"ts_ms":{},"kind":{{"ToolResult":{{"tool_use_id":"call_p","content":"ok\r!rm -rf /tmp/x\u0007 boom\u001b[0m","is_error":false}}}}}}"#,
            now_ms() - 20 * 60 * 1000
        );
        let (line, _) = decide(
            &child_of(&[USER, old.as_str()]),
            &CursorEntry { seen: Some("9".into()), silent_at: None },
            now_ms(),
        );
        let line = line.unwrap();
        assert!(line.contains("silent 20 min · last: ok!rm -rf /tmp/x boom[0m"), "{line:?}");
        assert!(!line.chars().any(char::is_control), "{line:?}");
    }

    #[test]
    fn a_steer_opens_the_frame_a_bare_start_never_decides_anything() {
        // An external steer is a turn's opening record just as a first prompt
        // is, so the calls segment counts from it.
        let (line, _) = plan(&[START, EXTERNAL, ASSISTANT, SETTLED], Some("0"));
        let line = line.unwrap();
        assert!(line.contains("1 calls"), "counted from the steer: {line}");
        assert!(line.contains("last: \"Let me read the slot catalog first.\""), "{line}");

        // A tail holding only a `SessionStart` is not an event of its own.
        assert_eq!(plan(&[START], Some("0")).0, None);
    }

    #[test]
    fn a_cursor_outside_the_tail_treats_the_whole_tail_as_new_once() {
        // `seen` names a record the window no longer holds: everything in the
        // tail is new ONCE, and nothing is said about what was lost.
        let (line, entry) = plan(&[USER, ASSISTANT, SETTLED], Some("9999"));
        assert!(line.unwrap().contains("settled"), "the window's whole content is new once");
        assert_eq!(entry.seen.as_deref(), Some("131"), "the cursor catches up to the tail");

        // The very NEXT pass over the same tail has nothing new at all.
        let (line, entry) = plan(&[USER, ASSISTANT, SETTLED], entry.seen.as_deref());
        assert_eq!(line, None);
        assert_eq!(entry.seen.as_deref(), Some("131"));

        // A child never tracked at all (no cursor entry) is the same shape.
        let (line, _) = plan(&[USER, SETTLED], None);
        assert!(line.unwrap().contains("settled"));
    }

    #[test]
    fn the_silence_line_fires_once_and_re_arms_on_a_new_record() {
        let old = format!(
            r#"{{"id":7,"parent":6,"ts_ms":{},"kind":{{"AssistantMessage":{{"content":[{{"type":"text","text":"quiet"}}]}}}}}}"#,
            now_ms() - 20 * 60 * 1000
        );
        let child = child_of(&[USER, old.as_str()]);
        let seen = "7";

        // First quiet pass: the line, and the latch.
        let (line, entry) = decide(&child, &CursorEntry { seen: Some(seen.into()), silent_at: None }, now_ms());
        assert!(line.unwrap().contains("silent 20 min"));
        assert_eq!(entry.silent_at.as_deref(), Some("7"));

        // Second quiet pass, same tail, latch set: nothing.
        let (line, entry2) = decide(
            &child,
            &CursorEntry { seen: Some(seen.into()), silent_at: entry.silent_at.clone() },
            now_ms(),
        );
        assert_eq!(line, None, "one line per silence");
        assert_eq!(entry2.silent_at.as_deref(), Some("7"), "the latch survives");

        // A NEW record re-arms it: the next settle returns the latch to
        // absent, so a later silence has a line of its own.
        let revived = child_of(&[USER, old.as_str(), SETTLED]);
        let (line, entry3) = decide(
            &revived,
            &CursorEntry { seen: Some(seen.into()), silent_at: Some("7".into()) },
            now_ms(),
        );
        assert!(line.unwrap().contains("settled"));
        assert_eq!(entry3.silent_at, None, "a new record re-arms the latch");
        assert_eq!(entry3.seen.as_deref(), Some("131"));

        // A quiet turn that has NOT reached ten minutes is nothing.
        let fresh = format!(
            r#"{{"id":8,"parent":7,"ts_ms":{},"kind":{{"AssistantMessage":{{"content":[{{"type":"text","text":"still going"}}]}}}}}}"#,
            now_ms() - 60 * 1000
        );
        let (line, _) = decide(
            &child_of(&[USER, fresh.as_str()]),
            &CursorEntry { seen: Some("8".into()), silent_at: None },
            now_ms(),
        );
        assert_eq!(line, None, "one quiet minute is not silence");
    }

    // ── the cursor on disk, and the delivery, end to end ─────────────────

    /// Isolate every env var this module's writers read, the same shape
    /// `doorbell.rs`'s own `setup` uses.
    fn setup(tag: &str) -> PathBuf {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", root.join("state"));
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_SESSION_ID");
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        root
    }

    fn daemon_inv() -> Invocation {
        Invocation {
            path: vec!["session".to_string(), "reap".to_string()],
            args: Vec::new(),
            flags: std::collections::BTreeMap::new(),
            door: Door::Daemon,
        }
    }

    /// A live eidolon child on the roster: its presence `meta.json` (the
    /// locator's own source), its trace file beside it, and the record whose
    /// `parentSessionId` names `parent`.
    fn child_fixture(root: &Path, id: &str, parent: &str, body: &[&str]) {
        let sessions = root.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let trace = sessions.join(format!("{id}.jsonl"));
        std::fs::write(&trace, format!("{}\n", body.join("\n"))).unwrap();

        let presence = root.join("eidolon").join(id);
        std::fs::create_dir_all(&presence).unwrap();
        std::fs::write(
            presence.join("meta.json"),
            format!(
                r#"{{"id":"{id}","pid":4242,"log":"{id}.eid","cwd":"/w","model":"ollama:x","title":"t","busy":false,"trace":"{}"}}"#,
                trace.display()
            ),
        )
        .unwrap();

        let mut file: SessionsFile = load_stage(&sessions_path()).unwrap_or_default();
        let mut rec = session(id, "/w", "working", "2026-09-12T00:00:00Z", Some(parent));
        rec.agent = "eidolon".to_string();
        rec.petname = Some("brave-otter".to_string());
        rec.kind = Some("agent".to_string());
        file.sessions.push(rec);
        file.schema_version = "0".to_string();
        write_stage(&sessions_path(), &file).unwrap();
    }

    /// Register `id` as a HEADLESS conducted parent wrap with a bound control
    /// socket — the shape a delivered ping-back may actually reach.
    fn headless_parent(id: &str, agent: &str) -> UnixListener {
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some(agent),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );
        stamp_headless(id);
        listener
    }

    fn read_all(listener: UnixListener) -> Vec<u8> {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let _ = conn.read_to_end(&mut buf);
        buf
    }

    /// A `TurnSettled` record with an arbitrary id — the shape a test uses to
    /// give one child a SECOND turn, so a later pass has something new to
    /// decide.
    fn settle(id: &str) -> String {
        format!(
            r#"{{"id":{id},"parent":{id},"ts_ms":{},"kind":{{"TurnSettled":{{"stop_reason":"end_turn","usage":{{}}}}}}}}"#,
            now_ms()
        )
    }

    /// Rewrite a fixture child's trace body — one more turn on the same child,
    /// the way an eidolon appends to its own `.jsonl`.
    fn advance_trace(root: &Path, id: &str, body: &[&str]) {
        let trace = root.join("sessions").join(format!("{id}.jsonl"));
        std::fs::write(&trace, format!("{}\n", body.join("\n"))).unwrap();
    }

    #[test]
    fn a_delivered_line_reaches_a_headless_parent_and_the_cursor_stops_a_second_pass() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);
        let root = setup("pingback-deliver-once");
        let listener = headless_parent("wrap-1", "claude");
        child_fixture(&root, "user-0001", "wrap-1", &[USER, ASSISTANT, SETTLED]);

        let acc = std::thread::spawn(move || read_all(listener));
        let report = pingback(&daemon_inv(), &[]);
        let bytes = acc.join().unwrap();

        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.starts_with("[eidolon brave-otter] settled end_turn"),
            "the parent hears its child: {text:?}"
        );
        assert!(!text.contains("\n["), "exactly one line: {text:?}");
        assert!(!text.contains("from "), "no provenance prefix: {text:?}");
        assert!(text.ends_with("\n\r"), "the line, then the target's own submit key: {bytes:?}");
        assert_eq!(report.delivered.len(), 1, "{report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");

        // The claim landed BEFORE the delivery: a second pass over the same
        // tail has nothing left to say, and writes no socket.
        let cursor: CursorFile = serde_json::from_str(&std::fs::read_to_string(pingback_path()).unwrap()).unwrap();
        assert_eq!(
            cursor.get("user-0001").and_then(|e| e.seen.clone()).as_deref(),
            Some("131")
        );
        let again = pingback(&daemon_inv(), &[]);
        assert_eq!(again, PingbackReport::default(), "at-most-once: the second pass is silent");

        // One audit line, under this lane's own gate label.
        let log = std::fs::read_to_string(root.join("log")).unwrap();
        assert!(log.contains("autogate-child"), "{log}");
        assert!(log.contains("delivered to `wrap-1`"), "{log}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_line_goes_out_over_a_live_channel_socket_with_no_submit_keystroke() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);
        let root = setup("pingback-channel");
        // An interactive parent (never `stamp_headless`) — the channel is what
        // makes it reachable at all, and it takes the line with no keystroke.
        let socket = conduct_socket_path("wrap-1");
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let pty = UnixListener::bind(&socket).unwrap();
        do_session_start(
            "wrap-1",
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );
        let channel = channel_socket_path("wrap-1");
        std::fs::create_dir_all(channel.parent().unwrap()).unwrap();
        let channel_listener = UnixListener::bind(&channel).unwrap();

        child_fixture(&root, "user-0001", "wrap-1", &[USER, ASK]);
        let acc = std::thread::spawn(move || read_all(channel_listener));
        let report = pingback(&daemon_inv(), &[]);
        let bytes = acc.join().unwrap();

        assert_eq!(String::from_utf8_lossy(&bytes), "[eidolon brave-otter] asking: \"Overwrite?\"\n");
        assert_eq!(report.delivered.len(), 1, "{report:?}");
        pty.set_nonblocking(true).unwrap();
        assert!(
            pty.accept().is_err(),
            "the channel wins: the PTY is never written to"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_delivered_line_is_never_folded_into_the_sweep_and_other_doors_skip_it() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pingback-door-gate");
        let listener = headless_parent("wrap-1", "claude");
        child_fixture(&root, "user-0001", "wrap-1", &[USER, SETTLED]);

        // Every other door forwards through the daemon instead — nothing is
        // delivered, and the cursor is not even claimed.
        let mut inv = daemon_inv();
        inv.door = Door::Cli;
        let report = pingback(&inv, &[]);
        assert_eq!(report, PingbackReport::default());
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err(), "a non-daemon door writes nothing");
        assert!(!pingback_path().exists(), "and claims nothing");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_shell_parent_is_skipped_and_never_written_to() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pingback-shell-parent");
        // A conducted shell: conductable, a real socket, and its agent is
        // `shell` — a line submitted here would RUN as a command.
        let listener = headless_parent("wrap-1", "shell");
        child_fixture(&root, "user-0001", "wrap-1", &[USER, SETTLED]);

        let report = pingback(&daemon_inv(), &[]);
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err(), "a bare shell is never injected into");
        assert_eq!(report.skipped, vec![("wrap-1".to_string(), "shell-parent".to_string())]);
        assert!(report.delivered.is_empty());
        // The line is lost, not replayed: the claim ran first, which is the
        // safe direction (a duplicate in a composer is the other one).
        let cursor: CursorFile = serde_json::from_str(&std::fs::read_to_string(pingback_path()).unwrap()).unwrap();
        assert_eq!(cursor.get("user-0001").and_then(|e| e.seen.clone()).as_deref(), Some("131"));
        assert_eq!(pingback(&daemon_inv(), &[]), PingbackReport::default());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_parent_that_is_gone_not_conductable_or_done_is_a_named_skip() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pingback-parent-skips");
        child_fixture(&root, "user-0001", "wrap-gone", &[USER, SETTLED]);
        // No record for `wrap-gone` at all.
        let report = pingback(&daemon_inv(), &[]);
        assert_eq!(report.skipped, vec![("wrap-gone".to_string(), "no-parent-record".to_string())]);

        // A recorded parent whose control socket file was never bound.
        let socket = conduct_socket_path("wrap-dead");
        do_session_start(
            "wrap-dead",
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );
        let mut file: SessionsFile = load_stage(&sessions_path()).unwrap();
        file.sessions
            .iter_mut()
            .find(|s| s.session_id == "user-0001")
            .unwrap()
            .parent_session_id = Some("wrap-dead".to_string());
        write_stage(&sessions_path(), &file).unwrap();
        // A FRESH settled record, so the cursor is not already past the tail:
        // every pass below has something new to decide, and the skip reason is
        // what the assertion is actually about.
        advance_trace(&root, "user-0001", &[USER, &settle("200")]);
        let report = pingback(&daemon_inv(), &[]);
        assert_eq!(report.skipped, vec![("wrap-dead".to_string(), "not-conductable".to_string())]);

        // Same parent, socket bound, but the record already ended.
        let listener = headless_parent("wrap-dead", "claude");
        let mut file: SessionsFile = load_stage(&sessions_path()).unwrap();
        file.sessions.iter_mut().find(|s| s.session_id == "wrap-dead").unwrap().state = "done".to_string();
        write_stage(&sessions_path(), &file).unwrap();
        advance_trace(&root, "user-0001", &[USER, &settle("201")]);
        let report = pingback(&daemon_inv(), &[]);
        assert_eq!(report.skipped, vec![("wrap-dead".to_string(), "parent-done".to_string())]);
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_dropped_child_reports_died_and_leaves_the_cursor_file() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pingback-dropped");
        let listener = headless_parent("wrap-1", "claude");
        child_fixture(&root, "user-0001", "wrap-1", &[USER, ASSISTANT]);

        // The child's own record was just dropped by the sync that ran before
        // this pass (`reap`'s order): the roster no longer holds it, and the
        // dropped set names it with the trace path its record carried.
        let trace = root.join("sessions").join("user-0001.jsonl");
        let mut file: SessionsFile = load_stage(&sessions_path()).unwrap();
        file.sessions.retain(|s| s.session_id != "user-0001");
        write_stage(&sessions_path(), &file).unwrap();

        // A stale entry the file already carried for it (the child was on the
        // roster on an earlier tick) — it must be GONE after this pass.
        std::fs::write(
            pingback_path(),
            r#"{"user-0001":{"seen":"2"},"user-other":{"seen":"9"}}"#,
        )
        .unwrap();

        let acc = std::thread::spawn(move || read_all(listener));
        let report = pingback(
            &daemon_inv(),
            &[DroppedEidolon {
                session_id: "user-0001".to_string(),
                petname: Some("brave-otter".to_string()),
                parent_session_id: Some("wrap-1".to_string()),
                agent: "eidolon".to_string(),
                trace: Some(trace),
            }],
        );
        let bytes = acc.join().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("[eidolon brave-otter] died mid-turn"), "{text:?}");
        assert_eq!(report.delivered.len(), 1, "{report:?}");

        // The entry leaves the file on the SAME pass — nothing lingers for a
        // child that is no longer on the roster, and every id whose eidolon
        // record is gone goes with it.
        let cursor: CursorFile = serde_json::from_str(&std::fs::read_to_string(pingback_path()).unwrap()).unwrap();
        assert!(cursor.is_empty(), "every entry without a roster record is gone: {cursor:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_child_that_says_nothing_new_keeps_its_place_and_never_rewrites_the_file() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pingback-quiet");
        let _listener = headless_parent("wrap-1", "claude");
        child_fixture(&root, "user-0001", "wrap-1", &[USER, SETTLED]);

        // A trace whose window holds no readable record at all: nothing is
        // examined, so no cursor entry is ever created for it.
        child_fixture(&root, "user-empty", "wrap-1", &[]);
        let report = pingback(&daemon_inv(), &[]);
        assert_eq!(report.delivered.len(), 1, "{report:?}");
        let cursor: CursorFile = serde_json::from_str(&std::fs::read_to_string(pingback_path()).unwrap()).unwrap();
        assert_eq!(cursor.len(), 1, "only the child with records has an entry: {cursor:?}");
        assert!(cursor.contains_key("user-0001"));

        // A second pass over the same quiet tail: the file is byte-identical
        // (change-only), so the daemon's tick writes nothing at all.
        let before = std::fs::read_to_string(pingback_path()).unwrap();
        let report = pingback(&daemon_inv(), &[]);
        assert_eq!(report, PingbackReport::default());
        assert_eq!(std::fs::read_to_string(pingback_path()).unwrap(), before);

        let _ = std::fs::remove_dir_all(&root);
    }
}
