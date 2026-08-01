//! `aoide usage` — the offline half of the usage widget (CONTRACTS.md §2/§4,
//! `state/usage.json` v0): a LOCAL token/cost rollup computed straight off
//! Claude Code's own on-disk transcripts (`~/.claude/projects/**/*.jsonl`),
//! same read pattern `graph/session_store.rs`'s `transcript_context_tokens`
//! uses for the context-window meter. No network, no credentials — this
//! machine's transcripts only. The `live` block in the written document is a
//! clearly-marked stub for a LATER task to fill in (the claude.ai account
//! usage fetch); readers must tolerate `live.ok == false`.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, Registry};
use crate::shellbridge;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["usage"],
        summary: "Local token/cost usage rollup (today/week) from this machine's Claude Code transcripts; writes state/usage.json.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_usage,
    ));
}

// ── state/usage.json shape (CONTRACTS.md §4, v0) ────────────────────────────

/// One bucket's rolled-up tokens + approximate USD cost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub(crate) struct TokenCost {
    pub tokens: u64,
    #[serde(rename = "costUsd")]
    pub cost_usd: f64,
}

/// The `local` block: a same-machine estimate, never a billing source of truth.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LocalUsage {
    pub note: &'static str,
    pub today: TokenCost,
    pub week: TokenCost,
}

const LOCAL_NOTE: &str = "local estimate, this machine only";

/// The `live` block — a stub in THIS task. `ok:false` always, with a reason;
/// readers (the widget) must tolerate this and fall back to `local`.
#[derive(Debug, Clone, Serialize)]
struct LiveUsage {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl LiveUsage {
    fn unavailable(reason: impl Into<String>) -> Self {
        LiveUsage {
            ok: false,
            error: Some(reason.into()),
        }
    }
}

/// The live-fetch seam. THIS task ships only the offline half (no network, no
/// credential reads anywhere in this module) — `fetch_live_usage` always
/// returns the stub below. A later task plugs the claude.ai OAuth/usage fetch
/// in here and flips `ok:true` on success; until then every `aoide usage` run
/// writes `live.ok:false` and callers must tolerate it (CONTRACTS.md §4).
//
// TODO(usage-live): the oauth/usage fetch plugs in here.
fn fetch_live_usage() -> LiveUsage {
    LiveUsage::unavailable("live fetch not wired yet")
}

// ── Pricing (approximate — embedded, not fetched) ───────────────────────────

/// Approximate USD-per-million-token rates for one model family.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Price {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
}

/// Approximate per-model-family pricing (USD / MTok), embedded so the local
/// rollup needs no network call. **Pricing is approximate and may drift** —
/// this is a cost ESTIMATE for a local widget, not a billing source of truth;
/// Anthropic's published pricing (platform.claude.com/docs/en/pricing) is
/// authoritative and this table is not kept in lockstep with it. Matches by
/// substring so a full/dated model id (`claude-opus-4-8`, `claude-sonnet-5`,
/// `claude-haiku-4-5`, `claude-fable-5`/`claude-mythos-5`) still resolves; an
/// unrecognized id falls back to the Sonnet-tier rate as a reasonable middle
/// estimate. `cache_read` is ~0.1x the input rate and `cache_write` ~1.25x
/// (the 5-minute-TTL write premium, the default TTL) — both derived from the
/// input rate rather than tabulated per model, since Anthropic's own cache
/// pricing is itself expressed as a multiplier of the base input rate.
pub(crate) fn model_price(model: &str) -> Price {
    let (input, output) = if model.contains("opus") {
        (5.00, 25.00)
    } else if model.contains("fable") || model.contains("mythos") {
        (10.00, 50.00)
    } else if model.contains("haiku") {
        (1.00, 5.00)
    } else {
        // "sonnet", or any unrecognized id: Sonnet-tier is the default estimate.
        (3.00, 15.00)
    };
    Price {
        input,
        output,
        cache_read: input * 0.1,
        cache_write: input * 1.25,
    }
}

// ── The local rollup (pure core + a defensive file walk) ───────────────────

/// One parsed `type:"assistant"` turn's contribution: when it happened, how
/// many tokens it moved, and its estimated USD cost.
struct TurnUsage {
    epoch: i64,
    tokens: u64,
    cost_usd: f64,
}

/// Parse one JSONL line into its usage contribution, or `None` when the line
/// isn't a usable assistant turn — malformed JSON, wrong `type`, an
/// unparseable/missing `timestamp`, or no `message.usage` block all yield
/// `None` (the walker skips it and moves on; a single bad line never aborts
/// the scan). Mirrors `graph/session_store.rs`'s `transcript_context_tokens`
/// field reads, plus the top-level `timestamp` and `message.model` fields it
/// doesn't need. Deliberately does NOT filter on `isSidechain` — a sub-agent's
/// turn spends real tokens too, and the local rollup is a whole-machine total.
fn parse_turn_usage(line: &str) -> Option<TurnUsage> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("assistant") {
        return None;
    }
    let ts = v.get("timestamp").and_then(Value::as_str)?;
    let epoch = crate::conductor::theme::parse_iso_utc(ts)?;
    let usage = v.get("message").and_then(|m| m.get("usage"))?;
    let get_u64 = |k: &str| usage.get(k).and_then(Value::as_u64).unwrap_or(0);
    let input = get_u64("input_tokens");
    let cache_creation = get_u64("cache_creation_input_tokens");
    let cache_read = get_u64("cache_read_input_tokens");
    let output = get_u64("output_tokens");
    let tokens = input + cache_creation + cache_read + output;
    let model = v
        .get("message")
        .and_then(|m| m.get("model"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let price = model_price(model);
    let cost_usd = (input as f64 / 1_000_000.0) * price.input
        + (output as f64 / 1_000_000.0) * price.output
        + (cache_read as f64 / 1_000_000.0) * price.cache_read
        + (cache_creation as f64 / 1_000_000.0) * price.cache_write;
    Some(TurnUsage {
        epoch,
        tokens,
        cost_usd,
    })
}

/// Pure core: bucket already-read JSONL lines into `today`/`week` sums against
/// a fixed `now` (epoch seconds) — no filesystem, no wall clock, so tests feed
/// fixture lines and a controlled `now` directly. `today` is every turn from
/// UTC midnight of `now`'s day through `now`; `week` is every turn from `now -
/// 7d` through `now` (a superset of `today`, not a disjoint bucket — mirrors
/// how a usage widget reads "today" and "this week" as two overlapping
/// windows, not a partition). "Local midnight" here means UTC midnight: the
/// crate's other timestamp helpers (`now_iso_utc`, `parse_iso_utc`) are UTC-only
/// (no `chrono-tz` in the lock), so the day boundary is UTC rather than this
/// machine's configured timezone — an approximation consistent with the rest
/// of the local rollup being an estimate, not authoritative.
fn scan_usage_lines<'a>(lines: impl Iterator<Item = &'a str>, now: i64) -> LocalUsage {
    let today_start = now - now.rem_euclid(86_400);
    let week_start = now - 7 * 86_400;
    let mut today = TokenCost::default();
    let mut week = TokenCost::default();
    for line in lines {
        let Some(t) = parse_turn_usage(line) else {
            continue;
        };
        if t.epoch < week_start || t.epoch > now {
            continue;
        }
        week.tokens += t.tokens;
        week.cost_usd += t.cost_usd;
        if t.epoch >= today_start {
            today.tokens += t.tokens;
            today.cost_usd += t.cost_usd;
        }
    }
    LocalUsage {
        note: LOCAL_NOTE,
        today,
        week,
    }
}

/// Recursively collect every `.jsonl` file under `dir` (defensive: an
/// unreadable directory/file, or a non-UTF8 name, is skipped rather than
/// aborting the walk — mirrors `transcript_tail`'s "best-effort" discipline).
/// Walks arbitrary depth so it also picks up sub-agent transcripts
/// (`<project>/<session>/subagents/agent-*.jsonl`) — those spend real tokens
/// too, so the whole-machine rollup should count them.
fn collect_jsonl(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                out.extend(contents.lines().map(String::from));
            }
        }
    }
}

/// Walk `dir` (the Claude Code projects root, `~/.claude/projects`) and roll
/// up local token/cost usage against `now` (epoch seconds). Thin wrapper
/// around [`collect_jsonl`] + [`scan_usage_lines`] — an absent/unreadable
/// `dir` yields an all-zero [`LocalUsage`] rather than an error (no Claude
/// Code transcripts on this machine is a normal, quiet state).
pub(crate) fn scan_usage(dir: &Path, now: i64) -> LocalUsage {
    let mut lines = Vec::new();
    collect_jsonl(dir, &mut lines);
    scan_usage_lines(lines.iter().map(String::as_str), now)
}

/// Resolve the Claude Code projects root: `$AOIDE_CLAUDE_PROJECTS_DIR` (a
/// test/override seam, absolute-or-not — tests point it at a scratch dir) else
/// `$HOME/.claude/projects`. `None` when neither resolves (no `$HOME`).
fn claude_projects_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AOIDE_CLAUDE_PROJECTS_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".claude").join("projects"))
}

// ── The command handler ─────────────────────────────────────────────────────

/// `aoide usage [--json]` — compute the local rollup, stamp the (stub) live
/// block, atomic-write `state/usage.json`, and report today's tokens/cost.
/// No secrets are read or written (there are none in this task's scope).
fn handle_usage(_inv: &Invocation) -> Outcome {
    let cmd = "usage";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let local = match claude_projects_dir() {
        Some(dir) => scan_usage(&dir, now),
        None => LocalUsage {
            note: LOCAL_NOTE,
            today: TokenCost::default(),
            week: TokenCost::default(),
        },
    };
    let live = fetch_live_usage();

    let body = json!({
        "schemaVersion": "0",
        "fetchedAt": crate::graph::now_iso_utc(),
        "live": live,
        "local": local,
    });
    let text = serde_json::to_string_pretty(&body).unwrap_or_default() + "\n";

    let target = shellbridge::state_dir().join("usage.json");
    if let Err(e) = shellbridge::atomic_write(&target, &text) {
        return Outcome::error(cmd, format!("failed to write {}: {e}", target.display()))
            .with_data(json!({
                "reason": "state-write-failed",
                "target": target.to_string_lossy(),
            }));
    }

    Outcome::ok(
        cmd,
        format!(
            "today {} tokens (~${:.2}, local estimate); week {} tokens (~${:.2}) — state/usage.json written",
            local.today.tokens, local.today.cost_usd, local.week.tokens, local.week.cost_usd
        ),
    )
    .changed(vec![target.to_string_lossy().into_owned()])
    .with_data(body)
}

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::*;
    use crate::output::Status;

    fn assistant_line(ts: &str, model: &str, input: u64, cache_creation: u64, cache_read: u64, output: u64) -> String {
        json!({
            "type": "assistant",
            "timestamp": ts,
            "message": {
                "model": model,
                "usage": {
                    "input_tokens": input,
                    "cache_creation_input_tokens": cache_creation,
                    "cache_read_input_tokens": cache_read,
                    "output_tokens": output,
                }
            }
        })
        .to_string()
    }

    fn epoch(ts: &str) -> i64 {
        crate::conductor::theme::parse_iso_utc(ts).unwrap()
    }

    // ── model_price ──────────────────────────────────────────────────────────

    #[test]
    fn model_price_known_families() {
        let opus = model_price("claude-opus-4-8");
        assert_eq!(opus.input, 5.00);
        assert_eq!(opus.output, 25.00);
        assert!((opus.cache_read - 0.5).abs() < 1e-9);
        assert!((opus.cache_write - 6.25).abs() < 1e-9);

        let sonnet = model_price("claude-sonnet-5");
        assert_eq!(sonnet.input, 3.00);
        assert_eq!(sonnet.output, 15.00);

        let haiku = model_price("claude-haiku-4-5");
        assert_eq!(haiku.input, 1.00);
        assert_eq!(haiku.output, 5.00);

        let fable = model_price("claude-fable-5");
        assert_eq!(fable.input, 10.00);
        assert_eq!(fable.output, 50.00);

        let mythos = model_price("claude-mythos-5");
        assert_eq!(mythos.input, 10.00);
        assert_eq!(mythos.output, 50.00);
    }

    #[test]
    fn model_price_unknown_defaults_to_sonnet_tier() {
        let unknown = model_price("claude-some-future-model-9000");
        let sonnet = model_price("claude-sonnet-5");
        assert_eq!(unknown, sonnet);
    }

    // ── scan_usage_lines (pure core) ────────────────────────────────────────

    #[test]
    fn scan_usage_lines_sums_today_and_week_separately() {
        let now = epoch("2026-07-31T12:00:00Z");
        let lines = vec![
            // Within today (today starts at 2026-07-31T00:00:00Z).
            assistant_line("2026-07-31T09:00:00Z", "claude-sonnet-5", 1000, 0, 0, 500),
            // Within week but NOT today (yesterday).
            assistant_line("2026-07-30T23:59:59Z", "claude-sonnet-5", 2000, 0, 0, 1000),
            // Outside both (8 days ago).
            assistant_line("2026-07-22T00:00:00Z", "claude-sonnet-5", 9999, 0, 0, 9999),
        ];
        let out = scan_usage_lines(lines.iter().map(String::as_str), now);

        // today: 1000 input + 500 output = 1500 tokens.
        assert_eq!(out.today.tokens, 1500);
        // week: today's 1500 + yesterday's 3000 = 4500 tokens.
        assert_eq!(out.week.tokens, 4500);
        assert!(out.today.cost_usd > 0.0);
        assert!(out.week.cost_usd > out.today.cost_usd);
        assert_eq!(out.note, LOCAL_NOTE);
    }

    #[test]
    fn scan_usage_lines_window_boundary_is_inclusive_at_the_edges() {
        let now = epoch("2026-07-31T12:00:00Z");
        // Exactly at today's start boundary — counts as today.
        let at_today_start = assistant_line("2026-07-31T00:00:00Z", "claude-sonnet-5", 100, 0, 0, 0);
        // One second before today's start — week only, not today.
        let just_before_today = assistant_line("2026-07-30T23:59:59Z", "claude-sonnet-5", 200, 0, 0, 0);
        // Exactly at the week boundary (now - 7d) — counts as week.
        let at_week_start = assistant_line("2026-07-24T12:00:00Z", "claude-sonnet-5", 300, 0, 0, 0);
        // One second before the week boundary — excluded entirely.
        let just_before_week = assistant_line("2026-07-24T11:59:59Z", "claude-sonnet-5", 400, 0, 0, 0);

        let lines = vec![at_today_start, just_before_today, at_week_start, just_before_week];
        let out = scan_usage_lines(lines.iter().map(String::as_str), now);

        assert_eq!(out.today.tokens, 100, "only the at-boundary line lands in today");
        assert_eq!(out.week.tokens, 100 + 200 + 300, "the pre-week line is excluded");
    }

    #[test]
    fn scan_usage_lines_skips_malformed_and_non_assistant_lines() {
        let now = epoch("2026-07-31T12:00:00Z");
        let lines = vec![
            "not json at all".to_string(),
            json!({"type": "user", "timestamp": "2026-07-31T09:00:00Z"}).to_string(),
            json!({"type": "assistant", "timestamp": "not-a-date", "message": {"usage": {}}}).to_string(),
            "".to_string(),
            assistant_line("2026-07-31T09:00:00Z", "claude-sonnet-5", 42, 0, 0, 8),
        ];
        let out = scan_usage_lines(lines.iter().map(String::as_str), now);
        assert_eq!(out.today.tokens, 50);
    }

    #[test]
    fn scan_usage_lines_includes_sidechain_turns() {
        // Sub-agent turns spend real tokens too — the local rollup does not
        // filter on isSidechain (unlike the context-window meter, which does).
        let now = epoch("2026-07-31T12:00:00Z");
        let mut v: Value = serde_json::from_str(&assistant_line(
            "2026-07-31T09:00:00Z",
            "claude-sonnet-5",
            10,
            0,
            0,
            5,
        ))
        .unwrap();
        v["isSidechain"] = json!(true);
        let out = scan_usage_lines(std::iter::once(v.to_string().as_str()), now);
        assert_eq!(out.today.tokens, 15);
    }

    // ── scan_usage (file walk) ──────────────────────────────────────────────

    #[test]
    fn scan_usage_walks_nested_jsonl_files() {
        let root = unique_tmp("usage-scan");
        let proj = root.join("-home-khoa-Aoide");
        let subagents = proj.join("sess-1").join("subagents");
        std::fs::create_dir_all(&subagents).unwrap();

        let now = epoch("2026-07-31T12:00:00Z");
        std::fs::write(
            proj.join("sess-1.jsonl"),
            assistant_line("2026-07-31T09:00:00Z", "claude-opus-4-8", 100, 0, 0, 50),
        )
        .unwrap();
        std::fs::write(
            subagents.join("agent-abc.jsonl"),
            assistant_line("2026-07-31T10:00:00Z", "claude-haiku-4-5", 20, 0, 0, 10),
        )
        .unwrap();

        let out = scan_usage(&root, now);
        assert_eq!(out.today.tokens, 150 + 30);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_usage_tolerates_a_missing_directory() {
        let out = scan_usage(Path::new("/nonexistent/does/not/exist"), 0);
        assert_eq!(out.today.tokens, 0);
        assert_eq!(out.week.tokens, 0);
    }

    // ── handle_usage (end-to-end: writes state/usage.json) ─────────────────

    #[test]
    fn handle_usage_writes_state_usage_json_with_stub_live_block() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STATE_DIR", "AOIDE_CLAUDE_PROJECTS_DIR"]);
        let root = unique_tmp("usage-handle");
        let state = root.join("state");
        let claude = root.join("claude-projects");
        std::fs::create_dir_all(&claude).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_CLAUDE_PROJECTS_DIR", &claude);

        let out = handle_usage(&inv(&["usage"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert!(out.changed.iter().any(|c| c.ends_with("usage.json")));

        let written = std::fs::read_to_string(state.join("usage.json")).unwrap();
        let v: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["schemaVersion"], "0");
        assert_eq!(v["live"]["ok"], false);
        assert!(v["live"]["error"].is_string());
        assert_eq!(v["local"]["note"], LOCAL_NOTE);
        assert_eq!(v["local"]["today"]["tokens"], 0);
        let _ = std::fs::remove_dir_all(&root);
    }
}
