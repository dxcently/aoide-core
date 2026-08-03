//! `aoide usage` — the offline half of the usage widget (CONTRACTS.md §2/§4,
//! `state/usage.json` v0): a LOCAL token/cost rollup computed straight off
//! Claude Code's own on-disk transcripts (`~/.claude/projects/**/*.jsonl`),
//! same read pattern `graph/session_store.rs`'s `transcript_context_tokens`
//! uses for the context-window meter. No network, no credentials — this
//! machine's transcripts only.
//!
//! The `live` block IS now wired to a real fetch ([`fetch_live_usage`]): it
//! reads the consumer OAuth token from `~/.claude/.credentials.json` and calls
//! Claude Code's own (unofficial, ToS-gray) `/api/oauth/usage` endpoint via
//! curl, with the token kept out of argv and off disk (the curl config is
//! piped over stdin, `--config -`, so the token never touches a file). ANY
//! failure degrades to `live.ok:false` + a **tokenless** reason, so readers
//! (the widget) must still tolerate `live.ok == false`. The token is never
//! logged, printed, or embedded in an error string or the written state file.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
use crate::fs as shellbridge;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

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

/// One live utilization meter — a `{utilization, resetsAt}` pair (the JSON keys
/// the widget reads). `resetsAt` is optional (some blocks omit it).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UsageMeter {
    pub utilization: f64,
    #[serde(rename = "resetsAt", skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
}

/// The `extraUsage` block — pay-as-you-go credit state.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ExtraUsage {
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
    #[serde(rename = "monthlyLimit", skip_serializing_if = "Option::is_none")]
    pub monthly_limit: Option<f64>,
    #[serde(rename = "usedCredits", skip_serializing_if = "Option::is_none")]
    pub used_credits: Option<f64>,
}

/// The `live` block — the claude.ai account-usage fetch. On a clean 200 this
/// carries the real plan/weekly utilization (`ok:true` + the optional blocks);
/// on ANY failure it degrades to `ok:false` + a **tokenless** reason and every
/// data field stays `None`, so `ok:false` still serializes as just
/// `{ok:false, error}` (shape-compatible with the v0 stub — the widget guards
/// every sub-field). SOURCE IS UNOFFICIAL: this reads Claude Code's own
/// `/api/oauth/usage` endpoint, which is undocumented and ToS-gray; treat a
/// failure as normal and fall back to `local`.
#[derive(Debug, Clone, Serialize)]
struct LiveUsage {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(rename = "fiveHour", skip_serializing_if = "Option::is_none")]
    five_hour: Option<UsageMeter>,
    #[serde(rename = "sevenDay", skip_serializing_if = "Option::is_none")]
    seven_day: Option<UsageMeter>,
    #[serde(rename = "sevenDayOpus", skip_serializing_if = "Option::is_none")]
    seven_day_opus: Option<UsageMeter>,
    #[serde(rename = "sevenDaySonnet", skip_serializing_if = "Option::is_none")]
    seven_day_sonnet: Option<UsageMeter>,
    #[serde(rename = "extraUsage", skip_serializing_if = "Option::is_none")]
    extra_usage: Option<ExtraUsage>,
}

impl LiveUsage {
    /// A clean failure: `ok:false` + a short tokenless reason, all data `None`.
    fn unavailable(reason: impl Into<String>) -> Self {
        LiveUsage {
            ok: false,
            error: Some(reason.into()),
            five_hour: None,
            seven_day: None,
            seven_day_opus: None,
            seven_day_sonnet: None,
            extra_usage: None,
        }
    }
}

/// The unofficial account-usage endpoint (Claude Code's own `/usage` fetch).
const OAUTH_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
/// The OAuth beta gate the endpoint requires.
const OAUTH_BETA: &str = "oauth-2025-04-20";
/// A sane `claude-code/<version>` fallback when `claude --version` can't be
/// read and `AOIDE_USAGE_UA` isn't set (a wrong/absent UA gets 429'd).
const FALLBACK_UA: &str = "claude-code/2.1.0";

// ── Pure parsing (no I/O, no network — unit-tested directly) ────────────────

/// Extract the consumer OAuth access token from a parsed `.credentials.json`
/// value: `.claudeAiOauth.accessToken`. `None` when the path is absent or the
/// value is empty. Never logs or returns anything but the token itself.
fn oauth_token_from_credentials(v: &Value) -> Option<String> {
    let tok = v
        .get("claudeAiOauth")
        .and_then(|o| o.get("accessToken"))
        .and_then(Value::as_str)?;
    if tok.is_empty() {
        None
    } else {
        Some(tok.to_string())
    }
}

/// Parse one `{utilization, resets_at}` API block into a [`UsageMeter`].
/// `None` when the block isn't an object with a numeric `utilization`.
fn parse_meter(v: &Value) -> Option<UsageMeter> {
    let obj = v.as_object()?;
    let utilization = obj.get("utilization").and_then(Value::as_f64)?;
    let resets_at = obj
        .get("resets_at")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(UsageMeter {
        utilization,
        resets_at,
    })
}

/// Parse the `extra_usage` API block into an [`ExtraUsage`]. `None` when it
/// isn't an object; missing sub-fields default (`is_enabled:false`, limits
/// `None`).
fn parse_extra(v: &Value) -> Option<ExtraUsage> {
    let obj = v.as_object()?;
    Some(ExtraUsage {
        is_enabled: obj
            .get("is_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        monthly_limit: obj.get("monthly_limit").and_then(Value::as_f64),
        used_credits: obj.get("used_credits").and_then(Value::as_f64),
    })
}

/// Pure core: turn a parsed 200-response body into a [`LiveUsage`]. Maps the
/// snake_case API blocks (`five_hour`, `seven_day`, `seven_day_opus`,
/// `seven_day_sonnet`, `extra_usage`) onto our camelCase `live` shape. A body
/// that is not an object, or carries none of the recognized blocks, degrades
/// to `unavailable("unparseable response")` — we never claim `ok:true` on a
/// shape we didn't recognize.
fn parse_oauth_usage(v: &Value) -> LiveUsage {
    let obj = match v.as_object() {
        Some(o) => o,
        None => return LiveUsage::unavailable("unparseable response"),
    };
    let five_hour = obj.get("five_hour").and_then(parse_meter);
    let seven_day = obj.get("seven_day").and_then(parse_meter);
    let seven_day_opus = obj.get("seven_day_opus").and_then(parse_meter);
    let seven_day_sonnet = obj.get("seven_day_sonnet").and_then(parse_meter);
    let extra_usage = obj.get("extra_usage").and_then(parse_extra);
    if five_hour.is_none()
        && seven_day.is_none()
        && seven_day_opus.is_none()
        && seven_day_sonnet.is_none()
        && extra_usage.is_none()
    {
        return LiveUsage::unavailable("unparseable response");
    }
    LiveUsage {
        ok: true,
        error: None,
        five_hour,
        seven_day,
        seven_day_opus,
        seven_day_sonnet,
        extra_usage,
    }
}

// ── The live fetch (curl, token kept out of argv) ───────────────────────────

/// Resolve the `.credentials.json` path: `$AOIDE_CLAUDE_CREDENTIALS` override
/// (a test/smoke seam) else `$HOME/.claude/.credentials.json`.
fn credentials_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AOIDE_CLAUDE_CREDENTIALS") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".claude").join(".credentials.json"))
}

/// Strip anything that could break out of a curl-config quoted value or an
/// HTTP header line: the quote/backslash that would end/escape the quoted
/// value, plus ALL control chars (CR/LF/NUL/TAB/VT/…) so a hostile
/// `$AOIDE_USAGE_UA` can carry no control bytes into the header at all.
fn sanitize_header_value(s: &str) -> String {
    s.chars()
        .filter(|c| !(c.is_control() || matches!(c, '"' | '\\')))
        .collect()
}

/// The `User-Agent` to send. Precedence: `$AOIDE_USAGE_UA` (used verbatim,
/// sanitized) → `claude-code/<version>` parsed from `claude --version` →
/// [`FALLBACK_UA`]. A wrong/absent UA is 429'd, so this is required.
fn resolve_user_agent() -> String {
    if let Ok(ua) = std::env::var("AOIDE_USAGE_UA") {
        let ua = sanitize_header_value(ua.trim());
        if !ua.is_empty() {
            return ua;
        }
    }
    if let Some(ver) = claude_cli_version() {
        return format!("claude-code/{ver}");
    }
    FALLBACK_UA.to_string()
}

/// Parse the version out of `claude --version` (`"2.1.217 (Claude Code)"` →
/// `"2.1.217"`). `None` when the binary is absent or the output is unusable.
fn claude_cli_version() -> Option<String> {
    let out = std::process::Command::new("claude")
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let tok = s.split_whitespace().next()?;
    let ver: String = tok
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if ver.is_empty() {
        None
    } else {
        Some(ver)
    }
}

/// Build the curl config body carrying the URL, the Bearer token, and the
/// beta/UA/content headers. **The token lives ONLY in this in-memory `String`**,
/// which is fed to curl over stdin (`--config -`) and never touches a file or
/// argv (`curl -H "Authorization: …"` would leak it to `ps`; a temp file could
/// be pre-created/symlink-raced by a second local uid). The token has already
/// been rejected if it carries a quote/newline/backslash, so the quoted
/// Authorization value can't be broken out of.
fn build_curl_config(token: &str, ua: &str) -> String {
    format!(
        "url = \"{OAUTH_USAGE_URL}\"\n\
         header = \"Authorization: Bearer {token}\"\n\
         header = \"anthropic-beta: {OAUTH_BETA}\"\n\
         header = \"User-Agent: {ua}\"\n\
         header = \"Content-Type: application/json\"\n"
    )
}

/// Run `curl -sS --max-time 15 -w '\n%{http_code}' --config -` with the config
/// `body` piped over stdin, and return `(http_code, body)`. The trailing line
/// printed by `-w` is the status; the rest is the response body. A spawn/pipe
/// failure, empty output, or a `000` (connection failure/timeout) code all map
/// to `Err("curl failed")`. `stderr` is discarded (`Stdio::null`) so nothing
/// curl prints can surface. The token exists only inside `body` (a private
/// `String` piped straight to curl) — never a file, never argv.
fn run_curl(body: &str) -> Result<(u16, String), String> {
    let mut child = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "15", "-w", "\n%{http_code}", "--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "curl failed".to_string())?;
    // Write the config to stdin and drop it (EOF) BEFORE waiting, so curl can
    // finish and we can't deadlock. The config is tiny (~few hundred bytes).
    {
        let mut si = child.stdin.take().ok_or("curl failed".to_string())?;
        si.write_all(body.as_bytes())
            .map_err(|_| "curl failed".to_string())?;
    }
    let out = child
        .wait_with_output()
        .map_err(|_| "curl failed".to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (body, code_str) = match stdout.rsplit_once('\n') {
        Some((b, c)) => (b, c.trim()),
        None => ("", stdout.trim()),
    };
    let code: u16 = code_str.parse().map_err(|_| "curl failed".to_string())?;
    if code == 0 {
        return Err("curl failed".to_string());
    }
    Ok((code, body.to_string()))
}

/// The live-fetch seam. Reads the consumer OAuth token from `.credentials.json`
/// at runtime, calls the unofficial `/api/oauth/usage` endpoint via curl (token
/// piped over stdin as a `--config -` body, never a file and never argv), and
/// maps a clean 200 onto the `live` block. ANY failure — missing credentials,
/// the "authorized for Claude Code only" rejection, a transport error, a
/// non-200, or an unparseable body — degrades to `ok:false` + a **tokenless**
/// reason. The token is never logged, printed, or embedded in an error string.
fn fetch_live_usage() -> LiveUsage {
    let path = match credentials_path() {
        Some(p) => p,
        None => return LiveUsage::unavailable("no ~/.claude credentials"),
    };
    let creds = match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(v) => v,
            Err(_) => return LiveUsage::unavailable("no ~/.claude credentials"),
        },
        Err(_) => return LiveUsage::unavailable("no ~/.claude credentials"),
    };
    let token = match oauth_token_from_credentials(&creds) {
        Some(t) => t,
        None => return LiveUsage::unavailable("no ~/.claude credentials"),
    };
    // The token becomes a quoted curl-config value; a token carrying a
    // quote/newline/backslash is malformed and would break the config line, so
    // reject it rather than emit a corrupt config. (Never log the token itself.)
    if token.contains(['"', '\n', '\r', '\\']) {
        return LiveUsage::unavailable("no ~/.claude credentials");
    }
    let ua = resolve_user_agent();
    // The config body — including the token — lives only in this in-memory
    // String and goes only over the pipe to curl's stdin, on every branch below.
    let body = build_curl_config(&token, &ua);
    match run_curl(&body) {
        Ok((200, body)) => match serde_json::from_str::<Value>(&body) {
            Ok(v) => parse_oauth_usage(&v),
            Err(_) => LiveUsage::unavailable("unparseable response"),
        },
        // The consumer OAuth token is only authorized for Claude Code itself;
        // this endpoint rejects other callers. Report it cleanly, don't retry.
        Ok((401, _)) | Ok((403, _)) => {
            LiveUsage::unavailable("unauthorized (consumer OAuth restricted to Claude Code)")
        }
        Ok((code, _)) => LiveUsage::unavailable(format!("http {code}")),
        Err(reason) => LiveUsage::unavailable(reason),
    }
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
    let epoch = crate::time::parse_iso_utc(ts)?;
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

/// `aoide usage [--json]` — compute the local rollup, stamp the live block,
/// atomic-write `state/usage.json`, and report today's tokens/cost. The live
/// fetch reads the consumer OAuth token at runtime but never writes, logs, or
/// embeds it (it goes only over the pipe to curl's stdin); only the parsed
/// usage numbers ever reach `state/usage.json`.
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
        "fetchedAt": crate::time::now_iso_utc(),
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
    use aoide_test_support::*;
    use aoide_protocol::output::Status;

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
        crate::time::parse_iso_utc(ts).unwrap()
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
    fn handle_usage_writes_state_usage_json_and_degrades_live_cleanly() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&[
            "AOIDE_STATE_DIR",
            "AOIDE_CLAUDE_PROJECTS_DIR",
            "AOIDE_CLAUDE_CREDENTIALS",
        ]);
        let root = unique_tmp("usage-handle");
        let state = root.join("state");
        let claude = root.join("claude-projects");
        std::fs::create_dir_all(&claude).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_CLAUDE_PROJECTS_DIR", &claude);
        // Point the live fetch at a nonexistent credentials file so it degrades
        // deterministically to ok:false — this test is hermetic (no network).
        std::env::set_var("AOIDE_CLAUDE_CREDENTIALS", root.join("no-such-creds.json"));

        let out = handle_usage(&inv(&["usage"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert!(out.changed.iter().any(|c| c.ends_with("usage.json")));

        let written = std::fs::read_to_string(state.join("usage.json")).unwrap();
        let v: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["schemaVersion"], "0");
        // Missing credentials → clean, tokenless degrade; ok:false emits only
        // {ok,error} (no data sub-fields leak in).
        assert_eq!(v["live"]["ok"], false);
        assert_eq!(v["live"]["error"], "no ~/.claude credentials");
        assert!(v["live"].get("fiveHour").is_none());
        assert!(v["live"].get("extraUsage").is_none());
        assert_eq!(v["local"]["note"], LOCAL_NOTE);
        assert_eq!(v["local"]["today"]["tokens"], 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── oauth_token_from_credentials (pure) ─────────────────────────────────

    #[test]
    fn oauth_token_from_credentials_reads_nested_path() {
        let creds = json!({
            "claudeAiOauth": {
                "accessToken": "tok-abc123",
                "refreshToken": "refresh-xyz",
                "expiresAt": 0
            }
        });
        assert_eq!(
            oauth_token_from_credentials(&creds),
            Some("tok-abc123".to_string())
        );
    }

    #[test]
    fn oauth_token_from_credentials_missing_or_empty_is_none() {
        assert_eq!(oauth_token_from_credentials(&json!({})), None);
        assert_eq!(
            oauth_token_from_credentials(&json!({"claudeAiOauth": {}})),
            None
        );
        assert_eq!(
            oauth_token_from_credentials(&json!({"claudeAiOauth": {"accessToken": ""}})),
            None
        );
        // Wrong shape entirely.
        assert_eq!(oauth_token_from_credentials(&json!("nope")), None);
    }

    // ── parse_oauth_usage (pure) ────────────────────────────────────────────

    /// A representative 200 body (snake_case, as the endpoint returns it).
    fn usage_200_body() -> Value {
        json!({
            "five_hour":        { "utilization": 42.5, "resets_at": "2026-08-01T18:00:00Z" },
            "seven_day":        { "utilization": 12,   "resets_at": "2026-08-07T00:00:00Z" },
            "seven_day_opus":   { "utilization": 5.0,  "resets_at": "2026-08-07T00:00:00Z" },
            "seven_day_sonnet": { "utilization": 7.0,  "resets_at": "2026-08-07T00:00:00Z" },
            "extra_usage":      { "is_enabled": true, "monthly_limit": 100.0, "used_credits": 3.5 }
        })
    }

    #[test]
    fn parse_oauth_usage_maps_full_body_to_camelcase_live_block() {
        let live = parse_oauth_usage(&usage_200_body());
        assert!(live.ok);
        assert!(live.error.is_none());

        let five = live.five_hour.as_ref().unwrap();
        assert!((five.utilization - 42.5).abs() < 1e-9);
        assert_eq!(five.resets_at.as_deref(), Some("2026-08-01T18:00:00Z"));
        // Integer utilization parses as f64.
        assert!((live.seven_day.as_ref().unwrap().utilization - 12.0).abs() < 1e-9);
        assert!((live.seven_day_opus.as_ref().unwrap().utilization - 5.0).abs() < 1e-9);
        assert!((live.seven_day_sonnet.as_ref().unwrap().utilization - 7.0).abs() < 1e-9);

        let extra = live.extra_usage.as_ref().unwrap();
        assert!(extra.is_enabled);
        assert_eq!(extra.monthly_limit, Some(100.0));
        assert_eq!(extra.used_credits, Some(3.5));

        // ok:true serializes the real camelCase shape.
        let v = serde_json::to_value(&live).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["fiveHour"]["utilization"], 42.5);
        assert_eq!(v["fiveHour"]["resetsAt"], "2026-08-01T18:00:00Z");
        assert_eq!(v["extraUsage"]["isEnabled"], true);
        assert_eq!(v["extraUsage"]["monthlyLimit"], 100.0);
        assert_eq!(v["extraUsage"]["usedCredits"], 3.5);
        // No stray `error` key on success.
        assert!(v.get("error").is_none());
    }

    #[test]
    fn parse_oauth_usage_tolerates_partial_and_missing_subfields() {
        // Only five_hour present, and it omits resets_at.
        let live = parse_oauth_usage(&json!({ "five_hour": { "utilization": 9.0 } }));
        assert!(live.ok);
        let five = live.five_hour.as_ref().unwrap();
        assert!((five.utilization - 9.0).abs() < 1e-9);
        assert!(five.resets_at.is_none());
        assert!(live.seven_day.is_none());
        // resetsAt skipped when None.
        let v = serde_json::to_value(&live).unwrap();
        assert!(v["fiveHour"].get("resetsAt").is_none());
        assert!(v.get("sevenDay").is_none());
    }

    #[test]
    fn parse_oauth_usage_malformed_degrades_to_ok_false() {
        // Not an object.
        let live = parse_oauth_usage(&json!("garbage"));
        assert!(!live.ok);
        assert_eq!(live.error.as_deref(), Some("unparseable response"));

        // An object with none of the recognized blocks.
        let live = parse_oauth_usage(&json!({ "unrelated": 1 }));
        assert!(!live.ok);
        assert_eq!(live.error.as_deref(), Some("unparseable response"));

        // A block whose utilization isn't numeric is dropped; if that leaves
        // nothing recognized, the whole thing degrades.
        let live = parse_oauth_usage(&json!({ "five_hour": { "utilization": "high" } }));
        assert!(!live.ok);
        assert_eq!(live.error.as_deref(), Some("unparseable response"));
    }

    #[test]
    fn unavailable_serializes_as_just_ok_false_and_error() {
        // Shape-compatibility with the v0 stub: ok:false emits ONLY {ok,error}.
        let live = LiveUsage::unavailable("no ~/.claude credentials");
        let v = serde_json::to_value(&live).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "no ~/.claude credentials");
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2, "only ok + error, no data fields");
        assert!(obj.get("fiveHour").is_none());
        assert!(obj.get("extraUsage").is_none());
    }

    #[test]
    fn sanitize_header_value_strips_breakout_chars() {
        assert_eq!(
            sanitize_header_value("claude-code/1.2.3\n\"evil\\"),
            "claude-code/1.2.3evil"
        );
    }
}
