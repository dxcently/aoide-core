//! `graph permit` — the herald's permission SUMMONS: publish one persistent,
//! visually distinct card for an agent session blocked on a permission prompt,
//! and type the human's answer back into the session when it arrives.
//!
//! The whole loop, end to end:
//!
//!   agent hits its permission prompt
//!     -> its harness fires a hook (claude: `Notification` carrying
//!        `notification_type: permission_prompt`; kimi: `PermissionRequest`)
//!     -> `graph session hook` maps it to the unconditional `awaiting` phase
//!        and, from that arm only, spawns THIS command detached
//!     -> the summons is PUBLISHED into the herald ledger
//!        (`stage/herald.json`, through the shellbridge) and this command returns
//!     -> the QML herald draws it with two real buttons and the human clicks
//!        one; the click rides back as `{"cmd":"heraldverdict", …}`
//!     -> the daemon calls [`answer_summons`], which types the verdict through
//!        [`crate::graph::session_send`] — the ONE gated injection door,
//!        called in-process, every outcome audited.
//!
//! ── Why the card moved to QML (2026-08-17) ──────────────────────────────
//! This command used to raise the card itself with `dunstify --wait` and block on
//! its exit. It could not offer two buttons: dunst has no per-region hit
//! testing, so every drawn control fired the same window-wide left-click
//! binding — a deny chip that approved. Deny had to ride the DISMISS gesture
//! instead, which meant a bulk "clear the desk" silently denied a pending
//! summons, and the label was the only thing keeping the two apart.
//!
//! Drawn by Quickshell, approve and deny are two ordinary hit-tested buttons
//! that say what they are and do what they say. The verdict is explicit or it
//! does not exist: a dismissal, an expiry, or a cleared desk now injects
//! NOTHING and the human answers in the terminal, where they always could.
//! Nothing is inferred from a gesture any more.
//!
//! ── The two guards ──────────────────────────────────────────────────────
//! 1. NOT CONDUCTABLE, NO SUMMONS. A session without a control socket has no
//!    channel to answer through, so the card is never raised — the alternative
//!    is a live-looking button that cannot do anything, which the house does
//!    not ship. This is also what keeps a plain (unconducted) terminal agent
//!    from raising desktop cards it could never answer.
//! 2. STILL AWAITING, OR NOTHING IS TYPED. Between publishing the card and the
//!    click, the human may well have answered in the terminal. The verdict is
//!    only injected while the session's canonical state is still `awaiting`;
//!    otherwise the summons resolves as `already-answered` and types nothing.
//!    (The keystrokes are printable digits, so even a lost race is a visible
//!    stray character rather than an interrupted turn — see
//!    `aoide_protocol::agents::PermissionKeys`.)
//!    This guard lives in [`answer_summons`], on the answering side, because
//!    that is where the race is: the gap between the card going up and the
//!    button being pressed.

use super::common::{require_flag, stage_error};
use super::model::{
    hooks_path, load_stage, merged_sessions, sessions_path, HooksFile, SessionsFile,
};
use aoide_protocol::agents::{agent_profile, AgentProfile, CLAUDE_PROFILE};
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The notification category a summons carries. The QML herald reads `kind`
/// rather than this string, but the category stays on the record: it is what a
/// dunst rule would filter on if the summons ever needs its own daemon-side
/// treatment again, and it names the card honestly in `dunstctl history`.
pub const SUMMONS_CATEGORY: &str = "x-aoide.permission";

// ── Pure: composing the card, and reading the answer ─────────────────────

/// The human's answer to one summons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::graph) enum Verdict {
    Approve,
    Deny,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Approve => "approve",
            Verdict::Deny => "deny",
        }
    }

    /// Read the wire's verdict string. A CLOSED set: only the two explicit
    /// answers exist, and anything else is not a verdict at all. There is no
    /// "unanswered" variant any more — a card that is dismissed, cleared or
    /// timed out simply never sends one, where the old dunstify path had to
    /// infer intent from a close reason.
    pub(in crate::graph) fn from_wire(s: &str) -> Option<Verdict> {
        match s.trim() {
            "approve" => Some(Verdict::Approve),
            "deny" => Some(Verdict::Deny),
            _ => None,
        }
    }
}

/// A session id shortened for the card's context line: a 36-char uuid would
/// wrap the tier and its tail says nothing extra to a human, so a long id is
/// cut to its uuid-style leading 8 (trailing separators trimmed, so a
/// `conduct-<pid>-<ts>` id does not end mid-hyphen) while a short id — every
/// hand-set `--id` — stays whole.
pub(in crate::graph) fn short_id(id: &str) -> String {
    if id.chars().count() <= 12 {
        return id.to_string();
    }
    id.chars()
        .take(8)
        .collect::<String>()
        .trim_end_matches(['-', '_', '.'])
        .to_string()
}

/// The human-facing handle for the waiting session. Prefers the node's `title`
/// — the one-line task the last delivered `graph send` auto-renamed it to, and
/// exactly what the dock and the graph tree show — because "reaper ghosts"
/// tells the human which agent is asking and a raw id never does. Falls back to
/// the id when the node was never named. Clipped: this rides at the END of an
/// already-clipped body line.
pub(in crate::graph) fn session_handle(title: Option<&str>, id: &str) -> String {
    match title.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => {
            let flat: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if flat.chars().count() > 28 {
                flat.chars().take(27).collect::<String>() + "…"
            } else {
                flat
            }
        }
        None => format!("session {}", short_id(id)),
    }
}

/// Tier 2 of the card: the tool being asked about, or a plain floor. Kept to
/// one short line — the title tier is a bold serif carve, not a paragraph.
pub(in crate::graph) fn summons_summary(tool: Option<&str>) -> String {
    match tool.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => format!("{t} · permission"),
        None => "permission requested".to_string(),
    }
}

/// Tier 3 of the card: what is being asked, and which session is waiting.
/// The `what` text is a hook payload's — untrusted, so it rides as DATA and
/// nothing here interprets it (the dunstrc renders both tiers as plain text,
/// `markup = no`, for exactly this reason). One line, clipped.
pub(in crate::graph) fn summons_body(what: Option<&str>, handle: &str) -> String {
    match what.map(str::trim).filter(|w| !w.is_empty()) {
        Some(w) => {
            let flat: String = w.split_whitespace().collect::<Vec<_>>().join(" ");
            let clipped: String = if flat.chars().count() > 90 {
                flat.chars().take(89).collect::<String>() + "…"
            } else {
                flat
            };
            format!("{clipped} — {handle}")
        }
        None => handle.to_string(),
    }
}

/// Is this session answerable at all? A summons is only ever raised for a
/// session that owns a control socket (guard 1 in the module header).
pub(in crate::graph) fn answerable(conductable: Option<bool>, socket: Option<&str>) -> bool {
    conductable == Some(true) && socket.map(|s| !s.is_empty()).unwrap_or(false)
}

/// The opt-out for the automatic summons: `AOIDE_HERALD_PERMIT` in
/// {0,false,no,off} silences it box-wide. Automatic desktop side effects get
/// an off switch; the command itself stays callable by hand either way.
pub(in crate::graph) fn summons_enabled(env_value: Option<&str>) -> bool {
    !matches!(
        env_value.map(str::trim),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

// ── The command ────────────────────────────────────────────────────────────

/// Resolve the harness profile for a session record's `agent` field, falling
/// back to claude the way every other hook consumer does. `pub(in
/// crate::graph)`: `send.rs`'s delivery path reuses this SAME resolver to
/// pick the target's submit keystroke — no second lookup of the same table.
pub(in crate::graph) fn profile_for_agent(agent: &str) -> &'static AgentProfile {
    agent_profile(agent).unwrap_or(&CLAUDE_PROFILE)
}

/// The ledger record for one summons. Pure, so the whole card can be asserted
/// without a socket or a compositor.
///
/// `stackTag` is one per session: a second prompt in the same session REPLACES
/// the standing card instead of piling a second one up (the ledger's
/// replace-by-tag rule, `herald::apply_push`). The id is derived from the same
/// tag so a verdict can address the card by name, and `timeoutMs = 0` because a
/// summons never expires on its own — somebody is blocked behind it.
/// The ledger id of the card standing for one session's summons.
///
/// The mapping lives HERE and nowhere else, because two sides depend on it
/// disagreeing about nothing: `graph permit` files the card under this id, and
/// the shellbridge takes it down under the same one after a verdict — but a
/// verdict is addressed to the SESSION, so one of the two has to convert.
pub fn summons_card_id(session_id: &str) -> String {
    format!("permit-{session_id}")
}

pub(in crate::graph) fn summons_record(
    agent: &str,
    id: &str,
    summary: &str,
    body: &str,
    received_at: String,
) -> crate::herald::Notification {
    crate::herald::Notification {
        id: summons_card_id(id),
        app: agent.to_string(),
        summary: summary.to_string(),
        body: body.to_string(),
        icon: String::new(),
        urgency: "critical".to_string(),
        progress: crate::herald::NO_PROGRESS,
        category: SUMMONS_CATEGORY.to_string(),
        stack_tag: format!("aoide-permit-{id}"),
        timeout_ms: 0,
        received_at,
        kind: crate::herald::KIND_SUMMONS.to_string(),
        session_id: id.to_string(),
    }
}

/// The session's canonical live state, hooks merged over the roster — the same
/// derivation the desktop renders, so "still awaiting" here means exactly what
/// the dock's peek means.
fn live_state(id: &str) -> Option<String> {
    let sessions: SessionsFile = load_stage(&sessions_path()).ok()?;
    let hooks: HooksFile = load_stage(&hooks_path()).ok()?;
    merged_sessions(&sessions.sessions, &hooks.hooks)
        .into_iter()
        .find(|s| s.session_id == id)
        .map(|s| s.state)
}

/// Type one verdict into the session: synthesize the exact `Invocation`
/// `aoide graph send --id <id> --yes -- <key>` would parse into and call
/// [`crate::graph::session_send`] directly — same-process, never a subprocess
/// shell-out, so there is no second injection path anywhere in this file and
/// the audit line is written by the door itself.
///
/// `--yes` is honest here and not a bypass: the gate exists to put a human in
/// the loop, and the human just clicked the card. NO `--submit` — the prompt
/// is a numbered hotkey select, so the digit alone answers it and a stray
/// newline would fall through to whatever came next.
fn type_verdict(inv: &Invocation, id: &str, key: &str) -> Outcome {
    let mut flags = BTreeMap::new();
    flags.insert("id".to_string(), id.to_string());
    flags.insert("yes".to_string(), "true".to_string());
    if let Some(log) = inv.flags.get("audit-log") {
        flags.insert("audit-log".to_string(), log.clone());
    }
    crate::graph::session_send(&Invocation {
        path: vec!["graph".to_string(), "send".to_string()],
        args: vec![key.to_string()],
        flags,
        door: inv.door,
    })
}

/// Type one explicit verdict into a waiting session — the answering half of the
/// summons, called by the shellbridge when the human clicks approve or deny in
/// the QML herald.
///
/// `id` is the SESSION id (the card's `sessionId`), not the card id. Guard 2
/// lives here: only a session whose canonical state is still `awaiting` is
/// typed into, so answering in the terminal while the card stands is never
/// typed over.
pub fn answer_summons(id: &str, verdict: &str) -> Outcome {
    let cmd = "graph.permit";
    let Some(verdict) = Verdict::from_wire(verdict) else {
        return Outcome::error(cmd, format!("`{verdict}` is not a verdict"))
            .with_data(json!({ "injected": false, "reason": "bad-verdict", "id": id }));
    };
    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        return Outcome::error(cmd, format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "id": id, "injected": false }));
    };
    let profile = profile_for_agent(&rec.agent);
    let Some(keys) = profile.permission_keys.as_ref() else {
        return Outcome::error(
            cmd,
            format!("no verified permission-prompt keys for `{}`", profile.name),
        )
        .with_data(json!({ "reason": "no-permission-keys", "id": id, "injected": false }));
    };
    let base = json!({ "id": id, "agent": profile.name, "verdict": verdict.label() });
    let with = |extra: Value| {
        let mut d = base.clone();
        if let (Some(o), Some(e)) = (d.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        d
    };
    // Guard 2: the human may have answered in the terminal while the card stood.
    let state = live_state(id).unwrap_or_default();
    if state != "awaiting" {
        return Outcome::ok(
            cmd,
            format!(
                "`{id}` no longer awaiting ({state}) — verdict `{}` not typed",
                verdict.label()
            ),
        )
        .with_data(with(
            json!({ "injected": false, "reason": "already-answered", "state": state }),
        ));
    }
    let key = match verdict {
        Verdict::Approve => keys.approve,
        Verdict::Deny => keys.deny,
    };
    // The daemon has no Invocation of its own to inherit an audit log from;
    // `type_verdict` falls back to the default log, which is where every other
    // daemon-side audit line already goes.
    let inv = Invocation {
        path: vec!["graph".to_string(), "permit".to_string()],
        args: vec![],
        flags: BTreeMap::new(),
        door: aoide_protocol::Door::Daemon,
    };
    let inner = type_verdict(&inv, id, key);
    if inner.status != Status::Ok {
        return Outcome::error(
            cmd,
            format!(
                "verdict `{}` for `{id}` could not be typed: {}",
                verdict.label(),
                inner.message
            ),
        )
        .with_data(with(json!({ "injected": false, "reason": "send-failed" })));
    }
    Outcome::ok(cmd, format!("`{id}`: {} (typed `{key}`)", verdict.label()))
        .changed(vec![format!("session {id}: permission {}", verdict.label())])
        .with_data(with(json!({ "injected": true, "key": key })))
}

/// `aoide graph permit --id <id> [--tool <name>] [--what <text>]` — publish the
/// permission summons for a conducted session.
///
/// Returns as soon as the card is filed. The human's answer arrives later,
/// through the QML herald's buttons and [`answer_summons`] — so unlike the old
/// dunstify path, nothing here blocks for as long as the card stands.
pub fn session_permit(inv: &Invocation) -> Outcome {
    let cmd = "graph.permit";
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    let tool = inv.flags.get("tool").map(String::as_str);
    let what = inv.flags.get("what").map(String::as_str);

    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        return Outcome::error(cmd, format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "id": id }));
    };
    // Guard 1: no channel to answer through means no card (module header).
    if !answerable(rec.conductable, rec.socket.as_deref()) {
        return Outcome::error(
            cmd,
            format!("session `{id}` is not conductable — no channel to answer a summons through"),
        )
        .with_data(json!({ "reason": "not-conductable", "id": id, "raised": false }));
    }
    let profile = profile_for_agent(&rec.agent);
    let Some(keys) = profile.permission_keys.as_ref() else {
        return Outcome::error(
            cmd,
            format!(
                "no verified permission-prompt keys for `{}` — refusing to guess at its prompt",
                profile.name
            ),
        )
        .with_data(json!({
            "reason": "no-permission-keys",
            "id": id,
            "agent": profile.name,
            "raised": false,
        }));
    };

    // The keys are checked HERE, before the card goes up, even though nothing
    // is typed until the answer comes back: a summons whose verdict could never
    // be delivered is a live-looking button that cannot do anything.
    let _ = keys;

    let summary = summons_summary(tool);
    let body = summons_body(what, &session_handle(rec.title.as_deref(), &id));
    let record = summons_record(
        profile.name,
        &id,
        &summary,
        &body,
        aoide_storage::time::now_iso_utc(),
    );
    if let Err(e) = crate::herald::publish(&record) {
        return Outcome::error(
            cmd,
            format!("could not reach the shellbridge to raise the summons: {e}"),
        )
        .with_data(json!({ "reason": "summons-unraisable", "id": id, "raised": false }));
    }
    Outcome::ok(cmd, format!("summons raised for `{id}`"))
        .changed(vec![format!("session {id}: permission summons raised")])
        .with_data(json!({
            "id": id,
            "agent": profile.name,
            "raised": true,
            "card": record.id,
        }))
}

/// Spawn `graph permit` DETACHED for a session that just went `awaiting` on a
/// permission prompt — the hook door's one call site. Best-effort and silent
/// by design: the hook runs inside a live agent session under a short timeout,
/// so it must never block on the card, never inherit its stdio, and never turn
/// a notification problem into a hook failure.
///
/// Every real guard lives in [`session_permit`] itself (unknown session, not
/// conductable, no verified keys), so this only checks the box-wide opt-out and
/// the one thing it can know for free: that there is an `aoide` on PATH to
/// re-enter.
pub(in crate::graph) fn spawn_summons(id: &str, what: Option<&str>) {
    if !summons_enabled(std::env::var("AOIDE_HERALD_PERMIT").ok().as_deref()) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    // Only ever re-enter the real `aoide` binary. Under `cargo test` — or any
    // other host that links this crate — `current_exe` is a harness that would
    // not understand these args at all, so there is nothing to re-enter.
    if exe.file_name().and_then(|n| n.to_str()) != Some("aoide") {
        return;
    }
    let mut args = vec!["graph".to_string(), "permit".to_string(), "--id".to_string(), id.to_string()];
    if let Some(w) = what.map(str::trim).filter(|w| !w.is_empty()) {
        args.push("--what".to_string());
        args.push(w.to_string());
    }
    let child = std::process::Command::new(exe)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    // Reap the handle without waiting on the card: the same detached-child
    // idiom shellbridge's notify-send spawn uses, so a standing summons can
    // never hold the hook (or a zombie) open.
    if let Ok(mut c) = child {
        std::thread::spawn(move || {
            let _ = c.wait();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_is_one_of_exactly_two_words() {
        assert_eq!(Verdict::from_wire("approve"), Some(Verdict::Approve));
        assert_eq!(Verdict::from_wire(" deny\n"), Some(Verdict::Deny));
        // Never a fuzzy match, and never a default: a permission gate has no
        // safe direction to fall back to, so a malformed verdict is no verdict.
        assert_eq!(Verdict::from_wire("approved"), None);
        assert_eq!(Verdict::from_wire("APPROVE"), None);
        assert_eq!(Verdict::from_wire("yes"), None);
        assert_eq!(Verdict::from_wire(""), None);
        assert_eq!(Verdict::from_wire("2"), None);
    }

    #[test]
    fn the_summons_card_carries_what_the_herald_needs_to_draw_it() {
        let card = summons_record(
            "claude",
            "sess-1",
            "Bash · permission",
            "rm -rf build/ — reaper ghosts",
            "2026-08-17T12:00:00Z".into(),
        );
        assert_eq!(card.kind, crate::herald::KIND_SUMMONS, "drawn with buttons");
        assert_eq!(card.session_id, "sess-1", "the verdict knows where to go");
        assert_eq!(card.timeout_ms, 0, "somebody is blocked behind it");
        assert_eq!(card.category, SUMMONS_CATEGORY);
        assert_eq!(card.progress, crate::herald::NO_PROGRESS);
        // The card is filed under the id the bridge later takes it down by.
        // A mismatch here does not fail loudly — it leaves an ANSWERED summons
        // standing on screen forever, so the mapping is pinned.
        assert_eq!(card.id, summons_card_id("sess-1"));
        assert_ne!(card.id, card.session_id, "the card id is not the session id");
        // One tag per session: a second prompt replaces the standing card.
        assert_eq!(card.stack_tag, "aoide-permit-sess-1");
        let second = summons_record("claude", "sess-1", "Edit · permission", "b", "t".into());
        assert_eq!(second.stack_tag, card.stack_tag);
        assert_eq!(second.id, card.id, "and addresses the same card");
    }

    #[test]
    fn agent_text_rides_the_card_as_data() {
        // The old path had to guard a leading `-` against dunstify's argv
        // parser. There is no argv any more — the text is a JSON field.
        let card = summons_record(
            "claude",
            "s",
            "-summary",
            "--force-with-lease `whoami`",
            "t".into(),
        );
        assert_eq!(card.summary, "-summary");
        assert_eq!(card.body, "--force-with-lease `whoami`");
    }

    #[test]
    fn answerable_requires_both_the_flag_and_a_non_empty_socket() {
        assert!(answerable(Some(true), Some("/run/user/1000/aoide/s.sock")));
        assert!(!answerable(Some(true), Some("")));
        assert!(!answerable(Some(true), None));
        assert!(!answerable(Some(false), Some("/run/user/1000/aoide/s.sock")));
        assert!(!answerable(None, Some("/run/user/1000/aoide/s.sock")));
    }

    #[test]
    fn summons_enabled_is_on_unless_explicitly_switched_off() {
        assert!(summons_enabled(None));
        assert!(summons_enabled(Some("")));
        assert!(summons_enabled(Some("1")));
        assert!(summons_enabled(Some("yes")));
        for off in ["0", "false", "no", "off", " off "] {
            assert!(!summons_enabled(Some(off)), "{off}");
        }
    }

    #[test]
    fn the_card_text_reads_as_two_tiers_and_never_wraps_on_a_long_ask() {
        assert_eq!(summons_summary(Some("Bash")), "Bash · permission");
        assert_eq!(summons_summary(Some("  ")), "permission requested");
        assert_eq!(summons_summary(None), "permission requested");

        let handle = session_handle(None, "3f9a1c2e-dead-beef");
        assert_eq!(
            summons_body(Some("rm -rf build/"), &handle),
            "rm -rf build/ — session 3f9a1c2e"
        );
        // No ask → the waiting session is still named.
        assert_eq!(summons_body(None, &handle), "session 3f9a1c2e");
        // Multi-line/whitespace-heavy asks collapse to one line…
        assert_eq!(
            summons_body(Some("line one\n   line two"), &handle),
            "line one line two — session 3f9a1c2e"
        );
        // …and a long one is clipped at a char boundary, not left to wrap.
        let long = "x".repeat(200);
        let body = summons_body(Some(&long), &handle);
        assert!(body.starts_with(&"x".repeat(89)));
        assert!(body.contains("… — session 3f9a1c2e"));
        assert_eq!(body.chars().count(), 90 + " — session 3f9a1c2e".chars().count());
    }

    #[test]
    fn the_handle_prefers_the_named_node_over_a_raw_id() {
        assert_eq!(
            session_handle(Some("fix the reaper's ghosts"), "3f9a1c2e-dead"),
            "fix the reaper's ghosts"
        );
        // A long title is clipped, not left to push the ask off the line.
        let long = session_handle(Some(&"word ".repeat(20)), "id");
        assert_eq!(long.chars().count(), 28);
        assert!(long.ends_with('…'));
        // Blank/whitespace titles fall through to the id.
        assert_eq!(session_handle(Some("  "), "3f9a1c2e-dead"), "session 3f9a1c2e");
        assert_eq!(session_handle(None, "3f9a1c2e-dead"), "session 3f9a1c2e");
    }

    #[test]
    fn short_id_is_char_safe_and_never_ends_mid_separator() {
        assert_eq!(short_id("3f9a1c2e-dead-beef"), "3f9a1c2e");
        // `conduct-<pid>-<ts>` must not clip to a trailing hyphen.
        assert_eq!(short_id("conduct-921951-1786953421"), "conduct");
        // A hand-set short id stays whole rather than being cut mid-word.
        assert_eq!(short_id("permit-test"), "permit-test");
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id(""), "");
        assert_eq!(short_id("ωωωωωωωωωωωωωω"), "ωωωωωωωω");
    }

    #[test]
    fn claude_and_kimi_carry_verified_permission_keys_pi_does_not() {
        let claude = profile_for_agent("claude");
        let keys = claude.permission_keys.as_ref().expect("claude's prompt was read live");
        assert_eq!(keys.approve, "1");
        assert_eq!(keys.deny, "3");
        // Not option 2 — a summons approves THIS request, not the session.
        assert_ne!(keys.approve, "2");
        // Kimi's prompt was read live too (2026-08-20 probe) — same shape.
        let kimi = profile_for_agent("kimi");
        let kimi_keys = kimi.permission_keys.as_ref().expect("kimi's prompt was read live");
        assert_eq!(kimi_keys.approve, "1");
        assert_eq!(kimi_keys.deny, "3");
        assert_ne!(kimi_keys.approve, "2");
        // pi's prompt has never been read live — it still refuses to guess.
        assert!(profile_for_agent("pi").permission_keys.is_none());
        // An unknown agent string falls back to claude, as everywhere else.
        assert_eq!(profile_for_agent("mystery").name, "claude");
        assert_eq!(profile_for_agent("").name, "claude");
    }

    #[test]
    fn spawn_summons_never_re_enters_a_test_harness() {
        // `current_exe` here is libtest, not `aoide` — the guard must make this
        // a silent no-op rather than spawning a process with args no harness
        // understands. (Every real guard is in `session_permit` itself.)
        spawn_summons("no-such-session", Some("probe"));
        spawn_summons("no-such-session", None);
    }

    #[test]
    fn permit_without_an_id_is_a_usage_error() {
        let out = session_permit(&Invocation {
            path: vec!["graph".into(), "permit".into()],
            args: vec![],
            flags: BTreeMap::new(),
            door: aoide_protocol::Door::Cli,
        });
        assert_eq!(out.status, Status::Usage);
    }

    #[test]
    fn permit_refuses_an_unconductable_session_without_raising_a_card() {
        let _g = crate::env_lock().lock().unwrap();
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = aoide_test_support::unique_tmp("permit-unconductable");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        // A hook-only session: registered, but no pty and no socket.
        std::fs::write(
            stage.join("sessions.json"),
            r#"{"schemaVersion":"0","sessions":[{"sessionId":"s1","agent":"claude","state":"awaiting","startedAt":"2026-01-01T00:00:00Z"}]}"#,
        )
        .unwrap();
        let inv = |id: &str| {
            let mut flags = BTreeMap::new();
            flags.insert("id".to_string(), id.to_string());
            Invocation {
                path: vec!["graph".into(), "permit".into()],
                args: vec![],
                flags,
                door: aoide_protocol::Door::Cli,
            }
        };
        let out = session_permit(&inv("s1"));
        assert_eq!(out.status, Status::Error);
        let data = out.data.unwrap();
        assert_eq!(data["reason"], "not-conductable");
        assert_eq!(data["raised"], false, "no card for a session that cannot answer");

        // An unknown id is a different, equally card-free error.
        let out = session_permit(&inv("nope"));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "session-not-found");

        let _ = std::fs::remove_dir_all(&stage);
    }
}
