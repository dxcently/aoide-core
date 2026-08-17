//! `graph permit` — the herald's permission SUMMONS: raise one persistent,
//! visually distinct notification for an agent session that is blocked on a
//! permission prompt, block on the human's answer, and type that answer back
//! into the session.
//!
//! The whole loop, end to end:
//!
//!   agent hits its permission prompt
//!     -> its harness fires a hook (claude: `Notification` carrying
//!        `notification_type: permission_prompt`; kimi: `PermissionRequest`)
//!     -> `graph session hook` maps it to the unconditional `awaiting` phase
//!        and, from that arm only, spawns THIS verb detached
//!     -> `dunstify --wait` raises the summons (category `x-aoide.permission`,
//!        which is what the dunstrc's `herald-summons` rule dresses) with ONE
//!        action, `approve`, and blocks
//!     -> the human left-clicks (dunst's `mouse_left_click = do_action`
//!        invokes the single action; dunstify prints `approve`) or
//!        middle-clicks (`close_current`; dunstify prints close reason `2`)
//!     -> the verdict is typed into the session through
//!        [`crate::graph::session_send`] — the ONE gated injection door,
//!        called in-process, every outcome audited.
//!
//! ── Why deny rides the close path ────────────────────────────────────────
//! dunst can route exactly ONE named action to a mouse button: `do_action`
//! invokes "the action determined by the `action_name` rule", falling back to
//! the notification's default/only action, and with two actions and no
//! `dmenu` on the box the context-menu route is a dead gesture. So the
//! summons carries a single `approve` action and DENY is the dismissal —
//! labelled on the card itself ("middle-click denies"), never inferred
//! silently. Everything that is not an explicit approve or an explicit
//! dismissal (an expiry, a `CloseNotification` from another client, a
//! replaced stack tag, no output at all) injects NOTHING: the human answers
//! in the terminal instead. Deny is also the fail-safe direction, so a
//! bulk `close_all` denying a pending summons is a defensible read of
//! "clear the desk", not a hazard.
//!
//! ── The two guards ──────────────────────────────────────────────────────
//! 1. NOT CONDUCTABLE, NO SUMMONS. A session without a control socket has no
//!    channel to answer through, so the card is never raised — the alternative
//!    is a live-looking button that cannot do anything, which the house does
//!    not ship. This is also what keeps a plain (unconducted) terminal agent
//!    from raising desktop cards it could never answer.
//! 2. STILL AWAITING, OR NOTHING IS TYPED. Between raising the card and the
//!    click, the human may well have answered in the terminal. The verdict is
//!    only injected while the session's canonical state is still `awaiting`;
//!    otherwise the summons resolves as `already-answered` and types nothing.
//!    (The keystrokes are printable digits, so even a lost race is a visible
//!    stray character rather than an interrupted turn — see
//!    `aoide_protocol::agents::PermissionKeys`.)

use super::common::{require_flag, stage_error};
use super::model::{
    hooks_path, load_stage, merged_sessions, sessions_path, HooksFile, SessionsFile,
};
use aoide_protocol::agents::{agent_profile, AgentProfile, CLAUDE_PROFILE};
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The notification category the dunstrc's `herald-summons` rule filters on.
/// Changing this string re-dresses the card as an ordinary toast — the two
/// live together in `modules/dendrites/dunst.nix`.
pub const SUMMONS_CATEGORY: &str = "x-aoide.permission";

/// The single dunst action key the summons carries (see the module header for
/// why there is exactly one).
const APPROVE_ACTION: &str = "approve";

/// dunstify's close-reason for "dismissed by the user" — the deny gesture.
const CLOSE_DISMISSED: &str = "2";

// ── Pure: composing the card, and reading the answer ─────────────────────

/// The human's answer to one summons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::graph) enum Verdict {
    Approve,
    Deny,
    /// Nobody answered THROUGH the card (expiry, a programmatic close, a
    /// replaced stack tag, a dead client). Injects nothing.
    Unanswered,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Approve => "approve",
            Verdict::Deny => "deny",
            Verdict::Unanswered => "unanswered",
        }
    }
}

/// Read `dunstify --wait`'s one line of stdout: the invoked action's key when
/// an action fired, else the numeric close reason. Pure so the mapping is
/// unit-tested without a notification daemon.
pub(in crate::graph) fn read_verdict(stdout: &str) -> Verdict {
    match stdout.trim() {
        APPROVE_ACTION => Verdict::Approve,
        CLOSE_DISMISSED => Verdict::Deny,
        _ => Verdict::Unanswered,
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
/// an off switch; the verb itself stays callable by hand either way.
pub(in crate::graph) fn summons_enabled(env_value: Option<&str>) -> bool {
    !matches!(
        env_value.map(str::trim),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

// ── The verb ────────────────────────────────────────────────────────────

/// Resolve the harness profile for a session record's `agent` field, falling
/// back to claude the way every other hook consumer does.
fn profile_for_agent(agent: &str) -> &'static AgentProfile {
    agent_profile(agent).unwrap_or(&CLAUDE_PROFILE)
}

/// Raise the summons and block until it is answered. Returns dunstify's one
/// line of stdout, or an error string when the client could not be run at all.
fn raise_summons(agent: &str, id: &str, summary: &str, body: &str) -> Result<String, String> {
    let out = std::process::Command::new("dunstify")
        .args([
            "--wait",
            "--urgency",
            "critical",
            "--expire-time",
            "0",
            "--app-name",
            agent,
            "--category",
            SUMMONS_CATEGORY,
            // One stack tag per session: a second prompt in the same session
            // REPLACES the standing card instead of piling a second one up.
            "--stack-tag",
            &format!("aoide-permit-{id}"),
            "--action",
            &format!("{APPROVE_ACTION},approve"),
            summary,
            body,
        ])
        .output()
        .map_err(|e| format!("cannot run dunstify (is the dunst dendrite enabled?): {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

/// `aoide graph permit --id <id> [--tool <name>] [--what <text>]` — raise the
/// permission summons for a conducted session and inject the human's verdict.
///
/// Blocks for as long as the card stands (a summons never times out), so every
/// automatic caller spawns it detached.
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

    let summary = summons_summary(tool);
    let body = summons_body(what, &session_handle(rec.title.as_deref(), &id));
    let stdout = match raise_summons(profile.name, &id, &summary, &body) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(cmd, e)
                .with_data(json!({ "reason": "summons-unraisable", "id": id, "raised": false }))
        }
    };
    let verdict = read_verdict(&stdout);
    let base = json!({
        "id": id,
        "agent": profile.name,
        "raised": true,
        "verdict": verdict.label(),
    });
    let with = |extra: Value| {
        let mut d = base.clone();
        if let (Some(o), Some(e)) = (d.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        d
    };

    let key = match verdict {
        Verdict::Approve => keys.approve,
        Verdict::Deny => keys.deny,
        Verdict::Unanswered => {
            return Outcome::ok(cmd, format!("summons for `{id}` closed unanswered"))
                .with_data(with(json!({ "injected": false, "reason": "unanswered" })))
        }
    };
    // Guard 2: the human may have answered in the terminal while the card
    // stood. Only a still-`awaiting` session gets typed into.
    let state = live_state(&id).unwrap_or_default();
    if state != "awaiting" {
        return Outcome::ok(
            cmd,
            format!("`{id}` no longer awaiting ({state}) — verdict `{}` not typed", verdict.label()),
        )
        .with_data(with(
            json!({ "injected": false, "reason": "already-answered", "state": state }),
        ));
    }
    let inner = type_verdict(inv, &id, key);
    if inner.status != Status::Ok {
        return Outcome::error(
            cmd,
            format!("verdict `{}` for `{id}` could not be typed: {}", verdict.label(), inner.message),
        )
        .with_data(with(json!({ "injected": false, "reason": "send-failed" })));
    }
    Outcome::ok(cmd, format!("`{id}`: {} (typed `{key}`)", verdict.label()))
        .changed(vec![format!("session {id}: permission {}", verdict.label())])
        .with_data(with(json!({ "injected": true, "key": key })))
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
    fn read_verdict_maps_the_three_outcomes_and_nothing_else() {
        assert_eq!(read_verdict("approve\n"), Verdict::Approve);
        assert_eq!(read_verdict("  approve  "), Verdict::Approve);
        // dunstify's close reasons: 1 expired, 2 dismissed, 3 CloseNotification.
        assert_eq!(read_verdict("2\n"), Verdict::Deny);
        assert_eq!(read_verdict("1\n"), Verdict::Unanswered);
        assert_eq!(read_verdict("3\n"), Verdict::Unanswered);
        assert_eq!(read_verdict(""), Verdict::Unanswered);
        // Never a fuzzy match — only the exact action key approves.
        assert_eq!(read_verdict("approved"), Verdict::Unanswered);
        assert_eq!(read_verdict("deny"), Verdict::Unanswered);
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
    fn only_claude_carries_verified_permission_keys_today() {
        let claude = profile_for_agent("claude");
        let keys = claude.permission_keys.as_ref().expect("claude's prompt was read live");
        assert_eq!(keys.approve, "1");
        assert_eq!(keys.deny, "3");
        // Not option 2 — a summons approves THIS request, not the session.
        assert_ne!(keys.approve, "2");
        // The unverified harnesses refuse rather than guess.
        assert!(profile_for_agent("kimi").permission_keys.is_none());
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
