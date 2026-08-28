//! `session grant undying on|off [--self | --id <id>]` — mark or unmark a
//! session DURABLE, so a project's whole undying set can later be
//! resurrected together (`resurrect`, `CONTRACTS.md`'s `state/undying.json`
//! section).
//!
//! Prototyped under the name "carry" (task #96, `graph session carry`);
//! shipped under this name at command-defrag lane U1 (2026-08-27); relocated
//! under the `session grant` positional-kind grammar at the session-surface
//! redesign (command-defrag lane X, 2026-08-28) — [`undying_grant`] is
//! [`super::grant::session_grant`]'s scripted-branch callee, not a
//! registered command in its own right anymore (the standalone `session
//! undying` path this absorbs is now unknown, same as a typo). The store
//! logic is untouched throughout: a thin command over `aoide_storage::
//! undying`'s CRUD (P-C1, landed) — no reimplementation here. This function
//! writes ONLY `state/undying.json`: unlike every other `session *` handler
//! in this crate, it takes no stage lock and does not route through
//! `aoide_client::daemon::daemon_dispatch` — `undying.json` is not a
//! `state/stage/` file, so it sits entirely outside the L4 dual-writer
//! surface (a second writer there would defeat the store's own
//! single-writer atomic-write discipline; see `undying.rs`'s own module doc
//! in `aoide-storage`).
//!
//! `--id` targets ANY session id, including one that has already left the
//! roster — no roster lookup gates the write. That is the whole point of the
//! design: a mark must be flippable post-mortem, off a bare ledger id, after
//! the session that owned it is gone.

use super::model::{load_stage, sessions_path, SessionsFile};
#[cfg(test)]
use super::model::{write_stage, RestoreSnapshot, SessionRecord};
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use aoide_storage::undying::{load_undying, save_undying, set_undying};
use serde_json::json;

/// `aoide session grant undying (on|off) [--self | --id <id>] [--json]` —
/// the SCRIPTED mark, called by [`super::grant::session_grant`] with the
/// state positional it already parsed off `inv.args[1]` (`inv.args[0]` is
/// the kind, `"undying"`, consumed by the dispatcher).
///
/// Target resolution: `--id <id>` names any session id directly; otherwise
/// `--self` (or a bare invocation, the same default) reads
/// `$AOIDE_SESSION_ID` — the same env var `window.rs`'s
/// `resolve_registration_parent` already treats as "this session". `--self`
/// and `--id` together is a usage error; neither an `--id` nor a resolvable
/// `$AOIDE_SESSION_ID` is likewise a usage error naming both — never a
/// silent no-op.
pub(super) fn undying_grant(inv: &Invocation, cmd: &str, state: &str) -> Outcome {
    let usage = "usage: aoide session grant undying (on|off) [--self | --id <id>] [--json]";

    let on = match state {
        "on" => true,
        "off" => false,
        other => {
            return Outcome::usage(
                cmd,
                format!(
                    "`{other}` is not an undying state — the only two are `on` and `off`\n{usage}"
                ),
            );
        }
    };

    let self_flag = inv.flag_present("self");
    let id_flag = inv
        .flags
        .get("id")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if self_flag && id_flag.is_some() {
        return Outcome::usage(cmd, format!("--self and --id are mutually exclusive\n{usage}"));
    }

    let id = match id_flag {
        Some(id) => id,
        None => match std::env::var("AOIDE_SESSION_ID").ok().filter(|s| !s.is_empty()) {
            Some(id) => id,
            None => {
                return Outcome::usage(
                    cmd,
                    format!(
                        "no session to mark undying: pass --self (reads $AOIDE_SESSION_ID) or \
                         --id <id> — neither was given and $AOIDE_SESSION_ID is unset\n{usage}"
                    ),
                );
            }
        },
    };

    let mut undying = load_undying();
    let transitioned = set_undying(&mut undying, &id, on);
    if let Err(e) = save_undying(&undying) {
        return Outcome::error(cmd, format!("failed to write undying.json: {e}"));
    }

    // Presence in the roster is INFORMATIONAL only — never a gate on the
    // write above, which must succeed for a dead id exactly the same way it
    // does for a live one (the post-mortem case this command exists for).
    // Reused below for the nothing-to-restore warning: a record found here
    // is the only signal this command has about what `id` actually is.
    let record = load_stage::<SessionsFile>(&sessions_path())
        .ok()
        .and_then(|f| f.sessions.into_iter().find(|s| s.session_id == id));
    let live = record.is_some();

    let verb = if on { "undying" } else { "not undying" };
    let mut message = format!("`{id}` is now {verb}");
    // Only worth warning on the way TO undying — turning it off never
    // promises a future restore. A dead/unknown id (not in the roster) has
    // no live signal to warn from either; silent there, same as `live`
    // above.
    if on {
        if let Some(rec) = &record {
            if let Some(warning) = nothing_to_restore_warning(&rec.agent, rec.restore.is_some()) {
                message = format!("{message} — {warning}");
            }
        }
    }
    let mut out = Outcome::ok(cmd, message);
    if transitioned {
        out = out.changed(vec![format!("{id}: {verb}")]);
    }
    out.with_data(json!({ "sessionId": id, "undying": on, "live": live }))
}

/// Whether `graph resurrect` will find anything beyond the bare spec to
/// restore for a session marked undying — the same two arms
/// `resurrect.rs::resolve_candidate` tries, mirrored here at MARK time
/// (task #100 follow-up to P-C6): the harness arm (`agent_profile(agent)`
/// carrying a verified `resume_args`) and the terminal arm (`has_capture` —
/// whether this session's own P-C5 restore snapshot was ever populated,
/// which `conduct.rs::captures_like_a_shell` now gates on the WRAPPED
/// command, never the agent label). Neither present means a later
/// resurrect has nothing to work with but the spec itself — worth telling
/// the operator NOW, at mark time, rather than only discovering it silently
/// at a resurrect that restores nothing.
pub(in crate::graph) fn nothing_to_restore_warning(agent: &str, has_capture: bool) -> Option<String> {
    if has_capture {
        return None;
    }
    if aoide_protocol::agents::agent_profile(agent)
        .and_then(|p| p.resume_args)
        .is_some()
    {
        return None;
    }
    Some(format!(
        "warning: `{agent}` has no restore capture and no verified resume flag — \
         resurrect will have nothing beyond the spec to restore for this session"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;
    use aoide_protocol::output::Status;

    /// Isolated state (+ stage, for the `live` check) dir per test, mirroring
    /// `resurrect.rs`'s own `setup` helper — same idiom, trimmed to what this
    /// command actually touches (no project registration needed).
    fn setup(tag: &str) -> std::path::PathBuf {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        root
    }

    /// `args` is vestigial post-relocation — `undying_grant` no longer reads
    /// `inv.args` at all (the state positional is a direct function
    /// parameter now, resolved by `grant.rs`'s dispatcher before this
    /// function is ever called) — kept only so a caller can still shape a
    /// realistic `Invocation` if some future test needs it.
    fn undying_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["session".into(), "grant".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn on_then_off_round_trips_through_the_undying_store() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-roundtrip");

        let on = undying_grant(&undying_invocation(&[], &[("id", "sess-1")]), "session.grant", "on");
        assert_eq!(on.status, Status::Ok, "msg: {}", on.message);
        assert_eq!(on.data.as_ref().unwrap()["undying"], true);
        assert_eq!(on.changed, vec!["sess-1: undying".to_string()]);
        assert!(aoide_storage::undying::is_undying(&aoide_storage::undying::load_undying(), "sess-1"));

        let off = undying_grant(&undying_invocation(&[], &[("id", "sess-1")]), "session.grant", "off");
        assert_eq!(off.status, Status::Ok, "msg: {}", off.message);
        assert_eq!(off.data.as_ref().unwrap()["undying"], false);
        assert_eq!(off.changed, vec!["sess-1: not undying".to_string()]);
        assert!(!aoide_storage::undying::is_undying(&aoide_storage::undying::load_undying(), "sess-1"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bare_invocation_defaults_to_the_ambient_session_id() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-bare-env");
        std::env::set_var("AOIDE_SESSION_ID", "env-sess");

        let out = undying_grant(&undying_invocation(&[], &[]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["sessionId"], "env-sess");
        assert!(aoide_storage::undying::is_undying(&aoide_storage::undying::load_undying(), "env-sess"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_self_flag_reads_the_same_ambient_session_id() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-self-flag");
        std::env::set_var("AOIDE_SESSION_ID", "self-sess");

        let out = undying_grant(&undying_invocation(&[], &[("self", "true")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["sessionId"], "self-sess");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The decision-2 proof: `--id` marks an id absent from `sessions.json`
    /// entirely — no roster lookup may gate the write, which is what makes
    /// the mark flippable post-mortem off a bare ledger id.
    #[test]
    fn id_marks_a_session_absent_from_the_roster() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-post-mortem");
        // sessions.json stays empty for this test — the id below is never in it.

        let out = undying_grant(&undying_invocation(&[], &[("id", "long-dead-id")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["undying"], true);
        assert_eq!(data["live"], false, "the id must never be required to be in the roster");
        assert!(aoide_storage::undying::is_undying(&aoide_storage::undying::load_undying(), "long-dead-id"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_reports_true_for_an_id_still_in_the_roster() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-live-true");
        let file = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![session("live-id", "/w", "working", "1", None)],
        };
        write_stage(&sessions_path(), &file).unwrap();

        let out = undying_grant(&undying_invocation(&[], &[("id", "live-id")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["live"], true);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_id_and_no_env_is_a_usage_error_naming_both() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-no-target");
        std::env::remove_var("AOIDE_SESSION_ID");

        let out = undying_grant(&undying_invocation(&[], &[]), "session.grant", "on");
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("--self"), "msg: {}", out.message);
        assert!(out.message.contains("--id"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn self_and_id_together_is_a_usage_error() {
        let out = undying_grant(&undying_invocation(&[], &[("self", "true"), ("id", "sess-1")]), "session.grant", "on");
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("mutually exclusive"), "msg: {}", out.message);
    }

    #[test]
    fn an_unknown_positional_word_is_a_usage_error_naming_both_states() {
        let out = undying_grant(&undying_invocation(&[], &[("id", "sess-1")]), "session.grant", "maybe");
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("on"), "msg: {}", out.message);
        assert!(out.message.contains("off"), "msg: {}", out.message);
    }

    // `missing_positional_is_a_usage_error` (the state positional absent
    // entirely) moved to `grant.rs`'s
    // `undying_kind_with_no_state_dispatches_to_the_picker_and_hits_its_tty_gate`
    // — that case now routes to the PICKER, not a usage error here, since
    // `session_grant`'s own dispatcher branches on `inv.args.get(1)` before
    // `undying_grant` is ever called; this function can no longer observe a
    // missing state at all.

    /// A re-mark (already-on, marked on again) is not a TRANSITION —
    /// `changed` stays empty, matching `set_undying`'s own idempotency
    /// contract (`aoide_storage::undying`).
    #[test]
    fn a_remark_is_ok_but_reports_no_transition() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-remark");

        let first = undying_grant(&undying_invocation(&[], &[("id", "sess-1")]), "session.grant", "on");
        assert_eq!(first.status, Status::Ok);
        assert!(!first.changed.is_empty());

        let second = undying_grant(&undying_invocation(&[], &[("id", "sess-1")]), "session.grant", "on");
        assert_eq!(second.status, Status::Ok);
        assert!(second.changed.is_empty(), "a re-mark is not a transition: {:?}", second.changed);
        assert_eq!(second.data.as_ref().unwrap()["undying"], true);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── nothing_to_restore_warning (task #100) ──────────────────────────

    /// The gate itself, table-driven: `has_capture` short-circuits
    /// regardless of agent, a registered harness profile's `resume_args`
    /// short-circuits regardless of capture, and only the neither case
    /// warns — the same two arms `resurrect.rs::resolve_candidate` tries.
    #[test]
    fn nothing_to_restore_warning_fires_only_when_neither_arm_resolves() {
        let cases: &[(&str, bool, bool)] = &[
            // (agent, has_capture, expect_warning)
            ("claude", false, false), // harness arm: registered resume_args.
            ("kimi", false, false),
            ("pi", false, false),
            ("shell", true, false), // terminal arm: capture ran.
            ("soak-a", true, false), // an overridden label with real capture.
            ("claude", true, false), // both arms present is still no warning.
            ("shell", false, true), // task #100's exact live shape: neither arm.
            ("soak-a", false, true),
            ("codex", false, true),
        ];
        for (agent, has_capture, expect_warning) in cases {
            let got = nothing_to_restore_warning(agent, *has_capture);
            assert_eq!(
                got.is_some(),
                *expect_warning,
                "nothing_to_restore_warning({agent:?}, {has_capture}) = {got:?}"
            );
        }
    }

    /// `session undying on --id <id>` surfaces the warning in the command's
    /// own Outcome message (not a log line) when the target session has
    /// neither capture nor a resumable harness profile — the P-C7 soak's
    /// exact live shape, reached through `--agent soak-a -- bash` and then
    /// marked undying.
    #[test]
    fn marking_a_captureless_non_harness_session_undying_warns_in_the_message() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-warn-neither-arm");
        let file = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![SessionRecord {
                agent: "soak-a".into(),
                restore: None,
                ..session("soak-sess", "/w", "working", "1", None)
            }],
        };
        write_stage(&sessions_path(), &file).unwrap();

        let out = undying_grant(&undying_invocation(&[], &[("id", "soak-sess")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert!(
            out.message.contains("warning:"),
            "a session with no capture and no resumable profile must warn: {}",
            out.message
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Silent otherwise: a session with real capture is never warned about,
    /// even under a caller-chosen agent label a profile lookup would miss.
    #[test]
    fn marking_a_captured_session_undying_is_silent() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-warn-captured");
        let file = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![SessionRecord {
                agent: "soak-a".into(),
                restore: Some(RestoreSnapshot {
                    cwd: Some("/w".into()),
                    idle: true,
                    argv: None,
                    typed: None,
                }),
                ..session("captured-sess", "/w", "working", "1", None)
            }],
        };
        write_stage(&sessions_path(), &file).unwrap();

        let out = undying_grant(&undying_invocation(&[], &[("id", "captured-sess")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert!(!out.message.contains("warning:"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Silent for a registered harness even with no capture — the harness
    /// arm (`agent_profile("claude").resume_args`) resolves instead.
    #[test]
    fn marking_a_harness_session_undying_is_silent_even_without_capture() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-warn-harness");
        let file = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![session("claude-sess", "/w", "working", "1", None)], // agent: "claude", restore: None.
        };
        write_stage(&sessions_path(), &file).unwrap();

        let out = undying_grant(&undying_invocation(&[], &[("id", "claude-sess")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert!(!out.message.contains("warning:"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Turning it OFF never warns, even for a session neither arm could
    /// ever resolve — the warning is only about a FUTURE resurrect, which
    /// `off` no longer promises at all.
    #[test]
    fn marking_undying_off_never_warns() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-warn-off");
        let file = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![SessionRecord {
                agent: "soak-a".into(),
                restore: None,
                ..session("soak-sess-off", "/w", "working", "1", None)
            }],
        };
        write_stage(&sessions_path(), &file).unwrap();

        let out = undying_grant(&undying_invocation(&[], &[("id", "soak-sess-off")]), "session.grant", "off");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert!(!out.message.contains("warning:"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A dead/unknown id (absent from the roster) has no live signal to
    /// warn from — silent, the same posture `live` already takes.
    #[test]
    fn marking_an_unrostered_id_undying_never_warns() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("undying-warn-unrostered");
        // sessions.json stays empty — the id below is never in it.

        let out = undying_grant(&undying_invocation(&[], &[("id", "long-dead-id")]), "session.grant", "on");
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert!(!out.message.contains("warning:"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }
}
