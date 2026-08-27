//! `session carry on|off [--self | --id <id>]` — mark or unmark a
//! session DURABLE, so a project's whole carried set can later be
//! resurrected together (`resurrect`, a later phase of the
//! durable-sessions plan; `CONTRACTS.md`'s `state/carry.json` section).
//!
//! P-C2 of that plan: the command only, over the store `aoide_storage::carry`
//! already provides (P-C1, landed) — no reimplementation of the store's CRUD
//! here. This handler writes ONLY `state/carry.json`: unlike every other
//! `session *` handler in this module, it takes no stage lock and does
//! not route through `aoide_client::daemon::daemon_dispatch` — `carry.json`
//! is not a `state/stage/` file, so it sits entirely outside the L4
//! dual-writer surface (a second writer there would defeat the store's own
//! single-writer atomic-write discipline; see `carry.rs`'s own module doc in
//! `aoide-storage`).
//!
//! `--id` targets ANY session id, including one that has already left the
//! roster — no roster lookup gates the write. That is the whole point of the
//! design: a mark must be flippable post-mortem, off a bare ledger id, after
//! the session that owned it is gone.

use super::common::require_args;
use super::model::{load_stage, sessions_path, SessionsFile};
#[cfg(test)]
use super::model::write_stage;
use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use aoide_storage::carry::{load_carry, save_carry, set_carried};
use serde_json::json;

/// `aoide session carry (on|off) [--self | --id <id>] [--json]`.
///
/// Target resolution: `--id <id>` names any session id directly; otherwise
/// `--self` (or a bare invocation, the same default) reads
/// `$AOIDE_SESSION_ID` — the same env var `window.rs`'s
/// `resolve_registration_parent` already treats as "this session". `--self`
/// and `--id` together is a usage error; neither an `--id` nor a resolvable
/// `$AOIDE_SESSION_ID` is likewise a usage error naming both — never a
/// silent no-op.
pub fn session_carry(inv: &Invocation) -> Outcome {
    let cmd = "session.carry";
    let usage = "usage: aoide session carry (on|off) [--self | --id <id>] [--json]";

    let args = match require_args(inv, &["on|off"]) {
        Ok(a) => a,
        Err(o) => return o,
    };
    let on = match args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Outcome::usage(
                cmd,
                format!(
                    "`{other}` is not a carry state — the only two are `on` and `off`\n{usage}"
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
                        "no session to carry: pass --self (reads $AOIDE_SESSION_ID) or \
                         --id <id> — neither was given and $AOIDE_SESSION_ID is unset\n{usage}"
                    ),
                );
            }
        },
    };

    let mut carried = load_carry();
    let transitioned = set_carried(&mut carried, &id, on);
    if let Err(e) = save_carry(&carried) {
        return Outcome::error(cmd, format!("failed to write carry.json: {e}"));
    }

    // Presence in the roster is INFORMATIONAL only — never a gate on the
    // write above, which must succeed for a dead id exactly the same way it
    // does for a live one (the post-mortem case this command exists for).
    let live = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions.iter().any(|s| s.session_id == id))
        .unwrap_or(false);

    let verb = if on { "carried" } else { "not carried" };
    let mut out = Outcome::ok(cmd, format!("`{id}` is now {verb}"));
    if transitioned {
        out = out.changed(vec![format!("{id}: {verb}")]);
    }
    out.with_data(json!({ "sessionId": id, "carried": on, "live": live }))
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

    fn carry_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["graph".into(), "session".into(), "carry".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn on_then_off_round_trips_through_the_carry_store() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("carry-roundtrip");

        let on = session_carry(&carry_invocation(&["on"], &[("id", "sess-1")]));
        assert_eq!(on.status, Status::Ok, "msg: {}", on.message);
        assert_eq!(on.data.as_ref().unwrap()["carried"], true);
        assert_eq!(on.changed, vec!["sess-1: carried".to_string()]);
        assert!(aoide_storage::carry::is_carried(&aoide_storage::carry::load_carry(), "sess-1"));

        let off = session_carry(&carry_invocation(&["off"], &[("id", "sess-1")]));
        assert_eq!(off.status, Status::Ok, "msg: {}", off.message);
        assert_eq!(off.data.as_ref().unwrap()["carried"], false);
        assert_eq!(off.changed, vec!["sess-1: not carried".to_string()]);
        assert!(!aoide_storage::carry::is_carried(&aoide_storage::carry::load_carry(), "sess-1"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bare_invocation_defaults_to_the_ambient_session_id() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("carry-bare-env");
        std::env::set_var("AOIDE_SESSION_ID", "env-sess");

        let out = session_carry(&carry_invocation(&["on"], &[]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["sessionId"], "env-sess");
        assert!(aoide_storage::carry::is_carried(&aoide_storage::carry::load_carry(), "env-sess"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_self_flag_reads_the_same_ambient_session_id() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("carry-self-flag");
        std::env::set_var("AOIDE_SESSION_ID", "self-sess");

        let out = session_carry(&carry_invocation(&["on"], &[("self", "true")]));
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
        let root = setup("carry-post-mortem");
        // sessions.json stays empty for this test — the id below is never in it.

        let out = session_carry(&carry_invocation(&["on"], &[("id", "long-dead-id")]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["carried"], true);
        assert_eq!(data["live"], false, "the id must never be required to be in the roster");
        assert!(aoide_storage::carry::is_carried(&aoide_storage::carry::load_carry(), "long-dead-id"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn live_reports_true_for_an_id_still_in_the_roster() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("carry-live-true");
        let file = SessionsFile {
            schema_version: "0".into(),
            sessions: vec![session("live-id", "/w", "working", "1", None)],
        };
        write_stage(&sessions_path(), &file).unwrap();

        let out = session_carry(&carry_invocation(&["on"], &[("id", "live-id")]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["live"], true);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_id_and_no_env_is_a_usage_error_naming_both() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("carry-no-target");
        std::env::remove_var("AOIDE_SESSION_ID");

        let out = session_carry(&carry_invocation(&["on"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("--self"), "msg: {}", out.message);
        assert!(out.message.contains("--id"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn self_and_id_together_is_a_usage_error() {
        let out = session_carry(&carry_invocation(&["on"], &[("self", "true"), ("id", "sess-1")]));
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("mutually exclusive"), "msg: {}", out.message);
    }

    #[test]
    fn an_unknown_positional_word_is_a_usage_error_naming_both_states() {
        let out = session_carry(&carry_invocation(&["maybe"], &[("id", "sess-1")]));
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("on"), "msg: {}", out.message);
        assert!(out.message.contains("off"), "msg: {}", out.message);
    }

    #[test]
    fn missing_positional_is_a_usage_error() {
        let out = session_carry(&carry_invocation(&[], &[("id", "sess-1")]));
        assert_eq!(out.status, Status::Usage);
    }

    /// A re-mark (already-on, marked on again) is not a TRANSITION —
    /// `changed` stays empty, matching `set_carried`'s own idempotency
    /// contract (`aoide_storage::carry`).
    #[test]
    fn a_remark_is_ok_but_reports_no_transition() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("carry-remark");

        let first = session_carry(&carry_invocation(&["on"], &[("id", "sess-1")]));
        assert_eq!(first.status, Status::Ok);
        assert!(!first.changed.is_empty());

        let second = session_carry(&carry_invocation(&["on"], &[("id", "sess-1")]));
        assert_eq!(second.status, Status::Ok);
        assert!(second.changed.is_empty(), "a re-mark is not a transition: {:?}", second.changed);
        assert_eq!(second.data.as_ref().unwrap()["carried"], true);

        let _ = std::fs::remove_dir_all(&root);
    }
}
