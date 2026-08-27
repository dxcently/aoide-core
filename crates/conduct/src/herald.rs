//! `aoide herald` — the notification ledger the Quickshell herald draws from.
//!
//! dunst owns `org.freedesktop.Notifications` and draws NOTHING (every rule in
//! `modules/dendrites/dunst.nix` sets `skip_display`). Each notification is
//! handed to `aoide herald push` through dunst's `script` hook, which reads the
//! `DUNST_*` environment and sends the record over the shellbridge socket. The
//! bridge daemon — the single writer, as it already is for `sessions.json` —
//! folds it into `state/stage/herald.json`, and the QML herald reads that file
//! and draws the real widget.
//!
//!   notification → dunst (daemon only) → `aoide herald push` → bridge socket
//!                → state/stage/herald.json → Quickshell
//!
//! ── Why the socket hop, and not a direct write ────────────────────────────
//! dunst runs its script asynchronously, so two notifications arriving together
//! are two `aoide herald push` processes. Both would read-modify-write the same
//! ledger, and the loser's entry would vanish — a silently dropped
//! notification, which is the one failure a notification system must not have.
//! The bridge's accept loop serialises them for free.
//!
//! ── What the environment does and does not carry (measured, 2026-08-17) ───
//! Proven against a live dunst 1.13.2 reloaded onto this exact rule shape:
//! the script fires under `skip_display`, `DUNST_PROGRESS` arrives as the
//! sender's value or `-1`, `DUNST_ICON_PATH` as a resolved path, and
//! `DUNST_CATEGORY` intact. Two sharp edges, both handled here rather than
//! papered over:
//!   - `DUNST_URGENCY` is UPPERCASE (`LOW`/`NORMAL`/`CRITICAL`). Lowered on the
//!     way in so the QML side matches one vocabulary.
//!   - `DUNST_TIMESTAMP` is a MONOTONIC number, not a wall clock — useless for
//!     "5 minutes ago". The ledger stamps its own `receivedAt` instead.
//! There is no `DUNST_ACTIONS`: a third-party sender's action labels never
//! reach us, so a plain toast carries no buttons. The case that matters is
//! unaffected — an aoide permission SUMMONS is published straight into this
//! ledger by `graph permit`, which knows its own verdicts.
//!
//! Sender text is DATA throughout: it is carried, never parsed, never
//! interpreted as markup or as a command, on either side of the seam.

use aoide_protocol::output::Outcome;
use aoide_protocol::Invocation;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Schema version of `herald.json` — bumped only on a breaking shape change.
pub const HERALD_SCHEMA: &str = "0";

/// How many notifications the ledger keeps. Matches the dunstrc's
/// `history_length`, so the dock ledger and `dunstctl history` agree on depth.
pub const LEDGER_CAP: usize = 20;

/// `progress` when the sender set no value — dunst's own sentinel, carried
/// through unchanged so the QML side has one number to test.
pub const NO_PROGRESS: i64 = -1;

/// One notification, as the QML herald reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    /// dunst's own notification id, or the summons' synthetic `permit-<id>`.
    pub id: String,
    /// The sending application (`DUNST_APP_NAME`), or the agent for a summons.
    pub app: String,
    pub summary: String,
    pub body: String,
    /// Absolute path to an image dunst already resolved, or empty.
    #[serde(default)]
    pub icon: String,
    /// `low` | `normal` | `critical` — lowercased on the way in.
    pub urgency: String,
    /// 0–100, or [`NO_PROGRESS`].
    pub progress: i64,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub stack_tag: String,
    /// Milliseconds; `0` means never expire. The QML herald owns the dismiss
    /// clock — a notification dunst never displays is never displayed, so dunst
    /// does not expire it either.
    pub timeout_ms: i64,
    /// Our own wall clock, because `DUNST_TIMESTAMP` is monotonic.
    pub received_at: String,
    /// `toast` | `summons`.
    pub kind: String,
    /// The waiting session, on a summons only.
    #[serde(default)]
    pub session_id: String,
}

/// `toast` — an ordinary notification. No buttons.
pub const KIND_TOAST: &str = "toast";
/// `summons` — an agent waiting on a permission verdict. Drawn with real
/// approve/deny buttons, answered through the bridge.
pub const KIND_SUMMONS: &str = "summons";

/// The ledger file: newest LAST, so the QML side reads it like a transcript.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeraldFile {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub notifications: Vec<Notification>,
}

/// `state/stage/herald.json` (command-defrag S1, 2026-08-27) -- core
/// conducting state, moved off `song/stage/` (lyra's tree).
pub fn herald_path() -> std::path::PathBuf {
    aoide_storage::fs::conducting_stage_dir().join("herald.json")
}

/// Fold one notification into the ledger. Pure, so the replace/append/cap rules
/// are tested without a daemon or a filesystem.
///
/// A non-empty `stackTag` REPLACES the entry holding the same tag rather than
/// piling a second one up — that is what makes a session's second permission
/// prompt supersede its first, and what keeps a volume OSD from filling the
/// ledger. Same for a repeated id (dunst reuses one on a `replaces_id` send).
/// Everything else appends, and the oldest fall off the front at [`LEDGER_CAP`].
pub fn apply_push(mut list: Vec<Notification>, incoming: Notification) -> Vec<Notification> {
    let existing = if !incoming.stack_tag.is_empty() {
        list.iter().position(|n| n.stack_tag == incoming.stack_tag)
    } else {
        list.iter().position(|n| n.id == incoming.id)
    };
    if let Some(i) = existing {
        list.remove(i);
    }
    list.push(incoming);
    if list.len() > LEDGER_CAP {
        let excess = list.len() - LEDGER_CAP;
        list.drain(..excess);
    }
    list
}

/// Drop one notification by id. Returns whether anything was removed, so the
/// bridge can tell a real dismissal from a double-click on a gone card.
pub fn apply_dismiss(list: &mut Vec<Notification>, id: &str) -> bool {
    let before = list.len();
    list.retain(|n| n.id != id);
    list.len() != before
}

/// Normalise dunst's SHOUTED urgency. Anything unrecognised reads as `normal`
/// — an unknown urgency should still show, not vanish or masquerade as an
/// alarm.
pub fn normalise_urgency(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => "low".to_string(),
        "critical" => "critical".to_string(),
        _ => "normal".to_string(),
    }
}

/// Parse a `DUNST_*` numeric field. Absent, empty and malformed all collapse to
/// `fallback`: a notification with a garbled progress value is still a
/// notification, and must never be dropped over it.
pub fn parse_num(raw: Option<&str>, fallback: i64) -> i64 {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(fallback)
}

/// Build the record from a `DUNST_*` environment reader. Takes the lookup as a
/// closure so the whole mapping is unit-tested without touching process env.
pub fn from_dunst_env<F>(get: F, received_at: String) -> Notification
where
    F: Fn(&str) -> Option<String>,
{
    let g = |k: &str| get(k).unwrap_or_default();
    let progress = parse_num(get("DUNST_PROGRESS").as_deref(), NO_PROGRESS);
    Notification {
        id: {
            let id = g("DUNST_ID");
            if id.trim().is_empty() {
                format!("herald-{received_at}")
            } else {
                id.trim().to_string()
            }
        },
        app: g("DUNST_APP_NAME"),
        summary: g("DUNST_SUMMARY"),
        body: g("DUNST_BODY"),
        icon: g("DUNST_ICON_PATH"),
        urgency: normalise_urgency(&g("DUNST_URGENCY")),
        // dunst sends -1 for "no value"; clamp anything else into 0..=100 so
        // the QML gauge never has to defend itself against a hostile sender.
        progress: if progress == NO_PROGRESS {
            NO_PROGRESS
        } else {
            progress.clamp(0, 100)
        },
        category: g("DUNST_CATEGORY"),
        stack_tag: g("DUNST_STACK_TAG"),
        timeout_ms: parse_num(get("DUNST_TIMEOUT").as_deref(), 0).max(0),
        received_at,
        kind: KIND_TOAST.to_string(),
        session_id: String::new(),
    }
}

/// `aoide herald push` — dunst's `script` hook. Reads the `DUNST_*`
/// environment, builds the record, and hands it to the bridge.
///
/// dunst appends its own five positional arguments (appname summary body icon
/// urgency) to every script it runs; they are ignored here in favour of the
/// environment, which carries strictly more (progress, category, stack tag,
/// timeout) and needs no positional parsing.
pub fn herald_push(_inv: &Invocation) -> Outcome {
    let cmd = "herald.push";
    let notif = from_dunst_env(
        |k| std::env::var(k).ok(),
        aoide_storage::time::now_iso_utc(),
    );
    // Nothing to show and nothing to file: a record with neither summary nor
    // body is not a notification, and forwarding it would only churn the ledger.
    if notif.summary.trim().is_empty() && notif.body.trim().is_empty() {
        return Outcome::ok(cmd, "empty notification ignored")
            .with_data(json!({ "pushed": false, "reason": "empty" }));
    }
    match publish(&notif) {
        Ok(()) => Outcome::ok(cmd, format!("pushed `{}`", notif.id)).with_data(json!({
            "pushed": true,
            "id": notif.id,
            "urgency": notif.urgency,
            "progress": notif.progress,
        })),
        Err(e) => Outcome::error(cmd, format!("could not reach the shellbridge: {e}"))
            .with_data(json!({ "pushed": false, "id": notif.id })),
    }
}

/// Send one record to the bridge for filing. The wire shape is the same
/// newline-delimited JSON the QML widgets already speak.
pub fn publish(notif: &Notification) -> std::io::Result<()> {
    let line = json!({ "cmd": "heraldpush", "notification": notif });
    crate::shellbridge::send_line(&line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notif(id: &str, tag: &str) -> Notification {
        Notification {
            id: id.to_string(),
            app: "probe".into(),
            summary: "s".into(),
            body: "b".into(),
            icon: String::new(),
            urgency: "normal".into(),
            progress: NO_PROGRESS,
            category: String::new(),
            stack_tag: tag.to_string(),
            timeout_ms: 0,
            received_at: "2026-08-17T00:00:00Z".into(),
            kind: KIND_TOAST.into(),
            session_id: String::new(),
        }
    }

    #[test]
    fn urgency_is_lowered_and_an_unknown_one_shows_as_normal() {
        // dunst SHOUTS these; the rest of the rig speaks lowercase.
        assert_eq!(normalise_urgency("LOW"), "low");
        assert_eq!(normalise_urgency("NORMAL"), "normal");
        assert_eq!(normalise_urgency("CRITICAL"), "critical");
        assert_eq!(normalise_urgency(" critical "), "critical");
        // Never silently an alarm, and never dropped.
        assert_eq!(normalise_urgency("emergency"), "normal");
        assert_eq!(normalise_urgency(""), "normal");
    }

    #[test]
    fn a_stack_tag_replaces_its_predecessor_instead_of_piling_up() {
        let mut list = vec![notif("1", "vol"), notif("2", "")];
        list = apply_push(list, notif("3", "vol"));
        assert_eq!(list.len(), 2, "the tagged entry was replaced, not appended");
        assert_eq!(list.last().unwrap().id, "3", "and the newcomer is newest");
        assert!(list.iter().all(|n| n.id != "1"));
    }

    #[test]
    fn an_untagged_repeat_of_the_same_id_replaces_too() {
        let list = apply_push(vec![notif("7", "")], notif("7", ""));
        assert_eq!(list.len(), 1);
        // …but two distinct untagged notifications both stand.
        let list = apply_push(list, notif("8", ""));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn the_ledger_is_capped_and_drops_the_oldest_first() {
        let mut list = Vec::new();
        for i in 0..(LEDGER_CAP + 5) {
            list = apply_push(list, notif(&i.to_string(), ""));
        }
        assert_eq!(list.len(), LEDGER_CAP);
        assert_eq!(list.first().unwrap().id, "5", "the oldest five fell off");
        assert_eq!(list.last().unwrap().id, (LEDGER_CAP + 4).to_string());
    }

    #[test]
    fn dismiss_removes_only_the_named_card() {
        let mut list = vec![notif("1", ""), notif("2", "")];
        assert!(apply_dismiss(&mut list, "1"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "2");
        // A second dismissal of a gone card is a no-op, not an error.
        assert!(!apply_dismiss(&mut list, "1"));
    }

    #[test]
    fn a_malformed_number_never_costs_the_notification() {
        assert_eq!(parse_num(Some("40"), NO_PROGRESS), 40);
        assert_eq!(parse_num(Some(" 40 "), NO_PROGRESS), 40);
        assert_eq!(parse_num(Some(""), NO_PROGRESS), NO_PROGRESS);
        assert_eq!(parse_num(None, NO_PROGRESS), NO_PROGRESS);
        assert_eq!(parse_num(Some("not a number"), NO_PROGRESS), NO_PROGRESS);
        assert_eq!(parse_num(Some("1e5"), 0), 0);
    }

    #[test]
    fn the_env_maps_to_a_record_the_way_a_live_daemon_sends_it() {
        // Exactly the shape a live dunst 1.13.2 fired at the probe script.
        let env = |k: &str| -> Option<String> {
            Some(
                match k {
                    "DUNST_ID" => "7",
                    "DUNST_APP_NAME" => "notify-send",
                    "DUNST_SUMMARY" => "probe two",
                    "DUNST_BODY" => "with progress",
                    "DUNST_URGENCY" => "CRITICAL",
                    "DUNST_PROGRESS" => "40",
                    "DUNST_TIMEOUT" => "0",
                    "DUNST_CATEGORY" => "",
                    _ => return None,
                }
                .to_string(),
            )
        };
        let n = from_dunst_env(env, "2026-08-17T12:00:00Z".into());
        assert_eq!(n.id, "7");
        assert_eq!(n.app, "notify-send");
        assert_eq!(n.urgency, "critical", "SHOUTED urgency is lowered");
        assert_eq!(n.progress, 40);
        assert_eq!(n.timeout_ms, 0, "critical never expires");
        assert_eq!(n.kind, KIND_TOAST);
        // Our own clock, never dunst's monotonic DUNST_TIMESTAMP.
        assert_eq!(n.received_at, "2026-08-17T12:00:00Z");
    }

    #[test]
    fn a_hostile_progress_value_cannot_overrun_the_gauge() {
        let with = |v: &str| {
            let v = v.to_string();
            from_dunst_env(
                move |k| match k {
                    "DUNST_SUMMARY" => Some("s".into()),
                    "DUNST_PROGRESS" => Some(v.clone()),
                    _ => None,
                },
                "t".into(),
            )
            .progress
        };
        assert_eq!(with("40"), 40);
        assert_eq!(with("999"), 100, "clamped, not trusted");
        assert_eq!(with("-5"), 0);
        // -1 is dunst's own "no value" sentinel and survives the clamp.
        assert_eq!(with("-1"), NO_PROGRESS);
    }

    #[test]
    fn a_notification_with_no_text_at_all_still_gets_an_id() {
        let n = from_dunst_env(|_| None, "2026-08-17T12:00:00Z".into());
        assert!(!n.id.is_empty(), "a missing DUNST_ID is synthesised, never blank");
        assert_eq!(n.urgency, "normal");
        assert_eq!(n.progress, NO_PROGRESS);
    }

    #[test]
    fn sender_text_is_carried_verbatim_and_never_interpreted() {
        // Markup, shell metacharacters and a leading dash all ride as DATA.
        let n = from_dunst_env(
            |k| match k {
                "DUNST_SUMMARY" => Some("<b>not markup</b>".into()),
                "DUNST_BODY" => Some("--force; rm -rf / `whoami`".into()),
                _ => None,
            },
            "t".into(),
        );
        assert_eq!(n.summary, "<b>not markup</b>");
        assert_eq!(n.body, "--force; rm -rf / `whoami`");
    }
}
