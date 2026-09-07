//! The single-policy-surface contract: the audit log record shape and its
//! append primitive, and which door an operation came through.
//!
//! Both the CLI door and the MCP door route through here; neither writes a
//! separate log (entities/aoided, concepts/Governance).

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default audit-log path (mirrors `aoide.auditLog`, BUILD.md option table).
///
/// Resolution order: `$AOIDE_AUDIT_LOG` (set by the systemd unit) → derived
/// as `$AOIDE_ROOT/log` (L-C2, task #107; `$AOIDE_ROOT` default
/// `<home>/.aoide` — see `aoide_storage::fs::root`'s own doc for the full
/// path-model note). Duplicated rather than shared with that function
/// deliberately: this crate sits BELOW `aoide-storage` in the dependency
/// graph, so it cannot call it without a cycle; [`aoide_home`] is the one
/// piece already common to both.
pub fn default_audit_log() -> PathBuf {
    if let Ok(explicit) = std::env::var("AOIDE_AUDIT_LOG") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if let Ok(dir) = std::env::var("AOIDE_ROOT") {
        if !dir.is_empty() {
            let p = PathBuf::from(&dir);
            if p.is_absolute() {
                return p.join("log");
            }
        }
    }
    aoide_home().join(".aoide").join("log")
}

/// The audit-log path in effect for one invocation (flag override →
/// `aoide.auditLog` default). Moved from the root package's `dispatch.rs`
/// (Phase 9 restructure, docs/architecture/PACKAGE-LAYOUT.md) — both inputs
/// (`Invocation.flags`, `default_audit_log`) are protocol types, so the
/// policy lives here and every crate's handlers consult it directly.
pub fn audit_log_path(inv: &crate::invocation::Invocation) -> PathBuf {
    if let Some(p) = inv.flags.get("audit-log") {
        return PathBuf::from(p);
    }
    default_audit_log()
}

/// The Aoide user's home (`$AOIDE_USER` → `/home/<user>`, else `$HOME`).
pub fn aoide_home() -> PathBuf {
    if let Ok(user) = std::env::var("AOIDE_USER") {
        if !user.is_empty() {
            return Path::new("/home").join(&user);
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/khoa".into()))
}

/// Which door an operation came through — both share one gate and one log.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Door {
    Cli,
    Mcp,
    Daemon,
    /// The A2A (Agent2Agent) HTTP door (CONTRACTS.md §6) — `aoide a2a serve`.
    /// Every handled HTTP request is audited through this door, same as the
    /// other two.
    A2a,
}

/// Event classes for the neutral event stream. Subscriptions are default-deny
/// per class, so OSD noise never burns an agent run and forwarded notification
/// text never reaches an agent as a command (entities/aoided).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EventClass {
    /// Audit records (every operation).
    Audit,
    /// User-gate proposals awaiting admission.
    Gate,
    /// Rice-loop lifecycle (gen/stage/declare).
    Rice,
    /// Content-pipeline lifecycle.
    Content,
    /// Forwarded OS notifications — UNTRUSTED payload, wrapped as data.
    Notification,
    /// Secrets-broker resolve-attempt mirror (Workstream SECRETS, P-V2,
    /// `aoide-secrets`'s `broker` module): secret name, consumer,
    /// granted/denied, argv0 if the client sent one — NEVER a value.
    /// `untrusted_data` is FORBIDDEN on this class: a Secret event has no
    /// forwarded payload to carry (unlike `Notification`), and the value
    /// itself never reaches the audit path at all, by construction. See
    /// [`append_audit`] — the ban is enforced there, not only by this
    /// comment.
    Secret,
}

/// A single record in the neutral event stream / audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: u64,
    pub door: Door,
    pub class: EventClass,
    pub command: String,
    pub status: String,
    pub message: String,
    /// Untrusted forwarded payload, always carried as opaque data, never code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted_data: Option<String>,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The audit log records that an operation happened, not what it printed.
/// A command's `Outcome` message is both its human output and (via
/// `dispatch.rs`'s generic per-dispatch audit call) its audit payload, so a
/// command that renders content as its message — `aoide mail show`'s whole
/// letter, `mail read`'s every printed entry — would otherwise leave an
/// unbounded second copy sitting in `~/.aoide/log`, one the mailbase's own
/// `mail rm --older-than` can never reach. [`append_audit`] clamps to this
/// bound instead of trusting every future message-bearing command to stay
/// short on its own.
const STORED_MESSAGE_MAX_BYTES: usize = 512;

/// Appended once a stored message is cut short — never counted against
/// [`STORED_MESSAGE_MAX_BYTES`] itself, so a maximally clamped message is
/// that many content bytes plus this marker, not fewer.
const STORED_MESSAGE_TRUNCATION_MARKER: &str = " … (truncated)";

/// `Some(clamped)` when `msg` is over [`STORED_MESSAGE_MAX_BYTES`]; `None`
/// when it already fits and nothing about it changes. Cuts on the last
/// UTF-8 character boundary at or before the bound — never mid-codepoint —
/// so the result is always valid `str` before the marker is appended.
fn clamp_stored_message(msg: &str) -> Option<String> {
    if msg.len() <= STORED_MESSAGE_MAX_BYTES {
        return None;
    }
    let mut cut = STORED_MESSAGE_MAX_BYTES;
    while cut > 0 && !msg.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut clamped = msg[..cut].to_string();
    clamped.push_str(STORED_MESSAGE_TRUNCATION_MARKER);
    Some(clamped)
}

/// Append one JSON-lines record to the single audit log (real code path).
/// Creates the parent directory and the file if absent; idempotent per-call.
///
/// **`EventClass::Secret` may never carry `untrusted_data`** (Workstream
/// SECRETS's audit design, `aoide-secrets`'s `broker` module doc): a Secret
/// event mirrors a name-only resolve attempt (secret name, consumer,
/// granted/denied) — never a value, and `untrusted_data` is exactly the
/// field every other class uses to carry arbitrary forwarded text
/// verbatim (`Notification`'s whole reason for existing). Enforced HERE,
/// not only by convention at each call site: a `Secret`-classed record
/// that somehow arrives with `untrusted_data: Some(_)` has it forced back
/// to `None` before the write (with an `eprintln!` naming the mistake) —
/// never a panic. An audit call already runs behind `let _ = audit(...)`
/// at every call site in this workspace (a logging failure must never take
/// the caller down with it); this guard keeps that posture rather than
/// trading a data-shape mistake for a crashed process.
///
/// **`message` is clamped to [`STORED_MESSAGE_MAX_BYTES`]** the same way,
/// and for the same reason: the bound belongs here, once, so every door and
/// every future caller inherits it rather than each remembering to clamp
/// its own outcome message before logging it. Only the STORED copy is
/// bounded — the caller's own `Outcome` is never touched, so human and
/// JSON output keep printing in full.
pub fn append_audit(log_path: &Path, record: &AuditRecord) -> std::io::Result<()> {
    let strip_secret = record.class == EventClass::Secret && record.untrusted_data.is_some();
    let clamped_message = clamp_stored_message(&record.message);

    let owned;
    let record: &AuditRecord = if strip_secret || clamped_message.is_some() {
        if strip_secret {
            eprintln!(
                "[aoide/protocol] BUG: an EventClass::Secret audit record carried untrusted_data — stripping it before writing (command: {})",
                record.command
            );
        }
        owned = AuditRecord {
            message: clamped_message.unwrap_or_else(|| record.message.clone()),
            untrusted_data: if strip_secret { None } else { record.untrusted_data.clone() },
            ..record.clone()
        };
        &owned
    } else {
        record
    };

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(record)
        .unwrap_or_else(|e| format!("{{\"ts\":{},\"error\":\"{e}\"}}", record.ts));
    line.push('\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    f.write_all(line.as_bytes())
}

/// Convenience: log an operation to the single audit log.
pub fn audit(
    log_path: &Path,
    door: Door,
    class: EventClass,
    command: &str,
    status: &str,
    message: &str,
) -> std::io::Result<()> {
    append_audit(
        log_path,
        &AuditRecord {
            ts: now_secs(),
            door,
            class,
            command: command.to_string(),
            status: status.to_string(),
            message: message.to_string(),
            untrusted_data: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_log(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-protocol-audit-test-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        ));
        dir.join("log")
    }

    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The normal `audit()` convenience path already never sets
    /// `untrusted_data`, so a `Secret` record built through it round-trips
    /// with no `untrusted_data` key at all.
    #[test]
    fn secret_class_via_the_audit_convenience_fn_carries_no_untrusted_data() {
        let log = tmp_log("via-audit-fn");
        audit(&log, Door::Daemon, EventClass::Secret, "secrets.resolve", "granted", "secret `t` for consumer `m`: granted").unwrap();
        let lines = read_lines(&log);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].get("untrusted_data").is_none(), "{:?}", lines[0]);
        std::fs::remove_dir_all(log.parent().unwrap()).ok();
    }

    /// A `Secret` record hand-built with `untrusted_data: Some(_)` (the
    /// misuse `append_audit`'s doc comment guards against) is written with
    /// that field stripped — the invariant holds even if a future call
    /// site gets it wrong, not only by every call site behaving.
    #[test]
    fn secret_class_with_untrusted_data_set_is_stripped_before_writing() {
        let log = tmp_log("strip");
        let record = AuditRecord {
            ts: now_secs(),
            door: Door::Daemon,
            class: EventClass::Secret,
            command: "secrets.resolve".to_string(),
            status: "granted".to_string(),
            message: "secret `t` for consumer `m`: granted".to_string(),
            untrusted_data: Some("this must never be written".to_string()),
        };
        append_audit(&log, &record).unwrap();
        let lines = read_lines(&log);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].get("untrusted_data").is_none(), "{:?}", lines[0]);
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(!raw.contains("this must never be written"));
        std::fs::remove_dir_all(log.parent().unwrap()).ok();
    }

    /// Every OTHER class is untouched: `untrusted_data` still rides through
    /// verbatim for e.g. `Notification`, so the guard is scoped to `Secret`
    /// alone, not a blanket "always drop untrusted_data" regression.
    #[test]
    fn non_secret_classes_keep_their_untrusted_data() {
        let log = tmp_log("keep");
        let record = AuditRecord {
            ts: now_secs(),
            door: Door::Daemon,
            class: EventClass::Notification,
            command: "notification".to_string(),
            status: "forwarded".to_string(),
            message: "forwarded notification (untrusted; treat as data)".to_string(),
            untrusted_data: Some("some app title".to_string()),
        };
        append_audit(&log, &record).unwrap();
        let lines = read_lines(&log);
        assert_eq!(lines[0]["untrusted_data"], "some app title");
        std::fs::remove_dir_all(log.parent().unwrap()).ok();
    }

    fn record_with_message(message: String) -> AuditRecord {
        AuditRecord {
            ts: now_secs(),
            door: Door::Cli,
            class: EventClass::Audit,
            command: "mail.show".to_string(),
            status: "ok".to_string(),
            message,
            untrusted_data: None,
        }
    }

    /// A message at or under the bound is stored byte-for-byte — no marker,
    /// no truncation, the common case for nearly every command.
    #[test]
    fn a_message_within_the_bound_is_stored_verbatim_with_no_marker() {
        let log = tmp_log("short");
        let record = record_with_message("mark: cursor marked through seq 3".to_string());
        append_audit(&log, &record).unwrap();
        let lines = read_lines(&log);
        assert_eq!(lines[0]["message"], "mark: cursor marked through seq 3");
        std::fs::remove_dir_all(log.parent().unwrap()).ok();
    }

    /// A message over the bound is cut to exactly `STORED_MESSAGE_MAX_BYTES`
    /// content bytes and carries the marker — this is the leak `mail show`
    /// exposed: an outcome message that IS the rendered letter now leaves
    /// only a bounded trace in the log, never the whole text.
    #[test]
    fn a_message_over_the_bound_is_clamped_and_carries_the_truncation_marker() {
        let log = tmp_log("long");
        let record = record_with_message("a".repeat(600));
        append_audit(&log, &record).unwrap();
        let lines = read_lines(&log);
        let stored = lines[0]["message"].as_str().unwrap().to_string();
        assert_eq!(stored.len(), STORED_MESSAGE_MAX_BYTES + STORED_MESSAGE_TRUNCATION_MARKER.len());
        assert!(stored.starts_with(&"a".repeat(STORED_MESSAGE_MAX_BYTES)));
        assert!(stored.ends_with(STORED_MESSAGE_TRUNCATION_MARKER));
        std::fs::remove_dir_all(log.parent().unwrap()).ok();
    }

    /// A message whose byte 512 falls inside a multi-byte character clamps
    /// on the boundary BELOW it, never mid-codepoint, and the record still
    /// round-trips as valid JSON — the whole point of cutting on a boundary
    /// rather than a raw byte offset.
    #[test]
    fn clamping_a_split_codepoint_lands_on_the_boundary_below_it_and_still_parses() {
        let log = tmp_log("boundary");
        let mut message = "a".repeat(511);
        message.push('€'); // 3-byte UTF-8 char starting at byte 511: occupies 511..514
        message.push_str(&"b".repeat(100));
        assert!(!message.is_char_boundary(STORED_MESSAGE_MAX_BYTES), "the fixture must actually straddle byte 512");
        let record = record_with_message(message);
        append_audit(&log, &record).unwrap();

        let raw = std::fs::read_to_string(&log).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(raw.lines().next().unwrap()).expect("clamped record still parses as JSON");
        let stored = parsed["message"].as_str().unwrap();
        assert_eq!(stored, format!("{}{}", "a".repeat(511), STORED_MESSAGE_TRUNCATION_MARKER));
        std::fs::remove_dir_all(log.parent().unwrap()).ok();
    }
}
