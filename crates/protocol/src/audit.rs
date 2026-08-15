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
/// from `$AOIDE_USER`/`$HOME` as `/home/<user>/Aoide/log`.
pub fn default_audit_log() -> PathBuf {
    if let Ok(explicit) = std::env::var("AOIDE_AUDIT_LOG") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    // `aoide.auditLog` defaults to `/home/<user>/Aoide/log`.
    if let Ok(user) = std::env::var("AOIDE_USER") {
        if !user.is_empty() {
            return Path::new("/home").join(&user).join("Aoide").join("log");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/khoa".into());
    Path::new(&home).join("Aoide").join("log")
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

/// Append one JSON-lines record to the single audit log (real code path).
/// Creates the parent directory and the file if absent; idempotent per-call.
pub fn append_audit(log_path: &Path, record: &AuditRecord) -> std::io::Result<()> {
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
