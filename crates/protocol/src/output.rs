//! Structured output envelopes and exit codes.
//!
//! Every command returns an [`Outcome`]; the dispatcher renders it as either
//! JSON (`--json`) or a human line, and maps its status to a process exit code.
//! This is the "every command emits `--json`, structured errors, meaningful
//! exit codes, reports exactly what changed" contract (CONTRACTS.md §3).

use serde::Serialize;
use serde_json::Value;

/// Canonical exit codes (must match `schema.rs` `exit_codes`).
pub mod exit {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const NOT_IMPLEMENTED: i32 = 64;
}

/// Coarse status of a command, one-to-one with an exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Ok,
    Error,
    Usage,
    NotImplemented,
}

impl Status {
    pub fn exit_code(self) -> i32 {
        match self {
            Status::Ok => exit::OK,
            Status::Error => exit::ERROR,
            Status::Usage => exit::USAGE,
            Status::NotImplemented => exit::NOT_IMPLEMENTED,
        }
    }
}

/// The structured result of running one command.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub status: Status,
    /// The command path that produced this, e.g. `rice.adopt`.
    pub command: String,
    /// Human-readable summary line.
    pub message: String,
    /// Whether this operation would route through the user rebuild gate.
    pub gated: bool,
    /// Exactly what changed (empty when nothing changed — idempotency signal).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<String>,
    /// Free-form structured payload (schema output, audit records, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Outcome {
    pub fn new(command: impl Into<String>, status: Status, message: impl Into<String>) -> Self {
        Outcome {
            status,
            command: command.into(),
            message: message.into(),
            gated: false,
            changed: Vec::new(),
            data: None,
        }
    }

    pub fn ok(command: impl Into<String>, message: impl Into<String>) -> Self {
        Outcome::new(command, Status::Ok, message)
    }

    pub fn error(command: impl Into<String>, message: impl Into<String>) -> Self {
        Outcome::new(command, Status::Error, message)
    }

    pub fn usage(command: impl Into<String>, message: impl Into<String>) -> Self {
        Outcome::new(command, Status::Usage, message)
    }

    /// The structured "not-implemented" stub every mutating skeleton returns.
    pub fn not_implemented(command: impl Into<String>, gated: bool) -> Self {
        let cmd = command.into();
        Outcome {
            status: Status::NotImplemented,
            message: format!(
                "`aoide {}` is a walking-skeleton stub: arg-parsing and schema are real, \
                 the live-system action is not yet implemented.",
                cmd.replace('.', " ")
            ),
            gated,
            changed: Vec::new(),
            data: None,
            command: cmd,
        }
    }

    pub fn gated(mut self, gated: bool) -> Self {
        self.gated = gated;
        self
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn changed(mut self, items: impl IntoIterator<Item = String>) -> Self {
        self.changed = items.into_iter().collect();
        self
    }

    /// Render + exit-code, honouring `--json`.
    pub fn render(&self, json: bool) -> (String, i32) {
        let code = self.status.exit_code();
        if json {
            let body = serde_json::to_string_pretty(self)
                .unwrap_or_else(|e| format!("{{\"status\":\"error\",\"message\":\"{e}\"}}"));
            (body, code)
        } else {
            let mut line = format!("[{}] {}: {}", tag(self.status), self.command, self.message);
            if !self.changed.is_empty() {
                line.push_str(&format!("\n  changed: {}", self.changed.join(", ")));
            }
            if self.gated {
                line.push_str("\n  (gated: routes through the user rebuild gate)");
            }
            (line, code)
        }
    }
}

fn tag(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Error => "error",
        Status::Usage => "usage",
        Status::NotImplemented => "not-implemented",
    }
}
