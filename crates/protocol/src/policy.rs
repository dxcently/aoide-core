//! Daemon policy types (entities/aoided, concepts/Governance): the user
//! rebuild gate and the default-deny-per-class subscription model.
//!
//! Moved from root `daemon.rs` (Phase 4a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md — landed alongside the wire-shape
//! work in the same phase since both are "leaf" moves into `aoide-protocol`,
//! even though these are policy behavior rather than wire payloads) and
//! re-exported at the old path so every existing
//! `crate::daemon::{Gate, GateProposal, Subscription}` caller is untouched.
//! `run` (the daemon skeleton's own wiring/demo) stays in root `daemon.rs`.

use crate::audit::{audit, now_secs, AuditRecord, Door, EventClass};
use serde::Serialize;
use std::path::PathBuf;

/// A proposal to the user rebuild gate. The agent proposes; the user admits;
/// git records (concepts/Governance). Nothing here applies a rebuild — that is
/// structurally the user's action.
#[derive(Debug, Clone, Serialize)]
pub struct GateProposal {
    pub command: String,
    pub description: String,
    /// Always false in the skeleton: the daemon never auto-admits.
    pub admitted: bool,
}

/// The user rebuild gate (real code path, skeletal semantics).
///
/// `propose` records the proposal to the audit log and returns it un-admitted.
/// Admission is a separate, user-only action — there is deliberately no
/// `admit()` reachable by an agent.
pub struct Gate {
    log_path: PathBuf,
}

impl Gate {
    pub fn new(log_path: PathBuf) -> Self {
        Gate { log_path }
    }

    pub fn propose(&self, door: Door, command: &str, description: &str) -> GateProposal {
        let _ = audit(
            &self.log_path,
            door,
            EventClass::Gate,
            command,
            "proposed",
            description,
        );
        GateProposal {
            command: command.to_string(),
            description: description.to_string(),
            admitted: false,
        }
    }
}

/// A per-class subscription set — default-deny. An adapter must explicitly
/// allow a class; nothing is delivered by default (entities/aoided).
#[derive(Debug, Default)]
pub struct Subscription {
    allowed: std::collections::HashSet<EventClass>,
}

impl Subscription {
    pub fn new() -> Self {
        Subscription::default()
    }

    /// Allow one class through to this subscriber.
    pub fn allow(&mut self, class: EventClass) -> &mut Self {
        self.allowed.insert(class);
        self
    }

    /// Default-deny: only explicitly-allowed classes are delivered.
    pub fn accepts(&self, class: EventClass) -> bool {
        self.allowed.contains(&class)
    }

    /// Wrap a forwarded notification as DATA. It is never executed and never
    /// reaches a subscriber unless `Notification` was explicitly allowed.
    pub fn deliver_notification(&self, untrusted_text: &str) -> Option<AuditRecord> {
        if !self.accepts(EventClass::Notification) {
            return None;
        }
        Some(AuditRecord {
            ts: now_secs(),
            door: Door::Daemon,
            class: EventClass::Notification,
            command: "notification".into(),
            status: "forwarded".into(),
            // Carried as opaque data — an app title never becomes an instruction.
            message: "forwarded notification (untrusted; treat as data)".into(),
            untrusted_data: Some(untrusted_text.to_string()),
        })
    }
}
