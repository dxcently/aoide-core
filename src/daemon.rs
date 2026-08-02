//! aoided — the orchestrator daemon skeleton (entities/aoided, concepts/Governance).
//!
//! Owns the single policy surface: the audit log, the user rebuild gate, and a
//! neutral event stream with a default-deny-per-class subscription model. Both
//! the CLI door and the MCP door route through here; neither writes a separate
//! log. Forwarded notification text is untrusted DATA and is never executed.
//!
//! Walking skeleton: the audit-log append and the gate are wired as real code
//! paths. The event bus + subscription model are real in-memory types with a
//! skeletal event loop.
//!
//! The audit-log contract (`Door`, `EventClass`, `AuditRecord`, `append_audit`,
//! `audit`, `default_audit_log`, `aoide_home`, `now_secs`) moved to
//! `aoide-protocol` (Phase 2 restructure, docs/architecture/PACKAGE-LAYOUT.md)
//! and is re-exported here so every existing `crate::daemon::*` caller is
//! untouched. `Gate`/`GateProposal`/`Subscription` (policy types) moved there
//! too (Phase 4a restructure) and are likewise re-exported. `run` (the daemon
//! skeleton's own wiring/demo) moved to `aoide-server` (Phase 4c restructure)
//! and is re-exported the same way — every existing `crate::daemon::*` caller
//! (incl. `bin/aoided.rs`, `commands/infra.rs`) is untouched.

pub use aoide_protocol::{
    append_audit, audit, aoide_home, default_audit_log, AuditRecord, Door, EventClass,
};
pub use aoide_protocol::{Gate, GateProposal, Subscription};
pub use aoide_server::daemon::run;
