//! The audit-log contract, re-exported from `aoide-protocol` — same seam
//! `aoide-cli`'s own `daemon.rs` uses (`Door`, `EventClass`, `AuditRecord`,
//! `append_audit`, `audit`, `default_audit_log`, `aoide_home`). Lyra has no
//! `daemon`/`aoided` verb of its own (that stays core identity, P-A4 plan)
//! so — unlike the core crate's `daemon.rs` — nothing here re-exports
//! `aoide_server::daemon::run`.

pub use aoide_protocol::{
    append_audit, audit, aoide_home, default_audit_log, AuditRecord, Door, EventClass,
};
