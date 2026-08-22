//! `who` — thin registration over `crate::graph::who` (messaging/presence
//! plan, P-C2). Handler body lives in `graph/who.rs`; this module only
//! wires schema metadata to the already-public `crate::graph::who` function
//! — nothing here duplicates presence-projection logic, same discipline
//! `commands/graph.rs` follows for the rest of the `graph` domain.
//!
//! Moved-in position: registered LAST in `cli`'s `commands::all()` (the
//! plan's B3/append-only precedent) — a new verb never reorders an
//! existing `register()` call, only appends after it.

use aoide_protocol::registry::{arg, cmd, flag, Registry};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["who"],
        summary: "Live presence: this box's own sessions plus every registered peer, probed in parallel on every call (Unicode roster; --json emits the structured presence document).",
        args: [arg!("filter", "string", false, "Narrow what's displayed (never what's probed): a local session id/tail4/petname, a host/role/petname line, peer/<rest>, or a plain substring against a node/session name.")],
        flags: [flag!("all", "bool", "Also list `done` sessions (omitted by default).")],
        gated: false,
        implemented: true,
        handler: crate::graph::who,
        examples: [
            "who",
            "who --all",
            "who yomi-strix",
        ],
    ));
}
