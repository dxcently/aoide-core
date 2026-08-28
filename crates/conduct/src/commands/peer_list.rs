//! `peer list` — thin registration over `crate::graph::peer_list` (task
//! #120 P2, the one-glance mesh roster). Handler body lives in
//! `graph/peer_list.rs`; this module only wires schema metadata to the
//! already-public `crate::graph::peer_list` function — the same discipline
//! `commands/graph.rs` follows for bare `session`, whose probe core (`who.rs`,
//! now the shared roster core — the standalone `who` command it once backed
//! is retired) this roster reuses.
//!
//! Registered in THIS crate (not `aoide-client` beside the rest of the
//! `peer` family) because the roster is a presence projection over
//! `who.rs`'s own core, and `aoide-client` cannot depend on `aoide-conduct`
//! (the edge runs the other way). Moved-in position: registered LAST in
//! `cli`'s `commands::all()` (the append-only precedent) — a new command
//! never reorders an existing `register()` call, only appends after it.

use aoide_protocol::registry::{cmd, Registry};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "list"],
        summary: "One-glance mesh roster: this host, every registered peer (live-probed presence + running sessions, cache fallback), and every advertising instance heard in one bounded discovery sweep (--json emits the structured roster; peer status keeps the deep per-peer registry detail).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::peer_list,
        examples: [
            "peer list",
            "peer list --json",
        ],
    ));
}
