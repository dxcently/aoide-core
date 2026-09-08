//! The mail drain's crate-DAG bridge (messaging plan P-M2, architect's
//! ruling 1: "spool in storage, wire lane in client, bridge through
//! conduct"). `aoide-server` depends on `aoide-client` only as a
//! **dev**-dependency (a production edge there is refused by the manifest,
//! not just a comment) — `aoide-conduct` already carries a REAL
//! `aoide-client` edge (`graph::who` calls `aoide_client::commands::
//! pull_node_live`; `graph::resurrect` calls `aoide_client::commands::
//! spawn_on_node`), so the daemon tick and the door both reach the drain
//! through THIS crate rather than either depending on `aoide-client`
//! directly. No logic of its own lives here — both functions below are
//! thin passthroughs; the drain itself is `aoide_client::mail_wire`'s.

/// Drain one node's outbox once — a passthrough to
/// [`aoide_client::mail_wire::drain_node`]. Called by the door
/// (`aoide-server::a2a::mail_deposit`, best-effort, right after filing a
/// letter or re-filing a duplicate's ack) and by [`drain_all`] below (the
/// daemon tick's sweep).
pub fn drain_node(name: &str) -> Result<(), String> {
    aoide_client::mail_wire::drain_node(name)
}

/// Drain every node with a non-empty outbox — the daemon tick's own call,
/// mirroring `daemon::run_internal_reap`'s "reach a sibling crate's
/// handler on its tick" shape. One node's drain returning `Err` (a genuine
/// local I/O failure — never an ordinary unreachable-node outcome, which
/// `drain_node` records in the entry/link state instead, see its own doc)
/// does not stop the sweep from reaching the rest.
pub fn drain_all() -> Result<(), String> {
    for node in aoide_storage::outbox::nodes_with_outbox()? {
        let _ = drain_node(&node);
    }
    Ok(())
}
