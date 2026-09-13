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

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_storage::node_store::Node;
    use aoide_storage::outbox::OutboxEntry;

    fn root(tag: &str) -> (aoide_test_support::EnvSaver, std::path::PathBuf) {
        aoide_test_support::isolated_mail_root(tag)
    }

    fn unpaired_node(name: &str) -> Node {
        Node {
            name: name.to_string(),
            url: "http://127.0.0.1:1".to_string(), // nothing listens here
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-09-07T00:00:00Z".to_string(),
        }
    }

    /// A minimal fake `aoide/mailDeposit` door — mirrors
    /// `aoide_client::mail_wire`'s own module-local copy (a tiny
    /// per-module fixture, not a reach across crates).
    fn fake_deposit_server(body: &'static str) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            loop {
                let Ok((mut stream, _)) = accepter.accept() else { break };
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (listener, port)
    }

    /// `drain_all` walks every node with a non-empty outbox independently
    /// (this module's own doc: one node's `Err` never stops the sweep) — a
    /// permanently dead LINK is a much narrower failure than an `Err`
    /// (`drain_node` never returns one for an unreachable node, see its own
    /// doc), so this pins the stronger, more common case directly: one
    /// dead node's entries staying stuck must never keep another node's
    /// perfectly healthy entries from draining in the SAME sweep.
    #[test]
    fn one_dead_nodes_entries_never_block_another_nodes_drain() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("drain-all-one-dead-node");

        let (listener, port) = fake_deposit_server(
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"accepted"}}"#,
        );
        let mut healthy = unpaired_node("healthy");
        healthy.url = format!("http://127.0.0.1:{port}/");
        aoide_storage::node_store::save_nodes(&[unpaired_node("dead"), healthy]).unwrap();

        let dead_env = aoide_storage::mail::mint_outbound_letter("alice", "dead", "bob", "hi").unwrap();
        aoide_storage::outbox::write_entry("dead", &OutboxEntry::fresh(dead_env)).unwrap();

        let to = aoide_storage::mail::Address { node: "origin-node".to_string(), name: "bob".to_string() };
        let healthy_env = aoide_storage::mail::mint_ack("alice", to, "acked-msgid").unwrap();
        aoide_storage::outbox::write_entry("healthy", &OutboxEntry::fresh(healthy_env)).unwrap();

        drain_all().unwrap();

        let dead_remaining = aoide_storage::outbox::list_entries("dead").unwrap();
        assert_eq!(dead_remaining.len(), 1, "the dead node's entry survives a transport failure");

        let healthy_remaining = aoide_storage::outbox::list_entries("healthy").unwrap();
        assert!(
            healthy_remaining.is_empty(),
            "the healthy node's receipt must still retire even though 'dead' drained first"
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
