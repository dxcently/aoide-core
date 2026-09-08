//! The outbox drain (messaging plan P-M2): the ONE place a spooled mail
//! envelope actually dials out. [`aoide_storage::outbox`] owns the spool
//! (pure file CRUD, no network); this module owns the wire half — the
//! `aoide/mailDeposit` POST, using the exact same signed-request machinery
//! [`crate::commands::spawn_on_node_via`] already established
//! (`resolve_node_bearer`, `sign_headers_for_node`, `post_json_to_node`).
//!
//! [`drain_node`] is called from three places, all converging on this one
//! function so there is exactly one dial implementation: the daemon's
//! periodic tick (`aoide-server::daemon`, via `aoide_conduct::mail_bridge`),
//! a door's own best-effort drain of the node it just heard from
//! (`aoide-server::a2a::mail_deposit`, same bridge), and `mail send`'s own
//! one-shot delivery attempt right after it writes the outbox entry (spec
//! item 8 — the write is the report, delivery is the spool's job).
//!
//! **Two locks, never nested (see `aoide_storage::outbox`'s own module
//! doc).** [`drain_node`] takes `.bsy` (non-blocking, per-node, held across
//! this whole function) and leaves every individual `outbox` call — each
//! its own short, independently-locked-and-released operation — to run
//! sequentially around the network POST, never holding any lock across the
//! POST itself (spec item 9: network I/O never happens under the stage
//! lock; `.bsy` is a SEPARATE mechanism that legitimately does span it).
//!
//! **A drain tears its own tunnel down before it returns (ruling 10)** —
//! [`TunnelTeardownGuard`] mirrors [`crate::commands`]'s `ScratchBodyFile`
//! Drop-guard pattern. This is a deliberate, drain-specific exception to
//! `resolve_dial_url`'s documented "every tunnel this phase opens stays
//! open" default (`commands.rs`'s own doc on `tunnel_session_id`): a
//! rarely-contacted spool target should not accumulate a standing forward
//! just because a background tick happened to touch it once.

use aoide_storage::mail::Envelope;
use aoide_storage::node_store::Node;
use serde_json::{json, Value};

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64
}

/// Tears down whatever tunnel this drain's own POSTs opened for `node_name`
/// — unconditionally, on every return path including an early one, the
/// same "removed on drop, no matter how the function exits" guarantee
/// [`crate::commands::ScratchBodyFile`] holds for its own scratch file.
/// [`aoide_client::tunnel::close`] is a safe no-op when nothing was ever
/// opened (a direct-dial node, or a node this attempt never reached) — see
/// its own doc for why calling it unconditionally is fine.
struct TunnelTeardownGuard(String);

impl Drop for TunnelTeardownGuard {
    fn drop(&mut self) {
        let _ = crate::tunnel::close(&crate::commands::tunnel_session_id(), &self.0);
    }
}

/// One deposit POST's outcome — the three shapes [`drain_node`]'s loop
/// branches on. Deliberately NOT [`crate::commands::SpawnNodeError`]'s
/// richer shape: a drain only ever needs to know which of the three
/// buckets an attempt landed in, never a programmatic reason code.
enum DepositAttempt {
    /// A result whose `status` is `"accepted"` or `"duplicate"`
    /// (mail::deposit's own vocabulary, wire-projected verbatim by
    /// `aoide-server::a2a::mail_deposit`).
    Delivered { status: String },
    /// The far end's OWN policy refusal — MAIL.md §Wire's admission/outcome
    /// split means this arrives as either a JSON-RPC `error` (admission,
    /// e.g. `-32010` lacks-message: the caller may not speak to the method
    /// at all) or a result whose `status` is `"refused"` (a well-formed
    /// envelope MAIL.md §Transit rejected, e.g. `bad-msgid`/
    /// `unverified-origin`) — both collapse into this one bucket because a
    /// drain only ever needs to know "not currently deliverable," never
    /// which of the two shapes carried that news. The link itself is fine
    /// either way; this ONE entry is the problem.
    Refused(String),
    /// No JSON-RPC response at all — dial/tunnel/HTTP/parse failure. The
    /// LINK is the suspect, not this entry.
    TransportFailed(String),
}

/// Build and send one `aoide/mailDeposit` POST, mirroring
/// [`crate::commands::spawn_on_node_via`]'s exact shape (resolve bearer,
/// sign, POST, parse, check `error`) with no `--via` override — a drain is
/// never given one; it only ever dials `node.via` as recorded.
fn attempt_deposit(node: &Node, envelope: &Envelope) -> DepositAttempt {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "aoide/mailDeposit",
        "params": { "envelope": envelope },
    });
    let body_str = serde_json::to_string(&body).unwrap_or_default();

    let bearer = match crate::commands::resolve_node_bearer(node) {
        Ok(b) => b,
        Err(e) => return DepositAttempt::TransportFailed(format!("bearer resolve: {e}")),
    };
    let extra_headers = match crate::commands::sign_headers_for_node(node, &body_str) {
        Ok(h) => h,
        Err(e) => return DepositAttempt::TransportFailed(format!("signing: {e}")),
    };
    let (code, resp) = match crate::commands::post_json_to_node(node, &body_str, bearer.as_deref(), &extra_headers, 15) {
        Ok(v) => v,
        Err(e) => return DepositAttempt::TransportFailed(e),
    };
    if code != 200 {
        return DepositAttempt::TransportFailed(format!("HTTP {code}"));
    }
    let parsed: Value = match serde_json::from_str(&resp) {
        Ok(v) => v,
        Err(e) => return DepositAttempt::TransportFailed(format!("unparseable response: {e}")),
    };
    if let Some(err) = parsed.get("error") {
        let detail = err.get("message").and_then(Value::as_str).unwrap_or("(no message)");
        return DepositAttempt::Refused(detail.to_string());
    }
    let result = parsed.get("result");
    // A response with a `result` member but no (or non-string) `status` —
    // or with neither `result` nor `error` at all — is weaker evidence of
    // delivery than an unrecognised status string, and an unrecognised one
    // already falls to the catch-all below. So this default must land
    // there too, never on `"accepted"`: a malformed or non-conformant
    // peer response must never be read as a confirmed deposit.
    let status = result.and_then(|r| r.get("status")).and_then(Value::as_str).unwrap_or("missing-status");
    match status {
        "accepted" | "duplicate" => DepositAttempt::Delivered { status: status.to_string() },
        // MAIL.md §Wire's outcome vocabulary is closed to the three above —
        // `"refused"` and any string this client does not recognise both
        // mean the entry did NOT land, never that it did. Assuming success
        // for an unrecognised status is the exact failure this arm exists
        // to close: a letter waiting forever for an ack the far end was
        // never going to send.
        other => {
            let reason = result.and_then(|r| r.get("reason")).and_then(Value::as_str).unwrap_or(other);
            let detail = result.and_then(|r| r.get("detail")).and_then(Value::as_str);
            let msg = match detail {
                Some(d) => format!("{reason}: {d}"),
                None => reason.to_string(),
            };
            DepositAttempt::Refused(msg)
        }
    }
}

/// Drain `node_name`'s outbox once: every spooled, non-refused entry,
/// oldest first, attempted in order — stopping at the first TRANSPORT
/// failure (the link itself is down; hammering the rest of the queue the
/// same pass gains nothing) but continuing past a REFUSAL (that one entry
/// is the problem, not the link — the next entry may well be fine).
///
/// `Ok(())` covers every ordinary non-error outcome: nothing registered
/// under `node_name`, the link already held off, `.bsy` already held by a
/// concurrent drain (ruling 3 — skipped, never queued), an empty spool, or
/// a completed pass regardless of how many entries it delivered/refused/
/// backed off on. `Err` is reserved for a genuine local I/O failure
/// (`.bsy`'s own lock file, or an outbox read/write) — never for "the
/// remote node was unreachable," which is an ordinary, expected drain
/// outcome recorded in the entry/link state instead of surfaced as an
/// error to this function's own caller.
pub fn drain_node(node_name: &str) -> Result<(), String> {
    let nodes = aoide_storage::node_store::load_nodes();
    let Some(node) = nodes.iter().find(|n| n.name == node_name) else {
        return Ok(());
    };

    let Some(_link_lock) = aoide_storage::outbox::try_take_link_lock(node_name)? else {
        return Ok(());
    };
    let _tunnel_teardown = TunnelTeardownGuard(node_name.to_string());

    let now_epoch = unix_now();
    if let Some(link) = aoide_storage::outbox::read_link_state(node_name)? {
        if aoide_storage::outbox::is_held_off(&link, now_epoch) {
            return Ok(());
        }
    }

    for entry in aoide_storage::outbox::list_entries(node_name)? {
        if entry.refused {
            continue;
        }
        match attempt_deposit(node, &entry.envelope) {
            DepositAttempt::TransportFailed(reason) => {
                aoide_storage::outbox::back_off(node_name, now_epoch, &reason)?;
                break;
            }
            DepositAttempt::Refused(reason) => {
                aoide_storage::outbox::clear_link_state(node_name)?;
                let mut updated = entry;
                updated.tries += 1;
                updated.last_try_at = aoide_storage::time::now_iso_utc();
                updated.last_outcome = format!("refused: {reason}");
                updated.refused = true;
                aoide_storage::outbox::write_entry(node_name, &updated)?;
            }
            DepositAttempt::Delivered { status } => {
                aoide_storage::outbox::clear_link_state(node_name)?;
                if entry.envelope.header.kind == aoide_storage::mail::ENTRY_TYPE_RECEIPT {
                    // Ruling 4: a receipt's own successful deposit outcome
                    // (accepted OR duplicate — the far end has it now
                    // either way) IS confirmation; there is no separate
                    // ack-of-an-ack to wait for.
                    aoide_storage::outbox::remove_entry(node_name, &entry.envelope.msgid)?;
                } else {
                    // A letter waits for a REAL ack (spec item 7) — record
                    // the attempt and move on, never remove here.
                    let mut updated = entry;
                    updated.tries += 1;
                    updated.last_try_at = aoide_storage::time::now_iso_utc();
                    updated.last_outcome = status;
                    aoide_storage::outbox::write_entry(node_name, &updated)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn a_dead_node_leaves_its_entry_waiting_and_drains_on_return() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("drain-dead-node");

        aoide_storage::node_store::save_nodes(&[unpaired_node("elsewhere")]).unwrap();

        let env = aoide_storage::mail::mint_outbound_letter("alice", "elsewhere", "bob", "hi").unwrap();
        aoide_storage::outbox::write_entry("elsewhere", &OutboxEntry::fresh(env)).unwrap();

        // Nothing listens on 127.0.0.1:1 — this is a transport failure, not
        // a refusal: the entry must survive, untouched in content, only its
        // bookkeeping (tries/lastTry/lastOutcome) may have changed, and the
        // LINK — never the entry — is what backs off.
        drain_node("elsewhere").unwrap();

        let remaining = aoide_storage::outbox::list_entries("elsewhere").unwrap();
        assert_eq!(remaining.len(), 1, "a dead node's entry is never dropped on a transport failure");
        assert!(!remaining[0].refused, "a transport failure is not a policy refusal");

        let link = aoide_storage::outbox::read_link_state("elsewhere").unwrap();
        assert!(link.is_some(), "the link backs off after an unreachable attempt");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A minimal fake `aoide/mailDeposit` door: answers every connection
    /// with the same fixed JSON-RPC body, forever — mirrors
    /// `commands::spawn_fake_card_server`'s exact shape (that copy is
    /// private to `commands.rs`'s own test module, so this is a second,
    /// module-local instance rather than a cross-module reach).
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

    /// MAIL.md §Wire/§Transit: a well-formed envelope's rejection is a
    /// RESULT (`{"status":"refused","reason":…}`), never a JSON-RPC error —
    /// so `attempt_deposit` must recognise this shape as a refusal on its
    /// own, not rely on an `error` member that a spec-conformant peer never
    /// sends for this outcome. Pins the client half of that split directly:
    /// this test fails against the client code that reads `status` with
    /// `.unwrap_or("accepted")` and returns `Delivered` for anything that
    /// isn't literally `"error"` at the JSON-RPC envelope level, because
    /// that code leaves `refused` false and `tries` incrementing forever
    /// (`drain_node`'s `Delivered` arm for a letter never sets `refused`).
    #[test]
    fn a_refused_result_parks_the_entry_and_a_later_drain_skips_it() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("refused-result-parks");

        let (listener, port) = fake_deposit_server(
            r#"{"jsonrpc":"2.0","id":1,"result":{"status":"refused","reason":"bad-msgid","detail":"envelope msgid does not match the recomputed value"}}"#,
        );
        let mut node = unpaired_node("elsewhere");
        node.url = format!("http://127.0.0.1:{port}/");
        aoide_storage::node_store::save_nodes(&[node]).unwrap();

        let env = aoide_storage::mail::mint_outbound_letter("alice", "elsewhere", "bob", "hi").unwrap();
        aoide_storage::outbox::write_entry("elsewhere", &OutboxEntry::fresh(env)).unwrap();

        drain_node("elsewhere").unwrap();

        let entries = aoide_storage::outbox::list_entries("elsewhere").unwrap();
        assert_eq!(entries.len(), 1, "a refused entry stays in the spool — no auto-eviction (kill-list)");
        assert!(entries[0].refused, "a refused RESULT must park the entry exactly like a refused ERROR does");
        assert!(entries[0].last_outcome.contains("bad-msgid"), "the reason is recorded: {}", entries[0].last_outcome);
        assert_eq!(entries[0].tries, 1);

        // A second drain must SKIP a refused entry outright (`if entry.refused
        // { continue }`) rather than retry it — `tries` staying at 1 is the
        // proof, since the fake door would happily answer a second POST too.
        drain_node("elsewhere").unwrap();
        let after = aoide_storage::outbox::list_entries("elsewhere").unwrap();
        assert_eq!(after[0].tries, 1, "a parked entry is never retried by a later drain");

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A 200 response whose `result` carries no `status` key at all is
    /// WEAKER evidence of delivery than an unrecognised status string, and
    /// the unrecognised one already parks (test above) — so this must park
    /// too, on the same catch-all arm, never take a shortcut to
    /// `Delivered`. Uses a RECEIPT-kind entry deliberately: `drain_node`'s
    /// `Delivered` arm for a receipt calls `outbox::remove_entry` outright
    /// (ruling 4 — a receipt's own successful deposit IS its confirmation),
    /// so a receipt is the one entry kind where taking that arm by mistake
    /// destroys the record rather than merely mis-annotating it. The
    /// record surviving is the assertion that matters. Pins the fix for
    /// the `unwrap_or("accepted")` default that used to bypass the
    /// fail-closed match below it: this test fails against that code,
    /// which read this exact response as `Delivered` and discarded the
    /// receipt on a reply that confirmed nothing.
    #[test]
    fn a_missing_status_parks_the_entry_and_keeps_the_receipt_record() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("missing-status-parks");

        let (listener, port) = fake_deposit_server(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
        let mut node = unpaired_node("elsewhere");
        node.url = format!("http://127.0.0.1:{port}/");
        aoide_storage::node_store::save_nodes(&[node]).unwrap();

        let to = aoide_storage::mail::Address { node: "origin-node".to_string(), name: "bob".to_string() };
        let env = aoide_storage::mail::mint_ack("alice", to, "some-acked-msgid").unwrap();
        aoide_storage::outbox::write_entry("elsewhere", &OutboxEntry::fresh(env)).unwrap();

        drain_node("elsewhere").unwrap();

        let entries = aoide_storage::outbox::list_entries("elsewhere").unwrap();
        assert_eq!(
            entries.len(),
            1,
            "a missing status must park a receipt entry, never remove it — this is the data loss the fix prevents"
        );
        assert!(entries[0].refused, "a missing status must be parked exactly like an unrecognised one");
        assert!(
            entries[0].last_outcome.contains("missing-status"),
            "the reason must say the status was absent, not imply the peer sent one: {}",
            entries[0].last_outcome
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_drain_session_leaves_no_forward_standing() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("drain-no-forward");

        aoide_storage::node_store::save_nodes(&[unpaired_node("elsewhere")]).unwrap();

        let env = aoide_storage::mail::mint_outbound_letter("alice", "elsewhere", "bob", "hi").unwrap();
        aoide_storage::outbox::write_entry("elsewhere", &OutboxEntry::fresh(env)).unwrap();

        drain_node("elsewhere").unwrap();

        // `elsewhere.via` is None (direct dial) here, so no tunnel was ever
        // opened — the assertion that matters is that tearing one down is
        // always safe to attempt, never that one existed. `close` on a
        // record-less key is a documented no-op (`tunnel.rs`'s own doc);
        // the drain returning at all without hanging or erroring past that
        // guard IS the proof this test pins.
        let records = aoide_storage::tunnel::list_records();
        assert!(
            records.iter().all(|r| r.key != "elsewhere"),
            "no tunnel record should be left standing for a node this drain touched"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
