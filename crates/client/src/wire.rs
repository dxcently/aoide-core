//! The A2A client-side wire builders: resolving a remote AgentCard URL, and
//! building the outbound `message/send` JSON-RPC request body aoide POSTs
//! when reaching a registered node.
//!
//! Moved from root `src/a2a.rs` (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md — the CLIENT-side region of that file;
//! the server-side JSON-RPC/HTTP door, AgentCard building from the LOCAL
//! command registry, and everything else stays in root, Phase 4c's job).
//! Re-exported at the old `crate::a2a::{resolve_card_url,
//! build_message_send_body}` path so every existing caller is untouched.

use aoide_protocol::wire::{JsonRpcRequest, Message, MessageSendParams, Part};
use serde_json::{json, Value};

/// Resolve the AgentCard URL to GET from a user-supplied `url`: if it already
/// points at a card (`…/agent-card.json`) use it verbatim, otherwise treat it
/// as an origin and append the well-known path. Pure.
pub fn resolve_card_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.ends_with("agent-card.json") {
        trimmed.to_string()
    } else {
        format!("{}/.well-known/agent-card.json", trimmed.trim_end_matches('/'))
    }
}

/// Build the JSON-RPC `message/send` request body aoide POSTs when DRIVING a
/// registered node (the outbound half of the bidirectional link). Mirrors
/// the inbound shape the server's `parse_message_send_params` (`src/a2a.rs`)
/// reads. Pure — the caller generates `message_id`, so the body stays
/// deterministic in tests.
///
/// `context_id` threads a target session id for a NODE send (messaging plan
/// P-C3: `graph send --to <node>/<query>` resolves a remote sessionId and
/// hands it here so the receiving node's `message_send` Inject arm can find
/// it — see `crates/server/src/a2a.rs::decide_send_action`). Every OTHER
/// caller (today: `node spawn`, addressing a node with no aoide sessionId
/// to target) passes `None`.
pub fn build_message_send_body(text: &str, message_id: &str, context_id: Option<&str>) -> Value {
    let params = MessageSendParams {
        message: Message {
            role: "user".to_string(),
            parts: vec![Part {
                kind: "text".to_string(),
                text: Some(text.to_string()),
                extra: Default::default(),
            }],
            message_id: Some(message_id.to_string()),
            context_id: context_id.map(str::to_string),
            metadata: None,
        },
    };
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "message/send".to_string(),
        params: serde_json::to_value(&params).expect("MessageSendParams always serializes"),
    };
    serde_json::to_value(&req).expect("JsonRpcRequest always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_card_url_appends_well_known_unless_already_a_card() {
        assert_eq!(
            resolve_card_url("http://127.0.0.1:8710"),
            "http://127.0.0.1:8710/.well-known/agent-card.json"
        );
        // Trailing slash is not doubled.
        assert_eq!(
            resolve_card_url("http://127.0.0.1:8710/"),
            "http://127.0.0.1:8710/.well-known/agent-card.json"
        );
        // An explicit card URL is used verbatim.
        assert_eq!(
            resolve_card_url("http://h/.well-known/agent-card.json"),
            "http://h/.well-known/agent-card.json"
        );
    }

    // ── The outbound message/send request-body builder (pure) ────────────────
    //
    // The original test also round-tripped this body through the server's
    // `parse_message_send_params` (`src/a2a.rs`) to prove the shapes match —
    // that half stayed in root `a2a.rs`'s own test module (Phase 4b restructure)
    // since `parse_message_send_params` is server-side inbound parsing, not
    // moving to this crate.

    #[test]
    fn build_message_send_body_matches_the_jsonrpc_shape() {
        let body = build_message_send_body("hello there", "mid-123", None);
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 1);
        assert_eq!(body["method"], "message/send");
        let msg = &body["params"]["message"];
        assert_eq!(msg["role"], "user");
        assert_eq!(msg["messageId"], "mid-123");
        assert!(msg.get("contextId").is_none(), "None stays absent, not null-present");
        let parts = msg["parts"].as_array().unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0]["kind"], "text");
        assert_eq!(parts[0]["text"], "hello there");
    }

    #[test]
    fn build_message_send_body_threads_a_context_id_when_given() {
        // P-C3: a node-targeted send carries the resolved remote sessionId
        // as `contextId` so the receiving node's Inject arm can find it.
        let body = build_message_send_body("hello there", "mid-123", Some("sess-9"));
        assert_eq!(body["params"]["message"]["contextId"], "sess-9");
    }
}
