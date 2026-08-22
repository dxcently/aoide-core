//! The A2A client-side wire builders/parsers: resolving/parsing a remote
//! AgentCard, and building the outbound `message/send` JSON-RPC request body
//! aoide POSTs when DRIVING a registered external agent.
//!
//! Moved from root `src/a2a.rs` (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md — the CLIENT-side region of that file;
//! the server-side JSON-RPC/HTTP door, AgentCard building from the LOCAL
//! command registry, and everything else stays in root, Phase 4c's job).
//! Re-exported at the old `crate::a2a::{resolve_card_url, parse_agent_card,
//! build_message_send_body}` path so every existing caller is untouched.

use aoide_protocol::wire::{JsonRpcRequest, Message, MessageSendParams, Part};
use aoide_storage::a2a_store::A2aAgent;
use serde_json::{json, Value};

// ── AgentCard parsing (client side — the shape a REMOTE card presents) ───────

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

/// The `scheme://host[:port]/` origin of a URL (drops path/query) — the
/// fallback `message/send` endpoint when a card names no `url`. Pure.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return url.to_string(),
    };
    let host = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host}/")
}

/// The `message/send` endpoint a card advertises: its flat `url` (the A2A
/// v0.3.x JSON-RPC binding — the shape aoide's own card emits), else the first
/// `interfaces[].url` (the v1.0 form), filtered to a non-empty string. Pure.
fn card_endpoint(card: &Value) -> Option<String> {
    if let Some(u) = card
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Some(u.to_string());
    }
    card.get("interfaces")
        .and_then(Value::as_array)
        .and_then(|xs| xs.first())
        .and_then(|i| i.get("url"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parse a fetched AgentCard into a registry entry. Requires at least a
/// non-empty `name`; keeps `description`; resolves the POST endpoint via
/// [`card_endpoint`], falling back to the origin of `fetch_url` (the URL the
/// card was GET'd from). Pure — the fetch itself is the handler's job.
pub fn parse_agent_card(
    card: &Value,
    fetch_url: &str,
    registered_at: &str,
) -> Result<A2aAgent, String> {
    let name = card
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AgentCard has no `name`".to_string())?;
    let description = card
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let url = card_endpoint(card).unwrap_or_else(|| origin_of(fetch_url));
    Ok(A2aAgent {
        name: name.to_string(),
        url,
        description,
        registered_at: registered_at.to_string(),
    })
}

/// Build the JSON-RPC `message/send` request body aoide POSTs when DRIVING a
/// registered external agent (the outbound half of the bidirectional link).
/// Mirrors the inbound shape the server's `parse_message_send_params`
/// (`src/a2a.rs`) reads. Pure — the caller generates `message_id`, so the
/// body stays deterministic in tests.
///
/// `context_id` threads a target session id for a PEER send (messaging plan
/// P-C3: `graph send --to <peer>/<query>` resolves a remote sessionId and
/// hands it here so the receiving peer's `message_send` Inject arm can find
/// it — see `crates/server/src/a2a.rs::decide_send_action`). Every OTHER
/// caller (today: `a2a agent send`, driving an unrelated registered A2A
/// agent that has no notion of an aoide sessionId) passes `None`, which
/// reproduces the old hardcoded-`None` body byte-for-byte — this parameter
/// is additive, nothing else about the wire shape changed.
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

    // ── AgentCard parsing (client side) ──────────────────────────────────────

    #[test]
    fn parse_agent_card_reads_name_description_and_card_url_endpoint() {
        // A card that names its own flat `url` (aoide's own v0.3.x shape): the
        // endpoint is that url, not the fetch origin.
        let card = json!({
            "name": "peer",
            "description": "a friendly agent",
            "url": "http://10.0.0.5:8710/",
            "skills": [],
        });
        let agent = parse_agent_card(&card, "http://10.0.0.5:8710/.well-known/agent-card.json", "NOW").unwrap();
        assert_eq!(agent.name, "peer");
        assert_eq!(agent.description, "a friendly agent");
        assert_eq!(agent.url, "http://10.0.0.5:8710/");
        assert_eq!(agent.registered_at, "NOW");
    }

    #[test]
    fn parse_agent_card_falls_back_to_fetch_origin_and_v1_interfaces() {
        // No flat `url` → fall back to the origin of the fetch URL.
        let card = json!({ "name": "originless" });
        let agent = parse_agent_card(&card, "http://host:9000/.well-known/agent-card.json", "T").unwrap();
        assert_eq!(agent.url, "http://host:9000/");
        assert_eq!(agent.description, "");

        // v1.0 `interfaces` array form → first interface url wins.
        let card = json!({
            "name": "v1",
            "interfaces": [{ "transport": "JSONRPC", "url": "http://host:9000/rpc" }],
        });
        let agent = parse_agent_card(&card, "http://host:9000/x", "T").unwrap();
        assert_eq!(agent.url, "http://host:9000/rpc");
    }

    #[test]
    fn parse_agent_card_missing_name_is_an_error() {
        assert!(parse_agent_card(&json!({ "description": "no name here" }), "http://x/", "T").is_err());
        // A present-but-empty name is also rejected.
        assert!(parse_agent_card(&json!({ "name": "  " }), "http://x/", "T").is_err());
    }

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
        // P-C3: a peer-targeted send carries the resolved remote sessionId
        // as `contextId` so the receiving peer's Inject arm can find it.
        let body = build_message_send_body("hello there", "mid-123", Some("sess-9"));
        assert_eq!(body["params"]["message"]["contextId"], "sess-9");
    }
}
