//! The peer-federation client-side wire builders/parsers (CONTRACTS.md §7):
//! the outbound `aoide/graphSummary` JSON-RPC request body, and parsing a
//! peer's response into a `state/peer-cache/<name>.json` entry
//! (`aoide-storage::peer_store::PeerCacheEntry`).
//!
//! Mirrors `wire.rs`'s separation exactly — the pure wire shapes live here,
//! the curl transport + CLI verbs (`peer add|list|remove|pull|status`) live
//! in `commands.rs`, same split as `wire.rs`/`commands.rs`'s existing
//! `a2a agent *` verbs.

use aoide_protocol::wire::JsonRpcRequest;
use aoide_storage::peer_store::PeerCacheEntry;
use serde_json::{json, Value};

/// Build the JSON-RPC `aoide/graphSummary` request body `peer pull` POSTs to
/// a registered peer's endpoint. No params — the method takes none
/// (CONTRACTS.md §7). Pure.
pub fn build_graph_summary_request() -> Value {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "aoide/graphSummary".to_string(),
        params: json!({}),
    };
    serde_json::to_value(&req).expect("JsonRpcRequest always serializes")
}

/// Parse a peer's `aoide/graphSummary` JSON-RPC response into a FRESH
/// [`PeerCacheEntry`] for `name`. Requires `result.schemaVersion == "0"` and
/// a `result.graph` object; `result.instance` rides through verbatim when
/// present. Pure — the HTTP fetch itself is the caller's (`commands.rs`) job.
pub fn parse_graph_summary_response(resp: &Value, name: &str, fetched_at: &str) -> Result<PeerCacheEntry, String> {
    if let Some(err) = resp.get("error") {
        let detail = err.get("message").and_then(Value::as_str).unwrap_or("(no message)");
        return Err(format!("peer returned an error: {detail}"));
    }
    let result = resp
        .get("result")
        .ok_or_else(|| "response has no `result`".to_string())?;
    let schema_version = result.get("schemaVersion").and_then(Value::as_str).unwrap_or("");
    if schema_version != "0" {
        return Err(format!("unsupported schemaVersion `{schema_version}` (expected \"0\")"));
    }
    let graph = result
        .get("graph")
        .filter(|g| g.is_object())
        .ok_or_else(|| "response has no `graph` object".to_string())?
        .clone();
    Ok(PeerCacheEntry {
        schema_version: "0".to_string(),
        name: name.to_string(),
        instance: result.get("instance").cloned(),
        graph: Some(graph),
        fetched_at: Some(fetched_at.to_string()),
        stale: false,
        last_error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_graph_summary_request_matches_the_jsonrpc_shape() {
        let body = build_graph_summary_request();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], "aoide/graphSummary");
        assert!(body["params"].is_object());
    }

    #[test]
    fn parse_graph_summary_response_extracts_a_fresh_cache_entry() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "schemaVersion": "0",
                "instance": { "name": "yomi-strix", "url": "http://yomi-strix:8710/", "emittedAt": "2026-08-14T00:00:00Z" },
                "graph": { "schemaVersion": "0", "nodes": [], "edges": [] },
            }
        });
        let entry = parse_graph_summary_response(&resp, "yomi-strix", "2026-08-14T00:05:00Z").unwrap();
        assert_eq!(entry.name, "yomi-strix");
        assert!(!entry.stale);
        assert_eq!(entry.fetched_at.as_deref(), Some("2026-08-14T00:05:00Z"));
        assert_eq!(entry.instance.unwrap()["name"], "yomi-strix");
        assert_eq!(entry.graph.unwrap()["schemaVersion"], "0");
    }

    #[test]
    fn parse_graph_summary_response_rejects_an_error_or_wrong_schema_or_missing_graph() {
        let err_resp = json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "method not found" } });
        assert!(parse_graph_summary_response(&err_resp, "p", "T").is_err());

        let bad_schema = json!({ "result": { "schemaVersion": "99", "graph": {} } });
        assert!(parse_graph_summary_response(&bad_schema, "p", "T").is_err());

        let no_graph = json!({ "result": { "schemaVersion": "0" } });
        assert!(parse_graph_summary_response(&no_graph, "p", "T").is_err());

        let empty = json!({});
        assert!(parse_graph_summary_response(&empty, "p", "T").is_err());
    }
}
