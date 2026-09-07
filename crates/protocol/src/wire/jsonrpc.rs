//! The JSON-RPC 2.0 envelope shapes shared by the A2A door (`a2a.rs`, an
//! HTTP/1.1 binding) and the MCP door (`mcp.rs`, a stdio binding) — both
//! doors speak the same request/response/error envelope over different
//! transports, so it lives here once instead of twice.
//!
//! Incoming *requests* are deliberately NOT parsed through [`JsonRpcRequest`]
//! by either door today: both doors read `id`/`method`/`params` straight off
//! the raw `serde_json::Value` with per-field fallbacks (missing `id` → null,
//! missing `method` → `""`, missing `params` → null) so that a structurally
//! odd request (e.g. a top-level JSON value that isn't even an object) still
//! degrades to a clean `-32600`/`-32601` JSON-RPC error instead of a hard
//! parse failure — the same hostile-input tolerance the rest of `a2a.rs`
//! practices. [`JsonRpcRequest`] exists for the OUTBOUND side ( building a
//! request this process sends, e.g. `a2a.rs::build_message_send_body`) and
//! as the shared shape description; it is not force-fit onto the inbound
//! path where doing so would trade that tolerance for strictness.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JSON-RPC 2.0 request envelope — used when THIS process is the one
/// building a request to send (e.g. the outbound `message/send` aoide POSTs
/// to a registered node). `params` stays a raw [`Value`] rather than a
/// method-specific type, since the shape of `params` depends on `method`;
/// callers build the method-specific params type (e.g.
/// [`super::a2a::MessageSendParams`]) and convert it to `Value` first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 response envelope — exactly one of `result`/`error` is
/// ever populated (never both, never neither), matching the JSON-RPC 2.0
/// spec and the shape both doors' `json!{...}` builders always produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// A successful response carrying `result`.
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// An error response carrying a JSON-RPC error code + message.
    pub fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
}

/// A JSON-RPC 2.0 error object (`response.error`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ok_response_omits_the_error_key_entirely() {
        let resp = JsonRpcResponse::ok(json!(7), json!({ "a": 1 }));
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["result"]["a"], 1);
        assert!(v.get("error").is_none(), "serialized: {v}");
    }

    #[test]
    fn err_response_omits_the_result_key_entirely() {
        let resp = JsonRpcResponse::err(Value::Null, -32601, "method not found: bogus");
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["error"]["code"], -32601);
        assert_eq!(v["error"]["message"], "method not found: bogus");
        assert!(v.get("result").is_none(), "serialized: {v}");
    }

    #[test]
    fn jsonrpc_request_defaults_absent_id_and_params_to_null() {
        let req: JsonRpcRequest = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "method": "tasks/get",
        }))
        .unwrap();
        assert_eq!(req.id, Value::Null);
        assert_eq!(req.method, "tasks/get");
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn jsonrpc_request_round_trips_a_full_request() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": { "message": { "role": "user" } },
        });
        let req: JsonRpcRequest = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(req.id, json!(1));
        assert_eq!(req.method, "message/send");
        assert_eq!(req.params["message"]["role"], "user");
        let back = serde_json::to_value(&req).unwrap();
        assert_eq!(back, raw);
    }
}
