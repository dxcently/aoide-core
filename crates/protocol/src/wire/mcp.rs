//! MCP (Model Context Protocol) wire shapes — the stdio JSON-RPC door
//! (root `src/mcp.rs`): the `initialize` handshake result, the generated
//! `tools/list` array (one tool per registry command), and the `tools/call`
//! result envelope.
//!
//! Request-side parsing (`params.name`/`params.arguments` off an incoming
//! `tools/call`) stays `Value`-based in `mcp.rs`, same reasoning as the A2A
//! door's inbound JSON-RPC parsing: `arguments`'s shape is whatever the
//! target command's own args/flags schema says, not a shape fixed here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `initialize`'s result (the MCP handshake).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: InitializeCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// `InitializeResult.capabilities` — aoide advertises tool support only, with
/// no sub-capabilities (`listChanged` etc.) yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InitializeCapabilities {
    pub tools: ToolsCapability,
}

/// Deliberately empty — serializes as `{}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolsCapability {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// `tools/list`'s result: one [`Tool`] per registry command
/// (`mcp.rs::tool_list`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolList {
    pub tools: Vec<Tool>,
}

/// One MCP tool, generated 1:1 from a `Command` (CONTRACTS.md §3): its
/// dotted path is the tool name, its args/flags become the JSON-Schema
/// `inputSchema`, and `annotations.gated` surfaces the command's gate so an
/// MCP client can warn before calling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: ToolInputSchema,
    pub annotations: ToolAnnotations,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolInputSchema {
    /// Always `"object"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub properties: BTreeMap<String, ToolProperty>,
    pub required: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolProperty {
    #[serde(rename = "type")]
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolAnnotations {
    pub gated: bool,
}

/// `tools/call`'s result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallResult {
    pub content: Vec<ToolCallContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallContent {
    /// Always `"text"` — aoide's `tools/call` only ever returns one text
    /// block (the command's rendered `Outcome`).
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_result_matches_the_captured_handshake_shape() {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: InitializeCapabilities { tools: ToolsCapability {} },
            server_info: ServerInfo { name: "aoide".to_string(), version: "0.0.0".to_string() },
        };
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["protocolVersion"], "2024-11-05");
        assert_eq!(v["capabilities"]["tools"], json!({}));
        assert_eq!(v["serverInfo"]["name"], "aoide");
        assert_eq!(v["serverInfo"]["version"], "0.0.0");
    }

    #[test]
    fn tool_round_trips_the_captured_tool_shape() {
        let mut properties = BTreeMap::new();
        properties.insert(
            "id".to_string(),
            ToolProperty { kind: "string".to_string(), description: "the session id".to_string() },
        );
        let tool = Tool {
            name: "foo.bar".to_string(),
            description: "does a thing".to_string(),
            input_schema: ToolInputSchema {
                kind: "object".to_string(),
                properties,
                required: vec!["id".to_string()],
            },
            annotations: ToolAnnotations { gated: true },
        };
        let raw = json!({
            "name": "foo.bar",
            "description": "does a thing",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string", "description": "the session id" } },
                "required": ["id"],
            },
            "annotations": { "gated": true },
        });
        assert_eq!(serde_json::to_value(&tool).unwrap(), raw);
        let back: Tool = serde_json::from_value(raw).unwrap();
        assert_eq!(back, tool);
    }

    #[test]
    fn tool_call_result_matches_the_captured_shape_and_is_error_flag() {
        let result = ToolCallResult {
            content: vec![ToolCallContent { kind: "text".to_string(), text: "{}".to_string() }],
            is_error: false,
        };
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["content"][0]["type"], "text");
        assert_eq!(v["content"][0]["text"], "{}");
        assert_eq!(v["isError"], false);
    }
}
