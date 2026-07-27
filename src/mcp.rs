//! Minimal MCP stdio server (concepts/Agent-Interface, Tier 2).
//!
//! The tool list is GENERATED from `schema --json` — each command becomes one
//! tool — and `tools/call` dispatches back into the same command handlers the
//! CLI uses. One implementation, two doors, no drift.
//!
//! This is a minimal, dependency-free JSON-RPC 2.0 over newline-delimited
//! stdin/stdout: enough for a per-session agent to enumerate and call tools.

use crate::daemon::Door;
use crate::dispatch::{self, Invocation};
use crate::schema;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Generate the MCP `tools` array from the command schema. Each command →
/// one tool named by its dotted path; its args/flags become the inputSchema.
pub fn tool_list() -> Value {
    let tools: Vec<Value> = schema::commands()
        .iter()
        .map(|c| {
            let mut props = serde_json::Map::new();
            let mut required: Vec<String> = Vec::new();

            for a in c.args {
                props.insert(
                    a.name.to_string(),
                    json!({ "type": json_type(a.ty), "description": a.description }),
                );
                if a.required {
                    required.push(a.name.to_string());
                }
            }
            for f in c.flags {
                props.insert(
                    f.name.to_string(),
                    json!({ "type": json_type(f.ty), "description": f.description }),
                );
            }

            json!({
                "name": c.dotted(),
                "description": c.summary,
                "inputSchema": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
                // Surface the gate so an MCP client can warn before calling.
                "annotations": { "gated": c.gated },
            })
        })
        .collect();

    json!({ "tools": tools })
}

fn json_type(ty: &str) -> &'static str {
    match ty {
        "int" | "integer" => "integer",
        "bool" | "boolean" => "boolean",
        _ => "string",
    }
}

/// Build an [`Invocation`] from an MCP `tools/call` (tool name + arguments).
fn invocation_from_call(name: &str, arguments: &Value) -> Option<Invocation> {
    let cmd = schema::commands()
        .into_iter()
        .find(|c| c.dotted() == name)?;
    let path: Vec<String> = cmd.path.iter().map(|s| s.to_string()).collect();

    let mut args: Vec<String> = Vec::new();
    let mut flags: BTreeMap<String, String> = BTreeMap::new();

    if let Some(obj) = arguments.as_object() {
        // Positional args, in schema order.
        for a in cmd.args {
            if let Some(v) = obj.get(a.name) {
                args.push(value_to_string(v));
            }
        }
        // Flags by name.
        for f in cmd.flags {
            if let Some(v) = obj.get(f.name) {
                flags.insert(f.name.to_string(), value_to_string(v));
            }
        }
    }

    Some(Invocation {
        path,
        args,
        flags,
        door: Door::Mcp,
    })
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Handle one JSON-RPC request, returning the response Value (or None for
/// notifications that take no reply).
fn handle(req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    let result: Result<Value, (i64, String)> = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "aoide", "version": schema::AOIDE_VERSION },
        })),
        "tools/list" => Ok(tool_list()),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            match invocation_from_call(name, &arguments) {
                Some(inv) => {
                    let outcome = dispatch::dispatch(&inv);
                    let text = serde_json::to_string_pretty(&outcome).unwrap_or_default();
                    Ok(json!({
                        "content": [ { "type": "text", "text": text } ],
                        "isError": outcome.status != crate::output::Status::Ok,
                    }))
                }
                None => Err((-32602, format!("unknown tool: {name}"))),
            }
        }
        // Notifications (no id) — acknowledge silently.
        m if m.starts_with("notifications/") => return None,
        other => Err((-32601, format!("method not found: {other}"))),
    };

    // Notifications without an id get no response.
    id.as_ref()?;

    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err((code, message)) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    })
}

/// Serve the MCP protocol over stdio (newline-delimited JSON-RPC).
pub fn serve_stdio() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0", "id": Value::Null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                });
                writeln!(out, "{err}")?;
                out.flush()?;
                continue;
            }
        };
        if let Some(resp) = handle(&req) {
            writeln!(out, "{resp}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_list_is_derived_one_to_one_from_the_schema() {
        let tools = tool_list();
        let arr = tools["tools"].as_array().unwrap();
        assert_eq!(arr.len(), schema::commands().len());
        // Every command name appears as a tool name.
        let names: std::collections::HashSet<String> = arr
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for c in schema::commands() {
            assert!(
                names.contains(&c.dotted()),
                "tool missing for {}",
                c.dotted()
            );
        }
    }

    #[test]
    fn tools_call_dispatches_into_the_same_handlers() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "guide", "arguments": {} }
        });
        let resp = handle(&req).unwrap();
        assert!(resp["result"]["content"][0]["text"].is_string());
        assert_eq!(resp["result"]["isError"], false);
    }
}
