//! Minimal MCP stdio server (concepts/Agent-Interface, Tier 2).
//!
//! The tool list is GENERATED from the command registry — each command
//! becomes one tool — and `tools/call` dispatches back into the same command
//! handlers the CLI uses. One implementation, two doors, no drift (A2A,
//! `a2a.rs`, is the third door onto the same schema — CONTRACTS.md §6).
//!
//! This is a minimal, dependency-free JSON-RPC 2.0 over newline-delimited
//! stdin/stdout: enough for a per-session agent to enumerate and call tools.
//!
//! Extracted from root `src/mcp.rs` (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md). The old `dispatch::registry()` /
//! `dispatch::dispatch()` calls this module made are impossible here — the
//! fully-assembled command registry doesn't move to any crate until Phase 6
//! (`cli`), and `aoide-server` must sit BELOW the trunk, never depend on it.
//! [`serve_stdio`] (and everything it calls) takes the registry and a
//! dispatch fn pointer as parameters instead; root `lib.rs`'s
//! `mcp serve --stdio` launch site passes `dispatch::registry()` and
//! `dispatch::dispatch` in.

use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::registry::Registry;
use aoide_protocol::wire::{
    InitializeCapabilities, InitializeResult, JsonRpcResponse, ServerInfo, Tool, ToolAnnotations,
    ToolCallContent, ToolCallResult, ToolInputSchema, ToolList, ToolProperty, ToolsCapability,
};
use aoide_protocol::{Door, Invocation};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// A dispatch fn pointer: matches `aoide::dispatch::dispatch`'s exact
/// signature (a plain `fn`, not a closure — the process-wide dispatcher
/// captures nothing), so root can hand it in directly at the launch site.
pub type DispatchFn = fn(&Invocation) -> Outcome;

/// Generate the MCP `tools` array from the command schema. Each command →
/// one tool named by its dotted path; its args/flags become the inputSchema.
pub fn tool_list(registry: &Registry) -> Value {
    let tools: Vec<Tool> = registry
        .commands()
        .map(|c| {
            let mut properties: BTreeMap<String, ToolProperty> = BTreeMap::new();
            let mut required: Vec<String> = Vec::new();

            for a in c.args {
                properties.insert(
                    a.name.to_string(),
                    ToolProperty { kind: json_type(a.ty).to_string(), description: a.description.to_string() },
                );
                if a.required {
                    required.push(a.name.to_string());
                }
            }
            for f in c.flags {
                properties.insert(
                    f.name.to_string(),
                    ToolProperty { kind: json_type(f.ty).to_string(), description: f.description.to_string() },
                );
            }

            Tool {
                name: c.dotted(),
                description: c.summary.to_string(),
                input_schema: ToolInputSchema { kind: "object".to_string(), properties, required },
                // Surface the gate so an MCP client can warn before calling.
                annotations: ToolAnnotations { gated: c.gated },
            }
        })
        .collect();

    serde_json::to_value(ToolList { tools }).expect("ToolList always serializes")
}

fn json_type(ty: &str) -> &'static str {
    match ty {
        "int" | "integer" => "integer",
        "bool" | "boolean" => "boolean",
        _ => "string",
    }
}

/// Build an [`Invocation`] from an MCP `tools/call` (tool name + arguments).
fn invocation_from_call(name: &str, arguments: &Value, registry: &Registry) -> Option<Invocation> {
    let cmd = registry.commands().find(|c| c.dotted() == name)?;
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

/// `pub(crate)` (not `pub`) so [`crate::daemon`]'s own `dispatch` op
/// (P-D4, `docs/architecture/AOIDED.md`'s "L2" section) can reuse the exact
/// same JSON-value-to-wire-string conversion its `flags`/`args` parsing
/// needs — the "no cross-crate copying" convention
/// (`pkgs/aoide/crates/AGENTS.md`) applied within one crate too: widen a
/// `pub(crate)` scope rather than fork the four-line match a second time.
pub(crate) fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Handle one JSON-RPC request, returning the response Value (or None for
/// notifications that take no reply).
fn handle(req: &Value, registry: &Registry, dispatch: DispatchFn) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let init = InitializeResult {
                protocol_version: PROTOCOL_VERSION.to_string(),
                capabilities: InitializeCapabilities { tools: ToolsCapability {} },
                server_info: ServerInfo {
                    name: "aoide".to_string(),
                    version: aoide_protocol::registry::AOIDE_VERSION.to_string(),
                },
            };
            Ok(serde_json::to_value(init).expect("InitializeResult always serializes"))
        }
        "tools/list" => Ok(tool_list(registry)),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            match invocation_from_call(name, &arguments, registry) {
                Some(inv) => {
                    let outcome = dispatch(&inv);
                    let text = serde_json::to_string_pretty(&outcome).unwrap_or_default();
                    let result = ToolCallResult {
                        content: vec![ToolCallContent { kind: "text".to_string(), text }],
                        is_error: outcome.status != Status::Ok,
                    };
                    Ok(serde_json::to_value(result).expect("ToolCallResult always serializes"))
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
    let id = id.expect("id present (checked above)");

    let resp = match result {
        Ok(value) => JsonRpcResponse::ok(id, value),
        Err((code, message)) => JsonRpcResponse::err(id, code, message),
    };
    Some(serde_json::to_value(&resp).expect("JsonRpcResponse always serializes"))
}

/// Serve the MCP protocol over stdio (newline-delimited JSON-RPC).
///
/// `registry`/`dispatch` are injected (see the module doc comment) — root
/// `lib.rs` passes `dispatch::registry()` and `dispatch::dispatch`.
pub fn serve_stdio(registry: &Registry, dispatch: DispatchFn) -> std::io::Result<()> {
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
                let err = serde_json::to_value(JsonRpcResponse::err(
                    Value::Null,
                    -32700,
                    format!("parse error: {e}"),
                ))
                .expect("JsonRpcResponse always serializes");
                writeln!(out, "{err}")?;
                out.flush()?;
                continue;
            }
        };
        if let Some(resp) = handle(&req, registry, dispatch) {
            writeln!(out, "{resp}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::registry::Command;

    fn fake_handler(_inv: &Invocation) -> Outcome {
        Outcome::ok("fake", "fake")
    }

    /// A small fixture registry standing in for the real, fully-assembled one
    /// (`dispatch::registry()`, root-only — see the module doc comment): two
    /// commands, one gated, exercising the same shape `tool_list`/`handle`
    /// need without pulling in every command family.
    fn fixture_registry() -> Registry {
        let mut r = Registry::new();
        r.insert(Command {
            path: &["foo", "bar"],
            summary: "does a thing",
            args: &[],
            flags: &[],
            gated: true,
            implemented: true,
            internal: false,
            exit_codes: (),
            examples: &[],
            handler: fake_handler,
            available: || true,
        });
        r.insert(Command {
            path: &["guide"],
            summary: "onboarding text",
            args: &[],
            flags: &[],
            gated: false,
            implemented: true,
            internal: false,
            exit_codes: (),
            examples: &[],
            handler: fake_handler,
            available: || true,
        });
        r
    }

    #[test]
    fn tool_list_is_derived_one_to_one_from_the_registry() {
        let registry = fixture_registry();
        let tools = tool_list(&registry);
        let arr = tools["tools"].as_array().unwrap();
        assert_eq!(arr.len(), registry.commands().count());
        // Every command name appears as a tool name, and the gate surfaces.
        let names: std::collections::HashSet<String> = arr
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for c in registry.commands() {
            assert!(names.contains(&c.dotted()), "tool missing for {}", c.dotted());
        }
        let bar = arr.iter().find(|t| t["name"] == "foo.bar").unwrap();
        assert_eq!(bar["annotations"]["gated"], true);
    }

    #[test]
    fn tools_call_dispatches_into_the_injected_handler() {
        let registry = fixture_registry();
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "guide", "arguments": {} }
        });
        let resp = handle(&req, &registry, fake_handler).unwrap();
        assert!(resp["result"]["content"][0]["text"].is_string());
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn tools_call_on_an_unknown_tool_is_minus_32602() {
        let registry = fixture_registry();
        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "nope", "arguments": {} }
        });
        let resp = handle(&req, &registry, fake_handler).unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }
}
