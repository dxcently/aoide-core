//! Typed wire-payload shapes for the JSON-RPC 2.0 surfaces the A2A door
//! (`a2a.rs`, CONTRACTS.md §6) and the MCP door (`mcp.rs`) speak.
//!
//! Phase 4a restructure (docs/architecture/PACKAGE-LAYOUT.md): these types
//! replace the hand-assembled `json!{...}` trees those two root modules used
//! to build/parse their wire payloads with. The public functions that build
//! or consume a payload keep their existing `serde_json::Value` signatures —
//! callers are untouched — but internally now construct one of these structs
//! and convert it with `serde_json::to_value`/`from_value`, so the shape is
//! checked by the compiler instead of by hand. Because every one of those
//! functions round-trips through `Value` before it reaches a caller, and
//! `serde_json::Value`'s object map is key-sorted regardless of how it was
//! built (`json!{...}` literal order or struct-declaration order), the wire
//! bytes these functions produce are unchanged.
//!
//! - [`jsonrpc`] — the JSON-RPC 2.0 envelope shared by both doors.
//! - [`a2a`] — AgentCard, Task, Message/Part, `message/send` params, the SSE
//!   stream event shape (CONTRACTS.md §6).
//! - [`mcp`] — `initialize`, the tool list, and `tools/call` result shapes.

pub mod a2a;
pub mod jsonrpc;
pub mod mcp;

pub use a2a::*;
pub use jsonrpc::*;
pub use mcp::*;
