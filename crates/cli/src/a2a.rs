//! The A2A (Agent2Agent) door (CONTRACTS.md §6) — CLIENT half in this crate,
//! SERVER half in `aoide-server`.
//!
//! The SERVER half — the hand-rolled JSON-RPC 2.0/HTTP server (`serve`), the
//! AgentCard builder, `tasks/get`/`message/send`/SSE streaming, and the
//! bind/spawn-agent flag resolution — moved to `aoide-server` (Phase 4c
//! restructure, docs/architecture/PACKAGE-LAYOUT.md) and is re-exported below
//! so every existing `crate::a2a::*` caller is untouched.
//!
//! **One exception, unlike every prior phase's zero-call-site-churn:**
//! `serve`/`agent_card`/`agent_card_from_commands` now take the command
//! registry as a parameter (the DI seam `aoide-server`'s module doc comment
//! explains — a `server` crate cannot reach the crate-global, fully-assembled
//! `dispatch::registry()` without becoming `server → root`). `serve`'s ONE
//! caller (`lib.rs::run_cli`'s `a2a serve` launch site) was updated to pass
//! `dispatch::registry()` in.
//!
//! The CLIENT half — resolving/reaching a remote AgentCard (`resolve_card_url`,
//! `build_message_send_body`) — stays here, sourced through `aoide-client`
//! (Phase 4b), unchanged from that phase: it is the outbound half of the
//! bidirectional link, mirroring the inbound server above. The node registry
//! itself (CONTRACTS.md §7) lives in `aoide-storage::node_store` and
//! `aoide-client::commands::register_nodes`.

// ── SERVER half (aoide-server, Phase 4c) ─────────────────────────────────────
pub use aoide_server::a2a::{
    a2a_task_state, agent_card, agent_card_from_commands, decide_send_action, read_expected_token,
    resolve_bearer_secret, resolve_bind_port, resolve_discovery_advertise, resolve_node_name,
    resolve_spawn_agent, resolve_token_file, serve, ConnOrigin, SendAction, SessionRef,
};

// ── AgentCard resolution (client side) ────────────────────────────────────────
//
// Moved to `aoide-client` (Phase 4b restructure,
// docs/architecture/PACKAGE-LAYOUT.md — `resolve_card_url`,
// `build_message_send_body`); re-exported here so every existing
// `crate::a2a::{resolve_card_url, build_message_send_body}` caller is
// untouched.
pub use aoide_client::wire::{build_message_send_body, resolve_card_url};
