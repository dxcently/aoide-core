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
//! The CLIENT half — the external-agent registry (`state/a2a-agents.json`,
//! `agent add`/`list`/`remove`/`send`) and AgentCard parsing — stays here,
//! sourced through `aoide-storage` (Phase 3a) and `aoide-client` (Phase 4b),
//! unchanged from those phases: it folds into the session DAG as `kind:"a2a"`
//! nodes (`graph/doc.rs::build_graph`) and is the outbound half of the
//! bidirectional link, mirroring the inbound server above.

// ── SERVER half (aoide-server, Phase 4c) ─────────────────────────────────────
pub use aoide_server::a2a::{
    a2a_task_state, agent_card, agent_card_from_commands, decide_send_action, read_expected_token,
    resolve_bind_port, resolve_peer_name, resolve_spawn_agent, resolve_token_file, serve,
    PeerOrigin, SendAction, SessionRef,
};

// ── Client-side registry: external A2A agents (CONTRACTS.md §4/§6) ───────────
//
// `state/a2a-agents.json` (v0): the set of EXTERNAL A2A agents this aoide has
// registered by AgentCard URL (`aoide a2a agent add`). Each entry folds into
// the session DAG as a `kind:"a2a"` node (`graph/doc.rs::build_graph`) and is
// the outbound peer `aoide a2a agent send` drives. Tolerate-missing → empty
// (an absent file is simply "no agents registered"); keyed by the card `name`,
// dedupe/replace on re-add. This is the CLIENT half of §6 — the outbound,
// aoide-drives-a-remote-agent direction — mirroring the inbound server above.
//
// Moved to `aoide-storage` (Phase 3a restructure,
// docs/architecture/PACKAGE-LAYOUT.md); re-exported here so every existing
// `crate::a2a::{A2aAgent, load_agents, …}` caller is untouched.
pub use aoide_storage::a2a_store::{
    agents_path, load_agents, remove_agent, save_agents, upsert_agent, A2aAgent, A2aAgentRegistry,
    A2A_AGENTS_VERSION,
};

// ── AgentCard parsing (client side — the shape a REMOTE card presents) ───────
//
// Moved to `aoide-client` (Phase 4b restructure,
// docs/architecture/PACKAGE-LAYOUT.md — `resolve_card_url`, `parse_agent_card`,
// `build_message_send_body`, plus the private `origin_of`/`card_endpoint`
// helpers); re-exported here so every existing `crate::a2a::{resolve_card_url,
// parse_agent_card, build_message_send_body}` caller is untouched.
pub use aoide_client::wire::{build_message_send_body, parse_agent_card, resolve_card_url};

#[cfg(test)]
mod tests {
    use super::*;

    // ── Client-side registry: CRUD (pure, in-memory) ─────────────────────────
    //
    // Everything else that used to be tested here (AgentCard generation,
    // canonical_state->TaskState, tasks/get, decide_send_action,
    // message/send parsing, the HTTP/1.1 parse layer, SSE helpers, routing)
    // moved to `aoide-server`'s `a2a::tests` alongside the code it exercises
    // (Phase 4c restructure). `load_save_agents_round_trip_through_a_temp_state_dir`
    // moved to `aoide-storage`'s `a2a_store::tests` (Phase 3a) and
    // `parse_agent_card_*`/`resolve_card_url_*`/`build_message_send_body_*`
    // (shape-only) moved to `aoide-client`'s `wire::tests` (Phase 4b) —
    // this crate keeps only the CRUD helpers below, which never moved.

    fn fixture_agent(name: &str, url: &str) -> A2aAgent {
        A2aAgent {
            name: name.to_string(),
            url: url.to_string(),
            description: format!("{name} desc"),
            registered_at: "2026-08-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn upsert_agent_appends_then_dedupes_by_name() {
        let mut agents: Vec<A2aAgent> = Vec::new();
        upsert_agent(&mut agents, fixture_agent("alpha", "http://a/"));
        upsert_agent(&mut agents, fixture_agent("beta", "http://b/"));
        assert_eq!(agents.len(), 2);

        // Re-add `alpha` with a new endpoint → REPLACE in place (dedupe by name),
        // preserving order, not a second entry.
        let mut updated = fixture_agent("alpha", "http://a-new/");
        updated.description = "updated".into();
        upsert_agent(&mut agents, updated);
        assert_eq!(agents.len(), 2, "re-add replaces, never duplicates");
        assert_eq!(agents[0].name, "alpha");
        assert_eq!(agents[0].url, "http://a-new/");
        assert_eq!(agents[0].description, "updated");
    }

    #[test]
    fn remove_agent_is_idempotent() {
        let mut agents = vec![fixture_agent("alpha", "http://a/"), fixture_agent("beta", "http://b/")];
        assert!(remove_agent(&mut agents, "alpha"));
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "beta");
        // Removing an absent name is a no-op that reports `false`.
        assert!(!remove_agent(&mut agents, "alpha"));
        assert_eq!(agents.len(), 1);
    }
}
