//! The client-side A2A agent roster: `state/a2a-agents.json` (v0) — the set
//! of EXTERNAL A2A agents this aoide has registered by AgentCard URL (`aoide
//! a2a agent add`).
//!
//! Moved from `a2a.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::a2a::{A2aAgent, load_agents, …}` caller is untouched. The
//! server-side JSON-RPC door, AgentCard building, and everything else in
//! `a2a.rs` stays in root.

use crate::fs::{atomic_write, state_dir};
use serde::{Deserialize, Serialize};

/// `state/a2a-agents.json` schema version (CONTRACTS.md §4, v0).
pub const A2A_AGENTS_VERSION: &str = "0";

/// One registered external A2A agent. `url` is the RESOLVED `message/send`
/// endpoint (the card's own `url`/first-interface url, or the origin of the
/// fetched card URL) — what `agent send` POSTs to, NOT the card URL we GET'd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aAgent {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "registeredAt", default)]
    pub registered_at: String,
}

/// The `state/a2a-agents.json` container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct A2aAgentRegistry {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub agents: Vec<A2aAgent>,
}

/// The registry path: `state/a2a-agents.json` — the gitignored root-runtime
/// `state/` dir (CONTRACTS.md §2, the same root `state/usage.json` lives in),
/// NOT `song/stage/`.
pub fn agents_path() -> std::path::PathBuf {
    state_dir().join("a2a-agents.json")
}

/// Read the registry, tolerating a missing/corrupt/wrong-shape file as an
/// empty list (CONTRACTS.md §4 additive discipline — an absent file is simply
/// "no agents registered", never an error).
pub fn load_agents() -> Vec<A2aAgent> {
    match std::fs::read_to_string(agents_path()) {
        Ok(raw) => serde_json::from_str::<A2aAgentRegistry>(&raw)
            .map(|r| r.agents)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Atomic-write the registry (v0 shape) back to `state/a2a-agents.json`.
pub fn save_agents(agents: &[A2aAgent]) -> Result<(), String> {
    let reg = A2aAgentRegistry {
        schema_version: A2A_AGENTS_VERSION.to_string(),
        agents: agents.to_vec(),
    };
    let body = serde_json::to_string_pretty(&reg)
        .map_err(|e| format!("serialize a2a-agents.json: {e}"))?
        + "\n";
    let path = agents_path();
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Insert or REPLACE an agent by `name` (dedupe on re-add — the newest card
/// wins). Pure list mutation, so the CRUD is unit-testable off disk.
pub fn upsert_agent(agents: &mut Vec<A2aAgent>, agent: A2aAgent) {
    if let Some(slot) = agents.iter_mut().find(|a| a.name == agent.name) {
        *slot = agent;
    } else {
        agents.push(agent);
    }
}

/// Remove an agent by `name`. Returns whether anything was removed, so the
/// handler can report an idempotent no-op cleanly. Pure.
pub fn remove_agent(agents: &mut Vec<A2aAgent>, name: &str) -> bool {
    let before = agents.len();
    agents.retain(|a| a.name != name);
    agents.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture_agent(name: &str, url: &str) -> A2aAgent {
        A2aAgent {
            name: name.to_string(),
            url: url.to_string(),
            description: format!("{name} desc"),
            registered_at: "2026-08-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn load_save_agents_round_trip_through_a_temp_state_dir() {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-a2a-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        // Missing file → empty (tolerate-missing).
        assert!(load_agents().is_empty());

        let agents = vec![fixture_agent("alpha", "http://a/"), fixture_agent("beta", "http://b/")];
        save_agents(&agents).unwrap();
        let back = load_agents();
        assert_eq!(back, agents);

        // The on-disk shape carries the v0 schemaVersion.
        let raw = std::fs::read_to_string(agents_path()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["schemaVersion"], "0");
        assert_eq!(v["agents"].as_array().unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
    }
}
