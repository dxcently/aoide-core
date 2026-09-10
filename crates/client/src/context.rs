//! Explicit shared persona/memory fetches through the daemon's configured Mneme
//! credential. No cache, vault write, prompt insertion, or implicit access grant.

use aoide_protocol::{Door, Invocation};
use aoide_protocol::output::Outcome;
use aoide_storage::config::{AgentContext, ContextVault};
use aoide_storage::records::SessionsFile;
use aoide_storage::stage::{load_stage, sessions_path};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The local CLI asks aoided to read; its own token environment is never forwarded.
pub fn session_context(inv: &Invocation) -> Outcome {
    const CMD: &str = "context";
    match inv.door {
        Door::Cli => {
            // Six sequential reads/handshake requests plus one cleanup, 15s each.
            let mut out = crate::daemon::daemon_dispatch_with_timeout(inv, std::time::Duration::from_secs(120))
                .unwrap_or_else(|| failure("aoided must be running to fetch agent context"));
            if out.status != aoide_protocol::output::Status::Ok && out.data.is_none() {
                out.data = Some(json!({"complete":false}));
            }
            return out;
        }
        Door::Daemon => {}
        _ => return Outcome::error(CMD, "context is local-only; remote doors cannot use the daemon's Mneme credential"),
    }
    let Some(id) = inv.flags.get("id").filter(|id| !id.is_empty()) else {
        return Outcome::usage(CMD, "usage: aoide context --id <session-id>");
    };
    let sessions: SessionsFile = match load_stage(&sessions_path()) {
        Ok(sessions) => sessions,
        Err(e) => return Outcome::error(CMD, e),
    };
    let Some(session) = sessions.sessions.iter().find(|s| &s.session_id == id) else {
        return failure("unknown-session");
    };
    let Some(key) = session.enduring_agent_id.as_deref() else {
        return failure("session-has-no-enduring-binding");
    };
    let loaded = match aoide_storage::config::load() {
        Ok(config) => config,
        Err(e) => return Outcome::error(CMD, e.to_string()),
    };
    let Some(agent) = loaded.config.context.agents.get(key) else {
        return failure("unknown-enduring-agent");
    };
    let Some(vault) = loaded.config.context.vaults.get(&agent.vault) else {
        return failure("unknown-logical-vault");
    };
    let token = match std::env::var(&vault.token_env) {
        Ok(token) if !token.is_empty() && !token.chars().any(char::is_control) => token,
        _ => return Outcome::error(CMD, format!(
            "configure {} in aoided's environment before fetching context", vault.token_env,
        )).with_data(json!({"reason":"missing-or-invalid-daemon-credential", "complete":false})),
    };
    let mut client = match crate::mcp_client::McpSession::connect(|method: &str, body: &str, headers: &[(String, String)]| {
        crate::commands::request_json_with_headers(method, &vault.endpoint, body, &token, headers, 15)
    }) {
        Ok(client) => client,
        Err(reason) => return failure(&reason),
    };
    let mut data = fetch_context(id, key, agent, vault, |function, args| client.mneme_rpc(function, args));
    data["sessionCleanup"] = json!(client.close());
    if data["complete"] == true {
        Outcome::ok(CMD, "persona and memory fetched; reads are sequential, not an atomic vault snapshot").with_data(data)
    } else {
        Outcome::error(CMD, "agent context is incomplete; inspect retrieval errors before using it").with_data(data)
    }
}

fn failure(reason: &str) -> Outcome {
    Outcome::error("context", reason).with_data(json!({"reason":reason, "complete":false}))
}

fn fetch_context(
    session_id: &str,
    key: &str,
    agent: &AgentContext,
    vault: &ContextVault,
    mut rpc: impl FnMut(&str, Value) -> Result<String, String>,
) -> Value {
    let mut notes = Vec::new();
    let mut errors = Vec::new();
    for (role, requested) in [("persona", &agent.persona_note), ("memory", &agent.memory_note)] {
        let folder = requested.rsplit_once('/').map(|(folder, _)| folder).unwrap_or("");
        let fetched = (|| {
            let listing = rpc("list_notes", json!({"vault":vault.vault, "folder":folder}))?;
            if !listing.lines().any(|line| line.strip_prefix("- ") == Some(requested.as_str())) {
                return Err("canonical-reference-not-listed".into());
            }
            rpc("read_note", json!({"vault":vault.vault, "title":requested, "hashed":false}))
        })();
        match fetched {
            Ok(content) => notes.push(json!({
                "role":role, "requestedNote":requested, "pathListedBeforeRead":true,
                "sha256":Sha256::digest(content.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "retrievedAt":aoide_storage::time::now_iso_utc(), "content":content,
            })),
            Err(reason) => {
                errors.push(json!({"role":role, "requestedNote":requested, "reason":reason}));
                break;
            }
        }
    }
    json!({
        "sessionId":session_id, "enduringAgentId":key,
        "vaultRef":agent.vault, "endpoint":vault.endpoint, "serverVault":vault.vault,
        "complete":errors.is_empty(), "notes":notes, "errors":errors,
        "consistency":"sequential-not-atomic",
        "referenceResolution":"exact-path-listing-preflight; read_note may alias-resolve if the path changes before reading",
        "sourceRevision":null,
    })
}

pub fn register(r: &mut aoide_protocol::registry::Registry) {
    use aoide_protocol::registry::{cmd, flag};
    r.insert(cmd!(
        path: ["context"],
        summary: "Fetch a bound executor's canonical persona and memory through aoided's configured Mneme credential. Explicit local read; no cache, memory write, or prompt insertion.",
        args: [],
        flags: [flag!("id", "string", "Existing bound session id (required).")],
        gated: false,
        implemented: true,
        handler: session_context,
        examples: ["context --id executor-1 --json"],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> (AgentContext, ContextVault) {
        (AgentContext {
            vault:"knowledge".into(), persona_note:"personas/rook.md".into(), memory_note:"memory/rook.md".into(),
        }, ContextVault {
            endpoint:"https://mneme.invalid/mcp".into(), vault:"Personal".into(), token_env:"MNEME_TOKEN".into(),
        })
    }

    #[test]
    fn two_harness_sessions_share_sources_but_keep_executor_identity() {
        let (agent, vault) = config();
        let fetch = |id| fetch_context(id, "opaque-1", &agent, &vault, |function, args| {
            assert_eq!(args["vault"], "Personal");
            if function == "list_notes" { return Ok("2 note(s):\n- personas/rook.md\n- memory/rook.md".into()); }
            assert_eq!(function, "read_note");
            assert_eq!(args["hashed"], false);
            Ok("abc".into())
        });
        let claude = fetch("claude-executor");
        let codex = fetch("codex-executor");
        assert_ne!(claude["sessionId"], codex["sessionId"]);
        assert_eq!(claude["enduringAgentId"], codex["enduringAgentId"]);
        assert_eq!(claude["notes"][0]["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(claude["notes"][0]["content"], codex["notes"][0]["content"]);
        assert_eq!(claude["complete"], true);
        assert!(claude["sourceRevision"].is_null());
    }

    #[test]
    fn missing_canonical_path_does_not_fall_back_to_an_alias_read() {
        let (agent, vault) = config();
        let mut calls = 0;
        let data = fetch_context("s", "a", &agent, &vault, |function, _| {
            calls += 1;
            assert_eq!(function, "list_notes");
            Ok("1 note(s):\n- archive/rook.md".into())
        });
        assert_eq!(calls, 1);
        assert_eq!(data["complete"], false);
        assert_eq!(data["errors"][0]["reason"], "canonical-reference-not-listed");
        assert_eq!(data["notes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn denied_memory_is_an_explicit_partial_retrieval_without_fabricated_content() {
        let (agent, vault) = config();
        let data = fetch_context("s", "a", &agent, &vault, |function, args| {
            if args["folder"] == "memory" { return Err("mneme-access-denied".into()); }
            Ok(if function == "list_notes" { "1 note(s):\n- personas/rook.md" } else { "persona" }.into())
        });
        assert_eq!(data["complete"], false);
        assert_eq!(data["notes"].as_array().unwrap().len(), 1);
        assert_eq!(data["notes"][0]["role"], "persona");
        assert_eq!(data["errors"][0]["role"], "memory");
        assert_eq!(data["errors"][0]["reason"], "mneme-access-denied");
    }

    #[test]
    fn remote_doors_cannot_reach_credentials_or_network() {
        for door in [Door::Mcp, Door::A2a] {
            let out = session_context(&Invocation { path: vec!["context".into()],
                args:vec![], flags:Default::default(), door });
            assert_eq!(out.status, aoide_protocol::output::Status::Error);
            assert!(out.message.contains("local-only"));
        }
    }
}
