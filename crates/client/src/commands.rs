//! The client domain's CLI verbs (CONTRACTS.md §6): `a2a agent
//! add|list|remove|send` (the outbound half — aoide DRIVES external A2A
//! agents) and `adapter melete` (the neutral-event consumer).
//!
//! Moved from the root package's `src/commands/a2a.rs` + the client half of
//! `src/commands/infra.rs` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI verbs live with the
//! domain. The root package's `commands::all()` calls [`register_agents`]
//! directly after `aoide_server::commands::register_a2a_serve` and
//! [`register_post_graph`] directly before `aoide_conductor::commands::register`,
//! so `schema --json` order never shifts.
//!
//! The registry lives in `state/a2a-agents.json` (`aoide_storage::a2a_store`)
//! and folds into the session DAG as `kind:"a2a"` nodes
//! (`graph/doc.rs::build_graph`). These endpoints are external and carry NO
//! local credential, so a plain curl (url/body in argv or stdin) is fine;
//! SSRF isn't guarded: the url is the user's own CLI argument, a
//! user-initiated fetch.

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::io::Write;
use std::process::Stdio;

// ── curl transport ((code, body) discipline from commands/usage.rs) ─────────

/// Run `curl -sS --max-time 15 -w '\n%{http_code}' <extra…>`, optionally piping
/// `stdin_body` (for a POST via `--data-binary @-`), and return
/// `(http_code, body)`. The `-w` trailing line is the status; the rest is the
/// body. A spawn/pipe failure, empty/garbled output, or a `000` (connection
/// failure/timeout) all map to `Err`. `stderr` is nulled so nothing curl prints
/// surfaces. No secret is involved (external endpoint, no local credential), so
/// the url/body may ride in argv freely — this reuses usage.rs's parsing, not
/// its token-hiding.
fn run_curl(extra: &[&str], stdin_body: Option<&str>) -> Result<(u16, String), String> {
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sS", "--max-time", "15", "-w", "\n%{http_code}"]);
    cmd.args(extra);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.stdin(if stdin_body.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd
        .spawn()
        .map_err(|_| "curl failed (is curl installed?)".to_string())?;
    if let Some(body) = stdin_body {
        let mut si = child.stdin.take().ok_or_else(|| "curl failed".to_string())?;
        si.write_all(body.as_bytes())
            .map_err(|_| "curl failed".to_string())?;
    }
    let out = child
        .wait_with_output()
        .map_err(|_| "curl failed".to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (body, code_str) = match stdout.rsplit_once('\n') {
        Some((b, c)) => (b, c.trim()),
        None => ("", stdout.trim()),
    };
    let code: u16 = code_str
        .parse()
        .map_err(|_| "curl failed (no HTTP status)".to_string())?;
    if code == 0 {
        return Err("could not reach the agent (connection failed or timed out)".to_string());
    }
    Ok((code, body.to_string()))
}

/// A unique `messageId` for one outbound `message/send` (pid + wall-clock
/// nanos — never reused within a process).
fn gen_message_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("aoide-{}-{}", std::process::id(), nanos)
}

/// A short human summary of a `message/send` reply (a Task or a Message).
fn describe_result(resp: &Value) -> String {
    let Some(result) = resp.get("result") else {
        return "reply received".to_string();
    };
    if let Some(state) = result
        .get("status")
        .and_then(|s| s.get("state"))
        .and_then(Value::as_str)
    {
        let id = result.get("id").and_then(Value::as_str).unwrap_or("");
        return format!("task {id} [{state}]");
    }
    match result.get("kind").and_then(Value::as_str) {
        Some(kind) => format!("{kind} reply"),
        None => "reply received".to_string(),
    }
}

// ── The four `agent` verbs (client side, CONTRACTS.md §6) ────────────────────

/// `a2a agent add <url>` — fetch the AgentCard, parse it, register the agent.
fn handle_agent_add(inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.add";
    let url = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent add <url> [--json]"),
    };
    let card_url = crate::wire::resolve_card_url(&url);
    let (code, body) = match run_curl(&["--", &card_url], None) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("fetching AgentCard {card_url}: {e}"))
                .with_data(json!({ "reason": "fetch-failed", "url": card_url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("fetching AgentCard {card_url}: HTTP {code}"))
            .with_data(json!({ "reason": "fetch-http-error", "url": card_url, "httpCode": code }));
    }
    let card: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("parsing AgentCard {card_url}: {e}"))
                .with_data(json!({ "reason": "card-unparseable", "url": card_url }))
        }
    };
    let now = aoide_storage::time::now_iso_utc();
    let agent = match crate::wire::parse_agent_card(&card, &card_url, &now) {
        Ok(a) => a,
        Err(e) => {
            return Outcome::error(cmd, format!("invalid AgentCard {card_url}: {e}"))
                .with_data(json!({ "reason": "card-invalid", "url": card_url }))
        }
    };
    let mut agents = aoide_storage::a2a_store::load_agents();
    let replaced = agents.iter().any(|a| a.name == agent.name);
    aoide_storage::a2a_store::upsert_agent(&mut agents, agent.clone());
    if let Err(e) = aoide_storage::a2a_store::save_agents(&agents) {
        return Outcome::error(cmd, format!("writing the agent registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    let verb = if replaced { "updated" } else { "registered" };
    Outcome::ok(
        cmd,
        format!(
            "{verb} A2A agent `{}` → {} ({} total)",
            agent.name,
            agent.url,
            agents.len()
        ),
    )
    .changed(vec![aoide_storage::a2a_store::agents_path().to_string_lossy().into_owned()])
    .with_data(json!({ "agent": agent, "count": agents.len(), "replaced": replaced }))
}

/// `a2a agent list` — the registered agents (name · url · description).
fn handle_agent_list(_inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.list";
    let agents = aoide_storage::a2a_store::load_agents();
    let msg = if agents.is_empty() {
        "no external A2A agents registered".to_string()
    } else {
        let lines: Vec<String> = agents
            .iter()
            .map(|a| {
                if a.description.is_empty() {
                    format!("{} · {}", a.name, a.url)
                } else {
                    format!("{} · {} · {}", a.name, a.url, a.description)
                }
            })
            .collect();
        format!(
            "{} registered A2A agent(s):\n{}",
            agents.len(),
            lines.join("\n")
        )
    };
    Outcome::ok(cmd, msg).with_data(json!({ "agents": agents, "count": agents.len() }))
}

/// `a2a agent remove <name>` — drop the named agent (idempotent).
fn handle_agent_remove(inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.remove";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent remove <name> [--json]"),
    };
    let mut agents = aoide_storage::a2a_store::load_agents();
    if !aoide_storage::a2a_store::remove_agent(&mut agents, &name) {
        return Outcome::ok(cmd, format!("no A2A agent named `{name}` (nothing to remove)"))
            .with_data(json!({ "removed": false, "name": name, "count": agents.len() }));
    }
    if let Err(e) = aoide_storage::a2a_store::save_agents(&agents) {
        return Outcome::error(cmd, format!("writing the agent registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(
        cmd,
        format!("removed A2A agent `{name}` ({} remaining)", agents.len()),
    )
    .changed(vec![aoide_storage::a2a_store::agents_path().to_string_lossy().into_owned()])
    .with_data(json!({ "removed": true, "name": name, "count": agents.len() }))
}

/// `a2a agent send <name> <message>` — DRIVE a registered external agent: POST
/// a JSON-RPC `message/send` to its endpoint and report the returned
/// Task/Message. The outbound half of the bidirectional A2A link.
fn handle_agent_send(inv: &Invocation) -> Outcome {
    let cmd = "a2a.agent.send";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent send <name> <message> [--json]"),
    };
    let message = match inv.args.get(1).filter(|s| !s.is_empty()) {
        Some(m) => m.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide a2a agent send <name> <message> [--json]"),
    };
    let agents = aoide_storage::a2a_store::load_agents();
    let agent = match agents.iter().find(|a| a.name == name) {
        Some(a) => a.clone(),
        None => {
            return Outcome::error(
                cmd,
                format!("no A2A agent named `{name}` — register it first with `aoide a2a agent add <url>`"),
            )
            .with_data(json!({ "reason": "unknown-agent", "name": name }))
        }
    };
    let message_id = gen_message_id();
    let body = crate::wire::build_message_send_body(&message, &message_id);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let (code, resp) = match run_curl(
        &[
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            "--",
            &agent.url,
        ],
        Some(&body_str),
    ) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("driving `{name}` at {}: {e}", agent.url))
                .with_data(json!({ "reason": "send-failed", "name": name, "url": agent.url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("driving `{name}` at {}: HTTP {code}", agent.url))
            .with_data(json!({
                "reason": "send-http-error", "name": name, "url": agent.url,
                "httpCode": code, "body": resp,
            }));
    }
    let parsed: Value = serde_json::from_str(&resp).unwrap_or(Value::Null);
    // A JSON-RPC error still returns HTTP 200 — surface it as an error Outcome.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Outcome::error(cmd, format!("agent `{name}` returned an error: {detail}"))
            .with_data(json!({ "reason": "agent-error", "name": name, "response": parsed }));
    }
    Outcome::ok(
        cmd,
        format!("sent to `{name}` at {} — {}", agent.url, describe_result(&parsed)),
    )
    .with_data(json!({
        "name": name, "url": agent.url, "messageId": message_id, "response": parsed,
    }))
}

// ── The five `peer` verbs (CONTRACTS.md §7: same-network federation) ────────
//
// A peer is ANOTHER aoide instance, addressed by URL (topology-agnostic —
// the protocol never cares whether that URL happens to resolve on the same
// loopback host, a LAN, or a tailnet; it's just a URL). `peer add` verifies
// by fetching the peer's AgentCard first (mirrors `a2a agent add`'s
// verification-before-registering pattern exactly); `peer pull` calls the
// NEW `aoide/graphSummary` method (`aoide-server::a2a::graph_summary`) and
// caches the result; `build_graph` (`aoide-conduct`) folds a fresh cache in
// as a `peer:<name>` root node. The registry lives in `state/peers.json`
// (`aoide_storage::peer_store`), mirroring `state/a2a-agents.json` — external
// registry-style state, not song-scoped rehearsal state.

/// `peer add <name> <url> [--autogate]` — verify the peer by fetching its
/// AgentCard first (mirrors `a2a agent add`'s verification-before-registering
/// pattern above exactly), then register `name` → `url`. Unlike `a2a agent
/// add`'s upsert-replace-on-readd, a duplicate `name` is rejected cleanly —
/// CONTRACTS.md §7's explicit divergence (a peer's local nickname should
/// never be silently repointed at a different URL by a second `add`).
fn handle_peer_add(inv: &Invocation) -> Outcome {
    let cmd = "peer.add";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer add <name> <url> [--autogate] [--json]"),
    };
    let url = match inv.args.get(1).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer add <name> <url> [--autogate] [--json]"),
    };
    // `name` is joined straight into `state/peer-cache/<name>.json`
    // (`peer_store::peer_cache_path`) — reject a traversal shape here,
    // before it's ever registered, same guard `rice compose` applies to a
    // song name.
    if !aoide_storage::peer_store::valid_peer_name(&name) {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` is not a valid peer nickname: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }
    let autogate = inv.flag_present("autogate");

    let mut peers = aoide_storage::peer_store::load_peers();
    if peers.iter().any(|p| p.name == name) {
        return Outcome::error(cmd, format!("peer `{name}` is already registered — remove it first to re-add"))
            .with_data(json!({ "reason": "duplicate-name", "name": name }));
    }

    // Verify: fetch the peer's AgentCard BEFORE registering anything — a
    // peer that fails this fetch never gets added.
    let card_url = crate::wire::resolve_card_url(&url);
    let (code, body) = match run_curl(&["--", &card_url], None) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("verifying peer AgentCard at {card_url}: {e}"))
                .with_data(json!({ "reason": "fetch-failed", "url": card_url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("verifying peer AgentCard at {card_url}: HTTP {code}"))
            .with_data(json!({ "reason": "fetch-http-error", "url": card_url, "httpCode": code }));
    }
    if serde_json::from_str::<Value>(&body).is_err() {
        return Outcome::error(cmd, format!("verifying peer AgentCard at {card_url}: unparseable response"))
            .with_data(json!({ "reason": "card-unparseable", "url": card_url }));
    }

    let peer = aoide_storage::peer_store::Peer {
        name: name.clone(),
        url: url.clone(),
        autogate,
        added_at: aoide_storage::time::now_iso_utc(),
    };
    aoide_storage::peer_store::insert_peer(&mut peers, peer.clone());
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(
        cmd,
        format!(
            "registered peer `{name}` → {url}{} ({} total)",
            if autogate { " (autogate)" } else { "" },
            peers.len()
        ),
    )
    .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
    .with_data(json!({ "peer": peer, "count": peers.len() }))
}

/// `peer list` — the registered peers (name · url · autogate).
fn handle_peer_list(_inv: &Invocation) -> Outcome {
    let cmd = "peer.list";
    let peers = aoide_storage::peer_store::load_peers();
    let msg = if peers.is_empty() {
        "no peers registered".to_string()
    } else {
        let lines: Vec<String> = peers
            .iter()
            .map(|p| {
                if p.autogate {
                    format!("{} · {} · autogate", p.name, p.url)
                } else {
                    format!("{} · {}", p.name, p.url)
                }
            })
            .collect();
        format!("{} registered peer(s):\n{}", peers.len(), lines.join("\n"))
    };
    Outcome::ok(cmd, msg).with_data(json!({ "peers": peers, "count": peers.len() }))
}

/// `peer remove <name>` — deregister; a MISSING name is a clean error, not
/// idempotent-silent (following `rice draft drop <name>`'s precedent: a
/// missing target is a real mistake worth surfacing, unlike `a2a agent
/// remove`'s tolerate-missing stance — CONTRACTS.md §7 calls this out
/// explicitly as the deliberately different one). Also drops the peer's
/// cache file, if any, so a re-added-under-the-same-name peer never starts
/// from a stale leftover.
fn handle_peer_remove(inv: &Invocation) -> Outcome {
    let cmd = "peer.remove";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer remove <name> [--json]"),
    };
    // Defense in depth (mirrors `handle_peer_add`'s own guard): `name` is
    // about to reach `peer_cache_path(&name)` below via `remove_file`, a
    // DELETE — refuse a traversal shape even if it somehow got past `add`
    // (e.g. a hand-edited `state/peers.json`) before it ever reaches that
    // path join.
    if !aoide_storage::peer_store::valid_peer_name(&name) {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` is not a valid peer nickname: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }
    let mut peers = aoide_storage::peer_store::load_peers();
    if !aoide_storage::peer_store::remove_peer(&mut peers, &name) {
        return Outcome::error(cmd, format!("no peer named `{name}`"))
            .with_data(json!({ "reason": "unknown-peer", "name": name }));
    }
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    let _ = std::fs::remove_file(aoide_storage::peer_store::peer_cache_path(&name));
    Outcome::ok(cmd, format!("removed peer `{name}` ({} remaining)", peers.len()))
        .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
        .with_data(json!({ "removed": true, "name": name, "count": peers.len() }))
}

/// Pull ONE peer: POST `aoide/graphSummary`, parse, write the cache. On ANY
/// failure (unreachable, timeout, non-200, malformed) — mark the cache
/// STALE with the failure reason rather than deleting it or propagating the
/// error to the caller, so one peer being down never breaks `peer pull` for
/// the others (`handle_peer_pull` below iterates every selected peer through
/// this regardless of an individual failure). Returns a small JSON summary
/// row for the aggregate Outcome's `data.results`.
fn pull_one_peer(peer: &aoide_storage::peer_store::Peer) -> Value {
    let now = aoide_storage::time::now_iso_utc();
    let body = crate::peer::build_graph_summary_request();
    let body_str = serde_json::to_string(&body).unwrap_or_default();

    let attempt: Result<aoide_storage::peer_store::PeerCacheEntry, String> = (|| {
        let (code, resp_body) = run_curl(
            &["-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@-", "--", &peer.url],
            Some(&body_str),
        )?;
        if code != 200 {
            return Err(format!("HTTP {code}"));
        }
        let resp: Value =
            serde_json::from_str(&resp_body).map_err(|e| format!("unparseable response: {e}"))?;
        crate::peer::parse_graph_summary_response(&resp, &peer.name, &now)
    })();

    match attempt {
        Ok(entry) => {
            let write_err = aoide_storage::peer_store::save_peer_cache(&entry).err();
            match write_err {
                None => json!({ "name": peer.name, "ok": true, "fetchedAt": now }),
                Some(e) => json!({ "name": peer.name, "ok": false, "error": format!("cache write failed: {e}") }),
            }
        }
        Err(e) => {
            // Preserve whatever was already cached (the last GOOD pull) —
            // only flip `stale`/`lastError`; never delete, never blank the
            // peer out of the fold over a transient outage.
            let mut entry = aoide_storage::peer_store::load_peer_cache(&peer.name).unwrap_or_else(|| {
                aoide_storage::peer_store::PeerCacheEntry {
                    schema_version: "0".to_string(),
                    name: peer.name.clone(),
                    ..Default::default()
                }
            });
            entry.stale = true;
            entry.last_error = Some(e.clone());
            let _ = aoide_storage::peer_store::save_peer_cache(&entry);
            json!({ "name": peer.name, "ok": false, "error": e })
        }
    }
}

/// `peer pull [<name>]` — pull `aoide/graphSummary` from one (or, with no
/// name, EVERY) registered peer. One peer being down must never break the
/// command for the others — see [`pull_one_peer`].
fn handle_peer_pull(inv: &Invocation) -> Outcome {
    let cmd = "peer.pull";
    let peers = aoide_storage::peer_store::load_peers();
    let target = inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty());
    let selected: Vec<aoide_storage::peer_store::Peer> = match target {
        Some(name) => match peers.iter().find(|p| p.name == name) {
            Some(p) => vec![p.clone()],
            None => {
                return Outcome::error(cmd, format!("no peer named `{name}`"))
                    .with_data(json!({ "reason": "unknown-peer", "name": name }))
            }
        },
        None => peers,
    };
    if selected.is_empty() {
        return Outcome::ok(cmd, "no peers registered — nothing to pull").with_data(json!({ "results": [] }));
    }

    let results: Vec<Value> = selected.iter().map(pull_one_peer).collect();
    let ok_count = results.iter().filter(|r| r["ok"] == true).count();
    Outcome::ok(cmd, format!("pulled {ok_count}/{} peer(s) successfully", selected.len()))
        .with_data(json!({ "results": results }))
}

/// `peer status` — each registered peer's last-pull outcome and staleness
/// (`fresh` within [`aoide_storage::peer_store::PEER_CACHE_TTL_SECS`],
/// `stale` past it or explicitly marked so, `never-pulled` with no cache
/// file at all) — the same three-way classification `build_graph`'s fold
/// uses (`aoide-conduct::graph::doc`), so this and the DAG never disagree.
fn handle_peer_status(_inv: &Invocation) -> Outcome {
    let cmd = "peer.status";
    let peers = aoide_storage::peer_store::load_peers();
    let now_epoch =
        aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let rows: Vec<Value> = peers
        .iter()
        .map(|p| {
            let cache = aoide_storage::peer_store::load_peer_cache(&p.name);
            let (state, fetched_at, error) = match &cache {
                Some(entry) if aoide_storage::peer_store::is_cache_fresh(entry, now_epoch) => {
                    ("fresh", entry.fetched_at.clone(), None)
                }
                Some(entry) => ("stale", entry.fetched_at.clone(), entry.last_error.clone()),
                None => ("never-pulled", None, None),
            };
            json!({
                "name": p.name, "url": p.url, "autogate": p.autogate,
                "state": state, "fetchedAt": fetched_at, "error": error,
            })
        })
        .collect();
    let msg = if rows.is_empty() {
        "no peers registered".to_string()
    } else {
        format!("{} peer(s) registered", rows.len())
    };
    Outcome::ok(cmd, msg).with_data(json!({ "peers": rows }))
}

/// The five `peer` verbs (CONTRACTS.md §7), registered as their own group.
pub fn register_peers(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "add"],
        summary: "Register a peer aoide instance (verified by AgentCard fetch first) as a federation node in the session DAG.",
        args: [
            arg!("name", "string", true, "A local nickname for this peer."),
            arg!("url", "string", true, "The peer's A2A door URL (e.g. http://host:8710/)."),
        ],
        flags: [flag!("autogate", "bool", "Trust this peer: its inbound message/send auto-delivers without the pending queue.")],
        gated: false,
        implemented: true,
        handler: handle_peer_add,
    ));
    r.insert(cmd!(
        path: ["peer", "list"],
        summary: "List registered peers.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_list,
    ));
    r.insert(cmd!(
        path: ["peer", "remove"],
        summary: "Unregister a peer (a missing name is an error, not a silent no-op).",
        args: [arg!("name", "string", true, "The registered peer's name.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_remove,
    ));
    r.insert(cmd!(
        path: ["peer", "pull"],
        summary: "Pull aoide/graphSummary from one (or, with no name, every) registered peer and refresh its cache.",
        args: [arg!("name", "string", false, "Pull only this peer; omit to pull every registered peer.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_pull,
    ));
    r.insert(cmd!(
        path: ["peer", "status"],
        summary: "Report each registered peer's last-pull outcome and cache staleness.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_status,
    ));
}

/// `adapter melete`'s handler (moved from the root package's `infra.rs`).
fn handle_adapter_melete(_inv: &Invocation) -> Outcome {
    let status = crate::adapter::run_melete();
    Outcome::ok(
        "adapter.melete",
        "melete-adapter skeleton self-check complete",
    )
    .with_data(status)
}

/// The four `agent` verbs, registered at the historical `a2a` position
/// (directly after `a2a serve`, which `aoide-server` registers).
pub fn register_agents(r: &mut Registry) {
    r.insert(cmd!(
        path: ["a2a", "agent", "add"],
        summary: "Register an external A2A agent (by AgentCard URL) as a node in the session DAG.",
        args: [arg!("url", "string", true, "The external agent's AgentCard URL (or origin — the well-known path is appended).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_add,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "list"],
        summary: "List registered external A2A agents.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_list,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "remove"],
        summary: "Unregister an external A2A agent.",
        args: [arg!("name", "string", true, "The registered agent's name.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_remove,
    ));
    r.insert(cmd!(
        path: ["a2a", "agent", "send"],
        summary: "Drive a registered external A2A agent: POST a JSON-RPC message/send and report the returned Task/Message.",
        args: [
            arg!("name", "string", true, "The registered agent's name."),
            arg!("message", "string", true, "The message text to send."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_agent_send,
    ));
}

/// The post-`graph` client verb: `adapter melete` (registered directly
/// before `conductor`, which `aoide-conductor` registers).
pub fn register_post_graph(r: &mut Registry) {
    r.insert(cmd!(
        path: ["adapter", "melete"],
        summary: "Run the melete-adapter: consume the neutral event stream (default-deny per class).",
        args: [],
        flags: [flag!("run", "bool", "Run the long-lived adapter process.")],
        gated: false,
        implemented: true,
        handler: handle_adapter_melete,
    ));
}
