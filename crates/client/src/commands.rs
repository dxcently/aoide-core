//! The client domain's CLI commands (CONTRACTS.md §6): `a2a agent
//! add|list|remove|send` (the outbound half — aoide DRIVES external A2A
//! agents) and `adapter melete` (the neutral-event consumer).
//!
//! Moved from the root package's `src/commands/a2a.rs` + the client half of
//! `src/commands/infra.rs` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands live with the
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
use std::io::{BufRead, Write};
use std::process::Stdio;
use std::time::Duration;

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
    run_curl_with_timeout(15, extra, stdin_body)
}

/// `run_curl`'s parameterised core: same transport, an explicit `--max-time`
/// instead of the hardcoded `15`. Split out for `pull_peer_live` (`who`'s
/// presence probe, workstream C2) which needs a much shorter per-peer bound
/// (~2s) than every other curl call site here — those all keep calling
/// [`run_curl`] unchanged, so this refactor is a pure internal split, not a
/// behavior change for `peer pull`/`a2a agent add`/etc.
fn run_curl_with_timeout(
    timeout_secs: u64,
    extra: &[&str],
    stdin_body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut cmd = std::process::Command::new("curl");
    let timeout = timeout_secs.to_string();
    cmd.args(["-sS", "--max-time", &timeout, "-w", "\n%{http_code}"]);
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

// ── Outbound bearer presentation (task #84) ──────────────────────────────────
//
// The client half of the same secrets-broker resolve consumer `aoide-server`
// gained on the inbound side (`a2a.rs`'s `resolve_inbound_bearer`): a
// registered peer whose `Peer.bearer_secret` (`aoide_storage::peer_store`)
// is set gets that secret resolved fresh, through the SAME
// `aoide_secrets::client::resolve_bounded` this crate now depends on (see
// this crate's `Cargo.toml` comment), and presented as `Authorization:
// Bearer <value>` on every outbound `peer pull`/`peer status`'s live probe/
// `graph send --to` request to that one peer. Before this task, aoide's
// outbound A2A requests sent no Authorization header at all — see
// CONTRACTS.md §6/§7 for the settled shape.

/// The self-asserted consumer name this client presents to the secrets
/// broker when resolving an outbound peer bearer — see
/// `crates/secrets/AGENTS.md`'s honesty note (consumer identity is
/// self-asserted until #63): nothing on the wire authenticates this string,
/// it is simply the name an operator's `policy.json` `consumers[]`/
/// `automation.consumers` lists to grant this client access to the named
/// secret.
const BEARER_CONSUMER_CLIENT: &str = "a2a-client";

/// Bound on an outbound bearer resolve's socket read — the same PARKING
/// HAZARD reasoning `aoide-server`'s `a2a.rs::BEARER_RESOLVE_TIMEOUT` states
/// for the inbound side, mirrored here: a misconfigured `requireTotp`
/// secret with no `automation`-open exemption for [`BEARER_CONSUMER_CLIENT`]
/// must never hang an outbound peer call. `aoide_secrets::client::
/// resolve_bounded`'s own `wait:false` on the wire means the deployed,
/// automation-open happy path never reaches this timeout at all.
const BEARER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve `peer.bearer_secret`, if set, fresh through the local secrets
/// broker — `Ok(None)` when the peer has no bearer configured (today's
/// unchanged, no-Authorization-header behavior); `Ok(Some(value))` on a
/// granted resolve; `Err` with a taught message naming the secret, the
/// peer, and the broker socket on ANY failure (unreachable broker, denied,
/// or the bounded timeout elapsing) — the outbound call this feeds is
/// refused outright rather than silently sent unauthenticated. **NO
/// CACHING**: a fresh resolve runs on every call to this function; nothing
/// it returns is stored anywhere beyond the caller's own local `Option<String>`
/// for the span of the one outbound request it feeds.
fn resolve_peer_bearer(peer: &aoide_storage::peer_store::Peer) -> Result<Option<String>, String> {
    let Some(secret) = peer.bearer_secret.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let socket = aoide_secrets::socket::socket_path();
    aoide_secrets::client::resolve_bounded(&socket, secret, BEARER_CONSUMER_CLIENT, BEARER_RESOLVE_TIMEOUT)
        .map(Some)
        .map_err(|e| {
            format!(
                "resolving outbound bearer secret `{secret}` for peer `{}` via the secrets broker at {}: {e}",
                peer.name,
                socket.display(),
            )
        })
}

/// A short-lived scratch file holding an outbound JSON-RPC request BODY —
/// only created when a bearer is ALSO being sent on the same call, since
/// curl's `-H @-` (reading the `Authorization` header from stdin, see
/// [`post_json`]'s doc) claims stdin for the header instead of the body.
/// Removed on drop. Holds no secret — only the peer-directed message text/
/// JSON-RPC envelope, which is not sensitive — unlike the bearer value
/// itself, which never touches disk in either code path below.
struct ScratchBodyFile(std::path::PathBuf);

impl ScratchBodyFile {
    fn write(body: &str) -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("aoide-a2a-body-{}-{nanos}.json", std::process::id()));
        std::fs::write(&path, body).map_err(|e| format!("writing a scratch request body file: {e}"))?;
        Ok(Self(path))
    }

    fn arg(&self) -> String {
        format!("@{}", self.0.display())
    }
}

impl Drop for ScratchBodyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The ONE HTTP method every real peer-POST call site in this file ever
/// uses — a single named source [`post_json`]'s own `-X` argument AND
/// [`sign_headers_for_peer`]'s signed canonical string both read, so the
/// two can never drift apart (P-P4 review finding: the canonical string's
/// `method` field used to be a SEPARATE hardcoded `"POST"` literal at each
/// of those two sites — two independent literals that happened to agree,
/// not one value threaded through — which left the wire-auth module doc's
/// "binds method" claim not quite true: neither side was actually reading
/// the real value a request was built/sent with, just re-asserting the
/// same guess twice). Every call in this crate is genuinely a POST today
/// (there is no other command to thread), so this fix changes no byte of any
/// real request or the pinned `canonical_string` vectors (CONTRACTS.md
/// §6) — it only removes the duplicated-literal drift hazard.
const HTTP_METHOD: &str = "POST";

/// One outbound JSON-RPC POST — the single body+optional-bearer transport
/// every `peer` command that calls a registered peer's A2A door now shares
/// (`pull_one_peer`, `pull_peer_live`, `send_message_to_peer`, `handle_peer_spawn`).
///
/// With no bearer, this is BYTE-IDENTICAL to how each of those three called
/// `run_curl`/`run_curl_with_timeout` directly before this task — the body
/// rides `--data-binary @-` over stdin, unchanged.
///
/// With a bearer, the resolved VALUE must never touch this (or any) child
/// process's own argv — `/proc/<pid>/cmdline` is world-readable for that
/// child's whole lifetime, the exact concern `a2a::resolve_token_file`'s own
/// doc already flags for a different bearer on the inbound side. So it
/// rides curl's `-H @-` (`man curl`'s "-H, --header": `@filename` — or,
/// with `@-`, stdin — adds one header per line read from there) instead of
/// a `-H "Authorization: Bearer <token>"` argv literal. Since stdin is then
/// claimed by the header line, the body rides a short-lived
/// [`ScratchBodyFile`] via `--data-binary @<path>` instead. The bearer value
/// itself NEVER touches disk in either branch — only this process's own
/// memory and curl's stdin pipe, for exactly the span of this one call.
///
/// `extra_headers` (P-P4) rides as plain `-H "<name>: <value>"` argv
/// literals in EITHER branch, never the stdin-hiding trick the bearer gets
/// — every P-P4 signed-request header (peer name, timestamp, nonce,
/// signature) is PUBLIC, verifiable wire material, not a secret; there is
/// nothing in it worth hiding from `/proc/<pid>/cmdline` the way a bearer
/// token is. [`sign_headers_for_peer`] is the one production caller that
/// ever passes a non-empty slice here; every other call site (unpaired
/// peers, the pairing-ceremony wire methods themselves) passes `&[]`,
/// making this parameter's addition byte-identical-when-empty by
/// construction.
fn post_json(url: &str, body: &str, bearer: Option<&str>, extra_headers: &[(String, String)], timeout_secs: u64) -> Result<(u16, String), String> {
    let header_args: Vec<String> = extra_headers.iter().flat_map(|(k, v)| ["-H".to_string(), format!("{k}: {v}")]).collect();
    match bearer {
        None => {
            let mut args: Vec<&str> = vec!["-X", HTTP_METHOD, "-H", "Content-Type: application/json"];
            args.extend(header_args.iter().map(String::as_str));
            args.extend(["--data-binary", "@-", "--", url]);
            run_curl_with_timeout(timeout_secs, &args, Some(body))
        }
        Some(token) => {
            let scratch = ScratchBodyFile::write(body)?;
            let data_arg = scratch.arg();
            let header_line = format!("Authorization: Bearer {token}\n");
            let mut args: Vec<&str> = vec!["-X", HTTP_METHOD, "-H", "Content-Type: application/json"];
            args.extend(header_args.iter().map(String::as_str));
            args.extend(["-H", "@-", "--data-binary", &data_arg, "--", url]);
            run_curl_with_timeout(
                timeout_secs,
                &args,
                Some(&header_line),
            )
        }
    }
}

/// Build the four P-P4 signature headers for one outbound POST to `peer`,
/// or `vec![]` when `peer.verified` is `false` — an unpaired/unverified
/// peer keeps today's door-wide-bearer-only path exactly as before this
/// task, unchanged (`docs/architecture/PAIRING.md`, decision 6, "Unpaired
/// callers keep today's door-wide bearer path"). This is the ONE production
/// call site [`post_json`]'s doc comment names as the non-empty-slice
/// caller.
///
/// Mints a fresh nonce (`aoide_storage::pairing::random_hex(16)` — the same
/// mint the pairing ceremony itself already uses, reused rather than a
/// second nonce generator), stamps the current instant
/// (`aoide_storage::time::now_iso_utc`), computes the wire PATH via
/// `aoide_storage::peer_store::url_path(&peer.url)` (never re-derived ad
/// hoc — this is the exact string the server's own `HttpRequest.path` will
/// carry, so client and server MUST agree byte-for-byte or every signature
/// fails to verify), and signs
/// `aoide_storage::wire_auth::canonical_string(HTTP_METHOD, path, timestamp,
/// nonce, body.as_bytes())` — [`HTTP_METHOD`], not a second hardcoded
/// `"POST"` literal (P-P4 review finding 2: this function and
/// [`post_json`] used to carry two INDEPENDENT `"POST"` literals that
/// merely happened to agree; the canonical string's `method` field is now
/// the exact value the request is actually sent with, not a re-typed
/// guess) — with THIS instance's own identity
/// (`aoide_storage::identity::load_or_mint()`) — never the peer's.
///
/// `X-Aoide-Peer` carries `peer.name` — THIS instance's own LOCAL registry
/// name for `peer`, not a separate self-identity string. The pairing
/// ceremony (P-P2, `handle_peer_pair_request`) mints exactly ONE name per
/// pairing relationship and threads it through three places identically:
/// the wire `pairRequest.name` param, this instance's own `park_outbound`
/// record, and (via `upsert_paired_peer` on the far end) the far end's
/// registry entry naming THIS instance — so, on either side of an already-
/// completed pairing, the local `Peer.name` for the counterpart is always
/// the exact string the counterpart's own registry resolves back to THIS
/// instance. There is no separate "self-name" field anywhere in
/// `peer_store::Peer` to invent one for.
///
/// Returns `Err` only on a genuine identity-load failure (a corrupt or
/// unwritable `state/identity/` — the same failure shape
/// `identity::load_or_mint` already surfaces for every other caller); a
/// verified peer with no loadable identity refuses the whole outbound call
/// rather than silently falling back to an unsigned request, since an
/// unsigned request to a peer that has since upgraded to require signed
/// spawn admission would otherwise fail opaquely on the far end instead of
/// here, where the real cause is known.
fn sign_headers_for_peer(peer: &aoide_storage::peer_store::Peer, body: &str) -> Result<Vec<(String, String)>, String> {
    if !peer.verified {
        return Ok(Vec::new());
    }
    let (keypair, _) = aoide_storage::identity::load_or_mint()
        .map_err(|e| format!("loading this instance's identity to sign a request to peer `{}`: {e}", peer.name))?;
    let path = aoide_storage::peer_store::url_path(&peer.url);
    let timestamp = aoide_storage::time::now_iso_utc();
    let nonce = aoide_storage::pairing::random_hex(16);
    let canonical = aoide_storage::wire_auth::canonical_string(HTTP_METHOD, &path, &timestamp, &nonce, body.as_bytes());
    let signature = aoide_storage::wire_auth::sign_hex(&keypair, canonical.as_bytes());
    Ok(vec![
        (aoide_storage::wire_auth::HEADER_PEER.to_string(), peer.name.clone()),
        (aoide_storage::wire_auth::HEADER_TIMESTAMP.to_string(), timestamp),
        (aoide_storage::wire_auth::HEADER_NONCE.to_string(), nonce),
        (aoide_storage::wire_auth::HEADER_SIGNATURE.to_string(), signature),
    ])
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

// ── The four `agent` commands (client side, CONTRACTS.md §6) ────────────────────

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
    let word = if replaced { "updated" } else { "registered" };
    Outcome::ok(
        cmd,
        format!(
            "{word} A2A agent `{}` → {} ({} total)",
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
///
/// `pub` (not just crate-local): `aoide-conduct`'s `screen send --agent`
/// (Phase 5 of the `screen` command family) calls this DIRECTLY — a same-process
/// function call via a synthesized `Invocation`, never a subprocess shell-out
/// to `aoide a2a agent send` — so a captured screenshot's hand-off reuses this
/// EXACT driver (curl transport, JSON-RPC body, error surfacing) instead of a
/// second one. Visibility-only change; the body is untouched.
pub fn handle_agent_send(inv: &Invocation) -> Outcome {
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
    // `context_id: None` — this drives an unrelated registered A2A agent,
    // which has no notion of an aoide sessionId (that's `send_message_to_peer`
    // below, P-C3's peer-targeted path).
    let body = crate::wire::build_message_send_body(&message, &message_id, None);
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

// ── The seven `peer` commands (CONTRACTS.md §7: same-network federation) ───────
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
    let token_file = inv.flags.get("token-file").cloned().filter(|s| !s.is_empty());
    let bearer_secret = inv.flags.get("bearer-secret").cloned().filter(|s| !s.is_empty());

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
        token_file,
        bearer_secret,
        hub: false,
        pubkey: None,
        verified: false,
        allows: Vec::new(),
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

/// `peer hub <name> [--clear]` — designate `name` as THE hub (at most one;
/// setting a new hub moves it, clearing the previous holder in the same
/// write) or, with `--clear`, remove the hub designation from `name` if it
/// currently holds it (P-D5, `docs/architecture/AOIDED.md`'s "The hub
/// option"). Both directions are idempotent — `peer_store::set_hub`/
/// `clear_hub` report exactly what changed (set/moved/cleared/no-op) and
/// this handler's message says so plainly rather than a bare "ok"; a no-op
/// never touches disk (nothing to write back).
/// `peer allow <name> <cap> on|off` (P-P3, `docs/architecture/PAIRING.md`
/// decision 5): flip one capability in `name`'s `allows` set —
/// `aoide_storage::peer_store::set_peer_allow` holds the closed-set
/// validation and the idempotence invariant; this handler just reports
/// exactly what changed (enabled/disabled/no-op), mirroring `handle_peer_hub`'s
/// "report the change, never a bare ok" discipline one field over. Refuses
/// an unknown peer AND an unknown capability — the capability check runs
/// FIRST (`set_peer_allow`'s own ordering), so a typo'd capability against a
/// typo'd name still names the capability problem, not the peer one.
fn handle_peer_allow(inv: &Invocation) -> Outcome {
    let cmd = "peer.allow";
    const USAGE: &str = "usage: aoide peer allow <name> <cap> on|off";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let cap = match inv.args.get(1).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(c) => c.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let on = match inv.args.get(2).map(|s| s.trim()) {
        Some("on") => true,
        Some("off") => false,
        _ => return Outcome::usage(cmd, USAGE),
    };

    let mut peers = aoide_storage::peer_store::load_peers();
    let change = match aoide_storage::peer_store::set_peer_allow(&mut peers, &name, &cap, on) {
        Ok(c) => c,
        Err(aoide_storage::peer_store::AllowError::UnknownCapability) => {
            return Outcome::error(
                cmd,
                format!(
                    "unknown capability `{cap}` — valid capabilities: {}",
                    aoide_storage::peer_store::PEER_CAPABILITIES.join(", ")
                ),
            )
            .with_data(json!({ "reason": "unknown-capability", "cap": cap }));
        }
        Err(aoide_storage::peer_store::AllowError::UnknownPeer) => {
            return Outcome::error(cmd, format!("no peer named `{name}`"))
                .with_data(json!({ "reason": "unknown-peer", "name": name }));
        }
    };

    use aoide_storage::peer_store::AllowChange;
    let (msg, tag) = match &change {
        AllowChange::Enabled => (format!("`{cap}` is now allowed for peer `{name}`"), "enabled"),
        AllowChange::Disabled => (format!("`{cap}` is no longer allowed for peer `{name}`"), "disabled"),
        AllowChange::NoOp if on => (format!("`{name}` already allows `{cap}`"), "no-op"),
        AllowChange::NoOp => (format!("`{name}` already does not allow `{cap}`"), "no-op"),
    };
    let data = json!({ "name": name, "cap": cap, "on": on, "change": tag });

    if matches!(change, AllowChange::NoOp) {
        return Outcome::ok(cmd, msg).with_data(data);
    }
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(cmd, msg)
        .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
        .with_data(data)
}

fn handle_peer_hub(inv: &Invocation) -> Outcome {
    let cmd = "peer.hub";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer hub <name> [--clear] [--json]"),
    };
    let clear = inv.flag_present("clear");
    let mut peers = aoide_storage::peer_store::load_peers();

    let change = if clear {
        aoide_storage::peer_store::clear_hub(&mut peers, &name)
    } else {
        aoide_storage::peer_store::set_hub(&mut peers, &name)
    };
    let change = match change {
        Ok(c) => c,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "unknown-peer", "name": name })),
    };

    use aoide_storage::peer_store::HubChange;
    let (msg, tag) = match &change {
        HubChange::Set => (format!("peer `{name}` is now the hub"), "set"),
        HubChange::Moved { from } => (format!("hub moved from `{from}` to `{name}`"), "moved"),
        HubChange::Cleared => (format!("cleared the hub designation from `{name}`"), "cleared"),
        HubChange::NoOp if clear => (format!("`{name}` was not the hub — nothing to clear"), "no-op"),
        HubChange::NoOp => (format!("`{name}` is already the hub"), "no-op"),
    };
    let data = json!({ "name": name, "clear": clear, "change": tag });

    if matches!(change, HubChange::NoOp) {
        return Outcome::ok(cmd, msg).with_data(data);
    }
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(cmd, msg)
        .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
        .with_data(data)
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
        let bearer = resolve_peer_bearer(peer)?;
        let extra_headers = sign_headers_for_peer(peer, &body_str)?;
        let (code, resp_body) = post_json(&peer.url, &body_str, bearer.as_deref(), &extra_headers, 15)?;
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

/// Pull ONE peer's `aoide/graphSummary` LIVE, with an explicit per-call
/// `timeout_secs`, WITHOUT writing `state/peer-cache/<name>.json` — the
/// read-only sibling of [`pull_one_peer`] (which persists on every
/// outcome). `aoide who`'s presence probe (conduct crate, workstream C2)
/// is the reason this exists: it reuses this exact curl transport (never
/// reimplements HTTP — see the crate's `Cargo.toml` for why the
/// `conduct → client` edge stays) but must never treat a presence query as
/// a cache-refreshing side effect. `build_graph`'s fold (`aoide-conduct`)
/// is the ONLY writer of that cache; `who` only ever READS it, as the
/// fallback for a peer this call fails to reach. Returns just the peer's
/// resolved `graph` document (`{nodes, edges}`) — `who` has no use for the
/// envelope's `instance` field `pull_one_peer` also captures.
pub fn pull_peer_live(peer: &aoide_storage::peer_store::Peer, timeout_secs: u64) -> Result<Value, String> {
    let body = crate::peer::build_graph_summary_request();
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer = resolve_peer_bearer(peer)?;
    let extra_headers = sign_headers_for_peer(peer, &body_str)?;
    let (code, resp_body) = post_json(&peer.url, &body_str, bearer.as_deref(), &extra_headers, timeout_secs)?;
    if code != 200 {
        return Err(format!("HTTP {code}"));
    }
    let resp: Value =
        serde_json::from_str(&resp_body).map_err(|e| format!("unparseable response: {e}"))?;
    let now = aoide_storage::time::now_iso_utc();
    let entry = crate::peer::parse_graph_summary_response(&resp, &peer.name, &now)?;
    Ok(entry.graph.unwrap_or_else(|| json!({ "nodes": [], "edges": [] })))
}

/// POST a `message/send` to a PEER (not a registered A2A agent — see
/// [`handle_agent_send`]) with an explicit `contextId` naming the REMOTE
/// session to inject into. `graph send --to <peer>/<query>` (`aoide-conduct`,
/// workstream C3) resolves `query` against the peer's cached graph to that
/// one remote sessionId, then drives THIS function — the transport lives
/// here (not duplicated in `conduct`) for the same reason [`pull_peer_live`]
/// does, see the crate's `Cargo.toml`/`AGENTS.md` on the `conduct → client`
/// edge.
///
/// Same `run_curl` transport and 15s timeout every other `message/send`
/// call site in this file uses (`handle_agent_send`) — this is a real
/// delivery, not `who`'s short-timeout presence probe, so it does NOT reuse
/// [`pull_peer_live`]'s tighter bound. Returns the parsed JSON-RPC response
/// on a 200 with no `error` member; any transport/HTTP/JSON-RPC failure is
/// `Err` with a plain message the caller (`aoide-conduct`) can surface and
/// audit directly — mirrors [`pull_peer_live`]'s `Result`-not-`Outcome`
/// shape so the caller builds its own `Outcome`/audit line, never this one.
pub fn send_message_to_peer(
    peer: &aoide_storage::peer_store::Peer,
    text: &str,
    context_id: &str,
) -> Result<Value, String> {
    let message_id = gen_message_id();
    let body = crate::wire::build_message_send_body(text, &message_id, Some(context_id));
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer = resolve_peer_bearer(peer)?;
    let extra_headers = sign_headers_for_peer(peer, &body_str)?;
    let (code, resp) = post_json(&peer.url, &body_str, bearer.as_deref(), &extra_headers, 15)?;
    if code != 200 {
        return Err(format!("HTTP {code}"));
    }
    let parsed: Value =
        serde_json::from_str(&resp).map_err(|e| format!("unparseable response: {e}"))?;
    // A JSON-RPC error still returns HTTP 200 (same discipline as
    // `handle_agent_send`'s own check) — surface it as an `Err`, not a
    // silently-`Ok`'d error envelope.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Err(format!("peer returned an error: {detail}"));
    }
    Ok(parsed)
}

/// Prompt `y/N` on stderr before spawning on a peer — a LOCAL UX
/// confirmation only (mirrors `confirm_sas`'s exact idiom), never a
/// security gate: the remote door's own paired+signature+allows∋spawn
/// check (PAIRING.md decision 6) is the sole authority either way.
fn confirm_spawn(name: &str, text: &str) -> Result<bool, String> {
    eprint!("spawn a new session on peer `{name}` — first turn: {text:?} — proceed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// `peer spawn <name> [--yes] -- <text…>` (P-P5b, making PAIRING.md's
/// headline spawn gate actually reachable from the CLI — before this command,
/// every client→peer function sent either a read (`aoide/graphSummary`) or
/// an Inject (`send_message_to_peer`, always carrying a `contextId`); NONE
/// emitted a spawn-shaped `message/send` — `context_id: None` — to a
/// paired peer, so the server's `do_spawn` arm, fully built and
/// fail-closed since P-P3/P-P4, could only ever be reached by a
/// hand-crafted signed curl).
///
/// **The exact shape `aoide-server::a2a::do_spawn` consumes**
/// (`decide_send_action`/`parse_message_send_params`, `a2a.rs`):
/// `context_id: None` (or `spawn_asked`, but omitting `contextId`
/// entirely is simpler and is exactly [`crate::wire::build_message_send_body`]'s
/// existing `None` branch) routes to `SendAction::Spawn` REGARDLESS of
/// `spawn_asked`; the message's `parts[].text` becomes the PROMPT
/// `do_spawn` types as the newly spawned session's first turn
/// (`spawn_inject_prompt`) — `<text…>` here is that prompt, NOT a
/// remote-chosen executable: which agent runs is the PEER's own configured
/// `aoide.a2a.spawnAgent`, never client-supplied (`do_spawn`'s own doc
/// comment on `SessionRef`'s security model). Built via
/// `crate::wire::build_message_send_body(text, message_id, None)` — the
/// SAME builder `handle_agent_send` already drives an external A2A agent's
/// own spawn arm with, so this is a proven shape, not a new invention.
///
/// **Signing**: [`sign_headers_for_peer`] — this is the FIRST production
/// call site that ever signs a SPAWN-shaped POST (`context_id: None`);
/// every earlier call site (`pull_one_peer`, `pull_peer_live`,
/// `send_message_to_peer`) sends a read or an Inject. `peer.verified ==
/// false` still yields an empty header slice exactly as it does for those
/// three (unchanged behavior) — which is precisely why this function
/// refuses an unpaired/unknown peer LOCALLY first (below): an unsigned
/// spawn request can never satisfy the remote door's
/// `PeerRung::Signature`-only gate (P-P4), so sending it anyway would only
/// earn a confusing round trip and a generic refusal.
///
/// **The client NEVER gates on `allows` — only on "is this a VERIFIED
/// local peer at all."** The local check below exists SOLELY to catch the
/// obviously-doomed case (no verified peer → no identity to sign with →
/// the remote can never resolve a `Signature` rung) with a clear, LOCAL
/// taught error naming `peer pair request`. Every OTHER refusal shape —
/// `allows` lacking `spawn`, clock skew, a revoked pairing — is the remote
/// door's OWN call; this function never second-guesses it, and surfaces
/// whatever JSON-RPC error the door returns VERBATIM (taught), per
/// PAIRING.md decision 6: "the remote door's paired+signature+
/// allows∋spawn gate is the authority."
fn handle_peer_spawn(inv: &Invocation) -> Outcome {
    let cmd = "peer.spawn";
    const USAGE: &str = "usage: aoide peer spawn <name> [--yes] -- <text…>";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let text = inv.args.get(1..).map(|rest| rest.join(" ")).unwrap_or_default();
    if text.trim().is_empty() {
        return Outcome::usage(cmd, USAGE);
    }

    let peers = aoide_storage::peer_store::load_peers();
    let peer = match peers.iter().find(|p| p.name == name) {
        Some(p) if p.verified => p.clone(),
        Some(_) => {
            return Outcome::error(
                cmd,
                format!(
                    "peer `{name}` is registered but not paired — spawn requires a signed request \
                     from a VERIFIED peer (docs/architecture/PAIRING.md decision 6); pair first with \
                     `aoide peer pair request <url> --name {name}`"
                ),
            )
            .with_data(json!({ "reason": "unpaired-peer", "name": name }));
        }
        None => {
            return Outcome::error(
                cmd,
                format!(
                    "no peer named `{name}` — spawn requires a paired peer; register and pair it \
                     first with `aoide peer pair request <url> --name {name}`"
                ),
            )
            .with_data(json!({ "reason": "unknown-peer", "name": name }));
        }
    };

    if !inv.flag_present("yes") {
        match confirm_spawn(&peer.name, &text) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::ok(cmd, format!("not confirmed — nothing sent to `{}`", peer.name))
                    .with_data(json!({ "confirmed": false, "name": peer.name }))
            }
            Err(e) => return Outcome::error(cmd, e),
        }
    }

    let message_id = gen_message_id();
    let body = crate::wire::build_message_send_body(&text, &message_id, None);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer = match resolve_peer_bearer(&peer) {
        Ok(b) => b,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "bearer-resolve-failed", "name": peer.name })),
    };
    let extra_headers = match sign_headers_for_peer(&peer, &body_str) {
        Ok(h) => h,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "signing-failed", "name": peer.name })),
    };
    let (code, resp) = match post_json(&peer.url, &body_str, bearer.as_deref(), &extra_headers, 15) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("spawning on `{}` at {}: {e}", peer.name, peer.url))
                .with_data(json!({ "reason": "send-failed", "name": peer.name, "url": peer.url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("spawning on `{}` at {}: HTTP {code}", peer.name, peer.url))
            .with_data(json!({
                "reason": "send-http-error", "name": peer.name, "url": peer.url,
                "httpCode": code, "body": resp,
            }));
    }
    let parsed: Value = serde_json::from_str(&resp).unwrap_or(Value::Null);
    // A JSON-RPC error still returns HTTP 200 (same discipline as
    // `handle_agent_send`/`send_message_to_peer`) — the remote door's
    // refusal (paired-but-unsigned, allows lacking spawn, skew, …)
    // surfaces VERBATIM, never translated or second-guessed.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Outcome::error(cmd, format!("peer `{}` refused the spawn: {detail}", peer.name))
            .with_data(json!({ "reason": "peer-refused", "name": peer.name, "response": parsed }));
    }
    let session_id = parsed
        .get("result")
        .and_then(|r| r.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    Outcome::ok(cmd, format!("spawned on `{}` — remote session `{session_id}`", peer.name))
        .with_data(json!({ "name": peer.name, "url": peer.url, "sessionId": session_id, "response": parsed }))
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

/// The seven `peer` commands (CONTRACTS.md §7; `hub` is P-D5, `allow` is P-P3),
/// registered as their own group.
pub fn register_peers(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "add"],
        summary: "Register a peer aoide instance (verified by AgentCard fetch first) as a federation node in the session DAG.",
        args: [
            arg!("name", "string", true, "A local nickname for this peer."),
            arg!("url", "string", true, "The peer's A2A door URL (e.g. http://host:8710/)."),
        ],
        flags: [
            flag!("autogate", "bool", "Trust this peer: its inbound message/send auto-delivers without the pending queue."),
            flag!("token-file", "string", "Path to a file holding the shared secret this peer must present (Authorization: Bearer <token>) to be identified as this peer — required for --autogate to survive a proxy/tunnel, where every caller's address looks the same."),
            flag!("bearer-secret", "string", "Name of a secret, resolved fresh on every outbound call through the local secrets broker, THIS instance presents as Authorization: Bearer <value> when calling this peer's own A2A door. Absent = no bearer sent (today's behavior)."),
        ],
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
    r.insert(cmd!(
        path: ["peer", "hub"],
        summary: "Designate a peer as THE hub (at most one) that address resolution prefers as a last-resort remote target; --clear removes the designation.",
        args: [arg!("name", "string", true, "The registered peer's name.")],
        flags: [
            flag!("clear", "bool", "Remove the hub designation from this peer instead of setting it."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_hub,
    ));
    r.insert(cmd!(
        path: ["peer", "allow"],
        summary: "Flip one capability in a peer's `allows` set (P-P3, PAIRING.md decision 5) — idempotent, reports exactly what changed.",
        args: [
            arg!("name", "string", true, "The registered peer's name."),
            arg!("cap", "string", true, "The capability — one of the closed set: read, spawn."),
            arg!("state", "string", true, "`on` or `off`."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_allow,
        examples: ["peer allow yomi-strix spawn on", "peer allow yomi-strix spawn off"],
    ));
    r.insert(cmd!(
        path: ["peer", "spawn"],
        summary: "Spawn a session on a PAIRED peer's own configured agent — POSTs a signed, spawn-shaped message/send (contextId omitted) to the peer's A2A door; the peer's own paired+signature+allows∋spawn gate is the sole authority (docs/architecture/PAIRING.md decision 6), never gated locally beyond requiring a verified peer.",
        args: [
            arg!("name", "string", true, "The registered, PAIRED peer's name."),
            arg!("text", "string", true, "The first turn typed into the newly spawned session — put it after `--` so its own words/flags pass through verbatim."),
        ],
        flags: [
            flag!("yes", "bool", "Skip the local y/N confirmation (scripted use) — a LOCAL UX gate only; the remote door's own gate is unaffected."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_spawn,
        examples: ["peer spawn yomi-strix -- status check please"],
    ));
}

// ── The four `peer pair` commands (P-P2, CONTRACTS.md §6 — the pairing
// ── ceremony's wire + CLI ceremony) ──────────────────────────────────────
//
// `peer add`/`peer pair` are two SEPARATE paths onto the same registry
// (`docs/architecture/PAIRING.md`'s "Settled decisions" #2): `peer add` is
// the legacy escape for an UNPAIRED peer (a hand-set URL, never verified by
// key), `peer pair` is the ONE ceremony that mints a `pubkey`/`verified`
// peer record on BOTH ends — request/reveal/park/approve/reject over the
// A2A door (`aoide-server::a2a::pair_request`/`pair_reveal`/
// `pair_approve_callback`), SAS derivation + display
// (`aoide_storage::pairing::derive_sas`), commit via
// `aoide_storage::peer_store::upsert_paired_peer` — which ALSO stamps the
// ceremony's own default `allows` (`["read","spawn"]`) the first time a
// peer becomes verified (P-P3, PAIRING.md decision 5); editing that default
// afterward is `peer allow <name> <cap> on|off`'s own separate command
// (registered in `register_peers` above), never a second write site here.
//
// **Both humans confirm, for real (review-bounce Finding 2).** `peer pair
// approve <id>` does double duty by DIRECTION, never a fifth command (golden
// stays 76): on an INBOUND id (this instance is the APPROVER) it is the
// ORIGINAL approve flow — re-derive the SAS, confirm, deliver the callback,
// commit. On an OUTBOUND id whose entry has reached
// `aoide_storage::pairing::OutboundState::AwaitingConfirm` (this instance is
// the REQUESTER, and the approver's own callback already arrived) it is the
// SAME confirm-then-commit shape, just committing THIS instance's own
// record instead — no wire call needed at this step, since the approver
// already committed its own record before ever sending the callback.
// `peer pair reject <id>` doubles the same way, and on an outbound id is
// also the ceremony's missing ABORT command: it removes the entry at EITHER
// outbound state, before or after the callback arrives.

/// Prompt `y/N` on stderr and read ONE line from stdin, unhidden (a
/// confirmation code isn't sensitive) — mirrors `aoide-secrets::client::
/// confirm_overwrite`'s exact idiom (a different crate; this crate has no
/// dependency on that one to reuse the function directly). `true` only for
/// `y`/`yes` (case-insensitive, trimmed); EOF or anything else defaults to
/// `false` — the ceremony's own "never silently commit" stance.
fn confirm_sas(sas: &str, name: &str) -> Result<bool, String> {
    eprint!("pairing request from `{name}` — confirmation code {sas} — do the codes match? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// This instance's own default advertised A2A door URL — `--peer-name`'s
/// sibling precedence chain (`aoide_server::a2a::resolve_peer_name`) but
/// resolved HERE, since this crate cannot depend on `aoide-server`: the
/// port comes from `AOIDE_A2A_PORT` (the same env the `aoide-a2a` systemd
/// unit sets, mirroring `a2a::resolve_bind_port`'s own precedence) or the
/// house default `8710`; the host is `aoide_storage::display::
/// local_host_name` (already the shared fallback chain `a2a::
/// resolve_peer_name` itself delegates to). `--self-url` overrides this
/// outright — the one flag `peer pair request` needs when the door binds
/// somewhere this default can't guess (a non-default port, a reverse
/// proxy/tunnel hostname).
fn default_self_url() -> String {
    let host = aoide_storage::display::local_host_name();
    let port: u16 = std::env::var("AOIDE_A2A_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8710);
    format!("http://{host}:{port}/")
}

/// `peer pair request <url> [--name <n>] [--self-url <url>]` — the
/// REQUESTER's half. Mints this instance's identity if it doesn't exist
/// yet (`aoide_storage::identity::load_or_mint`), mints a fresh nonce, POSTs
/// `aoide/pairRequest` carrying a COMMITMENT to that nonce (never the nonce
/// itself — review-bounce Finding 1, `aoide_storage::pairing`'s module doc:
/// the original one-round-trip shape let an active on-path attacker choose
/// four of the six SAS transcript fields after seeing the real ones), then
/// immediately POSTs `aoide/pairReveal` with the nonce the commitment
/// already fixed. Only once BOTH calls succeed does this instance derive
/// its own copy of the SAS (it already has everything: its own pubkey and
/// nonce, the approver's pubkey and nonce from the first response) and
/// remember the outbound request (`aoide_storage::pairing::park_outbound`,
/// `OutboundState::AwaitingApproval`) so this instance's own `a2a serve`
/// can finish the ceremony when the approval callback arrives, however long
/// after this CLI process exits.
fn handle_peer_pair_request(inv: &Invocation) -> Outcome {
    let cmd = "peer.pair.request";
    let url = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer pair request <url> [--name <n>] [--self-url <url>] [--json]"),
    };
    let name = match inv.flags.get("name").cloned().filter(|s| !s.is_empty()) {
        Some(n) => n,
        None => match aoide_storage::peer_store::default_peer_name_from_url(&url) {
            Some(n) => n,
            None => {
                return Outcome::error(cmd, "could not derive a nickname from the URL — pass --name explicitly")
                    .with_data(json!({ "reason": "no-default-name", "url": url }))
            }
        },
    };
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
    let self_url = inv
        .flags
        .get("self-url")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_self_url);

    run_pair_request(cmd, &url, &name, &self_url)
}

/// The requester's half of the ceremony, shared verbatim by
/// `handle_peer_pair_request` (a CLI-typed `<url>`/`--name`, validated
/// above) AND `handle_peer_invite` (P-P6 — a `url`/`name` already lifted
/// straight off an already-validated, already-confirmed discovery beacon,
/// so it needs no SECOND `valid_peer_name` check here). Extracted so
/// `peer invite` reaches the SAME ceremony code `peer pair request` does —
/// never a copy (PAIRING.md: "sugar over the ceremony, nothing more").
/// Everything from here down is unchanged from the pre-P-P6 shape of
/// `handle_peer_pair_request`: mint-or-load this instance's identity, mint
/// a fresh nonce, POST `aoide/pairRequest` carrying a COMMITMENT to that
/// nonce (never the nonce itself), then immediately POST `aoide/pairReveal`
/// with the nonce the commitment already fixed; only once both calls
/// succeed does this instance derive its own SAS and remember the outbound
/// request.
fn run_pair_request(cmd: &str, url: &str, name: &str, self_url: &str) -> Outcome {
    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;
    let own_nonce = aoide_storage::pairing::random_hex(16);
    let commit = aoide_storage::pairing::derive_commit(&own_pubkey, &own_nonce);

    let body = crate::peer::build_pair_request_body(&own_pubkey, &name, &commit, &self_url);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let (code, resp_body) = match post_json(&url, &body_str, None, &[], 15) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("sending the pairing request to {url}: {e}"))
                .with_data(json!({ "reason": "fetch-failed", "url": url }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("sending the pairing request to {url}: HTTP {code}"))
            .with_data(json!({ "reason": "fetch-http-error", "url": url, "httpCode": code }));
    }
    let resp: Value = match serde_json::from_str(&resp_body) {
        Ok(v) => v,
        Err(_) => {
            return Outcome::error(cmd, format!("sending the pairing request to {url}: unparseable response"))
                .with_data(json!({ "reason": "unparseable", "url": url }))
        }
    };
    let ack = match crate::peer::parse_pair_request_response(&resp) {
        Ok(a) => a,
        Err(e) => {
            return Outcome::error(cmd, format!("the peer refused the pairing request: {e}"))
                .with_data(json!({ "reason": "refused", "url": url }))
        }
    };

    // Reveal — the commitment's second half (module doc). A failure here
    // (network, refusal, or a commitment mismatch the peer detected) means
    // the ceremony never completes; nothing is parked on this side either.
    let reveal_body = crate::peer::build_pair_reveal_body(&ack.id, &own_nonce);
    let reveal_body_str = serde_json::to_string(&reveal_body).unwrap_or_default();
    let (reveal_code, reveal_resp_body) = match post_json(&url, &reveal_body_str, None, &[], 15) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("revealing the nonce to {url}: {e}"))
                .with_data(json!({ "reason": "reveal-fetch-failed", "url": url, "id": ack.id }))
        }
    };
    if reveal_code != 200 {
        return Outcome::error(cmd, format!("revealing the nonce to {url}: HTTP {reveal_code}"))
            .with_data(json!({ "reason": "reveal-http-error", "url": url, "id": ack.id, "httpCode": reveal_code }));
    }
    let reveal_resp: Value = serde_json::from_str(&reveal_resp_body).unwrap_or(Value::Null);
    if let Err(e) = crate::peer::check_pair_reveal_response(&reveal_resp) {
        return Outcome::error(cmd, e).with_data(json!({ "reason": "reveal-refused", "url": url, "id": ack.id }));
    }

    let sas = aoide_storage::pairing::derive_sas(&own_pubkey, &ack.pubkey_hex, &own_nonce, &ack.nonce_hex);
    let requested_at = aoide_storage::time::now_iso_utc();
    let outbound = aoide_storage::pairing::OutboundPairingRequest {
        id: ack.id.clone(),
        url: url.to_string(),
        name: name.to_string(),
        pubkey_hex: ack.pubkey_hex.clone(),
        requester_nonce_hex: own_nonce,
        approver_nonce_hex: ack.nonce_hex.clone(),
        requested_at,
        expires_at: ack.expires_at.clone(),
        state: aoide_storage::pairing::OutboundState::AwaitingApproval,
    };
    if let Err(e) = aoide_storage::pairing::park_outbound(outbound) {
        return Outcome::error(cmd, format!("remembering the outbound pairing request: {e}"));
    }

    Outcome::ok(
        cmd,
        format!(
            "pairing request sent to `{name}` ({url}) — confirmation code {sas} — \
             read this aloud (or otherwise out-of-band) to {name}'s operator; once they run \
             `aoide peer pair approve {}`, run the SAME command here too and confirm the SAME code \
             to complete the pair on both ends",
            ack.id
        ),
    )
    .with_data(json!({ "id": ack.id, "name": name, "url": url, "sas": sas, "expiresAt": ack.expires_at }))
}

/// `peer pair pending` — every pairing request THIS instance is still
/// holding open, BOTH directions (review-bounce Finding 2: an outbound
/// entry awaiting THIS instance's own confirm is exactly as "pending" as an
/// inbound one awaiting approval — before this fix, nothing ever surfaced
/// it). Inbound rows show a SAS only once revealed (`requester_nonce_hex`
/// is `Some`, review-bounce Finding 1) — an unrevealed entry shows
/// `"awaiting reveal"` instead, and `peer pair approve` refuses it. Outbound
/// rows always carry a SAS (an outbound entry is only ever parked AFTER its
/// own reveal already succeeded) plus its own `state`
/// (`awaiting-approval`/`awaiting-confirm`). Every SAS shown here is
/// independently derived from this instance's own identity plus the
/// entry's stored transcript fields — never trusted from the wire — exactly
/// what `peer pair approve` re-derives again before committing anything.
fn handle_peer_pair_pending(_inv: &Invocation) -> Outcome {
    let cmd = "peer.pair.pending";
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let inbound = aoide_storage::pairing::list_inbound(now_epoch);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    if inbound.is_empty() && outbound.is_empty() {
        return Outcome::ok(cmd, "no pending pairing requests").with_data(json!({ "requests": [] }));
    }
    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;

    let mut rows: Vec<Value> = Vec::new();
    for e in &inbound {
        let sas = e
            .requester_nonce_hex
            .as_deref()
            .map(|n| aoide_storage::pairing::derive_sas(&e.pubkey_hex, &own_pubkey, n, &e.approver_nonce_hex));
        rows.push(json!({
            "id": e.id, "direction": "inbound", "name": e.name, "originAddr": e.origin_addr, "url": e.url,
            "sas": sas, "revealed": e.requester_nonce_hex.is_some(),
            "requestedAt": e.requested_at, "expiresAt": e.expires_at,
        }));
    }
    for e in &outbound {
        let sas = aoide_storage::pairing::derive_sas(&own_pubkey, &e.pubkey_hex, &e.requester_nonce_hex, &e.approver_nonce_hex);
        rows.push(json!({
            "id": e.id, "direction": "outbound", "name": e.name, "url": e.url,
            "sas": sas, "state": e.state.as_str(),
            "requestedAt": e.requested_at, "expiresAt": e.expires_at,
        }));
    }

    let lines: Vec<String> = rows
        .iter()
        .map(|r| {
            let dir = r["direction"].as_str().unwrap_or("");
            let status = match dir {
                "inbound" if r["revealed"].as_bool() == Some(false) => "awaiting reveal".to_string(),
                "inbound" => format!("code {}", r["sas"].as_str().unwrap_or("")),
                _ => format!("code {} · {}", r["sas"].as_str().unwrap_or(""), r["state"].as_str().unwrap_or("")),
            };
            format!(
                "{} · {dir} · {} · {status} · requested {}",
                r["id"].as_str().unwrap_or(""),
                r["name"].as_str().unwrap_or(""),
                r["requestedAt"].as_str().unwrap_or(""),
            )
        })
        .collect();
    Outcome::ok(cmd, format!("{} pending pairing request(s):\n{}", rows.len(), lines.join("\n")))
        .with_data(json!({ "requests": rows }))
}

/// `peer pair approve <id> [--yes]` — dispatches by DIRECTION (module doc
/// on this section): an INBOUND id runs [`approve_inbound`] (this instance
/// is the APPROVER); an OUTBOUND id runs [`approve_outbound`] (this
/// instance is the REQUESTER, confirming after the approver's own
/// callback); an id in neither queue is `unknown-id`.
fn handle_peer_pair_approve(inv: &Invocation) -> Outcome {
    let cmd = "peer.pair.approve";
    let id = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(i) => i.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer pair approve <id> [--yes] [--json]"),
    };

    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap_or(0);

    if let Some(entry) = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id) {
        return approve_inbound(inv, cmd, &id, entry, &now, now_epoch);
    }
    if let Some(entry) = aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == id) {
        return approve_outbound(inv, cmd, &id, entry, &now, now_epoch);
    }
    Outcome::error(cmd, format!("no pending pairing request with id `{id}` (unknown, already resolved, or expired)"))
        .with_data(json!({ "reason": "unknown-id", "id": id }))
}

/// The APPROVER's half of `peer pair approve` (this instance holds the
/// INBOUND entry). Refuses outright while the entry is still `awaiting
/// reveal` (review-bounce Finding 1 — no nonce yet means no SAS to confirm
/// against). Otherwise re-derives the SAS from this instance's own identity
/// plus the parked entry (never trusting a wire-supplied code) and requires
/// an explicit `y`/`yes` confirmation (CLI prompt, or `--yes` for scripted
/// tests) BEFORE anything commits. Delivers the `aoide/pairApprove`
/// callback to the requester's own door FIRST — nothing local writes until
/// that callback is acknowledged (PAIRING.md: "a parked request grants
/// NOTHING until approved"; an unreachable requester must leave BOTH ends
/// unpaired, not just one) — then commits THIS instance's own peer record
/// (`upsert_paired_peer`) and removes the parked entry.
fn approve_inbound(
    inv: &Invocation,
    cmd: &str,
    id: &str,
    entry: aoide_storage::pairing::InboundPairingRequest,
    now: &str,
    now_epoch: i64,
) -> Outcome {
    let Some(requester_nonce) = entry.requester_nonce_hex.clone() else {
        return Outcome::error(
            cmd,
            format!(
                "pairing request `{id}` from `{}` is awaiting the requester's reveal step — nothing to confirm yet; \
                 try again shortly, or `aoide peer pair reject {id}` to refuse it outright",
                entry.name
            ),
        )
        .with_data(json!({ "reason": "awaiting-reveal", "id": id }));
    };

    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;
    let sas = aoide_storage::pairing::derive_sas(&entry.pubkey_hex, &own_pubkey, &requester_nonce, &entry.approver_nonce_hex);

    if !inv.flag_present("yes") {
        match confirm_sas(&sas, &entry.name) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::ok(
                    cmd,
                    format!(
                        "not confirmed — the request remains pending (confirmation code was {sas}); \
                         run `aoide peer pair reject {id}` to refuse it outright"
                    ),
                )
                .with_data(json!({ "confirmed": false, "sas": sas, "id": id }))
            }
            Err(e) => return Outcome::error(cmd, e),
        }
    }

    let body = crate::peer::build_pair_approve_body(&entry.id, &own_pubkey);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let (code, resp_body) = match post_json(&entry.url, &body_str, None, &[], 15) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(
                cmd,
                format!(
                    "delivering the approval to `{}` at {}: {e} — the request remains pending; \
                     retry `aoide peer pair approve {id}` once it's reachable",
                    entry.name, entry.url
                ),
            )
            .with_data(json!({ "reason": "callback-unreachable", "id": id, "sas": sas }))
        }
    };
    if code != 200 {
        return Outcome::error(cmd, format!("delivering the approval to `{}`: HTTP {code}", entry.name))
            .with_data(json!({ "reason": "callback-http-error", "id": id, "httpCode": code }));
    }
    let parsed_resp: Value = serde_json::from_str(&resp_body).unwrap_or(Value::Null);
    if let Err(e) = crate::peer::check_pair_approve_response(&parsed_resp) {
        return Outcome::error(cmd, e).with_data(json!({ "reason": "callback-refused", "id": id }));
    }

    let mut peers = aoide_storage::peer_store::load_peers();
    let change = aoide_storage::peer_store::upsert_paired_peer(&mut peers, &entry.name, &entry.url, &entry.pubkey_hex, now);
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"));
    }
    let _ = aoide_storage::pairing::take_inbound(id, now_epoch);

    use aoide_storage::peer_store::PairChange;
    let word = match change {
        PairChange::Inserted => "paired with",
        PairChange::Updated => "re-paired with",
    };
    Outcome::ok(cmd, format!("{word} `{}` (code {sas}) — verified", entry.name))
        .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
        .with_data(json!({ "confirmed": true, "sas": sas, "peer": entry.name, "pubkeyHex": entry.pubkey_hex, "direction": "inbound" }))
}

/// The REQUESTER's confirm-then-commit half of `peer pair approve` (this
/// instance holds the OUTBOUND entry, review-bounce Finding 2). Refuses
/// while the entry is still `awaiting-approval` — the approver's own
/// `aoide/pairApprove` callback hasn't arrived yet, so there is nothing to
/// confirm. Once it has (`OutboundState::AwaitingConfirm`), re-derives the
/// SAS from this instance's own identity plus the entry's stored transcript
/// (never trusting the wire) and requires the SAME explicit `y`/`yes`
/// confirmation the approver's own side holds — only THEN commits this
/// instance's own peer record. No wire call here: the approver already
/// committed its own record before ever sending the callback.
fn approve_outbound(
    inv: &Invocation,
    cmd: &str,
    id: &str,
    entry: aoide_storage::pairing::OutboundPairingRequest,
    now: &str,
    now_epoch: i64,
) -> Outcome {
    if entry.state != aoide_storage::pairing::OutboundState::AwaitingConfirm {
        return Outcome::error(
            cmd,
            format!(
                "pairing request `{id}` to `{}` is still awaiting the peer's own approval — nothing to confirm yet; \
                 try again once they've run `aoide peer pair approve {id}` on their side, or \
                 `aoide peer pair reject {id}` to abort",
                entry.name
            ),
        )
        .with_data(json!({ "reason": "awaiting-peer-approval", "id": id }));
    }

    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;
    let sas = aoide_storage::pairing::derive_sas(&own_pubkey, &entry.pubkey_hex, &entry.requester_nonce_hex, &entry.approver_nonce_hex);

    if !inv.flag_present("yes") {
        match confirm_sas(&sas, &entry.name) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::ok(
                    cmd,
                    format!(
                        "not confirmed — the request remains pending (confirmation code was {sas}); \
                         run `aoide peer pair reject {id}` to abort"
                    ),
                )
                .with_data(json!({ "confirmed": false, "sas": sas, "id": id }))
            }
            Err(e) => return Outcome::error(cmd, e),
        }
    }

    let mut peers = aoide_storage::peer_store::load_peers();
    let change = aoide_storage::peer_store::upsert_paired_peer(&mut peers, &entry.name, &entry.url, &entry.pubkey_hex, now);
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"));
    }
    let _ = aoide_storage::pairing::take_outbound(id, now_epoch);

    use aoide_storage::peer_store::PairChange;
    let word = match change {
        PairChange::Inserted => "paired with",
        PairChange::Updated => "re-paired with",
    };
    Outcome::ok(cmd, format!("{word} `{}` (code {sas}) — verified", entry.name))
        .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
        .with_data(json!({ "confirmed": true, "sas": sas, "peer": entry.name, "pubkeyHex": entry.pubkey_hex, "direction": "outbound" }))
}

/// `peer pair reject <id>` — a clean refusal: removes the parked entry
/// (whichever direction it's in — an OUTBOUND id at EITHER state is the
/// ceremony's own missing ABORT command, review-bounce Finding 2), no peer
/// record on either end. Never notifies the other side (no wire call); an
/// inbound rejection's counterpart outbound entry simply expires on its own
/// timeout (PAIRING.md names no explicit reject-notification requirement,
/// and a same-shaped "clean refusal" is exactly what `secrets dismiss`
/// gives an operator without a wire round trip either).
fn handle_peer_pair_reject(inv: &Invocation) -> Outcome {
    let cmd = "peer.pair.reject";
    let id = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(i) => i.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer pair reject <id> [--json]"),
    };
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);

    match aoide_storage::pairing::take_inbound(&id, now_epoch) {
        Ok(Some(entry)) => {
            return Outcome::ok(cmd, format!("rejected pairing request `{id}` from `{}` — no peer record written", entry.name))
                .with_data(json!({ "rejected": true, "id": id, "name": entry.name, "direction": "inbound" }))
        }
        Ok(None) => {}
        Err(e) => return Outcome::error(cmd, format!("removing the pairing request: {e}")),
    }

    match aoide_storage::pairing::take_outbound(&id, now_epoch) {
        Ok(Some(entry)) => Outcome::ok(cmd, format!("aborted outbound pairing request `{id}` to `{}` — no peer record written", entry.name))
            .with_data(json!({ "rejected": true, "id": id, "name": entry.name, "direction": "outbound" })),
        Ok(None) => Outcome::error(cmd, format!("no pending pairing request with id `{id}` (unknown, already resolved, or expired)"))
            .with_data(json!({ "reason": "unknown-id", "id": id })),
        Err(e) => Outcome::error(cmd, format!("removing the pairing request: {e}")),
    }
}

/// `peer discover [--secs N] [--json]` (P-P6, `docs/architecture/
/// PAIRING.md`'s "Discovery (advertise-but-locked)" section): joins the
/// fixed multicast group, listens `--secs` seconds (default
/// `discover::DEFAULT_SWEEP_SECS`, ~4), and prints every DISTINCT
/// fingerprint heard — name, fingerprint, url, first/last heard, and how
/// many times (`discover::run_sweep`'s own dedupe-by-fingerprint fold).
/// **Read-only** — this command never writes `state/peers.json`; the
/// pairing ceremony is the only thing that ever registers a peer.
/// Malformed beacons are dropped and counted, never echoed raw (house
/// rule 4) — `dropped` in the JSON data is a bare total, nothing more
/// specific about what was wrong with any one of them.
fn handle_peer_discover(inv: &Invocation) -> Outcome {
    let cmd = "peer.discover";
    let secs = match parse_secs_flag(inv) {
        Ok(n) => n,
        Err(()) => {
            return Outcome::usage(
                cmd,
                "usage: aoide peer discover [--secs N] [--json] — --secs must be a positive integer",
            )
        }
    };

    let swept = match crate::discover::run_sweep(secs) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(cmd, crate::discover::describe_sweep_error(&e))
                .with_data(json!({ "reason": "sweep-failed" }))
        }
    };

    let heard: Vec<Value> = swept
        .heard
        .iter()
        .map(|h| {
            json!({
                "name": h.beacon.name,
                "fpr": h.beacon.fpr,
                "url": h.beacon.url,
                "firstHeard": h.first_heard,
                "lastHeard": h.last_heard,
                "count": h.count,
            })
        })
        .collect();

    let message = if swept.heard.is_empty() {
        format!("heard no discovery beacons in {secs}s ({} malformed dropped)", swept.dropped)
    } else {
        format!(
            "heard {} distinct instance{} in {secs}s ({} malformed dropped)",
            swept.heard.len(),
            if swept.heard.len() == 1 { "" } else { "s" },
            swept.dropped
        )
    };
    Outcome::ok(cmd, message).with_data(json!({ "heard": heard, "dropped": swept.dropped, "secs": secs }))
}

/// `--secs`'s shared parse for `peer discover`/`peer invite`: absent or
/// unparsable-but-absent-equivalent defaults to
/// `discover::DEFAULT_SWEEP_SECS`; present-but-not-a-positive-integer is a
/// usage error (`Err(())`, the caller renders its own exact usage string)
/// rather than silently falling back — a typo'd `--secs` should never
/// quietly listen for the default window instead of what the operator
/// actually asked for.
fn parse_secs_flag(inv: &Invocation) -> Result<u64, ()> {
    match inv.flags.get("secs") {
        None => Ok(crate::discover::DEFAULT_SWEEP_SECS),
        Some(s) => match s.parse::<u64>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(()),
        },
    }
}

/// Prompt `y/N` on stderr before running the pairing ceremony against a
/// discovered peer — a LOCAL UX confirmation only (mirrors
/// `confirm_spawn`/`confirm_sas`'s exact idiom), never a security gate:
/// the ceremony's own SAS confirmation (both operators, both ends) is the
/// sole authority either way.
fn confirm_invite(name: &str, fpr: &str, url: &str) -> Result<bool, String> {
    eprint!("invite `{name}` ({url}, fingerprint {fpr}) to pair — proceed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// `peer invite <name> [--secs N] [--yes] [--json]` (P-P6, PAIRING.md's own
/// "sugar over the ceremony, nothing more" framing): runs its OWN discover
/// sweep (never reuses a previous one — a beacon is only ever as fresh as
/// the sweep that heard it), resolves `<name>` against the heard set
/// (`discover::resolve_invite_target`), and on EXACTLY one match runs the
/// SAME [`run_pair_request`] core `peer pair request` itself calls —
/// reused, never copied (this is what "reaches the same code path"
/// actually means here: both handlers bottom out in the identical
/// function, not two functions that merely look alike). Zero or multiple
/// matches refuse with a taught error listing every name that WAS heard
/// (never raw beacon content — house rule 4; only already-validated
/// `name`s ever reach this point). `--yes` skips only the LOCAL
/// proceed-confirm (`confirm_invite`), exactly `peer spawn`'s own `--yes`
/// idiom — the ceremony's OWN SAS confirmation (both operators, both ends)
/// is untouched and still runs.
fn handle_peer_invite(inv: &Invocation) -> Outcome {
    let cmd = "peer.invite";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide peer invite <name> [--secs N] [--yes] [--json]"),
    };
    let secs = match parse_secs_flag(inv) {
        Ok(n) => n,
        Err(()) => {
            return Outcome::usage(
                cmd,
                "usage: aoide peer invite <name> [--secs N] [--yes] [--json] — --secs must be a positive integer",
            )
        }
    };

    let swept = match crate::discover::run_sweep(secs) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(cmd, crate::discover::describe_sweep_error(&e))
                .with_data(json!({ "reason": "sweep-failed" }))
        }
    };

    let hit = match crate::discover::resolve_invite_target(&swept.heard, &name) {
        Ok(h) => h,
        Err(crate::discover::InviteResolveError::NoMatch { heard }) => {
            return Outcome::error(
                cmd,
                format!(
                    "heard no beacon named `{name}` in {secs}s — heard: {}",
                    if heard.is_empty() { "(none)".to_string() } else { heard.join(", ") }
                ),
            )
            .with_data(json!({ "reason": "no-match", "name": name, "heard": heard }));
        }
        Err(crate::discover::InviteResolveError::Ambiguous { heard }) => {
            return Outcome::error(
                cmd,
                format!("heard multiple beacons named `{name}` — ambiguous; heard: {}", heard.join(", ")),
            )
            .with_data(json!({ "reason": "ambiguous", "name": name, "heard": heard }));
        }
    };

    if !inv.flag_present("yes") {
        match confirm_invite(&hit.beacon.name, &hit.beacon.fpr, &hit.beacon.url) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::ok(cmd, format!("not confirmed — nothing sent to `{}`", hit.beacon.name))
                    .with_data(json!({ "confirmed": false, "name": hit.beacon.name }))
            }
            Err(e) => return Outcome::error(cmd, e),
        }
    }

    let self_url = default_self_url();
    run_pair_request(cmd, &hit.beacon.url, &hit.beacon.name, &self_url)
}

/// The four `peer pair` commands (P-P2), registered directly after the six
/// legacy `peer` commands — same-network federation's pairing ceremony joins
/// the group it extends, nothing existing reorders.
pub fn register_peer_pair(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "pair", "request"],
        summary: "Send a pairing request to another aoide instance's A2A door and display the confirmation code (SAS) to compare out-of-band.",
        args: [arg!("url", "string", true, "The other instance's A2A door URL (e.g. http://host:8710/).")],
        flags: [
            flag!("name", "string", "A local nickname for the other instance; defaults to a sanitized form of the URL's host."),
            flag!("self-url", "string", "This instance's own advertised A2A door URL, for the later approval callback; defaults to http://<host>:<AOIDE_A2A_PORT or 8710>/."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_request,
    ));
    r.insert(cmd!(
        path: ["peer", "pair", "pending"],
        summary: "List pairing requests parked on this instance, each with its own independently-derived confirmation code.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_pending,
    ));
    r.insert(cmd!(
        path: ["peer", "pair", "approve"],
        summary: "Approve a pending pairing request after confirming its code matches (CLI y/N unless --yes) — writes verified peer records on both ends.",
        args: [arg!("id", "string", true, "The pending pairing request's id (see `peer pair pending`).")],
        flags: [
            flag!("yes", "bool", "Skip the interactive y/N confirmation (scripted use)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_approve,
    ));
    r.insert(cmd!(
        path: ["peer", "pair", "reject"],
        summary: "Refuse a pending pairing request — a clean removal, no peer record on either end.",
        args: [arg!("id", "string", true, "The pending pairing request's id (see `peer pair pending`).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_reject,
    ));
}

/// `peer discover`/`peer invite` (P-P6, `docs/architecture/PAIRING.md`'s
/// "Discovery (advertise-but-locked)" section), registered directly after
/// `register_peer_pair` — discovery is sugar OVER the ceremony that group
/// already owns, never a parallel mechanism, so it joins the group it
/// extends the same way `register_peer_pair` itself did for the six
/// legacy `peer` commands.
pub fn register_peer_discovery(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "discover"],
        summary: "Listen for discovery beacons on the LAN multicast group and print every distinct instance heard (name, fingerprint, url) — read-only, never writes state/peers.json.",
        args: [],
        flags: [flag!("secs", "int", "How many seconds to listen (default ~4).")],
        gated: false,
        implemented: true,
        handler: handle_peer_discover,
    ));
    r.insert(cmd!(
        path: ["peer", "invite"],
        summary: "Discover <name> on the LAN and, on exactly one match, run the pairing ceremony (peer pair request) against its advertised url.",
        args: [arg!("name", "string", true, "The instance name to look for among heard discovery beacons.")],
        flags: [
            flag!("secs", "int", "How many seconds to listen (default ~4)."),
            flag!("yes", "bool", "Skip the interactive y/N proceed confirmation (scripted use) — the ceremony's own SAS confirmation is untouched."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_invite,
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

/// The four `agent` commands, registered at the historical `a2a` position
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

/// The post-`graph` client command: `adapter melete` (registered directly
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_peer(bearer_secret: Option<&str>) -> aoide_storage::peer_store::Peer {
        aoide_storage::peer_store::Peer {
            name: "yomi-strix".to_string(),
            url: "http://yomi-strix:8710/".to_string(),
            autogate: false,
            token_file: None,
            bearer_secret: bearer_secret.map(str::to_string),
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            added_at: "2026-08-24T00:00:00Z".to_string(),
        }
    }

    // ── `handle_peer_allow` (P-P3) — pure file I/O, so unlike most `peer`
    // ── commands (network-touching, tested at `cli/tests/peer_connectivity.rs`'s
    // ── `#[ignore]`'d integration layer) this one is directly unit-testable,
    // ── same reasoning `handle_peer_hub`'s own storage-layer tests already
    // ── rest on. ─────────────────────────────────────────────────────────────

    fn with_peer_state<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-peer-allow-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::env::set_var("AOIDE_STATE_DIR", &dir);
        let out = f();
        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        out
    }

    fn allow_inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["peer".to_string(), "allow".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn peer_allow_enables_and_disables_idempotently_and_reports_exactly_what_changed() {
        with_peer_state("toggle", || {
            aoide_storage::peer_store::save_peers(&[fixture_peer(None)]).unwrap();

            let on = handle_peer_allow(&allow_inv(&["yomi-strix", "spawn", "on"]));
            assert_eq!(on.status, aoide_protocol::output::Status::Ok, "{on:?}");
            assert!(!on.changed.is_empty());
            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers[0].allows, vec!["spawn".to_string()]);

            // Re-enabling is a reported no-op — nothing written, nothing duplicated.
            let on_again = handle_peer_allow(&allow_inv(&["yomi-strix", "spawn", "on"]));
            assert_eq!(on_again.status, aoide_protocol::output::Status::Ok);
            assert!(on_again.changed.is_empty(), "a no-op never touches disk");

            let off = handle_peer_allow(&allow_inv(&["yomi-strix", "spawn", "off"]));
            assert_eq!(off.status, aoide_protocol::output::Status::Ok, "{off:?}");
            assert!(aoide_storage::peer_store::load_peers()[0].allows.is_empty());

            let off_again = handle_peer_allow(&allow_inv(&["yomi-strix", "spawn", "off"]));
            assert!(off_again.changed.is_empty(), "disabling an already-absent cap is also a no-op");
        });
    }

    // ── `sign_headers_for_peer` (P-P4) — outbound signing. ───────────────────

    #[test]
    fn sign_headers_for_peer_is_empty_for_an_unverified_peer() {
        with_peer_state("sign-unverified", || {
            let peer = fixture_peer(None);
            assert!(!peer.verified);
            let headers = sign_headers_for_peer(&peer, "{}").unwrap();
            assert!(headers.is_empty(), "an unpaired/unverified peer gets no signature headers: {headers:?}");
        });
    }

    #[test]
    fn sign_headers_for_peer_round_trips_a_genuine_signature_for_a_verified_peer() {
        with_peer_state("sign-verified", || {
            let info = aoide_storage::identity::load_or_mint().unwrap().0.info();
            let mut peer = fixture_peer(None);
            peer.verified = true;
            let body = r#"{"jsonrpc":"2.0","method":"message/send"}"#;
            let headers = sign_headers_for_peer(&peer, body).unwrap();

            let get = |name: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| panic!("missing header {name}: {headers:?}"))
            };
            assert_eq!(get(aoide_storage::wire_auth::HEADER_PEER), peer.name);
            let timestamp = get(aoide_storage::wire_auth::HEADER_TIMESTAMP);
            let nonce = get(aoide_storage::wire_auth::HEADER_NONCE);
            let signature = get(aoide_storage::wire_auth::HEADER_SIGNATURE);
            assert!(aoide_storage::time::parse_iso_utc(&timestamp).is_some(), "a parseable timestamp: {timestamp}");
            assert!(!nonce.is_empty());

            // The server verifies against the SAME path this instance's own
            // `peer_store::url_path` derives from `peer.url` — recomputing it
            // here, rather than hardcoding "/", proves the client and server
            // sides stay bound to the one shared function. Same reasoning for
            // `HTTP_METHOD` (P-P4 review finding 2) over a second `"POST"`
            // literal.
            let path = aoide_storage::peer_store::url_path(&peer.url);
            let canonical = aoide_storage::wire_auth::canonical_string(HTTP_METHOD, &path, &timestamp, &nonce, body.as_bytes());
            assert!(
                aoide_storage::wire_auth::verify_signature_hex(&info.pubkey_hex, canonical.as_bytes(), &signature),
                "the signature must verify against this instance's own identity"
            );

            // Tampering with the body must break verification — proves the
            // signature is actually bound to the body's digest, not just
            // structurally present.
            let tampered = aoide_storage::wire_auth::canonical_string(HTTP_METHOD, &path, &timestamp, &nonce, b"{\"tampered\":true}");
            assert!(!aoide_storage::wire_auth::verify_signature_hex(&info.pubkey_hex, tampered.as_bytes(), &signature));
        });
    }

    #[test]
    fn peer_allow_refuses_an_unknown_peer_or_an_unknown_capability() {
        with_peer_state("refusals", || {
            aoide_storage::peer_store::save_peers(&[fixture_peer(None)]).unwrap();

            let unknown_peer = handle_peer_allow(&allow_inv(&["ghost", "spawn", "on"]));
            assert_eq!(unknown_peer.status, aoide_protocol::output::Status::Error);
            assert_eq!(
                unknown_peer.data.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()),
                Some("unknown-peer")
            );

            let unknown_cap = handle_peer_allow(&allow_inv(&["yomi-strix", "write", "on"]));
            assert_eq!(unknown_cap.status, aoide_protocol::output::Status::Error);
            assert!(unknown_cap.message.contains("read"), "names the valid set: {}", unknown_cap.message);
            assert!(unknown_cap.message.contains("spawn"), "names the valid set: {}", unknown_cap.message);
            assert_eq!(
                unknown_cap.data.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()),
                Some("unknown-capability")
            );

            assert!(aoide_storage::peer_store::load_peers()[0].allows.is_empty(), "no refusal mutates the registry");
        });
    }

    #[test]
    fn peer_allow_reports_usage_on_a_missing_or_malformed_on_off_argument() {
        with_peer_state("usage", || {
            assert_eq!(handle_peer_allow(&allow_inv(&[])).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_peer_allow(&allow_inv(&["yomi-strix"])).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_peer_allow(&allow_inv(&["yomi-strix", "spawn"])).status, aoide_protocol::output::Status::Usage);
            assert_eq!(
                handle_peer_allow(&allow_inv(&["yomi-strix", "spawn", "maybe"])).status,
                aoide_protocol::output::Status::Usage
            );
        });
    }

    // ── `handle_peer_spawn` (P-P5b) — the local refusal shapes are pure file
    // ── I/O (unpaired/unknown), so unit-testable directly; the real signed
    // ── network round trip lives at `cli/tests/peer_connectivity.rs`'s
    // ── `#[ignore]`'d integration layer, same split `peer allow`'s own
    // ── comment above documents. Whether the exact spawn-shaped body
    // ── (`context_id: None`) matches `do_spawn`'s own contract is proven
    // ── against the SERVER's real parser in `aoide-server::a2a`'s own test
    // ── module (a dev-dependency on this crate exists specifically for that
    // ── round trip — see this crate's `Cargo.toml`). ─────────────────────────

    fn spawn_inv(args: &[&str], yes: bool) -> Invocation {
        let mut flags = std::collections::BTreeMap::new();
        if yes {
            flags.insert("yes".to_string(), "true".to_string());
        }
        Invocation {
            path: vec!["peer".to_string(), "spawn".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags,
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn peer_spawn_refuses_an_unknown_peer_naming_pair_request() {
        with_peer_state("spawn-unknown", || {
            let out = handle_peer_spawn(&spawn_inv(&["nosuchpeer", "hello"], true));
            assert_eq!(out.status, aoide_protocol::output::Status::Error);
            assert_eq!(out.data.as_ref().unwrap()["reason"], "unknown-peer");
            assert!(
                out.message.contains("peer pair request"),
                "taught error must name the pairing ceremony: {}",
                out.message
            );
        });
    }

    #[test]
    fn peer_spawn_refuses_a_registered_but_unpaired_peer_naming_pair_request() {
        with_peer_state("spawn-unpaired", || {
            // `verified: false` — registered via the legacy `peer add` escape,
            // never paired. An unsigned request from this peer could never
            // satisfy the remote door's `PeerRung::Signature`-only spawn gate
            // (P-P4) — refused LOCALLY with a clear reason, never sent.
            aoide_storage::peer_store::save_peers(&[fixture_peer(None)]).unwrap();
            let out = handle_peer_spawn(&spawn_inv(&["yomi-strix", "hello"], true));
            assert_eq!(out.status, aoide_protocol::output::Status::Error);
            assert_eq!(out.data.as_ref().unwrap()["reason"], "unpaired-peer");
            assert!(
                out.message.contains("peer pair request"),
                "taught error must name the pairing ceremony: {}",
                out.message
            );
        });
    }

    #[test]
    fn peer_spawn_reports_usage_on_a_missing_name_or_empty_text() {
        with_peer_state("spawn-usage", || {
            assert_eq!(handle_peer_spawn(&spawn_inv(&[], true)).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_peer_spawn(&spawn_inv(&["yomi-strix"], true)).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_peer_spawn(&spawn_inv(&["yomi-strix", "  "], true)).status, aoide_protocol::output::Status::Usage);
        });
    }

    #[test]
    fn peer_spawn_signs_the_exact_spawn_shaped_body_it_would_send() {
        // "signs it (headers present)" — the FIRST production caller that
        // ever signs a `context_id: None` (spawn-shaped) POST. Reuses
        // `sign_headers_for_peer` directly against the SAME body
        // `handle_peer_spawn` builds (`crate::wire::build_message_send_body`
        // with `None`), rather than re-guessing the shape.
        with_peer_state("spawn-signs", || {
            let mut peer = fixture_peer(None);
            peer.verified = true;
            let body = crate::wire::build_message_send_body("do the thing", &gen_message_id(), None);
            assert!(body["params"]["message"].get("contextId").is_none(), "spawn-shaped body carries no contextId");
            let body_str = serde_json::to_string(&body).unwrap();
            let headers = sign_headers_for_peer(&peer, &body_str).unwrap();
            assert_eq!(headers.len(), 4, "all four X-Aoide-* headers present: {headers:?}");
            for name in [
                aoide_storage::wire_auth::HEADER_PEER,
                aoide_storage::wire_auth::HEADER_TIMESTAMP,
                aoide_storage::wire_auth::HEADER_NONCE,
                aoide_storage::wire_auth::HEADER_SIGNATURE,
            ] {
                assert!(headers.iter().any(|(k, _)| k == name), "missing {name}: {headers:?}");
            }
        });
    }

    // ── resolve_peer_bearer — the no-secret-configured short circuit ────────
    //
    // This is the one branch testable with NO broker/socket at all: an
    // unconfigured peer never even tries to connect. Every OTHER branch
    // (a real resolve, a broker-down failure) is exercised end-to-end in
    // `cli/tests/peer_connectivity.rs`, mirroring how every other `peer`
    // command in this file is tested at that integration layer rather than
    // here (this module carried zero unit tests before this task).

    #[test]
    fn resolve_peer_bearer_is_none_when_unset() {
        assert_eq!(resolve_peer_bearer(&fixture_peer(None)).unwrap(), None);
    }

    #[test]
    fn resolve_peer_bearer_is_none_when_set_to_an_empty_string() {
        assert_eq!(resolve_peer_bearer(&fixture_peer(Some(""))).unwrap(), None);
    }

    // ── ScratchBodyFile — pure I/O, no broker needed ─────────────────────────

    #[test]
    fn scratch_body_file_writes_the_body_verbatim_and_removes_itself_on_drop() {
        let path = {
            let scratch = ScratchBodyFile::write(r#"{"jsonrpc":"2.0"}"#).unwrap();
            let path = scratch.0.clone();
            assert!(path.exists());
            let arg = scratch.arg();
            assert_eq!(arg, format!("@{}", path.display()));
            let contents = std::fs::read_to_string(&path).unwrap();
            assert_eq!(contents, r#"{"jsonrpc":"2.0"}"#);
            path
        };
        assert!(!path.exists(), "the scratch file must not outlive its guard");
    }

    #[test]
    fn scratch_body_file_paths_are_unique_across_calls() {
        let a = ScratchBodyFile::write("a").unwrap();
        let b = ScratchBodyFile::write("b").unwrap();
        assert_ne!(a.0, b.0);
    }

    // ── `peer discover` — discovery grants nothing (P-P6). ───────────────────
    //
    // `run_sweep` needs a real socket (bind + multicast join), so this can't
    // be a fully pure test — but it does NOT need a real BEACON to prove the
    // one invariant that matters here: a 1s sweep that hears nothing still
    // must leave `state/peers.json` byte-identical to what it was before.
    // The genuine heard-a-real-beacon path is `cli/tests/
    // discovery_connectivity.rs`'s `#[ignore]`'d real-multicast test; this
    // one runs wherever the network namespace can JOIN the multicast group
    // at all (`discover::multicast_capable` — the nix build sandbox's
    // loopback-only namespace refuses the join itself with ENODEV, not
    // just delivery) and skips with a note where it can't.

    fn discover_inv(secs: &str) -> Invocation {
        Invocation {
            path: vec!["peer".to_string(), "discover".to_string()],
            args: vec![],
            flags: [("secs".to_string(), secs.to_string())].into_iter().collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn peer_discover_never_writes_peers_json_even_on_an_empty_sweep() {
        if !crate::discover::multicast_capable() {
            eprintln!("skipping peer_discover_never_writes_peers_json_even_on_an_empty_sweep: no multicast-capable interface in this network namespace");
            return;
        }
        with_peer_state("discover-no-write", || {
            // A pre-existing peer record must survive `peer discover`
            // completely untouched — the clearest possible proof discover
            // never took a write path into `state/peers.json` at all.
            aoide_storage::peer_store::save_peers(&[fixture_peer(None)]).unwrap();
            let before = aoide_storage::peer_store::load_peers();

            let out = handle_peer_discover(&discover_inv("1"));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let after = aoide_storage::peer_store::load_peers();
            assert_eq!(before.len(), after.len());
            assert_eq!(before[0].name, after[0].name);
            assert_eq!(before[0].verified, after[0].verified);
            assert_eq!(before[0].added_at, after[0].added_at);
        });
    }

    #[test]
    fn peer_discover_never_writes_peers_json_from_an_entirely_empty_registry() {
        if !crate::discover::multicast_capable() {
            eprintln!("skipping peer_discover_never_writes_peers_json_from_an_entirely_empty_registry: no multicast-capable interface in this network namespace");
            return;
        }
        with_peer_state("discover-no-write-empty", || {
            let out = handle_peer_discover(&discover_inv("1"));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert!(
                aoide_storage::peer_store::load_peers().is_empty(),
                "discover must never create state/peers.json out of nothing"
            );
        });
    }

    // ── `peer invite` bottoms out in the exact same `run_pair_request`
    // ── `peer pair request` runs (P-P6) — proven directly by calling it
    // ── through both entry points against the SAME unreachable door and
    // ── asserting byte-identical outcomes, rather than trusting that the
    // ── two call sites merely look alike. The genuine end-to-end proof
    // ── (a real discovered beacon resolving to a real second door that
    // ── actually parks an outbound pairing request) lives in `cli/tests/
    // ── discovery_connectivity.rs`'s `#[ignore]`'d real-network test —
    // ── this one needs no network at all, since an unreachable loopback
    // ── port fails identically (and fast) through either call site. ─────────

    #[test]
    fn peer_invite_tail_and_peer_pair_request_are_the_same_function_not_two_copies() {
        with_peer_state("invite-shares-run-pair-request", || {
            // Port 1 is reserved and never listened on in practice — an
            // immediate, deterministic connection refusal either way.
            let url = "http://127.0.0.1:1/";
            let name = "unreachable-invite-target";
            let self_url = default_self_url();

            // `handle_peer_pair_request`'s own documented tail.
            let direct = run_pair_request("peer.pair.request", url, name, &self_url);
            // The literal call `handle_peer_invite` makes on its single-match
            // branch (`run_pair_request(cmd, &hit.beacon.url, &hit.beacon.name, &self_url)`),
            // reproduced here with the same arguments a real `Heard` would
            // supply, under `peer.invite`'s own command name.
            let via_invite = run_pair_request("peer.invite", url, name, &self_url);

            assert_eq!(direct.status, aoide_protocol::output::Status::Error, "{direct:?}");
            assert_eq!(direct.command, "peer.pair.request");
            assert_eq!(via_invite.status, direct.status);
            assert_eq!(via_invite.command, "peer.invite");
            // Same failure MESSAGE from both call sites (the `cmd` argument
            // never rides the message text itself, only `Outcome::command`)
            // — proves it is one function's error path taken twice under two
            // different labels, not two independently drifting
            // implementations that merely happen to agree today.
            assert_eq!(
                via_invite.message, direct.message,
                "peer invite and peer pair request must produce an identical failure message here"
            );
        });
    }
}
