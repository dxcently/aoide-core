//! The client domain's CLI commands: `node add|remove|allow|hub|pull|
//! status` and `pair` + `pair reject|watch` +
//! `node discover|advertise` (CONTRACTS.md §7, same-network federation and
//! its pairing ceremony) and `adapter melete` (the neutral-event consumer).
//!
//! Moved from the root package's `src/commands/a2a.rs` + the client half of
//! `src/commands/infra.rs` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands live with the
//! domain. The root package's `commands::all()` calls [`register_nodes`]
//! directly after `aoide_server::commands::register_a2a_serve` and
//! [`register_post_graph`] directly before `aoide_conductor::commands::register`,
//! so `schema --json` order never shifts.
//!
//! A node is another aoide instance, addressed by URL and verified via its
//! AgentCard before registration (`aoide_storage::node_store`); registered
//! nodes fold into the session DAG as `kind:"node"` nodes
//! (`graph/doc.rs::build_graph`).

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
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

/// Hard byte cap every curl fetch in this crate is bounded by (#114) —
/// without it, a misbehaving or hostile far side (a compromised node, a
/// captive-portal proxy, `--no-verify` pointed at an arbitrary URL) could
/// hand back an unbounded body and grow this process's memory without
/// limit, since [`run_curl_with_timeout`] used to buffer the ENTIRE
/// response before ever looking at it.
///
/// **Investigated legitimate ceiling**: the biggest real payload any call
/// site here fetches is `node pull`'s `aoide/graphSummary` response, which
/// wraps `build_graph`'s node/edge list (`aoide_conduct::graph::doc::
/// build_graph`) verbatim. Each session node carries a few dozen
/// small/bounded fields (id, cwd, state, title, `say`) — `title`/`say` are
/// already truncated to well under 100 chars before they ever reach a
/// graph document (`aoide_conduct::graph::{permit,send}`'s 27/47/89-char
/// truncations) — so even a very large multi-host instance (thousands of
/// sessions + projects) tops out in the low single-digit megabytes once
/// JSON-encoded. `MAX_RESPONSE_BYTES` is 10x that generous estimate:
/// comfortably above any real graph pull, tight enough to still refuse a
/// runaway one.
const MAX_RESPONSE_BYTES: usize = 20 * 1024 * 1024; // 20 MiB

/// `run_curl`'s parameterised core: same transport, an explicit `--max-time`
/// instead of the hardcoded `15`. Split out for `pull_node_live` (the
/// roster core's presence probe, workstream C2 — reached via bare
/// `session`/`--hosts`) which needs a much shorter per-node bound
/// (~2s) than every other curl call site here — those all keep calling
/// [`run_curl`] unchanged, so this refactor is a pure internal split, not a
/// behavior change for `node pull`/`node add`/etc.
///
/// **#114: bounded by [`MAX_RESPONSE_BYTES`] two ways.** `--max-filesize`
/// (curl's own flag) refuses BEFORE download when the far side declares an
/// over-cap `Content-Length` up front — but curl's own docs are explicit
/// that this does NOT bind a chunked-Transfer-Encoding response, which
/// carries no such upfront length to check against. So the cap is ALSO
/// enforced on the bytes actually read into this process: stdout is read
/// in a bounded loop rather than handed to `wait_with_output` (which
/// buffers the whole response before this function ever sees a single
/// byte of it), and the child is killed the moment the running total
/// crosses the cap — every real fetch in this crate (`post_json`'s node
/// POSTs, the AgentCard GET, `mcp_client`'s Melete calls) routes through
/// this one function, so there is exactly one place this needed wiring.
fn run_curl_with_timeout(
    timeout_secs: u64,
    extra: &[&str],
    stdin_body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut cmd = std::process::Command::new("curl");
    let timeout = timeout_secs.to_string();
    let max_filesize = MAX_RESPONSE_BYTES.to_string();
    cmd.args(["-sS", "--max-time", &timeout, "--max-filesize", &max_filesize, "-w", "\n%{http_code}"]);
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
    let mut stdout_pipe = child.stdout.take().ok_or_else(|| "curl failed".to_string())?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stdout_pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("curl failed (reading its output)".to_string());
            }
        };
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_RESPONSE_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "response exceeded the {MAX_RESPONSE_BYTES}-byte cap \u{2014} refusing (the far side sent too much data)"
            ));
        }
    }
    drop(stdout_pipe);
    let _ = child.wait(); // exit status was never checked before this fix either — %{http_code} below is the real signal
    let stdout = String::from_utf8_lossy(&buf);
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
// registered node whose `Node.bearer_secret` (`aoide_storage::node_store`)
// is set gets that secret resolved fresh, through the SAME
// `aoide_secrets::client::resolve_bounded` this crate now depends on (see
// this crate's `Cargo.toml` comment), and presented as `Authorization:
// Bearer <value>` on every outbound `node pull`/`node status`'s live probe/
// `graph send --to` request to that one node. Before this task, aoide's
// outbound A2A requests sent no Authorization header at all — see
// CONTRACTS.md §6/§7 for the settled shape.

/// The self-asserted consumer name this client presents to the secrets
/// broker when resolving an outbound node bearer — see
/// `crates/secrets/AGENTS.md`'s honesty note (consumer identity is
/// self-asserted; #63's seal authenticates the session and its origin
/// class, never this string): nothing on the wire authenticates this string,
/// it is simply the name an operator's `policy.json` `consumers[]`/
/// `automation.consumers` lists to grant this client access to the named
/// secret.
const BEARER_CONSUMER_CLIENT: &str = "a2a-client";

/// Bound on an outbound bearer resolve's socket read — the same PARKING
/// HAZARD reasoning `aoide-server`'s `a2a.rs::BEARER_RESOLVE_TIMEOUT` states
/// for the inbound side, mirrored here: a misconfigured `requireTotp`
/// secret with no `automation`-open exemption for [`BEARER_CONSUMER_CLIENT`]
/// must never hang an outbound node call. `aoide_secrets::client::
/// resolve_bounded`'s own `wait:false` on the wire means the deployed,
/// automation-open happy path never reaches this timeout at all.
const BEARER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve `node.bearer_secret`, if set, fresh through the local secrets
/// broker — `Ok(None)` when the node has no bearer configured (today's
/// unchanged, no-Authorization-header behavior); `Ok(Some(value))` on a
/// granted resolve; `Err` with a taught message naming the secret, the
/// node, and the broker socket on ANY failure (unreachable broker, denied,
/// or the bounded timeout elapsing) — the outbound call this feeds is
/// refused outright rather than silently sent unauthenticated. **NO
/// CACHING**: a fresh resolve runs on every call to this function; nothing
/// it returns is stored anywhere beyond the caller's own local `Option<String>`
/// for the span of the one outbound request it feeds.
pub(crate) fn resolve_node_bearer(node: &aoide_storage::node_store::Node) -> Result<Option<String>, String> {
    let Some(secret) = node.bearer_secret.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let socket = aoide_secrets::socket::socket_path();
    aoide_secrets::client::resolve_bounded(&socket, secret, BEARER_CONSUMER_CLIENT, BEARER_RESOLVE_TIMEOUT)
        .map(Some)
        .map_err(|e| {
            format!(
                "resolving outbound bearer secret `{secret}` for node `{}` via the secrets broker at {}: {e}",
                node.name,
                socket.display(),
            )
        })
}

/// A short-lived scratch file holding an outbound JSON-RPC request BODY —
/// only created when a bearer is ALSO being sent on the same call, since
/// curl's `-H @-` (reading the `Authorization` header from stdin, see
/// [`post_json`]'s doc) claims stdin for the header instead of the body.
/// Removed on drop. Holds no secret — only the node-directed message text/
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

/// The ONE HTTP method every real node-POST call site in this file ever
/// uses — a single named source [`post_json`]'s own `-X` argument AND
/// [`sign_headers_for_node`]'s signed canonical string both read, so the
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
/// every `node` command that calls a registered node's A2A door now shares
/// (`pull_one_node`, `pull_node_live`, `send_message_to_node`, `handle_node_spawn`).
/// Widened to `pub(crate)` (M2, task #14) so `mcp_client`'s Melete calls
/// reuse this SAME transport rather than hand-rolling a second one — still
/// not exported past this crate.
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
/// — every P-P4 signed-request header (node name, timestamp, nonce,
/// signature) is PUBLIC, verifiable wire material, not a secret; there is
/// nothing in it worth hiding from `/proc/<pid>/cmdline` the way a bearer
/// token is. [`sign_headers_for_node`] is the one production caller that
/// ever passes a non-empty slice here; every other call site (unpaired
/// nodes, the pairing-ceremony wire methods themselves) passes `&[]`,
/// making this parameter's addition byte-identical-when-empty by
/// construction.
pub(crate) fn post_json(url: &str, body: &str, bearer: Option<&str>, extra_headers: &[(String, String)], timeout_secs: u64) -> Result<(u16, String), String> {
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

/// MCP needs response headers as well as the bounded body. Session headers and
/// credentials use stdin; the shared curl runner remains the only spawn point.
pub(crate) struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub(crate) fn request_json_with_headers(
    method: &str,
    url: &str,
    body: &str,
    bearer: &str,
    headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<HttpResponse, String> {
    if method != HTTP_METHOD && method != "DELETE" {
        return Err("unsupported MCP HTTP method".into());
    }
    if bearer.is_empty() || bearer.chars().any(char::is_control) {
        return Err("invalid bearer credential".into());
    }
    let mut header_lines = format!("Authorization: Bearer {bearer}\n");
    for (name, value) in headers {
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || value.chars().any(char::is_control) {
            return Err("invalid HTTP header".into());
        }
        header_lines.push_str(&format!("{name}: {value}\n"));
    }
    let scratch = ScratchBodyFile::write(body)?;
    let data_arg = scratch.arg();
    let (status, raw) = run_curl_with_timeout(timeout_secs, &[
        "--include", "--suppress-connect-headers", "-X", method,
        "-H", "Content-Type: application/json", "-H", "@-",
        "--data-binary", &data_arg, "--", url,
    ], Some(&header_lines))?;
    parse_http_response(status, &raw)
}

fn parse_http_response(status: u16, raw: &str) -> Result<HttpResponse, String> {
    let mut rest = raw;
    loop {
        let (block, body) = rest.split_once("\r\n\r\n")
            .or_else(|| rest.split_once("\n\n"))
            .ok_or("HTTP response has no header boundary")?;
        let mut lines = block.lines();
        let status_line = lines.next().ok_or("HTTP response has no status line")?;
        let mut parts = status_line.split_whitespace();
        if !parts.next().is_some_and(|v| v.starts_with("HTTP/")) {
            return Err("invalid HTTP status line".into());
        }
        let header_status = parts.next().and_then(|s| s.parse::<u16>().ok())
            .ok_or("invalid HTTP status code")?;
        if (100..200).contains(&header_status) {
            rest = body;
            continue;
        }
        if header_status != status {
            return Err("HTTP status does not match transport status".into());
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("invalid HTTP response header")?;
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
        return Ok(HttpResponse { status, headers, body: body.to_string() });
    }
}

// ── Dial resolution (ssh-transport lane, P-S4): the tunnel seam every
// ── outbound POST resolves through BEFORE it ever reaches `post_json` ───────
//
// `aoide_client::tunnel::open_or_reuse` (P-S3) opens/reuses the ssh child;
// `aoide_storage::tunnel::dial_url` (P-S2) rewrites the dial url's authority
// while preserving its PATH verbatim — §0.4's identity guarantee
// [`sign_headers_for_node`]'s canonical string depends on. Everything below
// is additive in front of `post_json`, which itself is UNCHANGED by this
// phase.

/// The session id a tunnel opened by this process's own dial resolution is
/// keyed under (the ssh-transport plan's open knob K3): the ambient
/// `AOIDE_SESSION_ID` a conducted session's parent already exports
/// (`aoide_conduct::graph::conduct::conduct_socket_path`'s own env — read
/// here as a plain env var, never a dependency on `aoide-conduct`: `client`
/// sits BELOW it in the crate DAG), or a process-scoped `pid-<pid>`
/// fallback for a bare shell that never went through `conduct`/`wrap`.
///
/// **P-S4 stops at resolving and passing this key through.** A tunnel
/// opened under the `AOIDE_SESSION_ID` case is deliberately left OPEN when
/// this process exits — reused by every later action under the same
/// conducted session (the plan's own "persistent within a session" shape),
/// closed only by P-S5's session-end fast path or its reaper backstop,
/// neither of which exists yet. A tunnel opened under the `pid-<pid>`
/// fallback is ALSO left open here, even though nothing will ever reuse
/// that exact key again (a pid is never repeated by a later invocation) —
/// closing it at this command's own exit was considered (K3's own "closed
/// on the command's own exit" shape) and deliberately NOT done: `pull_node_live`/
/// `send_message_to_node`/`spawn_on_node` are called from `aoide-conduct`
/// command handlers (`who.rs`/`send.rs`/`resurrect.rs`), not from a
/// client-owned CLI handler this phase can wrap — closing only at the
/// four client-owned handlers (`node add|invite|pair request|spawn`) while
/// leaving those three call sites unclosed would make the SAME function
/// behave inconsistently depending on which crate called it. A single,
/// uniform "every tunnel this phase opens stays open" story is more honest
/// than a partial close that only covers some call sites — P-S5 is where
/// the real lifecycle (both kinds, both close paths) belongs, all at once.
pub(crate) fn tunnel_session_id() -> String {
    std::env::var("AOIDE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("pid-{}", std::process::id()))
}

/// The port an ssh `-L` forward's REMOTE half should read from — every A2A
/// door binds `127.0.0.1` only (root `AGENTS.md`'s loopback-only-bind
/// invariant), so the forward always terminates on the far box's own
/// loopback; `via`'s `host` is what the tunnel dials INTO, never what the
/// forward reads FROM once inside (`aoide_client::tunnel::open_or_reuse`'s
/// own `remote_host`/`remote_port` parameters name this same split).
/// Extracted from `logical_url`'s own authority via
/// [`aoide_storage::node_store::url_host`]; falls back to the scheme's
/// conventional default (`80`/`443`) only when the url carries no explicit
/// port — every real node url in this system names its door port
/// explicitly, so this is a generous fallback, never the common case.
fn remote_port_from_url(logical_url: &str) -> Result<u16, String> {
    let host = aoide_storage::node_store::url_host(logical_url)
        .ok_or_else(|| format!("`{logical_url}` is not a url — cannot resolve a tunnel target port"))?;
    if let Some((_, port)) = host.rsplit_once(':') {
        return port
            .parse::<u16>()
            .map_err(|_| format!("`{logical_url}` has an unparseable port `{port}`"));
    }
    if logical_url.trim_start().starts_with("https://") {
        Ok(443)
    } else {
        Ok(80)
    }
}

/// Resolve the url a POST should actually dial. `via: None` is the
/// IDENTITY case — returns `logical_url` byte-for-byte, the "off = today's
/// behavior, unchanged" guarantee every call site below depends on and a
/// test pins directly. With a `via`, opens/reuses the tunnel keyed
/// `(session, tunnel_key)` (`aoide_client::tunnel::open_or_reuse`) and
/// rewrites `logical_url`'s authority to `127.0.0.1:<local port>` via
/// [`aoide_storage::tunnel::dial_url`], which preserves the PATH verbatim —
/// never re-derived here, so a dial url's path and
/// [`sign_headers_for_node`]'s canonical-string path can never drift apart
/// from two independent cuts of the same url.
fn resolve_dial_url(
    logical_url: &str,
    via: Option<&aoide_storage::tunnel::Via>,
    tunnel_key: &str,
) -> Result<String, String> {
    let Some(via) = via else {
        return Ok(logical_url.to_string());
    };
    let remote_port = remote_port_from_url(logical_url)?;
    let session_id = tunnel_session_id();
    let local_port = crate::tunnel::open_or_reuse(&session_id, tunnel_key, via, "127.0.0.1", remote_port)?;
    aoide_storage::tunnel::dial_url(logical_url, local_port)
}

/// [`post_json`] wrapped with dial resolution for a PAIRED
/// [`aoide_storage::node_store::Node`] — resolves `node.via` (parsed via
/// [`aoide_storage::tunnel::parse_via`]) into a dial url keyed by
/// `node.name` itself (already `valid_node_name`-shaped — every registered
/// node's own nickname, the identical shape [`aoide_storage::tunnel::
/// record_path`] requires of a tunnel `key`) BEFORE calling [`post_json`],
/// changing nothing about what `post_json` itself does. With no `node.via`
/// (today's every real node), [`resolve_dial_url`] is the identity
/// function — the url handed to `post_json` is `node.url`, BYTE-IDENTICAL
/// to every call site's own behavior before this function existed (pinned
/// per call site by this module's tests). An unparseable `node.via` (a
/// hand-edited `nodes.json`) is a hard `Err`, never a silent direct-dial
/// fallback — the same "malformed input refuses, never guesses" stance
/// [`aoide_storage::tunnel::parse_via`] itself holds.
pub(crate) fn post_json_to_node(
    node: &aoide_storage::node_store::Node,
    body: &str,
    bearer: Option<&str>,
    extra_headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<(u16, String), String> {
    let via = node
        .via
        .as_deref()
        .map(aoide_storage::tunnel::parse_via)
        .transpose()
        .map_err(|e| format!("node `{}`'s recorded via: {e}", node.name))?;
    let dial_url = resolve_dial_url(&node.url, via.as_ref(), &node.name)?;
    post_json(&dial_url, body, bearer, extra_headers, timeout_secs)
}

/// [`post_json_to_node`]'s own body, plus an explicit `via_override` that
/// BEATS `node.via` when present — [`spawn_on_node_via`]'s only caller
/// (`node spawn --via …`), the one call site an operator can override the
/// recorded transport marker from at call time. `via_override: None` makes
/// this byte-identical to [`post_json_to_node`] (resolves `node.via`
/// exactly the same way), which is why [`post_json_to_node`] itself is
/// NOT reimplemented in terms of this — the common, override-free path
/// stays the simpler function.
pub(crate) fn post_json_to_node_with_via_override(
    node: &aoide_storage::node_store::Node,
    body: &str,
    bearer: Option<&str>,
    extra_headers: &[(String, String)],
    timeout_secs: u64,
    via_override: Option<&aoide_storage::tunnel::Via>,
) -> Result<(u16, String), String> {
    if let Some(via) = via_override {
        let dial_url = resolve_dial_url(&node.url, Some(via), &node.name)?;
        return post_json(&dial_url, body, bearer, extra_headers, timeout_secs);
    }
    post_json_to_node(node, body, bearer, extra_headers, timeout_secs)
}

/// [`post_json`] wrapped with dial resolution for a CEREMONY call — no
/// `Node` record exists yet to read a marker off of ([`run_pair_request`]'s
/// `aoide/pairRequest`/`aoide/pairReveal`, [`approve_outbound`]'s
/// `aoide/pairPoll`), so `via`/`tunnel_key` are the CALLER's
/// own resolution (an explicit `--via` flag; never auto-derived here).
/// `bearer`/`extra_headers` are `None`/`&[]` at every real call site (the
/// ceremony's own protocol, `client/AGENTS.md`) — kept as parameters
/// anyway so this stays [`post_json`]'s same general shape, not a
/// ceremony-only special case.
fn post_json_via(
    logical_url: &str,
    via: Option<&aoide_storage::tunnel::Via>,
    tunnel_key: &str,
    body: &str,
    bearer: Option<&str>,
    extra_headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<(u16, String), String> {
    let dial_url = resolve_dial_url(logical_url, via, tunnel_key)?;
    post_json(&dial_url, body, bearer, extra_headers, timeout_secs)
}

/// Parse the `--via` flag shared by every CLI command that accepts the
/// ssh-transport marker (`node.add`, `node.invite`, `pair`,
/// `node.spawn`, P-S4): absent is `Ok(None)` (today's direct-dial default,
/// unchanged); present-but-unparsable is `Err` with
/// [`aoide_storage::tunnel::parse_via`]'s own taught message. A malformed
/// `--via` is a USAGE error, never a silent fallback to a direct dial —
/// the same "a typo'd flag never quietly behaves as if it were never
/// passed" stance [`parse_secs_flag`] already holds one flag over.
fn parse_via_flag(inv: &Invocation) -> Result<Option<aoide_storage::tunnel::Via>, String> {
    match inv.flags.get("via").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(spec) => aoide_storage::tunnel::parse_via(spec).map(Some),
    }
}

/// Build the four P-P4 signature headers for one outbound POST to `node`,
/// or `vec![]` when `node.verified` is `false` — an unpaired/unverified
/// node keeps today's door-wide-bearer-only path exactly as before this
/// task, unchanged (`docs/architecture/PAIRING.md`, decision 6, "Unpaired
/// callers keep today's door-wide bearer path"). This is the ONE production
/// call site [`post_json`]'s doc comment names as the non-empty-slice
/// caller.
///
/// Mints a fresh nonce (`aoide_storage::pairing::random_hex(16)` — the same
/// mint the pairing ceremony itself already uses, reused rather than a
/// second nonce generator), stamps the current instant
/// (`aoide_storage::time::now_iso_utc`), computes the wire PATH via
/// `aoide_storage::node_store::url_path(&node.url)` (never re-derived ad
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
/// (`aoide_storage::identity::load_or_mint()`) — never the node's.
///
/// `X-Aoide-Node` carries THIS instance's own SELF name
/// (`aoide_storage::display::local_host_name()`) — never `node.name`, which
/// is only this side's local nickname for the counterpart and carries no
/// meaning to the far end. Each instance identifies itself by its own self
/// name on every wire call that claims an identity: the pairing ceremony's
/// `pairRequest.name` (`run_pair_request`, same `local_host_name()` chain
/// the discovery advertisement and `graphSummary` also use) and this header both
/// say "this is who I am," so both carry the same value. The name is
/// ATTRIBUTION, not identity (#63 P-ID5): the far end resolves the caller
/// BY THE KEY THAT SIGNED (`aoide-server::a2a::verify_signed_request` tries
/// the signature against every verified node's stored pubkey and takes the
/// record whose key verifies — CONTRACTS.md §6 "Inbound verification"), so
/// a stale or mismatched name here never breaks authentication; the far end
/// audits the mismatch as attribution drift and proceeds under its own
/// record's name. The name's one identity-adjacent role on the far end is
/// the exact-name tiebreak when two of its records share this instance's
/// pubkey — one more reason this header stays the stable self name.
/// `--name`/`node.name` stay purely a local label this instance uses to
/// refer to the counterpart, never an identity claim that crosses the wire.
///
/// Returns `Err` only on a genuine identity-load failure (a corrupt or
/// unwritable `state/identity/` — the same failure shape
/// `identity::load_or_mint` already surfaces for every other caller); a
/// verified node with no loadable identity refuses the whole outbound call
/// rather than silently falling back to an unsigned request, since an
/// unsigned request to a node that has since upgraded to require signed
/// spawn admission would otherwise fail opaquely on the far end instead of
/// here, where the real cause is known.
pub(crate) fn sign_headers_for_node(node: &aoide_storage::node_store::Node, body: &str) -> Result<Vec<(String, String)>, String> {
    if !node.verified {
        return Ok(Vec::new());
    }
    let (keypair, _) = aoide_storage::identity::load_or_mint()
        .map_err(|e| format!("loading this instance's identity to sign a request to node `{}`: {e}", node.name))?;
    let path = aoide_storage::node_store::url_path(&node.url);
    let timestamp = aoide_storage::time::now_iso_utc();
    let nonce = aoide_storage::pairing::random_hex(16);
    let canonical = aoide_storage::wire_auth::canonical_string(HTTP_METHOD, &path, &timestamp, &nonce, body.as_bytes());
    let signature = aoide_storage::wire_auth::sign_hex(&keypair, canonical.as_bytes());
    Ok(vec![
        (aoide_storage::wire_auth::HEADER_NODE.to_string(), aoide_storage::display::local_host_name()),
        (aoide_storage::wire_auth::HEADER_TIMESTAMP.to_string(), timestamp),
        (aoide_storage::wire_auth::HEADER_NONCE.to_string(), nonce),
        (aoide_storage::wire_auth::HEADER_SIGNATURE.to_string(), signature),
    ])
}

/// Build a SIGNED `aoide/pairPoll` body for pairing request `id` (Design A,
/// task #119 — `approve_outbound`'s own poll step; REPLACES the old
/// `aoide/pairApprove` reverse callback). Unlike [`sign_headers_for_node`],
/// this can be called with NO [`aoide_storage::node_store::Node`] record at
/// all — none exists yet at poll time, that's the whole bootstrapping
/// problem P-P4's header scheme can't solve here
/// (`aoide-server::a2a::pair_poll`'s own doc). Signs
/// `aoide_storage::wire_auth::canonical_string("PAIRPOLL", id, timestamp,
/// nonce, &[])` with THIS instance's own identity — the SAME key that
/// produced `pubkeyHex` in the original `aoide/pairRequest`, which is what
/// the approver's door verifies against
/// ([`aoide_storage::pairing::InboundPairingRequest::pubkey_hex`], captured
/// at request time). Returns the serialized JSON-RPC body ready to POST.
fn build_signed_pair_poll_body(id: &str) -> Result<String, String> {
    let (keypair, _) =
        aoide_storage::identity::load_or_mint().map_err(|e| format!("loading this instance's identity to poll pairing request `{id}`: {e}"))?;
    let timestamp = aoide_storage::time::now_iso_utc();
    let nonce = aoide_storage::pairing::random_hex(16);
    let canonical = aoide_storage::wire_auth::canonical_string("PAIRPOLL", id, &timestamp, &nonce, &[]);
    let signature = aoide_storage::wire_auth::sign_hex(&keypair, canonical.as_bytes());
    let body = crate::node::build_pair_poll_body(id, &timestamp, &nonce, &signature);
    Ok(serde_json::to_string(&body).unwrap_or_default())
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

// ── The seven `node` commands (CONTRACTS.md §7: same-network federation) ───────
//
// A node is ANOTHER aoide instance, addressed by URL (topology-agnostic —
// the protocol never cares whether that URL happens to resolve on the same
// loopback host, a LAN, or a tailnet; it's just a URL). `node add` verifies
// by fetching the node's AgentCard first, before registering anything;
// `node pull` calls the NEW `aoide/graphSummary` method
// (`aoide-server::a2a::graph_summary`) and caches the result; `build_graph`
// (`aoide-conduct`) folds a fresh cache in as a `node:<name>` root node. The
// registry lives in `state/nodes.json` (`aoide_storage::node_store`) —
// external registry-style state, not song-scoped rehearsal state.

/// `node add <name> <url> [--autogate]` — verify the node by fetching its
/// AgentCard first, then register `name` → `url`. A duplicate `name` is
/// rejected cleanly — CONTRACTS.md §7's explicit stance (a node's local
/// nickname should never be silently repointed at a different URL by a
/// second `add`).
fn handle_node_add(inv: &Invocation) -> Outcome {
    let cmd = "node.add";
    const USAGE: &str = "usage: aoide node add <name> <url> [--autogate] [--no-verify] [--via ssh://[user@]host[:port]] [--json]";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let url = match inv.args.get(1).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    // An invalid --via is a usage error, never a silent fallback to a
    // direct dial (parse_via_flag's own stance).
    let via = match parse_via_flag(inv) {
        Ok(v) => v,
        Err(e) => return Outcome::usage(cmd, format!("{USAGE} — {e}")),
    };
    // `name` is joined straight into `state/node-cache/<name>.json`
    // (`node_store::node_cache_path`) — reject a traversal shape here,
    // before it's ever registered, same guard `rice compose` applies to a
    // song name.
    if !aoide_storage::node_store::valid_node_name(&name) {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` is not a valid node nickname: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }
    let autogate = inv.flag_present("autogate");
    let no_verify = inv.flag_present("no-verify");
    let token_file = inv.flags.get("token-file").cloned().filter(|s| !s.is_empty());
    let bearer_secret = inv.flags.get("bearer-secret").cloned().filter(|s| !s.is_empty());

    let mut nodes = aoide_storage::node_store::load_nodes();
    if nodes.iter().any(|p| p.name == name) {
        return Outcome::error(cmd, format!("node `{name}` is already registered — remove it first to re-add"))
            .with_data(json!({ "reason": "duplicate-name", "name": name }));
    }

    // Verify: fetch the node's AgentCard BEFORE registering anything — a
    // node that fails this fetch never gets added. This is the ONLY
    // network call `node add` ever makes, so it must dial through the
    // tunnel exactly like every other cross-box call when `--via` is
    // given (review finding, P-S4 follow-up): a loopback-bound door
    // reachable ONLY through the tunnel — precisely the scenario `--via`
    // exists for — used to fail verification here before the node was
    // ever registered, making the flag dead weight on `add`. `card_url`
    // stays the LOGICAL url for display and for the node record below;
    // `resolve_dial_url` (this module's own P-S4 funnel) rewrites the
    // fetch target's authority when a via is present, preserving its
    // `.well-known/agent-card.json` path verbatim — no signing is
    // involved either way (a card fetch is a plain GET, never a signed
    // request), so there is no canonical-string path to keep in sync
    // here, unlike the signed node calls this funnel also serves.
    //
    // `--no-verify` skips this entire block — for a node that serves no
    // AgentCard at all (a plain A2A client endpoint, e.g. an inbound-only
    // harness like Melete that never stood up the discovery surface this
    // fetch expects). The node is still recorded exactly as the verified
    // path records it below: `verified` was already hardcoded `false` on
    // this path regardless (a card fetch is reachability, never identity
    // — that only ever comes from `pair`), so skipping the fetch
    // changes nothing about what gets written, only whether this one GET
    // runs first.
    if !no_verify {
        let card_url = crate::wire::resolve_card_url(&url);
        let fetch_url = match resolve_dial_url(&card_url, via.as_ref(), &name) {
            Ok(u) => u,
            Err(e) => {
                return Outcome::error(cmd, format!("opening a tunnel to verify node AgentCard at {card_url}: {e}"))
                    .with_data(json!({ "reason": "tunnel-failed", "url": card_url }))
            }
        };
        let (code, body) = match run_curl(&["--", &fetch_url], None) {
            Ok(v) => v,
            Err(e) => {
                return Outcome::error(cmd, format!("verifying node AgentCard at {card_url}: {e}"))
                    .with_data(json!({ "reason": "fetch-failed", "url": card_url }))
            }
        };
        if code != 200 {
            return Outcome::error(cmd, format!("verifying node AgentCard at {card_url}: HTTP {code}"))
                .with_data(json!({ "reason": "fetch-http-error", "url": card_url, "httpCode": code }));
        }
        if serde_json::from_str::<Value>(&body).is_err() {
            return Outcome::error(cmd, format!("verifying node AgentCard at {card_url}: unparseable response"))
                .with_data(json!({ "reason": "card-unparseable", "url": card_url }));
        }
    }

    let node = aoide_storage::node_store::Node {
        name: name.clone(),
        url: url.clone(),
        autogate,
        token_file,
        bearer_secret,
        hub: false,
        pubkey: None,
        verified: false,
        allows: Vec::new(),
        via: via.as_ref().map(|v| v.to_string()),
        added_at: aoide_storage::time::now_iso_utc(),
    };
    aoide_storage::node_store::insert_node(&mut nodes, node.clone());
    if let Err(e) = aoide_storage::node_store::save_nodes(&nodes) {
        return Outcome::error(cmd, format!("writing the node registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(
        cmd,
        format!(
            "registered node `{name}` → {url}{} ({} total)",
            if autogate { " (autogate)" } else { "" },
            nodes.len()
        ),
    )
    .changed(vec![aoide_storage::node_store::nodes_path().to_string_lossy().into_owned()])
    .with_data(json!({ "node": node, "count": nodes.len() }))
}

/// `node remove <name>` — deregister; a MISSING name is a clean error, not
/// idempotent-silent (following `rice draft drop <name>`'s precedent: a
/// missing target is a real mistake worth surfacing — CONTRACTS.md §7 calls
/// this stance out explicitly). Also drops the node's cache file, if any,
/// so a re-added-under-the-same-name node never starts from a stale
/// leftover.
fn handle_node_remove(inv: &Invocation) -> Outcome {
    let cmd = "node.remove";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide node remove <name> [--json]"),
    };
    // Defense in depth (mirrors `handle_node_add`'s own guard): `name` is
    // about to reach `node_cache_path(&name)` below via `remove_file`, a
    // DELETE — refuse a traversal shape even if it somehow got past `add`
    // (e.g. a hand-edited `state/nodes.json`) before it ever reaches that
    // path join.
    if !aoide_storage::node_store::valid_node_name(&name) {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` is not a valid node nickname: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }
    let mut nodes = aoide_storage::node_store::load_nodes();
    if !aoide_storage::node_store::remove_node(&mut nodes, &name) {
        return Outcome::error(cmd, format!("no node named `{name}`"))
            .with_data(json!({ "reason": "unknown-node", "name": name }));
    }
    if let Err(e) = aoide_storage::node_store::save_nodes(&nodes) {
        return Outcome::error(cmd, format!("writing the node registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    let _ = std::fs::remove_file(aoide_storage::node_store::node_cache_path(&name));
    Outcome::ok(cmd, format!("removed node `{name}` ({} remaining)", nodes.len()))
        .changed(vec![aoide_storage::node_store::nodes_path().to_string_lossy().into_owned()])
        .with_data(json!({ "removed": true, "name": name, "count": nodes.len() }))
}

/// `node hub <name> [--clear]` — designate `name` as THE hub (at most one;
/// setting a new hub moves it, clearing the previous holder in the same
/// write) or, with `--clear`, remove the hub designation from `name` if it
/// currently holds it (P-D5, `docs/architecture/AOIDED.md`'s "The hub
/// option"). Both directions are idempotent — `node_store::set_hub`/
/// `clear_hub` report exactly what changed (set/moved/cleared/no-op) and
/// this handler's message says so plainly rather than a bare "ok"; a no-op
/// never touches disk (nothing to write back).
/// `node allow <name> <cap> on|off` (P-P3, `docs/architecture/PAIRING.md`
/// decision 5): flip one capability in `name`'s `allows` set —
/// `aoide_storage::node_store::set_node_allow` holds the closed-set
/// validation and the idempotence invariant; this handler just reports
/// exactly what changed (enabled/disabled/no-op), mirroring `handle_node_hub`'s
/// "report the change, never a bare ok" discipline one field over. Refuses
/// an unknown node AND an unknown capability — the capability check runs
/// FIRST (`set_node_allow`'s own ordering), so a typo'd capability against a
/// typo'd name still names the capability problem, not the node one.
fn handle_node_allow(inv: &Invocation) -> Outcome {
    let cmd = "node.allow";
    const USAGE: &str = "usage: aoide node allow <name> <cap> on|off";
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

    let mut nodes = aoide_storage::node_store::load_nodes();
    let change = match aoide_storage::node_store::set_node_allow(&mut nodes, &name, &cap, on) {
        Ok(c) => c,
        Err(aoide_storage::node_store::AllowError::UnknownCapability) => {
            return Outcome::error(
                cmd,
                format!(
                    "unknown capability `{cap}` — valid capabilities: {}",
                    aoide_storage::node_store::NODE_CAPABILITIES.join(", ")
                ),
            )
            .with_data(json!({ "reason": "unknown-capability", "cap": cap }));
        }
        Err(aoide_storage::node_store::AllowError::UnknownNode) => {
            return Outcome::error(cmd, format!("no node named `{name}`"))
                .with_data(json!({ "reason": "unknown-node", "name": name }));
        }
    };

    use aoide_storage::node_store::AllowChange;
    let (msg, tag) = match &change {
        AllowChange::Enabled => (format!("`{cap}` is now allowed for node `{name}`"), "enabled"),
        AllowChange::Disabled => (format!("`{cap}` is no longer allowed for node `{name}`"), "disabled"),
        AllowChange::NoOp if on => (format!("`{name}` already allows `{cap}`"), "no-op"),
        AllowChange::NoOp => (format!("`{name}` already does not allow `{cap}`"), "no-op"),
    };
    let data = json!({ "name": name, "cap": cap, "on": on, "change": tag });

    if matches!(change, AllowChange::NoOp) {
        return Outcome::ok(cmd, msg).with_data(data);
    }
    if let Err(e) = aoide_storage::node_store::save_nodes(&nodes) {
        return Outcome::error(cmd, format!("writing the node registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(cmd, msg)
        .changed(vec![aoide_storage::node_store::nodes_path().to_string_lossy().into_owned()])
        .with_data(data)
}

fn handle_node_hub(inv: &Invocation) -> Outcome {
    let cmd = "node.hub";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide node hub <name> [--clear] [--json]"),
    };
    let clear = inv.flag_present("clear");
    let mut nodes = aoide_storage::node_store::load_nodes();

    let change = if clear {
        aoide_storage::node_store::clear_hub(&mut nodes, &name)
    } else {
        aoide_storage::node_store::set_hub(&mut nodes, &name)
    };
    let change = match change {
        Ok(c) => c,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "unknown-node", "name": name })),
    };

    use aoide_storage::node_store::HubChange;
    let (msg, tag) = match &change {
        HubChange::Set => (format!("node `{name}` is now the hub"), "set"),
        HubChange::Moved { from } => (format!("hub moved from `{from}` to `{name}`"), "moved"),
        HubChange::Cleared => (format!("cleared the hub designation from `{name}`"), "cleared"),
        HubChange::NoOp if clear => (format!("`{name}` was not the hub — nothing to clear"), "no-op"),
        HubChange::NoOp => (format!("`{name}` is already the hub"), "no-op"),
    };
    let data = json!({ "name": name, "clear": clear, "change": tag });

    if matches!(change, HubChange::NoOp) {
        return Outcome::ok(cmd, msg).with_data(data);
    }
    if let Err(e) = aoide_storage::node_store::save_nodes(&nodes) {
        return Outcome::error(cmd, format!("writing the node registry: {e}"))
            .with_data(json!({ "reason": "registry-write-failed" }));
    }
    Outcome::ok(cmd, msg)
        .changed(vec![aoide_storage::node_store::nodes_path().to_string_lossy().into_owned()])
        .with_data(data)
}

/// Pull ONE node: POST `aoide/graphSummary`, parse, write the cache. On ANY
/// failure (unreachable, timeout, non-200, malformed) — mark the cache
/// STALE with the failure reason rather than deleting it or propagating the
/// error to the caller, so one node being down never breaks `node pull` for
/// the others (`handle_node_pull` below iterates every selected node through
/// this regardless of an individual failure). Returns a small JSON summary
/// row for the aggregate Outcome's `data.results`.
fn pull_one_node(node: &aoide_storage::node_store::Node) -> Value {
    let now = aoide_storage::time::now_iso_utc();
    let body = crate::node::build_graph_summary_request();
    let body_str = serde_json::to_string(&body).unwrap_or_default();

    let attempt: Result<aoide_storage::node_store::NodeCacheEntry, String> = (|| {
        let bearer = resolve_node_bearer(node)?;
        let extra_headers = sign_headers_for_node(node, &body_str)?;
        let (code, resp_body) = post_json_to_node(node, &body_str, bearer.as_deref(), &extra_headers, 15)?;
        if code != 200 {
            return Err(format!("HTTP {code}"));
        }
        let resp: Value =
            serde_json::from_str(&resp_body).map_err(|e| format!("unparseable response: {e}"))?;
        crate::node::parse_graph_summary_response(&resp, &node.name, &now)
    })();

    match attempt {
        Ok(entry) => {
            let write_err = aoide_storage::node_store::save_node_cache(&entry).err();
            match write_err {
                None => json!({ "name": node.name, "ok": true, "fetchedAt": now }),
                Some(e) => json!({ "name": node.name, "ok": false, "error": format!("cache write failed: {e}") }),
            }
        }
        Err(e) => {
            // Preserve whatever was already cached (the last GOOD pull) —
            // only flip `stale`/`lastError`; never delete, never blank the
            // node out of the fold over a transient outage.
            let mut entry = aoide_storage::node_store::load_node_cache(&node.name).unwrap_or_else(|| {
                aoide_storage::node_store::NodeCacheEntry {
                    schema_version: "0".to_string(),
                    name: node.name.clone(),
                    ..Default::default()
                }
            });
            entry.stale = true;
            entry.last_error = Some(e.clone());
            let _ = aoide_storage::node_store::save_node_cache(&entry);
            json!({ "name": node.name, "ok": false, "error": e })
        }
    }
}

/// Pull ONE node's `aoide/graphSummary` LIVE, with an explicit per-call
/// `timeout_secs`, WITHOUT writing `state/node-cache/<name>.json` — the
/// read-only sibling of [`pull_one_node`] (which persists on every
/// outcome). The roster core's presence probe (conduct crate, workstream
/// C2 — reached via bare `session`/`--hosts`; the standalone `who` command
/// it originally backed is retired, session-surface redesign, command-defrag
/// lane X, 2026-08-28) is the reason this exists: it reuses this exact curl
/// transport (never reimplements HTTP — see the crate's `Cargo.toml` for why
/// the `conduct → client` edge stays) but must never treat a presence query
/// as a cache-refreshing side effect. `build_graph`'s fold (`aoide-conduct`)
/// is the ONLY writer of that cache; the roster core only ever READS it, as
/// the fallback for a node this call fails to reach. Returns just the node's
/// resolved `graph` document (`{nodes, edges}`) — the roster core has no use
/// for the envelope's `instance` field `pull_one_node` also captures.
pub fn pull_node_live(node: &aoide_storage::node_store::Node, timeout_secs: u64) -> Result<Value, String> {
    let body = crate::node::build_graph_summary_request();
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer = resolve_node_bearer(node)?;
    let extra_headers = sign_headers_for_node(node, &body_str)?;
    let (code, resp_body) = post_json_to_node(node, &body_str, bearer.as_deref(), &extra_headers, timeout_secs)?;
    if code != 200 {
        return Err(format!("HTTP {code}"));
    }
    let resp: Value =
        serde_json::from_str(&resp_body).map_err(|e| format!("unparseable response: {e}"))?;
    let now = aoide_storage::time::now_iso_utc();
    let entry = crate::node::parse_graph_summary_response(&resp, &node.name, &now)?;
    Ok(entry.graph.unwrap_or_else(|| json!({ "nodes": [], "edges": [] })))
}

/// POST a `message/send` to a NODE with an explicit `contextId` naming the
/// REMOTE session to inject into. `graph send --to <node>/<query>` (`aoide-conduct`,
/// workstream C3) resolves `query` against the node's cached graph to that
/// one remote sessionId, then drives THIS function — the transport lives
/// here (not duplicated in `conduct`) for the same reason [`pull_node_live`]
/// does, see the crate's `Cargo.toml`/`AGENTS.md` on the `conduct → client`
/// edge.
///
/// Same `run_curl` transport and 15s timeout every other `message/send`
/// call site in this file uses — this is a real delivery, not the roster
/// core's short-timeout presence probe, so it does NOT reuse
/// [`pull_node_live`]'s tighter bound. Returns the parsed JSON-RPC response
/// on a 200 with no `error` member; any transport/HTTP/JSON-RPC failure is
/// `Err` with a plain message the caller (`aoide-conduct`) can surface and
/// audit directly — mirrors [`pull_node_live`]'s `Result`-not-`Outcome`
/// shape so the caller builds its own `Outcome`/audit line, never this one.
pub fn send_message_to_node(
    node: &aoide_storage::node_store::Node,
    text: &str,
    context_id: &str,
) -> Result<Value, String> {
    let message_id = gen_message_id();
    let body = crate::wire::build_message_send_body(text, &message_id, Some(context_id));
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer = resolve_node_bearer(node)?;
    let extra_headers = sign_headers_for_node(node, &body_str)?;
    let (code, resp) = post_json_to_node(node, &body_str, bearer.as_deref(), &extra_headers, 15)?;
    if code != 200 {
        return Err(format!("HTTP {code}"));
    }
    let parsed: Value =
        serde_json::from_str(&resp).map_err(|e| format!("unparseable response: {e}"))?;
    // A JSON-RPC error still returns HTTP 200 — surface it as an `Err`, not
    // a silently-`Ok`'d error envelope.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Err(format!("node returned an error: {detail}"));
    }
    Ok(parsed)
}

/// Prompt `y/N` before spawning on a node — a LOCAL UX confirmation only
/// (mirrors `confirm_invite`'s exact idiom), never a security gate: the
/// remote door's own paired+signature+allows∋spawn check (PAIRING.md
/// decision 6) is the sole authority either way. Retrofit onto
/// `aoide_protocol::pick::
/// confirm` (ONBOARD.md's prompt substrate section, P-I1): `inquire::
/// Confirm` on a tty, the identical stdin `y/N` read otherwise — the
/// question text itself is unchanged, `confirm` owns the `[y/N]` decoration
/// now instead of this function.
fn confirm_spawn(name: &str, text: &str) -> Result<bool, String> {
    aoide_protocol::pick::confirm(&format!("spawn a new session on node `{name}` — first turn: {text:?} — proceed?"))
}

/// `node spawn <name> [--yes] -- <text…>` (P-P5b, making PAIRING.md's
/// headline spawn gate actually reachable from the CLI — before this command,
/// every client→node function sent either a read (`aoide/graphSummary`) or
/// an Inject (`send_message_to_node`, always carrying a `contextId`); NONE
/// emitted a spawn-shaped `message/send` — `context_id: None` — to a
/// paired node, so the server's `do_spawn` arm, fully built and
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
/// remote-chosen executable: which agent runs is the NODE's own configured
/// `aoide.a2a.spawnAgent`, never client-supplied (`do_spawn`'s own doc
/// comment on `SessionRef`'s security model). Built via
/// `crate::wire::build_message_send_body(text, message_id, None)` — the
/// SAME builder every other `message/send` call site in this file uses, so
/// this is a proven shape, not a new invention.
///
/// **Signing**: [`sign_headers_for_node`] — this is the FIRST production
/// call site that ever signs a SPAWN-shaped POST (`context_id: None`);
/// every earlier call site (`pull_one_node`, `pull_node_live`,
/// `send_message_to_node`) sends a read or an Inject. `node.verified ==
/// false` still yields an empty header slice exactly as it does for those
/// three (unchanged behavior) — which is precisely why this function
/// refuses an unpaired/unknown node LOCALLY first (below): an unsigned
/// spawn request can never satisfy the remote door's
/// `NodeRung::Signature`-only gate (P-P4), so sending it anyway would only
/// earn a confusing round trip and a generic refusal.
///
/// **The client NEVER gates on `allows` — only on "is this a VERIFIED
/// local node at all."** The local check below exists SOLELY to catch the
/// obviously-doomed case (no verified node → no identity to sign with →
/// the remote can never resolve a `Signature` rung) with a clear, LOCAL
/// taught error naming `pair`. Every OTHER refusal shape —
/// `allows` lacking `spawn`, clock skew, a revoked pairing — is the remote
/// door's OWN call; this function never second-guesses it, and surfaces
/// whatever JSON-RPC error the door returns VERBATIM (taught), per
/// PAIRING.md decision 6: "the remote door's paired+signature+
/// allows∋spawn gate is the authority."
/// The wire-level twin of [`send_message_to_node`] for the SPAWN shape:
/// `context_id: None` routes `aoide-server::a2a::do_spawn` to spawn the
/// node's own configured `aoide.a2a.spawnAgent` and inject `text` as that
/// session's first turn (`spawn_inject_prompt`) — never a client-chosen
/// agent or argv (see [`handle_node_spawn`]'s own doc on the security
/// model this enforces). Extracted so this is the ONE place that builds and
/// sends a spawn-shaped `message/send`: [`handle_node_spawn`] (the CLI's
/// confirm-then-send wrapper, unchanged in shape) AND `aoide-conduct`'s
/// manifest remote-summon path (U4, command-defrag lane U — a manifest spec
/// whose `host` names a registered node drives this directly, with no
/// confirm: the manifest is itself the operator's standing declaration, the
/// same posture U2's local clean-spawn already takes toward a spec's own
/// `command`) call into. Returns the parsed JSON-RPC response on a 200 with
/// no `error` member; any transport/HTTP/JSON-RPC failure is `Err` with a
/// plain message the caller surfaces and audits directly — the same
/// `Result`-not-`Outcome` shape [`send_message_to_node`]/[`pull_node_live`]
/// hold, for the same reason (the caller builds its own `Outcome`).
pub fn spawn_on_node(
    node: &aoide_storage::node_store::Node,
    text: &str,
) -> Result<Value, SpawnNodeError> {
    spawn_on_node_via(node, text, None)
}

/// [`spawn_on_node`]'s own body, PLUS an optional `--via` OVERRIDE
/// (P-S4) — `handle_node_spawn` is the one production caller that ever
/// passes `Some` (an explicit `node spawn --via …`, which beats a
/// recorded `node.via`); every other caller (`aoide-conduct`'s manifest
/// remote-summon path, this function's own `spawn_on_node` above) passes
/// `None`, making `spawn_on_node` itself byte-identical-in-behavior to
/// before this override existed. Extracted rather than adding the
/// parameter to `spawn_on_node` directly so `aoide-conduct`'s existing
/// call site (`graph::resurrect.rs`) needs no change.
pub fn spawn_on_node_via(
    node: &aoide_storage::node_store::Node,
    text: &str,
    via_override: Option<&aoide_storage::tunnel::Via>,
) -> Result<Value, SpawnNodeError> {
    let message_id = gen_message_id();
    let body = crate::wire::build_message_send_body(text, &message_id, None);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer =
        resolve_node_bearer(node).map_err(|e| SpawnNodeError::new("bearer-resolve-failed", e))?;
    let extra_headers =
        sign_headers_for_node(node, &body_str).map_err(|e| SpawnNodeError::new("signing-failed", e))?;
    let (code, resp) = post_json_to_node_with_via_override(node, &body_str, bearer.as_deref(), &extra_headers, 15, via_override)
        .map_err(|e| SpawnNodeError::new("send-failed", e))?;
    if code != 200 {
        return Err(SpawnNodeError {
            reason: "send-http-error",
            message: format!("HTTP {code}"),
            http_code: Some(code),
            body: Some(resp),
        });
    }
    let parsed: Value = serde_json::from_str(&resp)
        .map_err(|e| SpawnNodeError::new("unparseable-response", format!("unparseable response: {e}")))?;
    // A JSON-RPC error still returns HTTP 200 (same discipline as
    // `send_message_to_node`) — the remote door's refusal (paired-but-
    // unsigned, allows lacking spawn, skew, …) surfaces VERBATIM, never
    // translated or second-guessed.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Err(SpawnNodeError::new(
            "node-refused",
            format!("node returned an error: {detail}"),
        ));
    }
    Ok(parsed)
}

/// [`spawn_on_node`]'s error: the wire stage that failed (`reason`, the same
/// vocabulary `handle_node_spawn`'s structured `data` always carried —
/// bearer-resolve-failed · signing-failed · send-failed · send-http-error ·
/// unparseable-response · node-refused) plus the human message; HTTP
/// failures keep their code and raw body for programmatic consumers.
#[derive(Debug)]
pub struct SpawnNodeError {
    pub reason: &'static str,
    pub message: String,
    pub http_code: Option<u16>,
    pub body: Option<String>,
}

impl SpawnNodeError {
    fn new(reason: &'static str, message: String) -> Self {
        Self { reason, message, http_code: None, body: None }
    }
}

impl std::fmt::Display for SpawnNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn handle_node_spawn(inv: &Invocation) -> Outcome {
    let cmd = "node.spawn";
    const USAGE: &str = "usage: aoide node spawn <name> [--yes] [--via ssh://[user@]host[:port]] -- <text…>";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let text = inv.args.get(1..).map(|rest| rest.join(" ")).unwrap_or_default();
    if text.trim().is_empty() {
        return Outcome::usage(cmd, USAGE);
    }
    // --via beats a recorded Node.via (spawn_on_node_via's own doc) — an
    // invalid --via is a usage error, never a silent fallback to the
    // recorded marker (parse_via_flag's own stance).
    let via_override = match parse_via_flag(inv) {
        Ok(v) => v,
        Err(e) => return Outcome::usage(cmd, format!("{USAGE} — {e}")),
    };

    let nodes = aoide_storage::node_store::load_nodes();
    let node = match nodes.iter().find(|p| p.name == name) {
        Some(p) if p.verified => p.clone(),
        Some(_) => {
            return Outcome::error(
                cmd,
                format!(
                    "node `{name}` is registered but not paired — spawn requires a signed request \
                     from a VERIFIED node (docs/architecture/PAIRING.md decision 6); pair first with \
                     `aoide pair <url> --name {name}`"
                ),
            )
            .with_data(json!({ "reason": "unpaired-node", "name": name }));
        }
        None => {
            return Outcome::error(
                cmd,
                format!(
                    "no node named `{name}` — spawn requires a paired node; register and pair it \
                     first with `aoide pair <url> --name {name}`"
                ),
            )
            .with_data(json!({ "reason": "unknown-node", "name": name }));
        }
    };

    if !inv.flag_present("yes") {
        match confirm_spawn(&node.name, &text) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::ok(cmd, format!("not confirmed — nothing sent to `{}`", node.name))
                    .with_data(json!({ "confirmed": false, "name": node.name }))
            }
            Err(e) => return Outcome::error(cmd, e),
        }
    }

    match spawn_on_node_via(&node, &text, via_override.as_ref()) {
        Ok(parsed) => {
            let session_id = parsed
                .get("result")
                .and_then(|r| r.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            Outcome::ok(cmd, format!("spawned on `{}` — remote session `{session_id}`", node.name))
                .with_data(json!({ "name": node.name, "url": node.url, "sessionId": session_id, "response": parsed }))
        }
        Err(e) => {
            let mut data = json!({ "reason": e.reason, "name": node.name, "url": node.url });
            if let Some(code) = e.http_code {
                data["httpCode"] = json!(code);
            }
            if let Some(body) = &e.body {
                data["body"] = json!(body);
            }
            Outcome::error(cmd, format!("spawning on `{}` at {}: {e}", node.name, node.url))
                .with_data(data)
        }
    }
}

/// `node pull [<name>]` — pull `aoide/graphSummary` from one (or, with no
/// name, EVERY) registered node. One node being down must never break the
/// command for the others — see [`pull_one_node`].
fn handle_node_pull(inv: &Invocation) -> Outcome {
    let cmd = "node.pull";
    let nodes = aoide_storage::node_store::load_nodes();
    let target = inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty());
    let selected: Vec<aoide_storage::node_store::Node> = match target {
        Some(name) => match nodes.iter().find(|p| p.name == name) {
            Some(p) => vec![p.clone()],
            None => {
                return Outcome::error(cmd, format!("no node named `{name}`"))
                    .with_data(json!({ "reason": "unknown-node", "name": name }))
            }
        },
        None => nodes,
    };
    if selected.is_empty() {
        return Outcome::ok(cmd, "no nodes registered — nothing to pull").with_data(json!({ "results": [] }));
    }

    let results: Vec<Value> = selected.iter().map(pull_one_node).collect();
    let ok_count = results.iter().filter(|r| r["ok"] == true).count();
    Outcome::ok(cmd, format!("pulled {ok_count}/{} node(s) successfully", selected.len()))
        .with_data(json!({ "results": results }))
}

/// `node status` — each registered node's full registry row (name/url/
/// autogate/tokenFile/bearerSecret/hub/pubkey/verified/allows/addedAt — the
/// same shape `node list` used to be the only place emitting, folded in
/// here so `node list` has nothing left to say `node status --json` doesn't
/// already say, command-defrag lane task #101) plus its last-pull outcome
/// and staleness (`fresh` within
/// [`aoide_storage::node_store::NODE_CACHE_TTL_SECS`], `stale` past it or
/// explicitly marked so, `never-pulled` with no cache file at all) — the
/// same three-way classification `build_graph`'s fold uses
/// (`aoide-conduct::graph::doc`), so this and the DAG never disagree. The
/// human-readable message stays the terse per-node-count summary; the full
/// row rides `--json`'s `data.nodes` only.
fn handle_node_status(_inv: &Invocation) -> Outcome {
    let cmd = "node.status";
    let nodes = aoide_storage::node_store::load_nodes();
    let now_epoch =
        aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let rows: Vec<Value> = nodes
        .iter()
        .map(|p| {
            let cache = aoide_storage::node_store::load_node_cache(&p.name);
            let (state, fetched_at, error) = match &cache {
                Some(entry) if aoide_storage::node_store::is_cache_fresh(entry, now_epoch) => {
                    ("fresh", entry.fetched_at.clone(), None)
                }
                Some(entry) => ("stale", entry.fetched_at.clone(), entry.last_error.clone()),
                None => ("never-pulled", None, None),
            };
            let mut row = serde_json::to_value(p).unwrap_or_else(|_| json!({}));
            if let Some(obj) = row.as_object_mut() {
                obj.insert("state".to_string(), json!(state));
                obj.insert("fetchedAt".to_string(), json!(fetched_at));
                obj.insert("error".to_string(), json!(error));
            }
            row
        })
        .collect();
    let msg = if rows.is_empty() {
        "no nodes registered".to_string()
    } else {
        format!("{} node(s) registered", rows.len())
    };
    Outcome::ok(cmd, msg).with_data(json!({ "nodes": rows }))
}

/// The seven `node` commands (CONTRACTS.md §7; `hub` is P-D5, `allow` is P-P3),
/// registered as their own group.
pub fn register_nodes(r: &mut Registry) {
    r.insert(cmd!(
        path: ["node", "add"],
        summary: "Register a node aoide instance (verified by AgentCard fetch first) as a federation node in the session DAG.",
        args: [
            arg!("name", "string", true, "A local nickname for this node."),
            arg!("url", "string", true, "The node's A2A door URL (e.g. http://host:8710/)."),
        ],
        flags: [
            flag!("autogate", "bool", "Trust this node: its inbound message/send auto-delivers without the pending queue."),
            flag!("no-verify", "bool", "Skip the AgentCard fetch entirely and register the node unverified — for a node that serves no AgentCard (a plain A2A client endpoint). `verified` stays false either way; a card fetch was never identity, only reachability."),
            flag!("token-file", "string", "Path to a file holding the shared secret this node must present (Authorization: Bearer <token>) to be identified as this node — required for --autogate to survive a proxy/tunnel, where every caller's address looks the same."),
            flag!("bearer-secret", "string", "Name of a secret, resolved fresh on every outbound call through the local secrets broker, THIS instance presents as Authorization: Bearer <value> when calling this node's own A2A door. Absent = no bearer sent (today's behavior)."),
            flag!("via", "string", "An ssh://[user@]host[:port] transport marker — cross-box calls to this node dial through an internal ssh tunnel to this target instead of the node's own url directly. Absent = direct dial (today's behavior)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_node_add,
    ));
    r.insert(cmd!(
        path: ["node", "remove"],
        summary: "Unregister a node (a missing name is an error, not a silent no-op).",
        args: [arg!("name", "string", true, "The registered node's name.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_node_remove,
    ));
    r.insert(cmd!(
        path: ["node", "pull"],
        summary: "Pull aoide/graphSummary from one (or, with no name, every) registered node and refresh its cache.",
        args: [arg!("name", "string", false, "Pull only this node; omit to pull every registered node.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_node_pull,
    ));
    r.insert(cmd!(
        path: ["node", "status"],
        summary: "Report each registered node's last-pull outcome and cache staleness.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_node_status,
    ));
    r.insert(cmd!(
        path: ["node", "hub"],
        summary: "Designate a node as THE hub (at most one) that address resolution prefers as a last-resort remote target; --clear removes the designation.",
        args: [arg!("name", "string", true, "The registered node's name.")],
        flags: [
            flag!("clear", "bool", "Remove the hub designation from this node instead of setting it."),
        ],
        gated: false,
        implemented: true,
        handler: handle_node_hub,
    ));
    r.insert(cmd!(
        path: ["node", "allow"],
        summary: "Flip one capability in a node's `allows` set (P-P3, PAIRING.md decision 5) — idempotent, reports exactly what changed.",
        args: [
            arg!("name", "string", true, "The registered node's name."),
            arg!("cap", "string", true, "The capability — one of the closed set: read, spawn, message."),
            arg!("state", "string", true, "`on` or `off`."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_node_allow,
        examples: ["node allow yomi-strix spawn on", "node allow yomi-strix spawn off"],
    ));
    r.insert(cmd!(
        path: ["node", "spawn"],
        summary: "Spawn a session on a PAIRED node's own configured agent — POSTs a signed, spawn-shaped message/send (contextId omitted) to the node's A2A door; the node's own paired+signature+allows∋spawn gate is the sole authority (docs/architecture/PAIRING.md decision 6), never gated locally beyond requiring a verified node.",
        args: [
            arg!("name", "string", true, "The registered, PAIRED node's name."),
            arg!("text", "string", true, "The first turn typed into the newly spawned session — put it after `--` so its own words/flags pass through verbatim."),
        ],
        flags: [
            flag!("yes", "bool", "Skip the local y/N confirmation (scripted use) — a LOCAL UX gate only; the remote door's own gate is unaffected."),
            flag!("via", "string", "An ssh://[user@]host[:port] transport marker for THIS call, overriding any via recorded on the node. Absent = the node's own recorded via, if any (today's behavior when neither is set)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_node_spawn,
        examples: ["node spawn yomi-strix -- status check please"],
    ));
}

// ── The `pair`/`pair reject`/`pair watch` commands (P-P2 through task #135
// ── P3', CONTRACTS.md §6 — the pairing ceremony's wire + CLI ceremony) ────
//
// `node add`/`pair` are two SEPARATE paths onto the same registry
// (`docs/architecture/PAIRING.md`'s "Settled decisions" #2): `node add` is
// the legacy escape for an UNPAIRED node (a hand-set URL, never verified by
// key), `pair` is the ONE ceremony that mints a `pubkey`/`verified`
// node record on BOTH ends — request/reveal/park/approve/reject over the
// A2A door (`aoide-server::a2a::pair_request`/`pair_reveal`/`pair_poll`),
// SAS derivation + display (`aoide_storage::pairing::derive_sas`), commit via
// `aoide_storage::node_store::upsert_paired_node` — which ALSO stamps the
// node's `allows` the first time it becomes verified (P-P3, PAIRING.md
// decision 5). That grant is `config.toml`'s `[pairing] defaultGrant`
// (`["read"]` unless an operator widened it), or the `--allow` typed on this
// one commit; `resolve_grant` is the single place either is read. Editing a
// LIVE grant afterward is `node allow <name> <cap> on|off`'s own separate
// command (registered in `register_nodes` above), never a second write site
// here — and a re-pairing never re-grants, so a revoked capability survives
// a key rotation.
//
// **Both humans confirm, for real, with a code EACH — never a code and a
// y/N (the mutual-code redesign, R1).** `pair <id>` does double duty by
// DIRECTION, never a fifth command (golden count unchanged — no new command
// path, only the completion trigger moved): on an INBOUND id (this instance
// is the APPROVER) it re-derives `derive_sas`, gates on the TYPED pairing
// code ([`CodeGate`] — max [`MAX_CODE_TRIES`] cumulative mismatches, then
// auto-deny), commits LOCALLY, and marks the entry approved for the
// requester's own poll to find (no wire call at all — [`approve_inbound`]'s
// own doc) — its Ok outcome hands back a SECOND code, `derive_reply_sas`,
// for this operator to read back to the requester. On an OUTBOUND id (this
// instance is the REQUESTER) it POLLS the approver's door first (over the
// SAME forward dial `pair`'s own request/reveal already used), and only
// once that poll comes back `approved` does it gate on the SAME
// [`CodeGate`] shape — this time against `derive_reply_sas`, the code the
// approver just read back — before committing ([`commit_outbound`]'s own
// doc has the full poll-then-gate mechanics). Neither leg's gate is ever a
// y/N: a code generated on the FAR screen, typed blind on this one, three
// strikes, `--yes` never a bypass, symmetric in both directions. `pair
// reject <id>` doubles the same way, and on an outbound id is also the
// ceremony's missing ABORT command: it removes the entry at either outbound
// state, whether or not a poll has succeeded yet.

/// The capability set a pairing commit stamps on a FIRST verification (task
/// #135 P1) — `Some` is the `--allow` an operator typed at this commit,
/// `None` reads `config.toml`'s `[pairing] defaultGrant`
/// (`aoide_storage::config`, whose own default is `["read"]`).
///
/// **Resolution lives here, not in the store.** `upsert_paired_node` takes
/// the finished list; a store function reading the config would be a second
/// resolution path, and it would have to swallow a malformed grants file at
/// the one moment that must fail loudly (`config`'s own module doc: "this one
/// must fail loudly, never guess"). So an unreadable or invalid `config.toml`
/// REFUSES the commit here rather than quietly falling back to the built-in
/// default — the ceremony is exactly where a wrong grant is expensive.
///
/// Both directions of `pair <id>` and both popup arms call this, so
/// there is one answer to "what is this pairing worth" per commit.
fn resolve_grant(grant: Option<&[String]>) -> Result<Vec<String>, String> {
    match grant {
        Some(g) => Ok(g.to_vec()),
        None => aoide_storage::config::load().map(|l| l.config.pairing.default_grant).map_err(|e| {
            format!("reading the default grant from the config: {e} — fix it, or name the grant outright with `--allow read` on this approve")
        }),
    }
}

/// Read `--allow` off the invocation, per the SAME closed vocabulary and the
/// SAME parser `config set pairing.defaultGrant` already uses
/// (`aoide_storage::config::parse_value` over
/// [`aoide_storage::node_store::NODE_CAPABILITIES`]) — never a second list to
/// drift. Comma-separated rather than a repeated flag because
/// `Invocation::flags` is a map, one value per name: a second `--allow` would
/// silently overwrite the first, which is the wrong failure for a grants
/// input. `--allow ""` is the empty grant — "verified, and allowed nothing
/// yet" is a real intent, the same one `config set pairing.defaultGrant ""`
/// already expresses.
fn parse_allow_flag(inv: &Invocation) -> Result<Option<Vec<String>>, String> {
    let Some(raw) = inv.flags.get("allow") else {
        return Ok(None);
    };
    let kind = aoide_storage::config::ValueKind::ClosedList(aoide_storage::node_store::NODE_CAPABILITIES);
    aoide_storage::config::parse_value(&kind, raw).map(Some).map_err(|e| format!("--allow: {e}"))
}

/// What a commit says about `allows`. A grant lands ONLY on a first
/// verification — `upsert_paired_node` leaves an already-verified node's set
/// exactly as it was, so a revoked capability stays revoked across a key
/// rotation. An `--allow` that silently did nothing is precisely the surprise
/// this clause exists to prevent, so the re-pair case says so and names the
/// command that does change a live grant.
fn grant_note(first_pairing: bool, allows: &[String]) -> String {
    match (first_pairing, allows.is_empty()) {
        (false, _) => ", grant unchanged (`node allow` edits a live one)".to_string(),
        (true, true) => ", granted nothing".to_string(),
        (true, false) => format!(", granted {}", allows.join(", ")),
    }
}

/// How many wrong pairing codes either leg's entry tolerates before the CLI
/// auto-resolves it (approver: auto-DENY via [`auto_deny_inbound`];
/// requester: auto-ABORT via [`auto_abort_outbound`]) — cumulative across
/// invocations (`aoide_storage::pairing::InboundPairingRequest::tries`/
/// `OutboundPairingRequest::tries` persist them, one file per direction) and
/// across the interactive prompt and the scripted `--code` path alike.
pub(crate) const MAX_CODE_TRIES: u32 = 3;

/// How `pair <id>` collects its typed-code confirmation, EITHER direction
/// (the mutual-code redesign, R1 — this enum was `InboundGate` before this
/// phase, approver-only; it is now direction-neutral because the variant
/// set, the resolution logic, and the mismatch bookkeeping are
/// byte-identical on both legs). The operator proves they hold the SAME
/// code the FAR screen shows by TYPING it, out-of-band (a phone call, a
/// glance), never by y/N-ing a code this side already printed — the
/// approver gates on `derive_sas`, the requester on `derive_reply_sas`, but
/// the gate SHAPE is one enum. Resolved by [`approve_inbound_leg`]
/// (approver)/[`outbound_gate_from`] (requester) from the invocation;
/// [`approve_inbound`]/[`commit_outbound`] each consume it AFTER their own
/// idempotent/state short-circuits, so those behave identically whichever
/// variant rides in.
pub(crate) enum CodeGate {
    /// Scripted `--code NNN-NNN`: validated once against the derived code;
    /// a mismatch counts one persisted try
    /// (`aoide_storage::pairing::record_inbound_code_try`/
    /// `record_outbound_code_try`, per direction).
    Code(String),
    /// Interactive CLI tty: prompt to type the code
    /// (`aoide_protocol::pick::text_input`), re-prompting on mismatch up
    /// to [`MAX_CODE_TRIES`] cumulative failures.
    Prompt,
    /// No way to collect a code — a non-CLI door, a non-tty CLI without
    /// `--code`, or `--yes` (which bypasses neither leg's code): a taught
    /// refusal, once the short-circuits above don't apply.
    Unavailable,
}

/// Does a typed/scripted pairing code match the derived SAS? Both sides are
/// trimmed and stripped of `-` and internal whitespace before comparing, so
/// `740729` and `740 729` match a SAS of `740-729` — the operator is copying
/// digits off another screen, and the separator carries no entropy. Pure,
/// so the comparison the whole gate rests on is testable with no tty.
fn code_matches(input: &str, sas: &str) -> bool {
    let norm = |s: &str| s.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>();
    let typed = norm(input);
    !typed.is_empty() && typed == norm(sas)
}

/// The taught refusal for [`CodeGate::Unavailable`] — one message for
/// every no-code shape (non-tty, non-CLI door, `--yes`), naming both the
/// terminal prompt and the scripted spelling.
fn inbound_code_refusal(cmd: &str, id: &str) -> Outcome {
    Outcome::usage(
        cmd,
        format!(
            "approving an inbound pairing request takes the TYPED pairing code as read from the \
             requester's screen — run `aoide pair {id}` on a real terminal to type it, \
             or pass `--code NNN-NNN` (scripted); `--yes` does not bypass the approver's code"
        ),
    )
}

/// Persist one wrong-code try ([`aoide_storage::pairing::record_inbound_code_try`])
/// and hand back the new cumulative count, or the ready-made refusal
/// `Outcome` when the entry vanished mid-prompt (expired) or the file write
/// failed — both `Code` and `Prompt` arms of [`approve_inbound`] land here,
/// never two hand-rolled copies of the same error mapping.
fn record_code_try(cmd: &str, id: &str, now_epoch: i64) -> Result<u32, Outcome> {
    match aoide_storage::pairing::record_inbound_code_try(id, now_epoch) {
        Ok(t) => Ok(t),
        Err(aoide_storage::pairing::MarkApprovedError::Unknown) => Err(Outcome::error(
            cmd,
            format!("no pending pairing request with id `{id}` (unknown, already resolved, or expired)"),
        )
        .with_data(json!({ "reason": "unknown-id", "id": id }))),
        Err(aoide_storage::pairing::MarkApprovedError::Io(e)) => Err(Outcome::error(cmd, format!("recording the code mismatch: {e}"))),
    }
}

/// Three cumulative code mismatches — the auto-deny (task #120 P3): the
/// SAME clean removal `pair reject` performs (parked entry taken,
/// nothing committed, no wire call), surfaced as its own distinct outcome
/// so the single audit log records the deny as `auto-deny-on-code-mismatch`
/// rather than an operator-initiated reject.
fn auto_deny_inbound(cmd: &str, id: &str, name: &str, now_epoch: i64) -> Outcome {
    if let Err(e) = aoide_storage::pairing::take_inbound(id, now_epoch) {
        return Outcome::error(cmd, format!("removing the pairing request after {MAX_CODE_TRIES} code mismatches: {e}"));
    }
    Outcome::error(
        cmd,
        format!(
            "{MAX_CODE_TRIES} code mismatches — auto-denied pairing request `{id}` from `{name}`: \
             parked entry removed, nothing committed; a fresh `aoide pair` on their side starts a new ceremony"
        ),
    )
    .with_data(json!({ "reason": "auto-deny-on-code-mismatch", "id": id, "name": name, "tries": MAX_CODE_TRIES, "rejected": true, "direction": "inbound" }))
}

/// [`inbound_code_refusal`]'s exact mirror for the REQUESTER'S own gate
/// (the mutual-code redesign, R1): `CodeGate::Unavailable` on an outbound
/// completion — no code can be collected here either — names the reply
/// code's own scripted spelling rather than the approver's.
fn outbound_code_refusal(cmd: &str, id: &str) -> Outcome {
    Outcome::usage(
        cmd,
        format!(
            "completing an outbound pairing request takes the TYPED reply code as read from the \
             approver's screen — run `aoide pair {id}` on a real terminal to type it, \
             or pass `--code NNN-NNN` (scripted); `--yes` does not bypass the requester's own gate"
        ),
    )
}

/// [`record_code_try`]'s exact mirror against
/// [`aoide_storage::pairing::record_outbound_code_try`] — both `Code` and
/// `Prompt` arms of [`commit_outbound`] land here.
fn record_outbound_try(cmd: &str, id: &str, now_epoch: i64) -> Result<u32, Outcome> {
    match aoide_storage::pairing::record_outbound_code_try(id, now_epoch) {
        Ok(t) => Ok(t),
        Err(aoide_storage::pairing::MarkApprovedError::Unknown) => Err(Outcome::error(
            cmd,
            format!("no pending pairing request with id `{id}` (unknown, already resolved, or expired)"),
        )
        .with_data(json!({ "reason": "unknown-id", "id": id }))),
        Err(aoide_storage::pairing::MarkApprovedError::Io(e)) => Err(Outcome::error(cmd, format!("recording the reply-code mismatch: {e}"))),
    }
}

/// [`auto_deny_inbound`]'s exact mirror on the REQUESTER'S own leg (the
/// mutual-code redesign, R1): the third cumulative reply-code mismatch is a
/// clean [`aoide_storage::pairing::take_outbound`] — nothing of THIS
/// instance's own commits. B is left holding a verified node that answers
/// nothing, which is PAIRING.md's own documented commit-asymmetry outcome
/// ("resolved by an ordinary expiring re-pair") — the taught error says
/// exactly that and names the re-pair, rather than inventing a special
/// recovery path.
fn auto_abort_outbound(cmd: &str, id: &str, name: &str, now_epoch: i64) -> Outcome {
    if let Err(e) = aoide_storage::pairing::take_outbound(id, now_epoch) {
        return Outcome::error(cmd, format!("removing the pairing request after {MAX_CODE_TRIES} reply-code mismatches: {e}"));
    }
    Outcome::error(
        cmd,
        format!(
            "{MAX_CODE_TRIES} reply-code mismatches — auto-aborted pairing request `{id}` to `{name}`: \
             nothing committed on this end; `{name}` is left holding a verified node that answers nothing until \
             an ordinary expiring re-pair resolves it"
        ),
    )
    .with_data(json!({ "reason": "auto-abort-on-code-mismatch", "id": id, "name": name, "tries": MAX_CODE_TRIES, "rejected": true, "direction": "outbound" }))
}

/// This instance's own default advertised A2A door URL — `--node-name`'s
/// sibling precedence chain (`aoide_server::a2a::resolve_node_name`) but
/// resolved HERE, since this crate cannot depend on `aoide-server`: the
/// port comes from `AOIDE_A2A_PORT` (the same env the `aoide-a2a` systemd
/// unit sets, mirroring `a2a::resolve_bind_port`'s own precedence) or the
/// house default `8710`; the host is `aoide_storage::display::
/// local_host_name` (already the shared fallback chain `a2a::
/// resolve_node_name` itself delegates to). `--self-url` overrides this
/// outright — the one flag `pair`'s url arm needs when the door binds
/// somewhere this default can't guess (a non-default port, a reverse
/// proxy/tunnel hostname).
pub(crate) fn default_self_url() -> String {
    let host = aoide_storage::display::local_host_name();
    format!("http://{host}:{}/", default_a2a_port())
}

/// This instance's own default reach-back hop claim (P-PV1) — the wire's
/// OPTIONAL `selfVia` field, carried beside `self_url` on `aoide/pairRequest`
/// so the approver (which only ever OBSERVES the request arriving over the
/// requester's own ssh tunnel, i.e. loopback) can record a `via` that
/// actually reaches back out: `ssh://<local login>@<host>`.
///
/// **The HOST half is the LOCAL OUTBOUND ADDRESS toward `toward` (host, or
/// `host:port`), never a claimed OS hostname (review finding — a live
/// LAN check found hostnames here resolving only through the router's
/// DHCP-DNS, and two boxes coming back as IPv6/link-local mixes:
/// resolution by luck, exactly the fragility the codebase's own K1 rule
/// —"never a claimed host" on [`aoide_storage::tunnel::default_via`] —
/// exists to avoid; every live `via` row is IP-based for the same reason).**
/// [`outbound_ip_toward`] opens a UDP socket, `connect`s it to `toward`
/// (no packet ever sent — `connect` on a UDP socket only picks a route),
/// and reads back the LOCAL address the kernel chose for that route: on an
/// ordinary LAN, the address the far side can actually reach this box at.
/// Falls back to [`aoide_storage::display::local_host_name`]'s claimed
/// hostname ONLY when the UDP trick itself fails (no route yet, or
/// anything else `connect`/`local_addr` can return an `Err` for) — still
/// self-asserted, best-effort DATA either way (the wire's own trust stays
/// in pubkeys + SAS, never this field). The LOGIN half is
/// [`crate::tunnel::local_login`]'s `$USER`/`$LOGNAME` chain, reused
/// verbatim from [`crate::tunnel::resolve_login`] — `None` when neither
/// env var is set (no guessed literal there either). `--self-via`
/// overrides this whole function outright, mirroring `--self-url`; every
/// caller only ever reaches this as an `Option::or_else` fallback.
pub(crate) fn default_self_via(toward: &str) -> Option<String> {
    let login = crate::tunnel::local_login().ok()?;
    let host = outbound_ip_toward(toward)
        .map(|ip| ip.to_string())
        .unwrap_or_else(aoide_storage::display::local_host_name);
    Some(format!("ssh://{login}@{host}"))
}

/// The local address the kernel would route a packet toward `toward`
/// (`host` or `host:port`) through — no packet is ever actually sent, a
/// UDP `connect` only resolves a route and binds the socket's local
/// endpoint to it. `toward` gets a dummy port appended (`8710`, never used
/// for anything beyond satisfying `ToSocketAddrs` — any nonzero port picks
/// the identical route) when it doesn't already carry one. `None` on any
/// failure (unresolvable host, no route, socket error) — the caller's own
/// fallback case, never a panic; this is a best-effort LAN heuristic, not
/// a guarantee.
fn outbound_ip_toward(toward: &str) -> Option<std::net::IpAddr> {
    let target = if toward.contains(':') { toward.to_string() } else { format!("{toward}:8710") };
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(&target).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// The house A2A door port this box assumes for itself AND for a
/// discovered node: `AOIDE_A2A_PORT` (the same env the `aoide-a2a`
/// systemd unit sets) or the house default `8710`. `pair`'s hostname
/// arm composes its dial target with this (task #120 — the advertisement
/// carries no door URL, so there is no per-node port to read off the
/// wire); a node on a non-default port takes the explicit `pair
/// <url>` path instead.
pub(crate) fn default_a2a_port() -> u16 {
    std::env::var("AOIDE_A2A_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8710)
}

/// The port a `scheme://host[:port][/path]` url's own authority carries —
/// lightweight, reusing [`aoide_storage::node_store::url_host`]'s existing
/// authority extraction rather than pulling in a full URL parser for one
/// field. `None` on an unparseable url, a bare host with no `:port`
/// segment at all, or a port that doesn't fit `u16` — every one of those
/// is a caller's fallback case, never a panic.
fn port_from_url(url: &str) -> Option<u16> {
    let authority = aoide_storage::node_store::url_host(url)?;
    let (_, port_str) = authority.rsplit_once(':')?;
    port_str.parse::<u16>().ok()
}

/// `pair <target>`'s EXPLICIT-DIAL arm (`target` is a URL) — the old
/// `node pair request <url>` handler's own body, unchanged: mints this
/// instance's identity if it doesn't exist yet
/// (`aoide_storage::identity::load_or_mint`), mints a fresh nonce, POSTs
/// `aoide/pairRequest` carrying a COMMITMENT to that nonce (never the nonce
/// itself — review-bounce Finding 1, `aoide_storage::pairing`'s module doc:
/// the original one-round-trip shape let an active on-path attacker choose
/// four of the six SAS transcript fields after seeing the real ones), then
/// immediately POSTs `aoide/pairReveal` with the nonce the commitment
/// already fixed. Only once BOTH calls succeed does this instance derive
/// its own copy of the SAS (it already has everything: its own pubkey and
/// nonce, the approver's pubkey and nonce from the first response) and
/// remember the outbound request (`aoide_storage::pairing::park_outbound`,
/// `OutboundState::AwaitingApproval`) so a LATER `pair <id>`
/// invocation — run whenever, long after this CLI process exits — can poll
/// the approver's door for the release ([`approve_outbound`]'s own doc, task
/// #119) and finish the ceremony. `--secs`/`--yes` are the hostname arm's
/// own flags and are simply inert here — a URL is already an explicit,
/// typed act with nothing to sweep for or confirm before dialing.
fn pair_via_url(cmd: &str, inv: &Invocation, url: &str, usage: &str) -> Outcome {
    let name = match inv.flags.get("name").cloned().filter(|s| !s.is_empty()) {
        Some(n) => n,
        None => match aoide_storage::node_store::default_node_name_from_url(url) {
            Some(n) => n,
            None => {
                return Outcome::error(cmd, "could not derive a nickname from the URL — pass --name explicitly")
                    .with_data(json!({ "reason": "no-default-name", "url": url }))
            }
        },
    };
    if !aoide_storage::node_store::valid_node_name(&name) {
        return Outcome::error(
            cmd,
            format!(
                "`{name}` is not a valid node nickname: must match `^[a-z0-9][a-z0-9-]*$` \
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
    // An invalid --via is a usage error, never a silent fallback to a
    // direct dial (parse_via_flag's own stance). Unlike the hostname arm
    // (K1's src_addr-derived default), an explicit URL target has no
    // observed address to fall back to — no `--via` means no via at all,
    // exactly today's behavior.
    let via = match parse_via_flag(inv) {
        Ok(v) => v,
        Err(e) => return Outcome::usage(cmd, format!("{usage} — {e}")),
    };
    // `default_self_via`'s outbound-route trick needs a real dial target —
    // when this call goes through a tunnel, the address actually routed to
    // is `via`'s own host (the ssh target), never the logical `url`'s host,
    // which the tunnel may make unreachable directly.
    let toward = match via.as_ref() {
        Some(v) => v.host.clone(),
        None => aoide_storage::node_store::url_host(url).unwrap_or_else(|| url.to_string()),
    };
    let self_via = inv
        .flags
        .get("self-via")
        .cloned()
        .filter(|s| !s.is_empty())
        .or_else(|| default_self_via(&toward));
    let finish = match pair_finish_from(inv) {
        Ok(f) => f,
        Err(e) => return Outcome::usage(cmd, format!("{usage} — {e}")),
    };
    if let Some(out) = refuse_detached_grant(cmd, &finish) {
        return out;
    }
    if let Some(out) = refuse_code_on_new_request(cmd, &finish) {
        return out;
    }

    run_pair_request(cmd, url, &name, &self_url, self_via.as_deref(), via.as_ref(), via.as_ref().map(|v| v.to_string()), &finish)
}

/// The requester's half of the ceremony, shared verbatim by
/// [`pair_via_url`] (`pair <url>` — a CLI-typed url/`--name`,
/// validated above) AND [`pair_with_heard`] (`pair <hostname>`/bare
/// `pair` — a `url`/`name` already lifted straight off an
/// already-validated, already-confirmed discovery advertisement, so it
/// needs no SECOND `valid_node_name` check here). Extracted so the
/// hostname arm reaches the SAME ceremony code the url arm does — never a
/// copy (PAIRING.md: "sugar over the ceremony, nothing more").
/// Everything from here down is unchanged from the pre-P-PV2 shape of
/// `handle_node_pair_request`: mint-or-load this instance's identity, mint
/// a fresh nonce, POST `aoide/pairRequest` carrying a COMMITMENT to that
/// nonce (never the nonce itself), then immediately POST `aoide/pairReveal`
/// with the nonce the commitment already fixed; only once both calls
/// succeed does this instance derive its own SAS and remember the outbound
/// request.
///
/// **P-S4's two additions, deliberately kept separate.** `dial_via` is what
/// the ceremony's OWN two POSTs below actually tunnel through — `None` for
/// a plain `pair <url>` (no observed address to derive a
/// default from) and, for the hostname arm/bare `pair`, an explicit
/// `--via` or else [`pair_with_heard`]'s own src_addr-derived default
/// (P-PV1: loopback-only doors, task #131 — a discovered node's door is
/// reached only through its ssh tunnel, so the ceremony's OWN dial needs
/// that same default, not only the record). `record_via` is the string
/// parked into [`aoide_storage::pairing::OutboundPairingRequest::via`] for
/// LATER commit onto the resulting node record, in the SEPARATE `pair
/// <id>` invocation that actually writes it (`approve_outbound`).
/// `self_via` (P-PV1) is this instance's OWN reach-back hop claim —
/// `ssh://<local login>@<local address routed toward the node>` by default
/// ([`default_self_via`] — the HOST half is the local outbound address the
/// kernel picks for a route toward the node, never a claimed OS hostname;
/// that function's own doc has the full reasoning), overridable by
/// `--self-via` — carried on the wire beside `self_url` so the far end,
/// which can only ever OBSERVE this request arriving over the tunnel (i.e.
/// loopback), has something to record a working `via` from at ITS OWN
/// approve-commit time ([`approve_inbound`]'s own doc).
pub(crate) fn run_pair_request(
    cmd: &str,
    url: &str,
    name: &str,
    self_url: &str,
    self_via: Option<&str>,
    dial_via: Option<&aoide_storage::tunnel::Via>,
    record_via: Option<String>,
    finish: &PairFinish,
) -> Outcome {
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

    // The wire `name` is this instance's OWN self-claimed name — the
    // approver records the requester under it verbatim (a2a.rs
    // `pair_request`'s contract). `name` (the `--name` flag) stays purely
    // this side's local nickname for the approver, recorded at
    // `remember_outbound` below; sending it here instead made the approver
    // file the requester under the requester's-nickname-for-the-approver
    // (the live yomi↔sakaki ceremony's phantom-node defect, 2026-08-26).
    let self_name = aoide_storage::display::local_host_name();
    let body = crate::node::build_pair_request_body(&own_pubkey, &self_name, &commit, &self_url, self_via);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let (code, resp_body) = match post_json_via(url, dial_via, name, &body_str, None, &[], 15) {
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
    let ack = match crate::node::parse_pair_request_response(&resp) {
        Ok(a) => a,
        Err(e) => {
            return Outcome::error(cmd, format!("the node refused the pairing request: {e}"))
                .with_data(json!({ "reason": "refused", "url": url }))
        }
    };

    // Reveal — the commitment's second half (module doc). A failure here
    // (network, refusal, or a commitment mismatch the node detected) means
    // the ceremony never completes; nothing is parked on this side either.
    let reveal_body = crate::node::build_pair_reveal_body(&ack.id, &own_nonce);
    let reveal_body_str = serde_json::to_string(&reveal_body).unwrap_or_default();
    let (reveal_code, reveal_resp_body) = match post_json_via(url, dial_via, name, &reveal_body_str, None, &[], 15) {
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
    if let Err(e) = crate::node::check_pair_reveal_response(&reveal_resp) {
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
        via: record_via,
        tries: 0,
    };
    if let Err(e) = aoide_storage::pairing::park_outbound(outbound) {
        return Outcome::error(cmd, format!("remembering the outbound pairing request: {e}"));
    }

    if finish.wait_secs == 0 {
        return Outcome::ok(
            cmd,
            format!(
                "pairing request sent to `{name}` ({url}) — confirmation code {sas} — \
                 read this aloud (or otherwise out-of-band) to {name}'s operator; once they run \
                 `aoide pair {}` and type it, they'll read back a REPLY code — \
                 finish here with `aoide pair {} --code NNN-NNN`, then type their reply code here",
                ack.id, ack.id
            ),
        )
        .with_data(json!({ "id": ack.id, "name": name, "url": url, "sas": sas, "expiresAt": ack.expires_at }));
    }

    eprintln!(
        "pairing request sent to `{name}` — confirmation code {sas}\n\
         read it aloud to {name}'s operator; they type it into `aoide pair`, then read a reply \
         code back to you — type their reply code here when this command asks.\n\
         waiting up to {}s — Ctrl-C leaves the request pending as `{}`.",
        finish.wait_secs, ack.id
    );
    wait_and_commit(cmd, &ack.id, name, &sas, finish)
}

/// What `pair` does once the request is parked — the difference between
/// the pre-P2 detached shape and the one-command ceremony (task #135 P2).
#[derive(Debug)]
pub(crate) struct PairFinish {
    /// Seconds to block polling for the approver's release. `0` parks and
    /// returns immediately: the pre-P2 behaviour, kept as the scripted escape
    /// for anything that cannot sit on a human.
    pub wait_secs: u64,
    /// `--yes` — skip THIS side's own PRE-REQUEST confirmations (the
    /// sweep's proceed prompt, the already-verified-node re-pair confirm).
    /// **Narrowed by the mutual-code redesign (R1): it no longer reaches
    /// the final gate.** The final commit is always a [`CodeGate`], built by
    /// [`outbound_gate_from`] — `--yes` with no `--code` and no tty still
    /// resolves to `CodeGate::Unavailable`, the same taught refusal the
    /// approver's own `--yes` gives; it was never a bypass of the code that
    /// actually secures the pair, only of the prompts that precede it.
    pub skip_confirm: bool,
    /// `--allow` — or, on a converge, `mesh.<name>.grant`
    /// (`crate::mesh::converge_finish`) — and `None` to read `[pairing]
    /// defaultGrant`. Only `None` reaches that fallback: an EMPTY list is
    /// the distinct "grant nothing" intent, from either source.
    pub grant: Option<Vec<String>>,
    /// `--code NNN-NNN` (the mutual-code redesign, R1) — the scripted reply
    /// code, carried through so a resumed blocking wait
    /// ([`wait_and_commit`]) can complete a poll-released entry without a
    /// tty, the same way a zero-wait resume already could via
    /// [`resume_outbound_leg`]. `None` on every NEW-request arm (refused
    /// outright by [`refuse_code_on_new_request`] — no reply code can exist
    /// yet at request time).
    pub code: Option<String>,
    /// Which door this invocation came through — [`outbound_gate_from`]'s
    /// own `CodeGate::Prompt` arm needs it (`aoide_protocol::pick::
    /// interactive`), and `wait_and_commit`'s poll loop has no
    /// `&Invocation` of its own to read it from otherwise.
    pub door: aoide_protocol::Door,
}

impl PairFinish {
    /// Park and return — the pre-`--wait` shape, kept for the tests so none
    /// of them sit on a poll (every production caller builds from flags via
    /// `pair_finish_from` now).
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        PairFinish { wait_secs: 0, skip_confirm: false, grant: None, code: None, door: aoide_protocol::Door::Cli }
    }
}

/// How often the wait re-polls the approver's door. `aoide/pairPoll` audits
/// only on RELEASE (`a2a.rs`), so a ten-minute wait costs the approver zero
/// audit lines — the cadence is bounded by politeness, not by log volume.
const PAIR_POLL_CADENCE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long `pair` waits for the far operator by default: ten minutes,
/// the span of a phone call in which two people read a code to each other.
const DEFAULT_PAIR_WAIT_SECS: u64 = 600;

/// Has the wait run out? Both sides are `u64` seconds and neither is cast:
/// the first shape compared a monotonic elapsed against `wait_secs as i64`,
/// so a `--wait` above `i64::MAX` reinterpreted as negative and "timed out"
/// on the first tick — the exact inverse of what the operator asked for
/// (review finding). Pure, so that inversion stays proven rather than argued.
fn wait_is_over(elapsed_secs: u64, wait_secs: u64) -> bool {
    elapsed_secs >= wait_secs
}

/// Build the post-request behaviour off `pair`'s own flags. `--wait 0`
/// is the documented escape back to the pre-P2 detached shape, for anything
/// scripted that cannot sit on a human.
pub(crate) fn pair_finish_from(inv: &Invocation) -> Result<PairFinish, String> {
    let wait_secs = match inv.flags.get("wait") {
        Some(raw) => raw.trim().parse::<u64>().map_err(|_| format!("--wait takes whole seconds (0 to park and return), not `{raw}`"))?,
        None => DEFAULT_PAIR_WAIT_SECS,
    };
    Ok(PairFinish {
        wait_secs,
        skip_confirm: inv.flag_present("yes"),
        grant: parse_allow_flag(inv)?,
        code: inv.flags.get("code").cloned().filter(|c| !c.trim().is_empty()),
        door: inv.door,
    })
}

/// A NEW request carries no reply code to validate yet (the mutual-code
/// redesign, R1) — `derive_reply_sas` needs BOTH sides' nonces, which don't
/// exist on this side as a completed transcript until the approver has
/// approved and read their own reply code back. `--code` on a fresh request
/// is a scripting mistake, not a shorthand for anything: refused with the
/// spelling that DOES work once the id exists. Checked by both REQUEST arms
/// only ([`pair_via_url`], the sweep arms feeding [`pair_with_heard`]) —
/// the RESUME leg ([`resume_outbound_leg`]) is exactly where `--code` is
/// legal, so it never calls this.
fn refuse_code_on_new_request(cmd: &str, finish: &PairFinish) -> Option<Outcome> {
    finish.code.as_ref().map(|_| {
        Outcome::usage(
            cmd,
            "--code has nothing to validate yet on a NEW request — no reply code exists until the far side approves \
             and reads their own reply code back; complete with `aoide pair <id> --code NNN-NNN` once they have",
        )
    })
}

/// The REQUESTER's own code gate, resolved off `finish` the SAME way
/// [`approve_inbound_leg`] resolves the approver's off an `&Invocation`
/// (the mutual-code redesign, R1) — `--code` scripted, a real CLI tty
/// prompts, anything else (including `--yes`, which bypasses neither leg's
/// gate) refuses. Shared by [`resume_outbound_leg`]'s zero-wait commit and
/// [`wait_and_commit`]'s own poll-released commit so the two paths can
/// never resolve a DIFFERENT gate for the same flags.
fn outbound_gate_from(finish: &PairFinish) -> CodeGate {
    match finish.code.clone() {
        Some(code) => CodeGate::Code(code),
        None if finish.skip_confirm => CodeGate::Unavailable,
        None if aoide_protocol::pick::interactive(finish.door) => CodeGate::Prompt,
        None => CodeGate::Unavailable,
    }
}

/// A NEW request with `--wait 0` parks and returns before anything commits,
/// so an `--allow` beside it has nowhere to land — the ceremony deliberately
/// never persists a grant on a parked entry (the User's decision: the grant
/// stays attached to a live human at commit time), and accepting the pair
/// silently would drop the flag, the same silent no-op `grant_note` exists
/// to prevent one step later (review finding). Checked by the REQUEST arms
/// only — the two here, plus `crate::mesh`'s converge, which asks this same
/// rule about the grant its declaration supplies and replaces only the
/// wording (no `--allow` was typed there). The RESUME leg keeps the
/// combination legal, because its `--wait 0` still polls once and can
/// commit.
pub(crate) fn refuse_detached_grant(cmd: &str, finish: &PairFinish) -> Option<Outcome> {
    (finish.wait_secs == 0 && finish.grant.is_some()).then(|| {
        Outcome::usage(
            cmd,
            "--allow needs a wait to land in: `--wait 0` parks the request and returns before anything commits, and a grant is never persisted on a parked entry — \
             retype --allow when completing (`aoide pair <id> --allow ...`)",
        )
    })
}

/// Block until the approver releases `id`, then confirm and commit — the
/// whole requester half in one command (task #135 P2, the User's ask: "`node
/// pair <target>` BLOCKS until done, timeout = nobody there").
///
/// Every terminal answer returns immediately: only [`PollOutcome::Pending`]
/// loops, so an unreachable box or a refused reveal fails on the first tick
/// rather than after the full wait. The grant resolves BEFORE the loop, so a
/// malformed `config.toml` refuses now rather than after ten minutes.
///
/// A timeout is not a failure of the pair — the request stays parked and
/// `pair <id>` still finishes it whenever the far operator gets
/// to it. That is the "nobody there" outcome, and it is why Ctrl-C is safe:
/// nothing here holds state the parked entry does not already have.
fn wait_and_commit(cmd: &str, id: &str, name: &str, sas: &str, finish: &PairFinish) -> Outcome {
    let allows = match resolve_grant(finish.grant.as_deref()) {
        Ok(a) => a,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "grant-unresolved", "id": id })),
    };
    // Task #135 popup-phase spec, part 4: this loop is the ONLY production
    // site that polls-and-can-commit an outbound request on its own — the
    // SAME id's `--popup` confirm dialog must not race it to the SAME
    // commit. Held for the rest of this function, however it returns
    // (`Drop`), so a timeout or an early bail never leaves a stale marker.
    let _pair_active_marker = crate::pair_watch::PairActiveMarker::acquire(id);
    // MONOTONIC, never the wall clock (review finding): an NTP step or a
    // suspend/resume during the wait moves `now_iso_utc` backward, and a
    // deadline measured against it then never arrives — the loop would poll
    // forever past the bound this command promised. `Instant` cannot go
    // backward, so the timeout holds whatever the clock does. The wall clock
    // is still read INSIDE the loop, where it belongs: entry expiry is a
    // stored ISO timestamp, so `list_outbound` must be asked in its terms.
    let began = std::time::Instant::now();
    let mut announced_minutes = 0_u64;

    loop {
        let now = aoide_storage::time::now_iso_utc();
        let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap_or(0);
        let Some(entry) = aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == id) else {
            return Outcome::error(
                cmd,
                format!("pairing request `{id}` to `{name}` is gone — it expired, or was rejected here, while this command waited"),
            )
            .with_data(json!({ "reason": "request-gone", "id": id }));
        };
        match poll_outbound_once(cmd, id, &entry, now_epoch) {
            PollOutcome::Released(released) => {
                let gate = outbound_gate_from(finish);
                // No tty and no `--code` (the mutual-code redesign, R1):
                // a blocking wait's own release is not the moment to hand
                // back a hard Usage refusal the way the one-shot resume leg
                // does — the entry is ALREADY parked at `awaiting-confirm`
                // (the poll's own transition), nothing here auto-commits or
                // counts a try either way, so this is the SAME "still
                // pending, finish later" shape [`wait_is_over`]'s own
                // timeout arm below already returns, not a distinct error
                // path.
                if matches!(gate, CodeGate::Unavailable) {
                    return Outcome::ok(
                        cmd,
                        format!(
                            "`{name}` approved — no terminal to type the reply code into; the request stays pending as `{id}`; \
                             finish with `aoide pair {id} --code NNN-NNN`"
                        ),
                    )
                    .with_data(json!({ "reason": "wait-no-code-available", "id": id, "name": name }));
                }
                return commit_outbound(gate, cmd, id, released, &now, now_epoch, &allows);
            }
            PollOutcome::Refused(out) => return out,
            PollOutcome::Pending => {}
        }

        let elapsed = began.elapsed().as_secs();
        if wait_is_over(elapsed, finish.wait_secs) {
            return Outcome::ok(
                cmd,
                format!(
                    "no answer from `{name}` within {}s — the request is still pending as `{id}` (code {sas}); \
                     run `aoide pair {id}` once they've approved on their side, or \
                     `aoide pair reject {id}` to abort",
                    finish.wait_secs
                ),
            )
            .with_data(json!({ "reason": "wait-timeout", "id": id, "name": name, "sas": sas, "waitSecs": finish.wait_secs }));
        }
        // One line a minute, never one per tick: a wait this long must show
        // it is alive, and 120 lines of dots is not showing anything.
        if elapsed / 60 > announced_minutes {
            announced_minutes = elapsed / 60;
            eprintln!("still waiting on `{name}` ({elapsed}s elapsed of {})", finish.wait_secs);
        }
        std::thread::sleep(PAIR_POLL_CADENCE);
    }
}

/// The pending listing (bare `pair` off a tty, and its --json face) — every
/// pairing request THIS instance is still holding
/// open, BOTH directions (review-bounce Finding 2: an outbound entry
/// awaiting THIS instance's own confirm is exactly as "pending" as an
/// inbound one awaiting approval — before that fix, nothing ever surfaced
/// it). Inbound rows carry `revealed` (`requester_nonce_hex.is_some()`,
/// review-bounce Finding 1) — an unrevealed entry shows `"awaiting
/// reveal"`, and `pair <id>` refuses it. An APPROVED inbound entry
/// (Design A, task #119 — [`InboundPairingRequest::approved`]) stays
/// listed here too, showing `"approved · awaiting their poll"` plus a hint
/// to re-run `aoide pair <id>` (the mutual-code redesign, R1 — that re-run
/// re-derives and re-displays the reply code for an operator who lost it) —
/// it remains parked (never taken) until the requester's own
/// `aoide/pairPoll` releases it or it expires, so the approver's own
/// operator can still see it's done its part. Outbound rows carry their own
/// `state` (`awaiting-approval`/`awaiting-confirm`).
///
/// **Never either pairing code (P-PV2, the User's locked spec; extends
/// unchanged to the reply code, R1).** The plain code is read off the
/// REQUESTER's own terminal and typed on the APPROVER's; the reply code
/// runs the same comparison in reverse — printing either here too would
/// defeat the whole point of an out-of-band comparison (an operator could
/// just read both sides off this one listing instead of actually comparing
/// two independent screens). `pair <id>` still independently re-derives
/// whichever code its own leg needs from this instance's own identity plus
/// the entry's stored transcript fields — never trusted from the wire —
/// exactly as before; only THIS row listing
/// stops showing it.
fn pending_listing(cmd: &str) -> Outcome {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let inbound = aoide_storage::pairing::list_inbound(now_epoch);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    if inbound.is_empty() && outbound.is_empty() {
        return Outcome::ok(cmd, "no pending pairing requests").with_data(json!({ "requests": [] }));
    }

    let mut rows: Vec<Value> = Vec::new();
    for e in &inbound {
        rows.push(json!({
            "id": e.id, "direction": "inbound", "name": e.name, "originAddr": e.origin_addr, "url": e.url,
            "revealed": e.requester_nonce_hex.is_some(), "approved": e.approved,
            "requestedAt": e.requested_at, "expiresAt": e.expires_at,
        }));
    }
    for e in &outbound {
        rows.push(json!({
            "id": e.id, "direction": "outbound", "name": e.name, "url": e.url,
            "state": e.state.as_str(),
            "requestedAt": e.requested_at, "expiresAt": e.expires_at,
        }));
    }

    let lines: Vec<String> = rows
        .iter()
        .map(|r| {
            let dir = r["direction"].as_str().unwrap_or("");
            let status = match dir {
                "inbound" if r["revealed"].as_bool() == Some(false) => "awaiting reveal".to_string(),
                "inbound" if r["approved"].as_bool() == Some(true) => {
                    "approved · awaiting their poll · re-run `aoide pair <id>` to re-show the reply code".to_string()
                }
                "inbound" => "revealed · run `aoide pair <id>` with the code from their screen".to_string(),
                _ => r["state"].as_str().unwrap_or("").to_string(),
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

/// The APPROVER's half of `pair <id>` (this instance holds the
/// INBOUND entry). Refuses outright while the entry is still `awaiting
/// reveal` (review-bounce Finding 1 — no nonce yet means no SAS to confirm
/// against). Otherwise re-derives the SAS from this instance's own identity
/// plus the parked entry (never trusting a wire-supplied code) and requires
/// an explicit `y`/`yes` confirmation (CLI prompt, or `--yes` for scripted
/// tests) BEFORE anything commits.
///
/// **Design A (task #119): PURELY LOCAL — no network call at all.** The old
/// shape delivered an `aoide/pairApprove` callback to the requester's own
/// door FIRST, which meant a requester whose door was loopback-only
/// ([[doors-loopback-only]]) could never be reached, and the ceremony could
/// never complete. Now: commit THIS instance's own node record
/// (`upsert_paired_node`), then mark the parked entry
/// [`aoide_storage::pairing::InboundPairingRequest::approved`]
/// (`mark_inbound_approved`) and leave it PARKED — never taken — so the
/// requester's own `aoide/pairPoll` (over the SAME forward dial the request/
/// reveal already used) can find and release it later, however long after
/// this command exits. "A parked request grants NOTHING until approved"
/// (PAIRING.md) still holds: nothing is released to anyone until BOTH this
/// commit AND a correctly-signed poll from the ORIGINAL requester happen.
///
/// Idempotent: re-running this against an already-approved entry is a no-op
/// success (no second code prompt, no second `upsert_paired_node`) — the
/// operator may have run it twice, or the popup arm may re-offer a stale
/// row before its own state catches up.
///
/// **The gate is the TYPED pairing code (task #120 P3, [`CodeGate`]).**
/// The approver's operator types the code as read off the REQUESTER's
/// screen (out-of-band — a phone call, a glance) and this compares it
/// against the locally derived SAS; the prompt itself never echoes that SAS
/// — printing the expected value beside the input would collapse the
/// comparison into a copy exercise and defeat the whole gate. A mismatch
/// counts one persisted try ([`aoide_storage::pairing::record_inbound_code_try`],
/// cumulative across invocations and across the interactive/scripted
/// paths); the [`MAX_CODE_TRIES`]rd mismatch auto-denies
/// ([`auto_deny_inbound`] — the same clean removal `pair reject`
/// performs, audited under its own reason). An abort (`Esc`, `Ctrl-C`)
/// leaves the entry pending with no try counted — an abort is not a wrong
/// code. **`pair_watch --popup`'s own dialog is `CodeGate::Code`
/// too** (P-PV3, task #132): it collects the SAME typed code this gate
/// already validates everywhere else, so the popup arm runs through this
/// exact match arm, not a separate no-prompt one.
pub(crate) fn approve_inbound(
    gate: CodeGate,
    cmd: &str,
    id: &str,
    entry: aoide_storage::pairing::InboundPairingRequest,
    now: &str,
    now_epoch: i64,
    grant: Option<&[String]>,
) -> Outcome {
    if entry.approved {
        // The operator who lost the popup (or fat-fingered a relay) re-runs
        // `aoide pair <id>` — re-derive and re-display the SAME reply code
        // rather than leaving them with nothing to relay a second time.
        // `None` only on an identity-load failure (best-effort — the
        // idempotent success itself never depends on it).
        let reply_sas = aoide_storage::identity::load_or_mint().ok().and_then(|(kp, _)| {
            entry
                .requester_nonce_hex
                .as_deref()
                .map(|n| aoide_storage::pairing::derive_reply_sas(&entry.pubkey_hex, &kp.info().pubkey_hex, n, &entry.approver_nonce_hex))
        });
        let name = &entry.name;
        let message = match &reply_sas {
            Some(code) => format!("already approved `{name}` — re-run `aoide pair {id}` to re-show the reply code, or relay THIS one if you haven't yet: {code}"),
            None => format!("already approved `{name}` — waiting for their own `aoide pair {id}` to complete their side"),
        };
        return Outcome::ok(cmd, message)
            .with_data(json!({ "confirmed": true, "id": id, "node": entry.name, "alreadyApproved": true, "replySas": reply_sas }));
    }

    // Resolved BEFORE the code gate, not beside the commit that uses it: a
    // malformed `config.toml` would otherwise refuse only after the operator
    // had already read a code off the far screen and typed it here.
    let allows = match resolve_grant(grant) {
        Ok(a) => a,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "grant-unresolved", "id": id })),
    };

    let Some(requester_nonce) = entry.requester_nonce_hex.clone() else {
        return Outcome::error(
            cmd,
            format!(
                "pairing request `{id}` from `{}` is awaiting the requester's reveal step — nothing to confirm yet; \
                 try again shortly, or `aoide pair reject {id}` to refuse it outright",
                entry.name
            ),
        )
        .with_data(json!({ "reason": "awaiting-reveal", "id": id }));
    };

    // An entry already at the try limit is denied up front, before any gate
    // arm runs — a crash between the third try's persisted increment and its
    // auto-deny (the one window where tries == MAX survives on disk) must
    // not leave an approvable entry behind.
    if entry.tries >= MAX_CODE_TRIES {
        return auto_deny_inbound(cmd, id, &entry.name, now_epoch);
    }

    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;
    let sas = aoide_storage::pairing::derive_sas(&entry.pubkey_hex, &own_pubkey, &requester_nonce, &entry.approver_nonce_hex);

    match gate {
        CodeGate::Unavailable => return inbound_code_refusal(cmd, id),
        CodeGate::Code(code) => {
            if !code_matches(&code, &sas) {
                let tries = match record_code_try(cmd, id, now_epoch) {
                    Ok(t) => t,
                    Err(out) => return out,
                };
                if tries >= MAX_CODE_TRIES {
                    return auto_deny_inbound(cmd, id, &entry.name, now_epoch);
                }
                return Outcome::error(
                    cmd,
                    format!(
                        "code mismatch — try {tries} of {MAX_CODE_TRIES}; {} more before this request is auto-denied",
                        MAX_CODE_TRIES - tries
                    ),
                )
                .with_data(json!({ "reason": "code-mismatch", "id": id, "tries": tries }));
            }
        }
        CodeGate::Prompt => loop {
            // The prompt names the code's SHAPE, never its value (module
            // doc's echo invariant).
            let typed = match aoide_protocol::pick::text_input(&format!(
                "pairing request from `{}` — type the confirmation code shown on the requester's screen (NNN-NNN):",
                entry.name
            )) {
                Ok(t) => t,
                Err(e) => return Outcome::error(cmd, e),
            };
            let Some(typed) = typed else {
                return Outcome::ok(
                    cmd,
                    format!("not confirmed — the request remains pending; run `aoide pair reject {id}` to refuse it outright"),
                )
                .with_data(json!({ "confirmed": false, "id": id }));
            };
            if code_matches(&typed, &sas) {
                break;
            }
            let tries = match record_code_try(cmd, id, now_epoch) {
                Ok(t) => t,
                Err(out) => return out,
            };
            if tries >= MAX_CODE_TRIES {
                return auto_deny_inbound(cmd, id, &entry.name, now_epoch);
            }
            eprintln!("code mismatch — {} more tr{} before this request is auto-denied", MAX_CODE_TRIES - tries, if MAX_CODE_TRIES - tries == 1 { "y" } else { "ies" });
        },
    }

    // The mutual-code redesign (R1): B's own reply code, derived NOW
    // (everything it needs — both pubkeys, both nonces — is already in
    // hand) so the Ok outcome below can hand it back to this operator to
    // relay out-of-band. `derive_reply_sas`'s arg order mirrors `derive_sas`
    // above exactly (requester_pubkey, approver_pubkey, requester_nonce,
    // approver_nonce) — never trusted from the wire, computed identically
    // to how the requester will independently re-derive the SAME value.
    let reply_sas = aoide_storage::pairing::derive_reply_sas(&entry.pubkey_hex, &own_pubkey, &requester_nonce, &entry.approver_nonce_hex);

    // P-S4/P-PV1: the APPROVER's own commit. `InboundPairingRequest` carries
    // no OBSERVED transport marker (through a tunnel, `origin_addr` reads
    // "loopback", per §0.7 — not a usable source) — but P-PV1 (task #131)
    // gives it a CLAIMED one: when the wire's `selfVia` rode this entry
    // (`entry.self_via`), the requester's own door is reachable only
    // through that hop, the same convention the sakaki/chiyo/osaka node
    // rows already hold by hand — `url` becomes the loopback-as-seen-from-
    // the-far-side door (`http://127.0.0.1:<AOIDE_A2A_PORT or 8710>/`,
    // never `entry.url`'s requester-observed host, which the approver can
    // never dial directly through the tunnel) and `via` becomes the claim
    // itself, committed in the SAME write as the pairing commit below
    // (`set_node_via`'s own doc on why it's a sibling writer beside
    // `upsert_paired_node`). No claim on the entry (an old requester, or
    // one with nothing to claim) commits EXACTLY today's shape: `entry.url`
    // verbatim, `via` left `None` — the same "absent by default" a fresh
    // `Node` already carries.
    //
    // The PORT in the loopback rewrite is the REQUESTER's own door port,
    // parsed off `entry.url` (their own `self_url`, already encoding
    // whatever port their door actually binds — review finding, first
    // pass wrongly read THIS box's own `AOIDE_A2A_PORT`, which has no
    // relation to the requester's) — `default_a2a_port()` is only ever a
    // fallback for the rare case `entry.url` carries no parseable port at
    // all (a malformed or hand-edited self-claim).
    let record_url = match entry.self_via.as_deref() {
        Some(_) => {
            let port = port_from_url(&entry.url).unwrap_or_else(default_a2a_port);
            format!("http://127.0.0.1:{port}/")
        }
        None => entry.url.clone(),
    };
    let mut nodes = aoide_storage::node_store::load_nodes();
    let first_pairing = !nodes.iter().any(|p| p.name == entry.name && p.verified);
    let change = aoide_storage::node_store::upsert_paired_node(&mut nodes, &entry.name, &record_url, &entry.pubkey_hex, now, &allows);
    if let Some(via) = entry.self_via.as_deref() {
        if let Err(e) = aoide_storage::node_store::set_node_via(&mut nodes, &entry.name, Some(via)) {
            return Outcome::error(cmd, format!("recording the node's transport marker: {e}"));
        }
    }
    if let Err(e) = aoide_storage::node_store::save_nodes(&nodes) {
        return Outcome::error(cmd, format!("writing the node registry: {e}"));
    }
    // Design A: mark approved, never take — the entry stays parked for the
    // requester's own poll to find (module doc above).
    let _ = aoide_storage::pairing::mark_inbound_approved(id, now_epoch);

    use aoide_storage::node_store::PairChange;
    let word = match change {
        PairChange::Inserted => "paired with",
        PairChange::Updated => "re-paired with",
    };
    Outcome::ok(
        cmd,
        format!(
            "{word} `{}` (code {sas}) — verified{}; read THIS code back to `{}`'s operator: {reply_sas} — \
             they finish with `aoide pair {id} --code …`",
            entry.name,
            grant_note(first_pairing, &allows),
            entry.name,
        ),
    )
    .changed(vec![aoide_storage::node_store::nodes_path().to_string_lossy().into_owned()])
    .with_data(json!({ "confirmed": true, "sas": sas, "replySas": reply_sas, "node": entry.name, "pubkeyHex": entry.pubkey_hex, "direction": "inbound", "grant": allows, "grantStamped": first_pairing }))
}

/// The REQUESTER's poll-then-confirm-then-commit half of `pair
/// <id>` (this instance holds the OUTBOUND entry, review-bounce
/// Finding 2's mutual confirmation, preserved) — ONE poll
/// ([`poll_outbound_once`]) then the commit ([`commit_outbound`]), which is
/// all this function is since task #135 P2 lifted both halves out.
///
/// **Design A (task #119): POLLS instead of waiting on a callback.** The old
/// shape refused outright while `state == AwaitingApproval`, waiting for an
/// `aoide/pairApprove` callback the approver's door would dial in to
/// deliver — unreachable when THIS instance's own door is loopback-only
/// ([[doors-loopback-only]]). A [`PollOutcome::Pending`] answer refuses here
/// with the SAME "still awaiting the node's own approval" message the old
/// callback-wait refusal gave — an ordinary, expected outcome while the
/// operators are still comparing codes out loud, and the ONE arm a blocking
/// caller retries instead of returning.
///
/// `gate` (the mutual-code redesign, R1 — was `skip_confirm: bool`): same
/// meaning and shape as [`approve_inbound`]'s own `gate` parameter — this
/// leg gates on [`aoide_storage::pairing::derive_reply_sas`] the identical
/// way the approver's leg gates on `derive_sas`, threaded straight through
/// to [`commit_outbound`].
pub(crate) fn approve_outbound(
    gate: CodeGate,
    cmd: &str,
    id: &str,
    entry: aoide_storage::pairing::OutboundPairingRequest,
    now: &str,
    now_epoch: i64,
    grant: Option<&[String]>,
) -> Outcome {
    // Resolved before the poll: a malformed `config.toml` refuses without a
    // network round trip and without asking the operator to confirm a code
    // this side would then decline to commit.
    let allows = match resolve_grant(grant) {
        Ok(a) => a,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "grant-unresolved", "id": id })),
    };

    let entry = match poll_outbound_once(cmd, id, &entry, now_epoch) {
        PollOutcome::Released(e) => e,
        PollOutcome::Refused(out) => return out,
        PollOutcome::Pending => {
            return Outcome::error(
                cmd,
                format!(
                    "pairing request `{id}` to `{}` is still awaiting the node's own approval — nothing to confirm yet; \
                     try again once they've run `aoide pair {id}` on their side, or \
                     `aoide pair reject {id}` to abort",
                    entry.name
                ),
            )
            .with_data(json!({ "reason": "awaiting-node-approval", "id": id }))
        }
    };

    commit_outbound(gate, cmd, id, entry, now, now_epoch, &allows)
}

/// What one `aoide/pairPoll` round trip learned. Split out (task #135 P2) so
/// the poll has ONE implementation: `pair <id>` calls it once, a
/// blocking `pair` calls it on a cadence, and `mesh pair` will too. A
/// second copy of this loop anywhere is the design error this exists to
/// prevent — the SAS/transcript binding below is the whole security of the
/// requester's half, and it must not be re-derived per caller.
pub(crate) enum PollOutcome {
    /// The approver released: the entry is now `AwaitingConfirm` and carries
    /// the released pubkey, bound to what this instance learned at request
    /// time.
    Released(aoide_storage::pairing::OutboundPairingRequest),
    /// Nobody has approved yet. The ONLY outcome a `--wait` loop retries —
    /// every other arm is terminal, so a loop that retried them would hammer
    /// an unreachable box or a refused reveal forever.
    Pending,
    /// A terminal refusal, already shaped as the [`Outcome`] the caller
    /// returns. Shaping it here rather than returning an error type keeps the
    /// taught wording and the `reason` codes in ONE place across all callers.
    Refused(Outcome),
}

/// Poll the approver's door once for `id`'s release (`aoide/pairPoll`, over
/// the SAME forward dial `pair`'s own request/reveal already used).
///
/// An entry already at `AwaitingConfirm` is [`PollOutcome::Released`]
/// immediately with no wire call: it was released by an earlier poll whose
/// operator then declined the confirm prompt, and re-polling a released
/// request would ask the approver to release something it already did.
pub(crate) fn poll_outbound_once(cmd: &str, id: &str, entry: &aoide_storage::pairing::OutboundPairingRequest, now_epoch: i64) -> PollOutcome {
    if entry.state != aoide_storage::pairing::OutboundState::AwaitingApproval {
        return PollOutcome::Released(entry.clone());
    }
    let poll_body = match build_signed_pair_poll_body(id) {
        Ok(b) => b,
        Err(e) => return PollOutcome::Refused(Outcome::error(cmd, e).with_data(json!({ "reason": "identity-io-failed", "id": id }))),
    };
    let via = match entry.via.as_deref().map(aoide_storage::tunnel::parse_via).transpose() {
        Ok(v) => v,
        Err(e) => {
            return PollOutcome::Refused(Outcome::error(
                cmd,
                format!("the pairing request's own recorded `via` no longer parses: {e}"),
            ))
        }
    };
    let (code, resp_body) = match post_json_via(&entry.url, via.as_ref(), &entry.name, &poll_body, None, &[], 15) {
        Ok(v) => v,
        Err(e) => {
            return PollOutcome::Refused(
                Outcome::error(
                    cmd,
                    format!("polling `{}` at {}: {e} — retry `aoide pair {id}` once it's reachable", entry.name, entry.url),
                )
                .with_data(json!({ "reason": "poll-unreachable", "id": id })),
            )
        }
    };
    if code != 200 {
        return PollOutcome::Refused(
            Outcome::error(cmd, format!("polling `{}`: HTTP {code}", entry.name))
                .with_data(json!({ "reason": "poll-http-error", "id": id, "httpCode": code })),
        );
    }
    let parsed: Value = serde_json::from_str(&resp_body).unwrap_or(Value::Null);
    let status = match crate::node::parse_pair_poll_response(&parsed) {
        Ok(s) => s,
        Err(e) => return PollOutcome::Refused(Outcome::error(cmd, e).with_data(json!({ "reason": "poll-refused", "id": id }))),
    };
    let polled_pubkey = match status {
        crate::node::PairPollStatus::Pending => return PollOutcome::Pending,
        crate::node::PairPollStatus::Approved { pubkey_hex } => pubkey_hex,
    };
    // The SAS/transcript binding (review-bounce Finding 2, preserved):
    // a released pubkey that does not match what THIS instance learned
    // at request time is refused here, entry untouched — the SAME
    // rejection the old callback's own mismatch handling gave.
    match aoide_storage::pairing::mark_outbound_awaiting_confirm(id, &polled_pubkey, now_epoch) {
        Ok(marked) => PollOutcome::Released(marked),
        Err(aoide_storage::pairing::ConfirmMarkError::Mismatch) => PollOutcome::Refused(
            Outcome::error(
                cmd,
                format!("the node's released identity does not match what this instance learned at request time for `{}` — refusing to bind a substituted reveal", entry.name),
            )
            .with_data(json!({ "reason": "reveal-mismatch", "id": id })),
        ),
        Err(aoide_storage::pairing::ConfirmMarkError::Unknown) => PollOutcome::Refused(
            Outcome::error(cmd, format!("no pending outbound pairing request with id `{id}` (unknown, already resolved, or expired)"))
                .with_data(json!({ "reason": "unknown-id", "id": id })),
        ),
        Err(aoide_storage::pairing::ConfirmMarkError::Io(e)) => {
            PollOutcome::Refused(Outcome::error(cmd, format!("resolving the outbound pairing request: {e}")))
        }
    }
}

/// The REQUESTER's gate-then-commit half, on an entry a poll already
/// released (the mutual-code redesign, R1 — the old shape's `y`/`N` over
/// the SAME `derive_sas` code this side already printed at request time is
/// GONE; this now gates on `derive_reply_sas`, the code the approver reads
/// back after typing THIS side's own code). Split out beside
/// [`poll_outbound_once`] (task #135 P2) for the same reason: a blocking
/// `pair` and `mesh pair` both finish a ceremony here, and neither may
/// re-derive the reply code or re-implement the commit.
///
/// **The gate is the TYPED reply code — [`CodeGate`], the approver's own
/// gate shape, mirrored.** Everything [`approve_inbound`]'s own doc states
/// about its gate holds here identically, on the other leg: the reply code
/// comes from this instance's own identity plus the entry's STORED
/// transcript, never from the wire; the prompt never echoes it; a mismatch
/// counts one persisted try ([`aoide_storage::pairing::
/// record_outbound_code_try`]); the [`MAX_CODE_TRIES`]rd mismatch
/// auto-aborts ([`auto_abort_outbound`] — a clean `take_outbound`, nothing
/// of THIS instance's own commits). An entry already at the limit is denied
/// up front, before the gate ever runs (the same crash-window guard
/// [`approve_inbound`]'s own up-front check closes). The approver already
/// committed its own record locally, before this instance ever polled; this
/// writes only THIS end's.
pub(crate) fn commit_outbound(
    gate: CodeGate,
    cmd: &str,
    id: &str,
    entry: aoide_storage::pairing::OutboundPairingRequest,
    now: &str,
    now_epoch: i64,
    allows: &[String],
) -> Outcome {
    if entry.tries >= MAX_CODE_TRIES {
        return auto_abort_outbound(cmd, id, &entry.name, now_epoch);
    }

    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;
    let reply_sas = aoide_storage::pairing::derive_reply_sas(&own_pubkey, &entry.pubkey_hex, &entry.requester_nonce_hex, &entry.approver_nonce_hex);

    match gate {
        CodeGate::Unavailable => return outbound_code_refusal(cmd, id),
        CodeGate::Code(code) => {
            if !code_matches(&code, &reply_sas) {
                let tries = match record_outbound_try(cmd, id, now_epoch) {
                    Ok(t) => t,
                    Err(out) => return out,
                };
                if tries >= MAX_CODE_TRIES {
                    return auto_abort_outbound(cmd, id, &entry.name, now_epoch);
                }
                return Outcome::error(
                    cmd,
                    format!(
                        "reply-code mismatch — try {tries} of {MAX_CODE_TRIES}; {} more before this request is auto-aborted",
                        MAX_CODE_TRIES - tries
                    ),
                )
                .with_data(json!({ "reason": "code-mismatch", "id": id, "tries": tries }));
            }
        }
        CodeGate::Prompt => loop {
            // The prompt names the code's SHAPE, never its value — the same
            // echo invariant `approve_inbound`'s own prompt holds.
            let typed = match aoide_protocol::pick::text_input(&format!(
                "pairing with `{}` — type the REPLY code shown on their screen (NNN-NNN):",
                entry.name
            )) {
                Ok(t) => t,
                Err(e) => return Outcome::error(cmd, e),
            };
            let Some(typed) = typed else {
                return Outcome::ok(
                    cmd,
                    format!("not confirmed — the request remains pending; run `aoide pair reject {id}` to abort"),
                )
                .with_data(json!({ "confirmed": false, "id": id }));
            };
            if code_matches(&typed, &reply_sas) {
                break;
            }
            let tries = match record_outbound_try(cmd, id, now_epoch) {
                Ok(t) => t,
                Err(out) => return out,
            };
            if tries >= MAX_CODE_TRIES {
                return auto_abort_outbound(cmd, id, &entry.name, now_epoch);
            }
            eprintln!(
                "reply-code mismatch — {} more tr{} before this request is auto-aborted",
                MAX_CODE_TRIES - tries,
                if MAX_CODE_TRIES - tries == 1 { "y" } else { "ies" }
            );
        },
    }

    let mut nodes = aoide_storage::node_store::load_nodes();
    let first_pairing = !nodes.iter().any(|p| p.name == entry.name && p.verified);
    let change = aoide_storage::node_store::upsert_paired_node(&mut nodes, &entry.name, &entry.url, &entry.pubkey_hex, now, allows);
    // P-S4: the via this ceremony resolved back at `pair` request
    // time (K1's src_addr-derived default, or an explicit `--via`) rode
    // the parked entry here — commit it onto the node record in the SAME
    // write as the pairing commit above, via the sibling writer
    // (`set_node_via`'s own doc on why it's separate from
    // `upsert_paired_node`'s signature). ONLY when `entry.via` is `Some`
    // (review fix, P-S4 follow-up) — a plain re-pair with no `--via` must
    // LEAVE a previously-recorded via (e.g. one earlier `pair` set)
    // exactly as it was, the same "untouched unless this call names a change"
    // stance `upsert_paired_node` itself already holds for `autogate`/
    // `tokenFile`/`bearerSecret`/`hub`/`allows` on re-pairing; calling
    // `set_node_via` unconditionally with `None` would silently WIPE that
    // marker as a side effect of an unrelated re-pair, never a deliberate
    // clear.
    if let Some(via) = entry.via.as_deref() {
        if let Err(e) = aoide_storage::node_store::set_node_via(&mut nodes, &entry.name, Some(via)) {
            return Outcome::error(cmd, format!("recording the node's transport marker: {e}"));
        }
    }
    if let Err(e) = aoide_storage::node_store::save_nodes(&nodes) {
        return Outcome::error(cmd, format!("writing the node registry: {e}"));
    }
    let _ = aoide_storage::pairing::take_outbound(id, now_epoch);

    use aoide_storage::node_store::PairChange;
    let word = match change {
        PairChange::Inserted => "paired with",
        PairChange::Updated => "re-paired with",
    };
    Outcome::ok(cmd, format!("{word} `{}` (reply code {reply_sas}) — verified{}", entry.name, grant_note(first_pairing, allows)))
        .changed(vec![aoide_storage::node_store::nodes_path().to_string_lossy().into_owned()])
        .with_data(json!({ "confirmed": true, "replySas": reply_sas, "node": entry.name, "pubkeyHex": entry.pubkey_hex, "direction": "outbound", "grant": allows, "grantStamped": first_pairing }))
}

/// `pair reject <id|name>` — a clean refusal: removes the parked entry
/// (whichever direction it's in — an OUTBOUND id at EITHER state is the
/// ceremony's own missing ABORT command, review-bounce Finding 2), no node
/// record on either end. Never notifies the other side (no wire call); an
/// inbound rejection's counterpart outbound entry simply expires on its own
/// timeout (PAIRING.md names no explicit reject-notification requirement,
/// and a same-shaped "clean refusal" is exactly what `secrets dismiss`
/// gives an operator without a wire round trip either).
fn handle_pair_reject(inv: &Invocation) -> Outcome {
    let cmd = "pair.reject";
    let target = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(t) => t.to_string(),
        None => return Outcome::usage(cmd, "usage: aoide pair reject <id|name> [--json]"),
    };
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    let inbound = aoide_storage::pairing::list_inbound(now_epoch);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);
    // An exact id wins outright (ids come from this family's own messages);
    // otherwise a name matching exactly ONE pending request resolves to its
    // id, several refuse with the ids, and none falls through to
    // `reject_by_id`'s own taught unknown-id error, verbatim.
    if inbound.iter().any(|e| e.id == target) || outbound.iter().any(|e| e.id == target) {
        return reject_by_id(cmd, &target);
    }
    let ids: Vec<String> = inbound
        .iter()
        .filter(|e| e.name == target)
        .map(|e| e.id.clone())
        .chain(outbound.iter().filter(|e| e.name == target).map(|e| e.id.clone()))
        .collect();
    match ids.as_slice() {
        [one] => reject_by_id(cmd, one),
        [] => reject_by_id(cmd, &target),
        _ => Outcome::usage(cmd, format!("multiple pending requests involve `{target}` — name one by id: {}", ids.join(", ")))
            .with_data(json!({ "reason": "ambiguous-target", "target": target, "ids": ids })),
    }
}

/// The shared body of `pair reject` — extracted (P-P5) so
/// `pair_watch`'s own popup arm (a `--yes`-shaped CLI invocation is the
/// wrong shape for a dialog's "Reject request" button, which knows only
/// the id) can call it directly with no [`Invocation`] to construct.
/// Whichever direction the id is parked in, removes it — no node record
/// on either end, no wire notification to the other side (module doc on
/// [`handle_pair_reject`]).
pub(crate) fn reject_by_id(cmd: &str, id: &str) -> Outcome {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);

    match aoide_storage::pairing::take_inbound(id, now_epoch) {
        Ok(Some(entry)) => {
            return Outcome::ok(cmd, format!("rejected pairing request `{id}` from `{}` — no node record written", entry.name))
                .with_data(json!({ "rejected": true, "id": id, "name": entry.name, "direction": "inbound" }))
        }
        Ok(None) => {}
        Err(e) => return Outcome::error(cmd, format!("removing the pairing request: {e}")),
    }

    match aoide_storage::pairing::take_outbound(id, now_epoch) {
        Ok(Some(entry)) => Outcome::ok(cmd, format!("aborted outbound pairing request `{id}` to `{}` — no node record written", entry.name))
            .with_data(json!({ "rejected": true, "id": id, "name": entry.name, "direction": "outbound" })),
        Ok(None) => Outcome::error(cmd, format!("no pending pairing request with id `{id}` (unknown, already resolved, or expired)"))
            .with_data(json!({ "reason": "unknown-id", "id": id })),
        Err(e) => Outcome::error(cmd, format!("removing the pairing request: {e}")),
    }
}

/// `pair watch [--popup] [--json]`'s launch-record handler (P-P5) —
/// the SAME shape `aoide_server::commands::handle_events_tail`/
/// `aoide_secrets::commands::handle_secrets_watch` already hold for a
/// foreground/blocking command: this only gates the door and refuses a
/// `--popup`+`--json` combo; the blocking loop itself
/// (`crate::pair_watch::run`) runs from `cli`'s `special` hook, dispatched
/// to AFTER this handler records the launch attempt through the single
/// audit log. CLI-only — a follow-style command that blocks a connection
/// until Ctrl-C makes no sense over MCP/A2A, the same reasoning
/// `secrets watch`/`events tail` already established for the same shape
/// of command.
fn handle_pair_watch(inv: &Invocation) -> Outcome {
    let cmd = "pair.watch";
    if inv.door != aoide_protocol::Door::Cli {
        return Outcome::usage(
            cmd,
            "pair watch is a foreground follow that blocks until Ctrl-C; run it from a terminal (not over this door)",
        );
    }
    if inv.flag_present("popup") && inv.flag_present("json") {
        return Outcome::usage(
            cmd,
            "pair watch: --popup and --json are mutually exclusive — --popup replaces the terminal narration with a \
             confirm dialog, --json emits narration-only machine-readable lines; pick one",
        );
    }
    Outcome::ok(cmd, "watching pairing events")
}

/// `node discover [--secs N] [--json]` (P-P6 + task #120,
/// `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
/// section): listens on the fixed UDP port for `--secs` seconds (default
/// `discover::DEFAULT_SWEEP_SECS`, ~4) and prints every DISTINCT
/// (name, source) heard — name, the claimed ssh hop (`user`@`host`),
/// `srcAddr`, first/last heard, and how many times
/// (`discover::run_sweep`'s own bounded fold). `host`/`user` are the
/// advertisement's own CLAIM; `srcAddr` is the packet's actual source
/// address, an OBSERVATION this process made directly (P-S1) — shown side
/// by side precisely so an operator can see them disagree. **Read-only**
/// — this command never writes `state/nodes.json`; the pairing ceremony
/// is the only thing that ever registers a node. Malformed advertisements
/// are dropped and counted, never echoed raw (house rule 4) — `dropped`
/// in the JSON data is a bare total, nothing more specific about what was
/// wrong with any one of them.
fn handle_node_discover(inv: &Invocation) -> Outcome {
    let cmd = "node.discover";
    let secs = match parse_secs_flag(inv) {
        Ok(n) => n,
        Err(()) => {
            return Outcome::usage(
                cmd,
                "usage: aoide node discover [--secs N] [--json] — --secs must be a positive integer",
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
                "name": h.advertisement.name,
                "host": h.advertisement.host,
                "user": h.advertisement.user,
                "srcAddr": h.src_addr,
                "firstHeard": h.first_heard,
                "lastHeard": h.last_heard,
                "count": h.count,
            })
        })
        .collect();

    let message = if swept.heard.is_empty() {
        format!("heard no discovery advertisements in {secs}s ({} malformed dropped)", swept.dropped)
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

/// `--secs`'s shared parse, parameterized by DEFAULT: absent or
/// unparsable-but-absent-equivalent defaults to `default`;
/// present-but-not-a-positive-integer is a usage error (`Err(())`, the
/// caller renders its own exact usage string) rather than silently falling
/// back — a typo'd `--secs` should never quietly listen for the default
/// window instead of what the operator actually asked for.
fn parse_secs_flag_with_default(inv: &Invocation, default: u64) -> Result<u64, ()> {
    match inv.flags.get("secs") {
        None => Ok(default),
        Some(s) => match s.parse::<u64>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(()),
        },
    }
}

/// `node discover`'s own default window ([`crate::discover::DEFAULT_SWEEP_SECS`],
/// ~4s) — unrelated to and unchanged by P-PV2; [`pair_via_hostname`] holds
/// its own, much longer, default instead ([`PAIR_TARGET_SWEEP_SECS`]).
fn parse_secs_flag(inv: &Invocation) -> Result<u64, ()> {
    parse_secs_flag_with_default(inv, crate::discover::DEFAULT_SWEEP_SECS)
}

/// Prompt `y/N` on stderr before running the pairing ceremony against a
/// discovered node — a LOCAL UX confirmation only (the same hand-rolled
/// stdin idiom this family's OTHER confirms shared before their P-I1
/// retrofit onto `aoide_protocol::pick::confirm`), never a security gate:
/// the ceremony's own typed-code confirmation (both operators, both ends,
/// both directions since R1) is the sole authority either way. Shows BOTH
/// the advertisement's claimed ssh
/// hop (`user`@`host`) and `src_addr` (the packet's OBSERVED source
/// address, P-S1) so the operator sees the claim and the observation side
/// by side before anything is dialed.
fn confirm_invite(name: &str, host: &str, user: &str, src_addr: &str) -> Result<bool, String> {
    eprint!("invite `{name}` (claims ssh {user}@{host}, observed at {src_addr}) to pair — proceed? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// [`handle_node_pair`]'s own default sweep window when `<target>` reads as
/// a hostname (P-PV2, the User's locked spec) — deliberately NOT
/// [`crate::discover::DEFAULT_SWEEP_SECS`] (`node discover`'s own ~4s,
/// unrelated and unchanged): a real LAN's advertise cadence is a ~30-40s
/// tick (`handle_node_advertise`'s own doc), so 4s reliably missed it in
/// practice — task #129's known miss. 45s comfortably spans one tick.
const PAIR_TARGET_SWEEP_SECS: u64 = 45;

/// `pair <target>`'s HOSTNAME arm (`target` is not a URL) — the old
/// `node invite <name>` handler's own body, unchanged apart from the
/// sweep default (above): runs its OWN discover sweep (never reuses a
/// previous one — an advertisement is only ever as fresh as the sweep that
/// heard it), resolves `target` against the heard set
/// (`discover::resolve_invite_target`), and on EXACTLY one match runs the
/// SAME [`run_pair_request`] core the url arm calls, through
/// [`pair_with_heard`] (the settled-target tail bare `pair`'s picker
/// shares) — reused, never copied (this is what "reaches the same code
/// path" actually means here: the handlers bottom out in the identical
/// function, not functions that merely look alike). Zero or multiple
/// matches refuse with a taught error listing every name that WAS heard
/// (never raw advertisement content — house rule 4; only
/// already-validated names ever reach this point). The ceremony url dialed
/// is composed from the hit's OBSERVED source address, never a claimed one
/// (P-S1), on the house door port ([`default_a2a_port`]) — the
/// advertisement deliberately carries NO door URL (rendezvous, not
/// authentication; `aoide_storage::advertise`'s module doc), so a
/// non-default far-end port needs the explicit url arm (`pair
/// <url>`) instead. Before dialing, the SELF-PAIR GUARD
/// (`discover::is_self_target`) refuses when the heard name is this
/// instance's own or the datagram came from loopback — the "you just
/// tried to pair with yourself" case owed here because this is where the
/// target is chosen (a broadcast always loops back to its own sender).
/// `--yes` skips only the LOCAL proceed-confirm (`confirm_invite`), exactly
/// `node spawn`'s own `--yes` idiom — the ceremony's OWN SAS confirmation
/// (both operators, both ends) is untouched and still runs.
fn pair_via_hostname(cmd: &str, inv: &Invocation, target: &str, usage: &str) -> Outcome {
    let secs = match parse_secs_flag_with_default(inv, PAIR_TARGET_SWEEP_SECS) {
        Ok(n) => n,
        Err(()) => {
            return Outcome::usage(cmd, format!("{usage} — --secs must be a positive integer"))
        }
    };
    // An invalid --via is a usage error, never a silent fallback (same
    // stance every other --via-accepting command holds).
    let via_flag = match parse_via_flag(inv) {
        Ok(v) => v,
        Err(e) => return Outcome::usage(cmd, format!("{usage} — {e}")),
    };
    let self_via_flag = inv.flags.get("self-via").cloned().filter(|s| !s.is_empty());

    let swept = match crate::discover::run_sweep(secs) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(cmd, crate::discover::describe_sweep_error(&e))
                .with_data(json!({ "reason": "sweep-failed" }))
        }
    };

    let hit = match crate::discover::resolve_invite_target(&swept.heard, target) {
        Ok(h) => h,
        Err(crate::discover::InviteResolveError::NoMatch { heard }) => {
            return Outcome::error(
                cmd,
                format!(
                    "heard no advertisement named `{target}` in {secs}s — heard: {}",
                    if heard.is_empty() { "(none)".to_string() } else { heard.join(", ") }
                ),
            )
            .with_data(json!({ "reason": "no-match", "name": target, "heard": heard }));
        }
        Err(crate::discover::InviteResolveError::Ambiguous { heard }) => {
            return Outcome::error(
                cmd,
                format!("heard multiple advertisements named `{target}` — ambiguous; heard: {}", heard.join(", ")),
            )
            .with_data(json!({ "reason": "ambiguous", "name": target, "heard": heard }));
        }
    };

    let own_name = aoide_storage::display::local_host_name();
    if crate::discover::is_self_target(&hit, &own_name) {
        return Outcome::error(
            cmd,
            format!(
                "`{}` resolves to this instance's own advertisement — refusing to pair with yourself",
                hit.advertisement.name
            ),
        )
        .with_data(json!({ "reason": "self-invite", "name": hit.advertisement.name, "srcAddr": hit.src_addr }));
    }

    if !inv.flag_present("yes") {
        match confirm_invite(&hit.advertisement.name, &hit.advertisement.host, &hit.advertisement.user, &hit.src_addr) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::ok(cmd, format!("not confirmed — nothing sent to `{}`", hit.advertisement.name))
                    .with_data(json!({ "confirmed": false, "name": hit.advertisement.name }))
            }
            Err(e) => return Outcome::error(cmd, e),
        }
    }

    let finish = match pair_finish_from(inv) {
        Ok(f) => f,
        Err(e) => return Outcome::usage(cmd, format!("{usage} — {e}")),
    };
    if let Some(out) = refuse_detached_grant(cmd, &finish) {
        return out;
    }
    if let Some(out) = refuse_code_on_new_request(cmd, &finish) {
        return out;
    }
    pair_with_heard(cmd, &hit, via_flag.as_ref(), self_via_flag.as_deref(), &finish)
}

/// The tail `pair`'s hostname arm ([`pair_via_hostname`]) and bare
/// `pair` share once a [`crate::discover::Heard`] target is settled (each
/// having already run its own guard/confirmation): compose the dial URL
/// from the hit's OBSERVED source address on the house door port
/// ([`default_a2a_port`] — the advertisement carries no door URL to read a
/// port off, by design), and run the SAME [`run_pair_request`] core the
/// url arm ([`pair_via_url`]) calls — reused, never forked.
///
/// P-PV1's settled default (task #131 — loopback-only doors, superseding
/// K1): the node this ceremony creates gets an automatic `via` derived from
/// the advertisement's OBSERVED source address plus its claimed ssh login
/// (task #120 — the one thing the wire exists to carry), so its own FUTURE
/// calls (pull/spawn/send) can reach it through an ssh tunnel — recorded at
/// `pair <id>` commit time, exactly as before. The SAME derived
/// default now ALSO rides the ceremony's OWN dial (`dial_via` below):
/// against a door that binds loopback-only, a direct dial to the observed
/// address never connects at all, so the ceremony itself needs the tunnel
/// too, not just the record it leaves behind. The one exception is an
/// advertisement with no ssh claim at all (`advertisement.user` empty) —
/// nothing to tunnel through, so the dial stays direct, exactly as before
/// P-PV1. An explicit `--via` beats this default outright, for both halves.
fn pair_with_heard(
    cmd: &str,
    hit: &crate::discover::Heard,
    via_flag: Option<&aoide_storage::tunnel::Via>,
    self_via_flag: Option<&str>,
    finish: &PairFinish,
) -> Outcome {
    let dial_url = format!("http://{}:{}/", hit.src_addr, default_a2a_port());
    let self_url = default_self_url();
    // `hit.src_addr` is the OBSERVED source address — the real dial target
    // this whole ceremony is already using, so it is also the right target
    // for `default_self_via`'s outbound-route trick.
    let self_via = self_via_flag.map(|s| s.to_string()).or_else(|| default_self_via(&hit.src_addr));
    let (dial_via, record_via) = resolve_pair_vias(hit, via_flag);
    run_pair_request(cmd, &dial_url, &hit.advertisement.name, &self_url, self_via.as_deref(), dial_via.as_ref(), record_via, &finish)
}

/// The pure decision [`pair_with_heard`] otherwise buries inline (P-PV1,
/// task #131) — split out so it is unit-testable with no dial, no tempdir,
/// no ssh: what `via` the ceremony's OWN two POSTs dial through, and what
/// `via` gets parked for LATER commit onto the resulting node record.
/// `record_via` is unconditional — the advertisement's observed address
/// plus its claimed login, string-rendered, exactly as it always has been,
/// even when that login is empty (`aoide_storage::tunnel::default_via`'s
/// own "empty user is absent, not refused" stance). `dial_via` rides the
/// SAME derived default too UNLESS the advertisement carried no ssh claim
/// at all (`hit.advertisement.user` empty) — nothing to tunnel through, so
/// the dial stays direct, exactly as it did before P-PV1. An explicit
/// `via_flag` beats both defaults outright, for both halves.
fn resolve_pair_vias(
    hit: &crate::discover::Heard,
    via_flag: Option<&aoide_storage::tunnel::Via>,
) -> (Option<aoide_storage::tunnel::Via>, Option<String>) {
    let default_via = aoide_storage::tunnel::default_via(&hit.src_addr, &hit.advertisement.user);
    let record_via = via_flag.map(|v| v.to_string()).or_else(|| Some(default_via.to_string()));
    let default_dial_via = (!hit.advertisement.user.is_empty()).then_some(default_via);
    let dial_via = via_flag.cloned().or(default_dial_via);
    (dial_via, record_via)
}

/// `node advertise on|off` (task #120): flip this instance's discovery
/// advertise switch (`aoide_storage::advertise::set_enabled`,
/// `state/advertise.json`). Idempotent, and says which of the two it was —
/// "flipped" names both states, "already" names the one it stays in. The
/// switch is READ by a running `a2a serve`'s advertise thread on every
/// tick (~30-40s), so no restart is involved — but no `a2a serve` running
/// means nothing is emitting either way, which the message teaches rather
/// than assumes.
fn handle_node_advertise(inv: &Invocation) -> Outcome {
    let cmd = "node.advertise";
    const USAGE: &str = "usage: aoide node advertise on|off";
    let on = match inv.args.first().map(|s| s.trim()) {
        Some("on") => true,
        Some("off") => false,
        _ => return Outcome::usage(cmd, USAGE),
    };
    let previous = match aoide_storage::advertise::set_enabled(on) {
        Ok(p) => p,
        Err(e) => {
            return Outcome::error(cmd, format!("writing the advertise switch: {e}"))
                .with_data(json!({ "reason": "switch-io-failed" }))
        }
    };
    let state = if on { "on" } else { "off" };
    let message = if previous == on {
        format!("discovery advertising already {state}")
    } else {
        format!(
            "discovery advertising: {} -> {state} — a running `a2a serve` picks this up within \
             ~40s; without one, nothing advertises either way",
            if previous { "on" } else { "off" }
        )
    };
    Outcome::ok(cmd, message).with_data(json!({ "enabled": on, "changed": previous != on }))
}

/// `node discover`/`node advertise` (P-P6 + task #120,
/// `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
/// section) — discovery is sugar OVER the ceremony `pair` owns, never a
/// parallel mechanism. `pair <hostname>`'s own hostname arm
/// ([`pair_via_hostname`], P-PV2) is the sugar-over-the-ceremony command —
/// `node invite` died in the same phase, hard cutover, no alias, and the
/// whole `node pair` family followed it in task #135 P3'.
pub fn register_node_discovery(r: &mut Registry) {
    r.insert(cmd!(
        path: ["node", "discover"],
        summary: "Listen for discovery advertisements on the LAN (UDP broadcast, fixed port) and print every distinct instance heard (name, claimed ssh hop user@host, and the observed source address) — read-only, never writes state/nodes.json.",
        args: [],
        flags: [flag!("secs", "int", "How many seconds to listen (default ~4).")],
        gated: false,
        implemented: true,
        handler: handle_node_discover,
    ));
    r.insert(cmd!(
        path: ["node", "advertise"],
        summary: "Switch this instance's discovery advertising on or off (state/advertise.json; default off) — a running a2a serve reads the switch every tick and emits name + ssh hop info only, never a door URL or key.",
        args: [arg!("state", "string", true, "`on` or `off`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_node_advertise,
        examples: ["node advertise on", "node advertise off"],
    ));
}

/// Bare `pair`'s sweep window (task #120 P3): one bounded listen, ~2s —
/// the same short window `node list`'s roster sweep settled on (a friendly
/// entry command should answer fast; a quiet LAN that needs longer has
/// `node discover --secs N`).
const PAIR_SWEEP_SECS: u64 = 2;

/// `aoide pair [<target>]` — the pairing ceremony's ONE entry point (task
/// #135 P3', the User's collapse: "the command set can just be aoide
/// pair"). No target: [`pair_overview`] — a menu on a real tty, the
/// pending listing anywhere else. A URL target: the explicit dial
/// ([`pair_via_url`], the scalpel, ungated). Anything else:
/// [`pair_continue_or_request`], the smart leg.
///
/// The arity guard is inherited from `node pair` (review finding, P-PV2
/// follow-up): a second positional is never valid syntax, and old
/// muscle-memory spellings (`pair request <url>`) must refuse loudly
/// rather than sweep for an advertiser literally named "request".
fn handle_pair(inv: &Invocation) -> Outcome {
    let cmd = "pair";
    const USAGE: &str = "usage: aoide pair [<name|url|id>] [--code NNN-NNN] [--wait SECS] [--allow read,spawn] [--yes] [--name <n>] [--via ssh://[user@]host[:port]] [--self-url <url>] [--self-via ssh://[user@]host] [--secs N] [--json] — bare `pair` lists pending requests (interactive menu on a tty); a target continues whatever leg of the ceremony already exists with it (approving an inbound request, resuming an outbound one), or starts a new request (a URL dials directly, anything else sweeps for an advertisement) and waits for the far approval";
    if inv.args.len() > 1 {
        return Outcome::usage(cmd, USAGE);
    }
    let Some(target) = inv.args.first().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return pair_overview(cmd, inv);
    };
    if target.contains("://") {
        return pair_via_url(cmd, inv, &target, USAGE);
    }
    pair_continue_or_request(cmd, inv, &target, USAGE)
}

/// `pair <target>` where the target is NOT a URL — one command, "make us
/// paired", routed by whatever half of a ceremony already exists with that
/// target. An exact pending-ID match wins over a name match, so an id
/// pasted from this command's own messages always lands; an inbound match
/// APPROVES (the old approve's inbound arm), an outbound match RESUMES
/// (poll → confirm → commit), and only when nothing is pending does this
/// become a NEW request (the hostname sweep arm), gated by
/// [`confirm_repair_if_verified`] when the name is already a verified node.
///
/// A hijack worry falls to the gate, not the routing: a stranger parking a
/// request under a known name only steers `pair <name>` into the
/// typed-code gate, where a code matching nothing commits nothing and
/// three mismatches auto-deny the stranger's own entry.
fn pair_continue_or_request(cmd: &str, inv: &Invocation, target: &str, usage: &str) -> Outcome {
    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap_or(0);
    let inbound = aoide_storage::pairing::list_inbound(now_epoch);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);

    if let Some(e) = inbound.iter().find(|e| e.id == target) {
        return approve_inbound_leg(cmd, inv, e.clone(), &now, now_epoch, usage);
    }
    if let Some(e) = outbound.iter().find(|e| e.id == target) {
        return resume_outbound_leg(cmd, inv, e.clone(), &now, now_epoch, usage);
    }

    let in_matches: Vec<&aoide_storage::pairing::InboundPairingRequest> = inbound.iter().filter(|e| e.name == target).collect();
    let out_matches: Vec<&aoide_storage::pairing::OutboundPairingRequest> = outbound.iter().filter(|e| e.name == target).collect();
    if in_matches.len() + out_matches.len() > 1 {
        let ids: Vec<&str> = in_matches.iter().map(|e| e.id.as_str()).chain(out_matches.iter().map(|e| e.id.as_str())).collect();
        return Outcome::usage(cmd, format!("multiple pending requests involve `{target}` — name one by id: {}", ids.join(", ")))
            .with_data(json!({ "reason": "ambiguous-target", "target": target, "ids": ids }));
    }
    if let Some(e) = in_matches.first() {
        return approve_inbound_leg(cmd, inv, (*e).clone(), &now, now_epoch, usage);
    }
    if let Some(e) = out_matches.first() {
        return resume_outbound_leg(cmd, inv, (*e).clone(), &now, now_epoch, usage);
    }

    if let Err(out) = confirm_repair_if_verified(cmd, inv, target) {
        return out;
    }
    pair_via_hostname(cmd, inv, target, usage)
}

/// The APPROVER's leg of `pair <target>` — gate selection verbatim from the
/// old `node pair approve` inbound arm ([`CodeGate`]): `--code`
/// scripted, a typed prompt on a real CLI tty, a taught refusal anywhere no
/// code can be collected. `--yes` deliberately maps to that refusal too —
/// it is never a bypass of the typed code, which is the gate that secures
/// the pair.
fn approve_inbound_leg(
    cmd: &str,
    inv: &Invocation,
    entry: aoide_storage::pairing::InboundPairingRequest,
    now: &str,
    now_epoch: i64,
    usage: &str,
) -> Outcome {
    let allow = match parse_allow_flag(inv) {
        Ok(a) => a,
        Err(e) => return Outcome::usage(cmd, format!("{usage} — {e}")),
    };
    let gate = match inv.flags.get("code").cloned().filter(|c| !c.trim().is_empty()) {
        Some(code) => CodeGate::Code(code),
        None if inv.flag_present("yes") => CodeGate::Unavailable,
        None if aoide_protocol::pick::interactive(inv.door) => CodeGate::Prompt,
        None => CodeGate::Unavailable,
    };
    let id = entry.id.clone();
    approve_inbound(gate, cmd, &id, entry, now, now_epoch, allow.as_deref())
}

/// The REQUESTER's leg of `pair <target>` on an entry this instance already
/// parked — the old outbound `node pair approve`, plus the wait: a nonzero
/// `--wait` blocks through [`wait_and_commit`] exactly as a fresh request
/// does, so "come back later" and "start one now" are the same command
/// either way. `--wait 0` is the scripted single-shot the old approve was:
/// one poll, commit if released, the park report if not — and unlike a NEW
/// request's `--wait 0`, `--allow` stays legal here because this leg can
/// commit.
fn resume_outbound_leg(
    cmd: &str,
    inv: &Invocation,
    entry: aoide_storage::pairing::OutboundPairingRequest,
    now: &str,
    now_epoch: i64,
    usage: &str,
) -> Outcome {
    let finish = match pair_finish_from(inv) {
        Ok(f) => f,
        Err(e) => return Outcome::usage(cmd, format!("{usage} — {e}")),
    };
    if finish.wait_secs == 0 {
        let id = entry.id.clone();
        return approve_outbound(outbound_gate_from(&finish), cmd, &id, entry, now, now_epoch, finish.grant.as_deref());
    }
    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let sas = aoide_storage::pairing::derive_sas(&kp.info().pubkey_hex, &entry.pubkey_hex, &entry.requester_nonce_hex, &entry.approver_nonce_hex);
    eprintln!(
        "resuming the pairing with `{}` (code {sas}) — waiting up to {}s; Ctrl-C leaves it pending as `{}`",
        entry.name, finish.wait_secs, entry.id
    );
    wait_and_commit(cmd, &entry.id, &entry.name, &sas, &finish)
}

/// `pair <name>` when `<name>` is ALREADY a verified node and no ceremony
/// is pending: under the smart command this is the thing an operator types
/// just to poke at a node, and a re-pair replaces key material — so it is
/// confirmed (interactive y/N; `--yes` scripted) rather than fired. Only
/// this NAME leg is gated: the explicit URL dial stays ungated, the
/// scalpel it always was, and `Err` here is the finished Outcome to return
/// (a decline is an Ok "nothing sent", not an error).
fn confirm_repair_if_verified(cmd: &str, inv: &Invocation, name: &str) -> Result<(), Outcome> {
    if !aoide_storage::node_store::load_nodes().iter().any(|p| p.name == name && p.verified) {
        return Ok(());
    }
    if inv.flag_present("yes") {
        return Ok(());
    }
    if !aoide_protocol::pick::interactive(inv.door) {
        return Err(Outcome::error(
            cmd,
            format!("`{name}` is already a verified node — re-pairing replaces its key material; re-run with --yes to proceed"),
        )
        .with_data(json!({ "reason": "already-paired", "name": name })));
    }
    match aoide_protocol::pick::confirm(&format!("`{name}` is already a verified node — re-pair (replaces its key material)?")) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Outcome::ok(cmd, "not re-paired — nothing sent").with_data(json!({ "confirmed": false, "name": name }))),
        Err(e) => Err(Outcome::error(cmd, e)),
    }
}

/// Bare `pair` — the ceremony's overview, shaped by the door. Non-tty,
/// `--json`, or a non-CLI door: [`pending_listing`], both directions — the
/// machine face agents drive (the old `node pending`, which died into
/// this). A real CLI tty: one menu over everything actionable — pending
/// requests first (pick one to approve or resume it), then a
/// [`PAIR_SWEEP_SECS`]s advertisement sweep's candidates (pick one to
/// request — the pick IS the proceed confirmation, so no second
/// `confirm_invite` y/N rides on top). Same facts either way; only the
/// door differs.
///
/// Row text renders only already-validated advertisement fields
/// (`advertise::parse_and_validate` gates every one — house rule 4) plus
/// the OBSERVED source address, claim and observation side by side. Own
/// advertisements are filtered up front (`discover::is_self_target`), so
/// the menu never offers a self-pair.
fn pair_overview(cmd: &str, inv: &Invocation) -> Outcome {
    if inv.flag_present("json") || !aoide_protocol::pick::interactive(inv.door) {
        return pending_listing(cmd);
    }
    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap_or(0);
    let inbound = aoide_storage::pairing::list_inbound(now_epoch);
    let outbound = aoide_storage::pairing::list_outbound(now_epoch);

    let swept = match crate::discover::run_sweep(PAIR_SWEEP_SECS) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(cmd, crate::discover::describe_sweep_error(&e))
                .with_data(json!({ "reason": "sweep-failed" }))
        }
    };
    let own_name = aoide_storage::display::local_host_name();
    let candidates: Vec<crate::discover::Heard> = swept
        .heard
        .into_iter()
        .filter(|h| !crate::discover::is_self_target(h, &own_name))
        .collect();

    if inbound.is_empty() && outbound.is_empty() && candidates.is_empty() {
        return Outcome::ok(
            cmd,
            format!(
                "nothing pending, and no advertising instances heard in {PAIR_SWEEP_SECS}s ({} malformed dropped) — on the OTHER box, \
                 switch advertising on with `aoide node advertise on` (a running `a2a serve` emits it within ~40s) \
                 and run `aoide pair` here again; or dial explicitly with \
                 `aoide pair <url> [--via ssh://[user@]host]`",
                swept.dropped
            ),
        )
        .with_data(json!({ "heard": 0, "dropped": swept.dropped }));
    }

    // Parallel row/action vectors: the row is what the operator reads, the
    // action is which leg the pick runs — kept side by side so they cannot
    // drift apart.
    enum Row {
        In(aoide_storage::pairing::InboundPairingRequest),
        Out(aoide_storage::pairing::OutboundPairingRequest),
        Heard(crate::discover::Heard),
    }
    let mut labels: Vec<String> = Vec::new();
    let mut actions: Vec<Row> = Vec::new();
    for e in inbound {
        let status = if e.approved {
            "approved; awaiting their poll"
        } else if e.requester_nonce_hex.is_some() {
            "awaiting your code"
        } else {
            "awaiting their reveal"
        };
        labels.push(format!("approve `{}` — inbound request {} ({status})", e.name, e.id));
        actions.push(Row::In(e));
    }
    for e in outbound {
        labels.push(format!("resume `{}` — outbound request {} ({})", e.name, e.id, e.state.as_str()));
        actions.push(Row::Out(e));
    }
    for h in candidates {
        labels.push(format!(
            "request `{}` — claims ssh {}@{}, observed at {}",
            h.advertisement.name, h.advertisement.user, h.advertisement.host, h.src_addr
        ));
        actions.push(Row::Heard(h));
    }

    match aoide_protocol::pick::choose("pair — which?", &labels, None) {
        None => Outcome::ok(cmd, "nothing chosen — nothing sent"),
        Some(i) => match actions.swap_remove(i) {
            Row::In(e) => approve_inbound_leg(cmd, inv, e, &now, now_epoch, "aoide pair"),
            Row::Out(e) => resume_outbound_leg(cmd, inv, e, &now, now_epoch, "aoide pair"),
            Row::Heard(h) => {
                if let Err(out) = confirm_repair_if_verified(cmd, inv, &h.advertisement.name) {
                    return out;
                }
                let finish = match pair_finish_from(inv) {
                    Ok(f) => f,
                    Err(e) => return Outcome::usage(cmd, e),
                };
                if let Some(out) = refuse_detached_grant(cmd, &finish) {
                    return out;
                }
                if let Some(out) = refuse_code_on_new_request(cmd, &finish) {
                    return out;
                }
                pair_with_heard(cmd, &h, None, None, &finish)
            }
        },
    }
}

/// The `pair` family — the pairing ceremony's whole CLI face (task #135
/// P3', superseding P-PV2's `node pair`/`node pending`/`node pair
/// approve|reject|watch`, which DIED in this collapse — hard cutover, no
/// aliases, the same way `node invite` died before them). The split it
/// leaves behind: `pair` MINTS verified node records; `node` operates on
/// the roster those records live in (list/allow/hub/spawn/add/discover/
/// advertise).
pub fn register_pair(r: &mut Registry) {
    r.insert(cmd!(
        path: ["pair"],
        summary: "Make this instance and a target paired — one command for the whole ceremony, routed by what already exists: a pending inbound request from the target is approved (typed pairing code; --code scripted), a pending outbound one is resumed (poll, then typed reply code; --code scripted), and nothing pending starts a new request (a URL dials directly, a name sweeps for its advertisement) then blocks up to --wait seconds for the far approval. Bare `pair` is the overview: an interactive menu over pending requests and heard advertisers on a real CLI tty, the pending listing (JSON-friendly) anywhere else.",
        args: [arg!("target", "string", false, "A node name/hostname, a pending request id, or a URL (e.g. http://host:8710/) to dial directly. Omitted: the overview/menu.")],
        flags: [
            flag!("code", "string", "The typed code, scripted: on an INBOUND request, the pairing code read from the requester's screen; on an OUTBOUND one, the reply code read from the approver's screen. A wrong code counts one persisted try; the 3rd cumulative mismatch auto-denies an inbound request or auto-aborts an outbound one."),
            flag!("wait", "int", "Seconds to block for the far operator (default 600). On a new request: park, then poll until approved or the wait runs out. On a resume: the same poll loop. --wait 0 parks a new request and returns immediately, or polls a resumed one exactly once."),
            flag!("allow", "string", "The capabilities this commit grants the node, comma-separated (read, spawn) — overriding config.toml's `[pairing] defaultGrant`, and empty (--allow \"\") to grant nothing. First verification only: re-pairing an already-verified node never re-grants, so use `node allow` to change a live grant."),
            flag!("yes", "bool", "Skip THIS side's own non-code confirmations — the sweep proceed prompt and the already-paired re-pair confirm. The final code gate, on either leg, still needs a real terminal prompt or --code; --yes alone there is a taught refusal, never a bypass."),
            flag!("name", "string", "URL target only: a local nickname for the other instance; defaults to a sanitized form of the URL's host."),
            flag!("via", "string", "An ssh://[user@]host[:port] transport marker — both the ceremony's own dial AND the resulting node's recorded via. Absent = direct dial."),
            flag!("self-url", "string", "This instance's own advertised A2A door URL, recorded on the far side's node record; defaults to http://<host>:<AOIDE_A2A_PORT or 8710>/."),
            flag!("self-via", "string", "This instance's own ssh://[user@]host reach-back hop claim, sent on the wire so an approver that only observes this request over a tunnel (loopback) can still record a working via; defaults to ssh://<local user>@<the local address routed toward the node>."),
            flag!("secs", "int", "Name target only: how many seconds to sweep for the advertisement (default 45)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_pair,
        examples: ["pair", "pair osaka", "pair osaka --code 839-035", "pair http://box:8710/ --wait 0"],
    ));
    r.insert(cmd!(
        path: ["pair", "reject"],
        summary: "Refuse (inbound) or abort (outbound) a pending pairing request, by id or by a name matching exactly one — a clean removal, no node record on either end, no wire call.",
        args: [arg!("target", "string", true, "The pending request's id, or a name matching exactly one pending request (see bare `pair`).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_pair_reject,
    ));
    r.insert(cmd!(
        path: ["pair", "watch"],
        summary: "Foreground, line-mode follow of the pairing-ceremony events feed (parked/revealed/awaiting-confirm) plus a 30s reconcile safety tick. --json emits one event object per line instead of narration. --popup (opt-in, aoide.a2a.pairingPopup) swaps the terminal narration for a typed-code entry dialog on each actionable request, either direction — lyra when it resolves, zenity otherwise — mutually exclusive with --json. CLI-only — blocks until Ctrl-C.",
        args: [],
        flags: [flag!(
            "popup",
            "bool",
            "Surface each actionable request as a typed-code entry dialog instead of terminal narration, either direction — lyra when it resolves, zenity otherwise. Requires one of the two on PATH. Mutually exclusive with --json."
        )],
        gated: false,
        implemented: true,
        handler: handle_pair_watch,
        examples: ["pair watch", "pair watch --json", "pair watch --popup"],
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

// ── `aoide mail` (messaging plan P-M1/P-M2, docs/architecture/MAIL.md) ─────

/// `aoide mail[.send|.read|.show|.mark|.rm|.outbox|.outbox.rm|.outbox.retry]`
/// commands.
/// Registered here, in `aoide-client`, rather than in `aoide-storage` where
/// the store itself ([`aoide_storage::mail`]/[`aoide_storage::outbox`])
/// lives: from P-M2 on, `mail send` can dial another node ([`crate::
/// mail_wire`]'s outbox drain), and `aoide-storage` sits below
/// `aoide-client` in the crate DAG and must not depend on it (P-M2
/// ruling 1). `mail outbox`/`mail outbox rm` are new at P-M2, `mail
/// outbox retry` is the un-park that makes a `refused` entry retriable
/// rather than a permanent verdict; `--hold`,
/// `mail route`, and mesh-aware addressing are later phases (MAIL.md
/// §Phases) and are not registered yet.
pub fn register_mail(r: &mut Registry) {
    r.insert(cmd!(
        path: ["mail"],
        summary: "Names with mail unread by this reader in this box's mailbase (state/mail/). This phase shows the names half only — the caller's own new letters is a later phase (P-M5).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mail_names,
        examples: ["mail"],
    ));
    r.insert(cmd!(
        path: ["mail", "send"],
        summary: "File a letter into the mailbase. --to self/<name> files locally — self never crosses the wire. --to <node>/<name> spools it into that (already verified/paired) node's outbox and makes one best-effort delivery attempt right away; this command reports the WRITE, never the delivery outcome — see `mail outbox` for that.",
        args: [arg!("text", "string", true, "The letter's text — put it after `--` so its own words/flags pass through verbatim.")],
        flags: [
            flag!("to", "string", "Recipient address, self/<name> or <node>/<name> (required). <node> must already be a verified node for anything but self. <name> is free text — a role name, never a session petname."),
            flag!("from", "string", "Sender attribution override (default: AOIDE_SESSION_ID). Attribution only, not authentication."),
            flag!("subject", "string", "Single-line subject; enables structured signed letter content."),
            flag!("thread", "string", "Existing thread ID (64 lowercase hex); omitted starts a fresh thread."),
            flag!("reply-to", "string", "Parent message ID (64 lowercase hex); requires --thread."),
            flag!("cc", "string", "Comma-separated node/mailbox recipients; each receives a signed copy. To may also be comma-separated with subject or cc."),
        ],
        gated: false,
        implemented: true,
        handler: handle_mail_send,
        examples: ["mail send --to self/conductor -- status?", "mail send --to yomi-strix/conductor -- build finished"],
    ));
    r.insert(cmd!(
        path: ["mail", "read"],
        summary: "Print unread letters and advance the reader's cursor. --for <name> reads one mailbox; --all-names reads every name with anything unread; --reread also reprints already-read entries for the name(s) selected (the cursor still only ever advances forward).",
        args: [],
        flags: [
            flag!("for", "string", "Read this mailbox name only. Mutually exclusive with --all-names."),
            flag!("all-names", "bool", "Read every name that has unread mail. Mutually exclusive with --for."),
            flag!("reread", "bool", "Also print already-read entries for the selected name(s)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_mail_read,
        examples: ["mail read --for conductor", "mail read --all-names"],
    ));
    r.insert(cmd!(
        path: ["mail", "show"],
        summary: "Print one entry by its exact msgid. Does not touch any cursor.",
        args: [arg!("msgid", "string", true, "The entry's msgid, as shown by `mail read`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mail_show,
        examples: ["mail show <msgid>"],
    ));
    r.insert(cmd!(
        path: ["mail", "mark"],
        summary: "Advance a mailbox's cursor to its latest entry without printing anything.",
        args: [],
        flags: [flag!("for", "string", "The mailbox name to mark (required).")],
        gated: false,
        implemented: true,
        handler: handle_mail_mark,
        examples: ["mail mark --for conductor"],
    ));
    r.insert(cmd!(
        path: ["mail", "rm"],
        summary: "Prune base.jsonl entries older than the given age. The only pruning there is — seen.jsonl (dedup memory) is never touched, so a pruned letter re-offered later is still recognised as a duplicate.",
        args: [],
        flags: [flag!("older-than", "string", "Age threshold, <N>d or <N>h (e.g. 30d, 12h). Required.")],
        gated: false,
        implemented: true,
        handler: handle_mail_rm,
        examples: ["mail rm --older-than 30d"],
    ));
    r.insert(cmd!(
        path: ["mail", "outbox"],
        summary: "List this box's own outbox: letters and acks spooled toward a node, not yet retired. Every listed entry is still waiting by definition (a retired entry is removed from the spool) — shows each one's own delivery bookkeeping (tries, last try, last outcome, refused).",
        args: [arg!("node", "string", false, "List only this node's outbox; omit to list every node with anything waiting.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mail_outbox,
        examples: ["mail outbox", "mail outbox yomi-strix"],
    ));
    r.insert(cmd!(
        path: ["mail", "outbox", "rm"],
        summary: "Explicitly retire one outbox entry by msgid, without waiting for a delivery ack. The only other way an entry retires is a destination-signed ack — the outbox itself is on the kill-list (no quota, no auto-eviction, no expiry).",
        args: [arg!("msgid", "string", true, "The entry's msgid, as shown by `mail outbox`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mail_outbox_rm,
        examples: ["mail outbox rm <msgid>"],
    ));
    r.insert(cmd!(
        path: ["mail", "outbox", "retry"],
        summary: "Un-park a refused outbox entry and attempt it once more, right away. `refused` is a PARKED state, not a kill-list: a policy refusal is remediable (the RECEIVING node grants `message` with `node allow <sender> message on`), so retry clears the flag — the stored signed envelope, the msgid and the try count all stay put — and drains that node once. `--refused` retries every parked entry for one node, or for every node with an outbox.",
        args: [arg!("msgid", "string", false, "The parked entry's msgid, as shown by `mail outbox`. Omitted with --refused. With --refused this positional is instead the node to sweep (omit for every node with an outbox).")],
        flags: [flag!("refused", "bool", "Retry every entry currently parked `refused` for the named node, or for every node with an outbox when no node is named.")],
        gated: false,
        implemented: true,
        handler: handle_mail_outbox_retry,
        examples: ["mail outbox retry <msgid>", "mail outbox retry --refused", "mail outbox retry --refused yomi-strix"],
    ));
}

/// The sender attribution for `mail send` — mirrors `aoide-conduct`'s own
/// `graph/send.rs::resolve_sender` shape (a tiny per-crate copy, not an
/// import: neither crate depends on the other). `--from` wins when
/// present, even empty (explicit anonymous, env fallback skipped on
/// purpose); otherwise `AOIDE_SESSION_ID` when non-empty. **Attribution
/// only, never authentication** — same caveat conduct's own copy
/// documents: any same-uid process can set either to anything.
fn mail_sender_attribution(inv: &Invocation) -> Option<String> {
    match inv.flags.get("from") {
        Some(f) if f.is_empty() => None,
        Some(f) => Some(f.replace(['\n', '\r'], " ")),
        None => std::env::var("AOIDE_SESSION_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.replace(['\n', '\r'], " ")),
    }
}

/// This process's own conducting session id, when set — the reader identity
/// [`aoide_storage::mail::read_for`]/[`aoide_storage::mail::read_all_names`]/
/// [`aoide_storage::mail::mark`]/[`aoide_storage::mail::names_with_unread`]
/// key a mark on. `None` outside a conducted session — the fallback to the
/// mailbox name itself is those functions' own, not this helper's, so an
/// unconducted caller still gets a real (pseudo-)reader with its own mark,
/// never a shared one.
fn mail_reader_session() -> Option<String> {
    std::env::var("AOIDE_SESSION_ID").ok().filter(|s| !s.is_empty())
}

/// A basic, fixed rendering frame for one entry (MAIL.md "Reading"): a
/// header line — msgid, from, mintedAt, mesh, via — then the text in a
/// fence. **Not the hardened P-M5 form**: no field clamping, no
/// backtick-length-adaptive fence (MAIL.md §Phases assigns "the reader
/// frame's field clamps and adaptive fence" to P-M5) — this only ever
/// renders entries already accepted into THIS box's own mailbase, never
/// raw wire input directly.
fn render_entry(e: &aoide_storage::mail::Entry) -> String {
    let h = &e.envelope.header;
    let mesh = if h.origin_mesh.is_empty() { "-" } else { h.origin_mesh.as_str() };
    format!(
        "msgid {}\nfrom {}/{}  mintedAt {}  mesh {}  via {}\n```\n{}\n```",
        e.envelope.msgid, h.from.node, h.from.name, h.minted_at, mesh, e.via, e.envelope.text
    )
}

/// `aoide mail [--json]` — bare listing: names with mail unread by this
/// reader (this process's own `AOIDE_SESSION_ID` via [`mail_reader_session`],
/// or the mailbox name itself outside a conducted session — that fallback
/// is `names_with_unread`'s own).
fn handle_mail_names(_inv: &Invocation) -> Outcome {
    let cmd = "mail";
    match aoide_storage::mail::names_with_unread(mail_reader_session().as_deref()) {
        Ok(names) => {
            let n = names.len();
            let body = if n == 0 { "no unread mail".to_string() } else { names.join("\n") };
            Outcome::ok(cmd, format!("{n} name{} with unread mail\n{body}", if n == 1 { "" } else { "s" }))
                .with_data(json!({ "names": names }))
        }
        Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
    }
}

/// A destination-signed ack for `msgid`, already sitting in `base` (THIS
/// box's own mailbase), claiming to be from `to_node` — the ONLY evidence
/// [`delivery_projection`] accepts for `status: "delivered"` (MAIL.md
/// "Status and the nodelist view": never inferred from the outbox entry's
/// own absence — `mail outbox rm` also removes it). Filing an entry whose
/// `header.from.node` names an external node is only ever reachable
/// through [`aoide_storage::mail::deposit`]'s own origin-signature check —
/// [`aoide_storage::mail::file_letter`]/`file_receipt` always stamp THIS
/// box's own name instead — so finding one here already carries that
/// proof; this never re-verifies it. `base` is a single
/// [`aoide_storage::mail::read_base`] shared across every entry a caller
/// projects (a `mail outbox` listing, or `mail send`'s post-spool read) —
/// hoisted there so this check never re-parses `base.jsonl` per entry; a
/// read failure degrades to an empty `base` (matching this check's own
/// former "no ack seen" default), never a propagated error.
fn has_delivered_ack(base: &[aoide_storage::mail::Entry], to_node: &str, msgid: &str) -> bool {
    base.iter().any(|e| {
        e.kind == aoide_storage::mail::ENTRY_TYPE_RECEIPT
            && e.envelope.header.from.node == to_node
            && e.envelope.text == msgid
    })
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// `data.delivery`'s fixed shape — every branch fills all five fields so a
/// caller never has to guess which are present for which status.
fn delivery_shape(status: &str, reason: Option<String>, scope: Option<&str>, next_attempt_at: Option<&str>, ack_pending: bool) -> Value {
    json!({
        "status": status,
        "reason": reason,
        "reasonScope": scope,
        "nextAttemptAt": next_attempt_at,
        "ackPending": ack_pending,
    })
}

/// `data.delivery`'s degraded fallback when a status READ itself fails —
/// distinct from every [`delivery_projection`] branch, which all assume
/// the entry/link were readable in the first place. Always `queued`: the
/// spool write already succeeded (`mail send`), or the entry is only being
/// LISTED, never written (`mail outbox`) — either way this failure is
/// about REPORTING, never about the mail itself, so calling it a durable
/// `failed` would be exactly the fabricated history the vocabulary rules
/// out.
fn delivery_status_unavailable(err: &str) -> Value {
    delivery_shape("queued", Some(format!("status unavailable: {err}")), Some("local"), None, false)
}

/// One outbox entry's delivery status, joined with its node's own link
/// state (MAIL.md "Outbox" / "Status and the nodelist view") — the ONE
/// projection both `mail send` (post-spool) and `mail outbox` render from,
/// so the two commands can never drift on what "queued"/"retrying"/etc.
/// mean. Vocabulary, in precedence order:
///
/// - `refused` (`entry.refused`) beats everything else outright —
///   automatic retries have already stopped for this one entry.
/// - `delivered`: a real, destination-signed ack already sits in this
///   box's own mailbase for this exact msgid ([`has_delivered_ack`]) —
///   stronger evidence than the entry's own bookkeeping, so it wins even
///   over a merely-`accepted` `last_outcome`. Normal operation never
///   actually reaches this combination: [`aoide_storage::outbox::
///   retire_by_ack`] removes the entry the instant that same ack lands
///   through the inbound door (`server::a2a::mail_deposit`); this only
///   fires if that removal step ever lags or fails and the entry is still
///   here to ask about.
/// - `accepted`: the peer's own deposit response said accepted/duplicate
///   (`entry.last_outcome`) but no ack has landed yet — `ackPending:
///   true`. A LATER, unrelated link failure rides beside it (reason and
///   `nextAttemptAt` from the link) without ever downgrading the status —
///   this entry already reached the peer; the link's later trouble is
///   about some other entry's dial, not this one's evidence.
/// - `retrying`: the node's link state file still exists — an unresolved
///   failure/backoff [`aoide_storage::outbox::clear_link_state`] hasn't
///   cleared yet.
/// - `queued`: none of the above — nothing has ever gone wrong, or
///   nothing has been attempted yet.
///
/// `base` is the caller's own single [`aoide_storage::mail::read_base`],
/// read once and reused across every entry the caller projects — never
/// re-read per entry here (see [`has_delivered_ack`]).
fn delivery_projection(
    base: &[aoide_storage::mail::Entry],
    node: &str,
    entry: &aoide_storage::outbox::OutboxEntry,
    link: Option<&aoide_storage::outbox::LinkState>,
) -> Value {
    if entry.refused {
        return delivery_shape("refused", non_empty(&entry.last_outcome), Some("entry"), None, false);
    }
    if has_delivered_ack(base, node, &entry.envelope.msgid) {
        return delivery_shape("delivered", None, None, None, false);
    }
    let accepted = matches!(entry.last_outcome.as_str(), "accepted" | "duplicate");
    if accepted {
        return match link {
            Some(l) => delivery_shape("accepted", non_empty(&l.last_outcome), Some("link"), Some(&l.next_attempt_at), true),
            None => delivery_shape("accepted", None, None, None, true),
        };
    }
    if let Some(l) = link {
        return delivery_shape("retrying", non_empty(&l.last_outcome), Some("link"), Some(&l.next_attempt_at), false);
    }
    delivery_shape("queued", None, None, None, false)
}

/// `mail send`'s own read of `data.delivery`, taken AFTER the best-effort
/// drain attempt below returns successfully (spec item 8: the write above
/// is already the report; this is additional, non-authoritative context).
/// Never invents `"delivered"` from an entry that has simply vanished (a
/// concurrent `mail outbox rm` racing this same command) — a missing
/// entry degrades to [`delivery_status_unavailable`], same as an outright
/// read error.
fn post_send_delivery(node: &str, msgid: &str) -> Value {
    let entries = match aoide_storage::outbox::list_entries(node) {
        Ok(es) => es,
        Err(e) => return delivery_status_unavailable(&e),
    };
    let Some(entry) = entries.iter().find(|e| e.envelope.msgid == msgid) else {
        return delivery_status_unavailable("entry no longer spooled");
    };
    let link = match aoide_storage::outbox::read_link_state(node) {
        Ok(l) => l,
        Err(e) => return delivery_status_unavailable(&e),
    };
    let base = aoide_storage::mail::read_base().unwrap_or_default();
    delivery_projection(&base, node, entry, link.as_ref())
}

/// `aoide mail send --to (self|<node>)/<name> [--from <who>] -- <text …> [--json]`.
/// `self` files locally with no wire ([`aoide_storage::mail::file_letter`]).
/// Any other `<node>` must already be a verified node — refused BEFORE
/// anything is spooled otherwise (`unknown-node`/`unpaired-node`). Once
/// verified, the entry is written to that node's outbox BEFORE any
/// delivery is attempted (spec item 8: "write is the report, delivery is
/// the spool's job") — a spooled write alone still reports `Ok`, even if
/// every following step fails. A best-effort [`crate::mail_wire::
/// drain_node`] follows, and `data.delivery` reports what it found —
/// [`delivery_projection`]'s shared vocabulary (also `mail outbox`'s own),
/// re-read from the outbox AFTER the drain rather than trusted from
/// before it, so a `mail send --json` caller never has to run a separate
/// `mail outbox` just to see whether the letter actually moved. A local
/// I/O failure IN THIS drain attempt itself (never "the remote node was
/// unreachable," which [`crate::mail_wire::drain_node`] already treats as
/// an ordinary recorded outcome) is the one case reported as `"failed"`.
fn handle_mail_send(inv: &Invocation) -> Outcome {
    if ["subject", "cc", "thread", "reply-to"].iter().any(|key| inv.flags.contains_key(*key)) {
        return crate::letter_send::send(inv, handle_mail_send);
    }
    let cmd = "mail.send";
    const USAGE: &str = "usage: aoide mail send --to (self|<node>)/<name> -- <text …>";
    let to = match inv.flags.get("to").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, USAGE),
    };
    let (node, name) = match to.split_once('/') {
        Some((n, rest)) if !n.is_empty() && !rest.is_empty() => (n, rest),
        _ => {
            return Outcome::usage(cmd, format!("`--to {to}` is not `<node>/<name>`"))
                .with_data(json!({ "reason": "bad-address", "to": to }));
        }
    };
    if !aoide_storage::node_store::valid_node_name(name) {
        return Outcome::error(cmd, "mailbox name must match ^[a-z0-9][a-z0-9-]*$")
            .with_data(json!({ "reason": "invalid-name" }));
    }
    if inv.args.is_empty() {
        return Outcome::usage(cmd, USAGE);
    }
    let text = inv.args.join(" ");
    let from = mail_sender_attribution(inv).unwrap_or_default();

    if node == "self" || node == aoide_storage::display::local_host_name() {
        return match aoide_storage::mail::file_letter(&from, name, &text) {
            Ok(entry) => {
                let mut data = serde_json::to_value(&entry).unwrap_or_default();
                // The doorbell (P-M5a-2, MAIL.md "Delivery and the
                // doorbell"): this crate cannot see `aoide-conduct` (the DAG
                // constraint `pkgs/aoide/crates/AGENTS.md` documents), so a
                // self-filed letter forwards `mail ring` through the
                // resident daemon rather than ringing in-process — the
                // daemon's own dispatch handler runs `aoide_conduct::graph::
                // mail_ring` under the SAME `.ring.lock` file any other
                // ringer takes. No daemon reachable (or this invocation is
                // itself already running INSIDE the daemon, `inv.door ==
                // Door::Daemon`, which `daemon_dispatch` always answers
                // `None` for) degrades to `"ring": "no-daemon"` — filing
                // still succeeded, so the outcome's own status stays Ok
                // either way; nothing rang, but nothing was lost either
                // (the next real ring trigger — another letter, or the
                // reader's own Stop hook — still finds the latch armed).
                let ring_inv = Invocation {
                    path: vec!["mail".to_string(), "ring".to_string()],
                    args: Vec::new(),
                    flags: {
                        let mut f = std::collections::BTreeMap::new();
                        f.insert("for".to_string(), name.to_string());
                        if let Some(reader) = mail_reader_session() {
                            f.insert("from".to_string(), reader);
                        }
                        f
                    },
                    door: inv.door,
                };
                let ring_value = match crate::daemon::daemon_dispatch(&ring_inv) {
                    None => json!("no-daemon"),
                    Some(out) if out.status == aoide_protocol::output::Status::Ok => {
                        out.data.unwrap_or(Value::Null)
                    }
                    Some(_) => json!("error"),
                };
                if let Some(obj) = data.as_object_mut() {
                    obj.insert("ring".to_string(), ring_value);
                }
                Outcome::ok(cmd, format!("filed to self/{name} (msgid {})", entry.envelope.msgid))
                    .changed(vec![format!("state/mail/base.jsonl: +1 letter to {name}")])
                    .with_data(data)
            }
            Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
        };
    }

    match aoide_storage::node_store::load_nodes().iter().find(|p| p.name == node) {
        Some(p) if p.verified => {}
        Some(_) => {
            return Outcome::error(
                cmd,
                format!(
                    "node `{node}` is registered but not paired — mail requires a VERIFIED node; \
                     pair first with `aoide pair <url> --name {node}`"
                ),
            )
            .with_data(json!({ "reason": "unpaired-node", "name": node }));
        }
        None => {
            return Outcome::error(cmd, format!("no node named `{node}`"))
                .with_data(json!({ "reason": "unknown-node", "name": node }));
        }
    }

    let envelope = match aoide_storage::mail::mint_outbound_letter(&from, node, name, &text) {
        Ok(e) => e,
        Err(e) => return Outcome::error(cmd, format!("state/mail: {e}")),
    };
    let msgid = envelope.msgid.clone();
    if let Err(e) = aoide_storage::outbox::write_entry(node, &aoide_storage::outbox::OutboxEntry::fresh(envelope.clone())) {
        return Outcome::error(cmd, format!("state/outbox: {e}"));
    }
    // Best-effort — this command already reported the WRITE above and
    // never lets a delivery outcome downgrade it (spec item 8). A dead
    // node, a policy refusal, anything at all: the entry stays spooled,
    // `data.delivery` below (and a later `mail outbox`) shows what
    // happened, and the daemon's own periodic drain (or the next `mail
    // send`/deposit from this node) tries again.
    let delivery = match crate::mail_wire::drain_node(node) {
        Ok(()) => post_send_delivery(node, &msgid),
        Err(e) => delivery_shape("failed", Some(e), Some("local"), None, false),
    };
    let mut data = serde_json::to_value(&envelope).unwrap_or_default();
    if let Some(obj) = data.as_object_mut() {
        obj.insert("delivery".to_string(), delivery);
    }

    Outcome::ok(cmd, format!("spooled to {node}/{name} (msgid {msgid})"))
        .changed(vec![format!("state/outbox/{node}/: +1 entry")])
        .with_data(data)
}

/// `aoide mail read (--for <name> | --all-names) [--reread] [--json]`.
fn handle_mail_read(inv: &Invocation) -> Outcome {
    let cmd = "mail.read";
    let reread = inv.flag_present("reread");
    let all_names = inv.flag_present("all-names");
    let for_name = inv.flags.get("for").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let reader = mail_reader_session();

    let result = match (&for_name, all_names) {
        (Some(_), true) => {
            return Outcome::usage(cmd, "usage: aoide mail read (--for <name> | --all-names) [--reread] — mutually exclusive")
        }
        (Some(name), false) => aoide_storage::mail::read_for(name, reread, reader.as_deref()),
        (None, true) => aoide_storage::mail::read_all_names(reread, reader.as_deref()),
        (None, false) => {
            return Outcome::usage(cmd, "usage: aoide mail read (--for <name> | --all-names) [--reread]")
        }
    };

    match result {
        Ok(entries) => {
            let n = entries.len();
            let body = if n == 0 {
                "nothing new".to_string()
            } else {
                entries.iter().map(render_entry).collect::<Vec<_>>().join("\n\n")
            };
            Outcome::ok(cmd, format!("{n} entr{}\n{body}", if n == 1 { "y" } else { "ies" }))
                .with_data(json!({ "entries": entries }))
        }
        Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
    }
}

/// `aoide mail show <msgid> [--json]`.
fn handle_mail_show(inv: &Invocation) -> Outcome {
    let cmd = "mail.show";
    let msgid = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, "usage: aoide mail show <msgid>"),
    };
    match aoide_storage::mail::show(msgid) {
        Ok(Some(entry)) => {
            Outcome::ok(cmd, render_entry(&entry)).with_data(serde_json::to_value(&entry).unwrap_or_default())
        }
        Ok(None) => Outcome::error(cmd, format!("no entry with msgid {msgid}"))
            .with_data(json!({ "reason": "not-found", "msgid": msgid })),
        Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
    }
}

/// `aoide mail mark --for <name> [--json]`.
fn handle_mail_mark(inv: &Invocation) -> Outcome {
    let cmd = "mail.mark";
    let name = match inv.flags.get("for").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, "usage: aoide mail mark --for <name>"),
    };
    match aoide_storage::mail::mark(name, mail_reader_session().as_deref()) {
        Ok(seq) => Outcome::ok(cmd, format!("{name}: cursor marked through seq {seq}"))
            .changed(vec![format!("state/mail/cursors.json: {name} -> {seq}")])
            .with_data(json!({ "name": name, "seq": seq })),
        Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
    }
}

/// `aoide mail rm --older-than <Nd|Nh> [--json]`.
fn handle_mail_rm(inv: &Invocation) -> Outcome {
    let cmd = "mail.rm";
    let raw = match inv.flags.get("older-than").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, "usage: aoide mail rm --older-than <Nd|Nh>"),
    };
    let secs = match aoide_storage::mail::parse_older_than(raw) {
        Some(s) => s,
        None => {
            return Outcome::usage(cmd, format!("`--older-than {raw}` is not `<N>d` or `<N>h` (e.g. 30d, 12h)"))
                .with_data(json!({ "reason": "bad-duration", "olderThan": raw }));
        }
    };
    match aoide_storage::mail::rm_older_than(secs) {
        Ok(n) => Outcome::ok(cmd, format!("{n} entr{} pruned", if n == 1 { "y" } else { "ies" }))
            .changed(vec![format!("state/mail/base.jsonl: {n} entries pruned")])
            .with_data(json!({ "pruned": n })),
        Err(e) => Outcome::error(cmd, format!("state/mail: {e}")),
    }
}

/// One node's `mail outbox --json` summary — depth, oldest `mintedAt` age,
/// a `tries` histogram, distinct `lastOutcome` counts, and how many entries
/// are parked `refused`. Computed straight off the same `entries` a node's
/// rows already carry, never a second `list_entries` read: the outbox
/// investigation's own point was that a flooded spool (16.5k duplicate
/// receipts sitting at `tries=0`) is invisible in the row-by-row listing
/// alone — a summary is the shape an operator actually needs to notice
/// that before it happens again.
fn outbox_node_summary(entries: &[aoide_storage::outbox::OutboxEntry]) -> Value {
    let depth = entries.len();
    let now = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc());
    let oldest_minted_at_age_secs = entries
        .iter()
        .filter_map(|e| aoide_storage::time::parse_iso_utc(&e.envelope.header.minted_at))
        .min()
        .zip(now)
        .map(|(oldest, now)| (now - oldest).max(0));
    let mut tries_histogram: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut last_outcome_counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut refused = 0u64;
    for e in entries {
        *tries_histogram.entry(e.tries.to_string()).or_insert(0) += 1;
        let outcome_key = if e.last_outcome.is_empty() { "(none)".to_string() } else { e.last_outcome.clone() };
        *last_outcome_counts.entry(outcome_key).or_insert(0) += 1;
        if e.refused {
            refused += 1;
        }
    }
    json!({
        "depth": depth,
        "oldestMintedAtAgeSecs": oldest_minted_at_age_secs,
        "tries": tries_histogram,
        "lastOutcomeCounts": last_outcome_counts,
        "refused": refused,
    })
}

/// `aoide mail outbox [<node>] [--json]` — every entry still waiting,
/// optionally filtered to one node. An unknown/empty node reports an empty
/// list, never an error — the same "absent is just nothing there yet"
/// stance [`aoide_storage::outbox::list_entries`] itself holds. Each row
/// carries `delivery` — [`delivery_projection`]'s join of the entry with
/// its OWN node's link state, read ONCE per node (never once per entry,
/// and never dialed at all: this command only ever reads, it drains
/// nothing). The mailbase [`has_delivered_ack`] needs is likewise read
/// ONCE for the whole listing, not once per node or per entry. A
/// link-state read failure for one node degrades just that node's rows to
/// `queued`/"status unavailable" ([`delivery_status_unavailable`]) rather
/// than failing the whole listing. `data.summary` adds
/// [`outbox_node_summary`]'s per-node depth/age/tries/outcome/refused
/// rollup beside the row-by-row `data.entries` — no new subcommand, the
/// same envelope, just a second field.
fn handle_mail_outbox(inv: &Invocation) -> Outcome {
    let cmd = "mail.outbox";
    let target = inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty());
    let nodes = match target {
        Some(n) => vec![n.to_string()],
        None => match aoide_storage::outbox::nodes_with_outbox() {
            Ok(ns) => ns,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        },
    };
    let base = aoide_storage::mail::read_base().unwrap_or_default();
    let mut rows: Vec<Value> = Vec::new();
    let mut summary = serde_json::Map::new();
    for node in &nodes {
        let entries = match aoide_storage::outbox::list_entries(node) {
            Ok(es) => es,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        };
        // Non-empty outboxes only, matching `nodes_with_outbox`'s own
        // no-arg-listing semantics (CONTRACTS.md delta point 3) — an
        // explicitly named but empty node gets no summary entry either,
        // so `summary`'s key set means the same thing whether it was
        // populated by a bare `mail outbox` sweep or a `mail outbox
        // <node>` narrowing.
        if !entries.is_empty() {
            summary.insert(node.clone(), outbox_node_summary(&entries));
        }
        let link = aoide_storage::outbox::read_link_state(node);
        for e in &entries {
            let to = &e.envelope.header.to;
            let delivery = match &link {
                Ok(l) => delivery_projection(&base, node, e, l.as_ref()),
                Err(err) => delivery_status_unavailable(err),
            };
            rows.push(json!({
                "node": node,
                "msgid": e.envelope.msgid,
                "to": format!("{}/{}", to.node, to.name),
                "tries": e.tries,
                "lastTryAt": e.last_try_at,
                "lastOutcome": e.last_outcome,
                "refused": e.refused,
                "delivery": delivery,
            }));
        }
    }
    let n = rows.len();
    let body = if n == 0 {
        "outbox empty — nothing waiting".to_string()
    } else {
        rows.iter()
            .map(|r| {
                let status = r["delivery"]["status"].as_str().unwrap_or("queued");
                let mut line = format!(
                    "{} -> {}  tries {}  {status}",
                    r["msgid"].as_str().unwrap_or(""),
                    r["to"].as_str().unwrap_or(""),
                    r["tries"],
                );
                if let Some(reason) = r["delivery"]["reason"].as_str() {
                    line.push_str(&format!("  reason {reason}"));
                }
                if let Some(next) = r["delivery"]["nextAttemptAt"].as_str() {
                    line.push_str(&format!("  nextAttemptAt {next}"));
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Outcome::ok(cmd, format!("{n} entr{} waiting\n{body}", if n == 1 { "y" } else { "ies" }))
        .with_data(json!({ "entries": rows, "summary": Value::Object(summary) }))
}

/// `aoide mail outbox rm <msgid> [--json]` — explicit retirement (spec item
/// 7's other half, beside a valid ack). Searches every node's spool for
/// `msgid`; in practice at most one holds it, since an entry always lives
/// under the exact node its own `to.node` named at spool time.
fn handle_mail_outbox_rm(inv: &Invocation) -> Outcome {
    let cmd = "mail.outbox.rm";
    let msgid = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return Outcome::usage(cmd, "usage: aoide mail outbox rm <msgid>"),
    };
    let nodes = match aoide_storage::outbox::nodes_with_outbox() {
        Ok(ns) => ns,
        Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
    };
    for node in &nodes {
        match aoide_storage::outbox::remove_entry(node, msgid) {
            Ok(true) => {
                return Outcome::ok(cmd, format!("removed {msgid} from {node}'s outbox"))
                    .changed(vec![format!("state/outbox/{node}/: -1 entry")])
                    .with_data(json!({ "node": node, "msgid": msgid }));
            }
            Ok(false) => continue,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        }
    }
    Outcome::error(cmd, format!("no outbox entry with msgid {msgid}"))
        .with_data(json!({ "reason": "not-found", "msgid": msgid }))
}

/// `aoide mail outbox retry <msgid> | --refused [<node>]` — the un-park.
/// **A policy refusal is a PARKED state, not a kill-list**: the `allows` set
/// that produced it is the RECEIVING node's record of the sender, so it is
/// remediable after the fact (`aoide node allow <sender> message on` run ON
/// THAT HOST) — and once it is, the parked entries must be able to move
/// without being re-minted (a fresh envelope would mint a fresh msgid and
/// defeat the far end's own dedup, `OutboxEntry`'s doc).
///
/// Both spellings un-park through [`aoide_storage::outbox::unpark_entry`]/
/// [`aoide_storage::outbox::unpark_refused`] and then call [`crate::mail_wire::
/// drain_node`] ONCE per affected node, so the operator sees the outcome now
/// instead of waiting up to a full daemon tick — `data` reports the same
/// [`delivery_projection`] vocabulary `mail send` reports after its own
/// best-effort drain ([`post_send_delivery`]), including the `"failed"`/
/// `"local"` shape when the drain itself hits a genuine local I/O error
/// (never for "the remote node was unreachable", which the drain records as
/// an ordinary link outcome).
///
/// `--refused` is the sweep: every currently parked entry for the named node,
/// or for every node with an outbox when no node is named. An entry that
/// vanishes mid-sweep (a concurrent `mail outbox rm`, or a real ack) simply
/// does not count, and neither spelling is an error when there is nothing
/// parked to retry — a redundant ask is a clean no-op, the same discipline
/// its `rm` sibling holds.
fn handle_mail_outbox_retry(inv: &Invocation) -> Outcome {
    const USAGE: &str = "usage: aoide mail outbox retry <msgid> | aoide mail outbox retry --refused [<node>]";
    let cmd = "mail.outbox.retry";
    let positional = inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()).map(str::to_string);
    if inv.flag_present("refused") {
        return retry_refused_entries(cmd, positional.as_deref());
    }
    let Some(msgid) = positional else {
        return Outcome::usage(cmd, USAGE);
    };
    let nodes = match aoide_storage::outbox::nodes_with_outbox() {
        Ok(ns) => ns,
        Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
    };
    for node in &nodes {
        // In practice at most one node holds `msgid` — an entry always lives
        // under the exact node its own `to.node` named at spool time — the
        // same walk `handle_mail_outbox_rm` does, for the same reason.
        let entries = match aoide_storage::outbox::list_entries(node) {
            Ok(es) => es,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        };
        let Some(entry) = entries.iter().find(|e| e.envelope.msgid == msgid) else { continue };
        if !entry.refused {
            return Outcome::ok(cmd, format!("{msgid} is not parked — a drain already attempts it"))
                .with_data(json!({ "reason": "not-refused", "node": node, "msgid": msgid }));
        }
        match aoide_storage::outbox::unpark_entry(node, &msgid) {
            Ok(true) => {}
            // Vanished between the read above and the un-park (a concurrent
            // rm or a real ack's own retirement) — nothing left to dial.
            Ok(false) => continue,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        }
        let delivery = match crate::mail_wire::drain_node(node) {
            Ok(()) => post_send_delivery(node, &msgid),
            Err(e) => delivery_shape("failed", Some(e), Some("local"), None, false),
        };
        return Outcome::ok(cmd, format!("un-parked {msgid} for {node} and attempted delivery"))
            .changed(vec![format!("state/outbox/{node}/{msgid}.json: refused -> false")])
            .with_data(json!({ "node": node, "msgid": msgid, "delivery": delivery }));
    }
    Outcome::error(cmd, format!("no outbox entry with msgid {msgid}"))
        .with_data(json!({ "reason": "not-found", "msgid": msgid }))
}

/// [`handle_mail_outbox_retry`]'s `--refused` half. `target` narrows the
/// sweep to one node (an unknown or empty node is an ordinary "nothing
/// parked", never an error — the same absent-is-nothing stance `mail outbox`
/// itself holds); `None` sweeps every node with an outbox.
fn retry_refused_entries(cmd: &str, target: Option<&str>) -> Outcome {
    let nodes = match target {
        Some(n) => vec![n.to_string()],
        None => match aoide_storage::outbox::nodes_with_outbox() {
            Ok(ns) => ns,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        },
    };
    let mut total = 0usize;
    let mut changed: Vec<String> = Vec::new();
    let mut per_node: Vec<Value> = Vec::new();
    for node in &nodes {
        // The parked set is read BEFORE the un-park so the report can say
        // which entries were retried, and whether a vanished one was a
        // receipt — whose own confirmed deposit IS its confirmation
        // (ruling 4), the one case an absence legitimately means delivered.
        let parked: Vec<(String, bool)> = match aoide_storage::outbox::list_entries(node) {
            Ok(es) => es
                .into_iter()
                .filter(|e| e.refused)
                .map(|e| (e.envelope.msgid, e.envelope.header.kind == aoide_storage::mail::ENTRY_TYPE_RECEIPT))
                .collect(),
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        };
        if parked.is_empty() {
            continue;
        }
        let unparked = match aoide_storage::outbox::unpark_refused(node) {
            Ok(n) => n,
            Err(e) => return Outcome::error(cmd, format!("state/outbox: {e}")),
        };
        let drain = crate::mail_wire::drain_node(node);
        // ONE post-drain read for the whole node, never one per entry — the
        // same single-read discipline `handle_mail_outbox` holds.
        let after = aoide_storage::outbox::list_entries(node);
        let mut rows: Vec<Value> = Vec::new();
        for (msgid, was_receipt) in &parked {
            let delivery = match &drain {
                Err(e) => delivery_shape("failed", Some(e.clone()), Some("local"), None, false),
                Ok(()) => match &after {
                    Ok(now) if now.iter().any(|e| e.envelope.msgid == *msgid) => post_send_delivery(node, msgid),
                    // Gone from the spool: a receipt's own successful deposit
                    // removes it outright, so that IS delivery; a letter is
                    // only ever removed by a concurrent `mail outbox rm` or a
                    // real ack, and neither is something to read from an
                    // absence (the same rule `post_send_delivery` holds).
                    Ok(_) if *was_receipt => delivery_shape("delivered", None, None, None, false),
                    Ok(_) => delivery_status_unavailable("entry no longer spooled"),
                    Err(e) => delivery_status_unavailable(e),
                },
            };
            rows.push(json!({ "msgid": msgid, "delivery": delivery }));
        }
        total += unparked;
        changed.push(format!("state/outbox/{node}/: {unparked} entr{} un-parked", if unparked == 1 { "y" } else { "ies" }));
        per_node.push(json!({ "node": node, "unparked": unparked, "retries": rows }));
    }
    if total == 0 {
        return Outcome::ok(cmd, "nothing parked — no refused outbox entries to retry")
            .with_data(json!({ "unparked": 0, "nodes": [] }));
    }
    let body = per_node
        .iter()
        .map(|n| {
            format!(
                "{}: {} entr{} un-parked, drain attempted",
                n["node"].as_str().unwrap_or(""),
                n["unparked"],
                if n["unparked"] == 1 { "y" } else { "ies" }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Outcome::ok(cmd, format!("{total} entr{} un-parked\n{body}", if total == 1 { "y" } else { "ies" }))
        .changed(changed)
        .with_data(json!({ "unparked": total, "nodes": per_node }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_node(bearer_secret: Option<&str>) -> aoide_storage::node_store::Node {
        aoide_storage::node_store::Node {
            name: "yomi-strix".to_string(),
            url: "http://yomi-strix:8710/".to_string(),
            autogate: false,
            token_file: None,
            bearer_secret: bearer_secret.map(str::to_string),
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-08-24T00:00:00Z".to_string(),
        }
    }

    // ── `resolve_pair_vias` (P-PV1, task #131) — pure, no dial, no tempdir,
    // ── so this seam is unit-testable directly, unlike `pair_with_heard`
    // ── itself (needs a live ssh + a live door to actually dial). ─────────

    fn heard_with_login(src_addr: &str, user: &str) -> crate::discover::Heard {
        crate::discover::Heard {
            advertisement: aoide_storage::advertise::build("box-a", "box-a", user),
            src_addr: src_addr.to_string(),
            first_heard: "T0".to_string(),
            last_heard: "T0".to_string(),
            count: 1,
        }
    }

    #[test]
    fn resolve_pair_vias_dial_rides_the_derived_default_when_the_ad_claims_a_login() {
        let hit = heard_with_login("10.0.0.5", "khoa");
        let (dial_via, record_via) = resolve_pair_vias(&hit, None);
        assert_eq!(dial_via.map(|v| v.to_string()), Some("ssh://khoa@10.0.0.5".to_string()), "the ceremony's OWN dial now rides the same derived default the record always got");
        assert_eq!(record_via, Some("ssh://khoa@10.0.0.5".to_string()));
    }

    #[test]
    fn resolve_pair_vias_keeps_a_direct_dial_when_the_ad_claims_no_login() {
        let hit = heard_with_login("10.0.0.5", "");
        let (dial_via, record_via) = resolve_pair_vias(&hit, None);
        assert!(dial_via.is_none(), "no ssh claim at all — nothing to tunnel through, dial stays direct exactly as before P-PV1");
        assert_eq!(record_via, Some("ssh://10.0.0.5".to_string()), "record_via is unconditional and unchanged by P-PV1 — still derived even with no claimed login");
    }

    #[test]
    fn resolve_pair_vias_an_explicit_via_beats_the_derived_default_for_both_halves() {
        let hit = heard_with_login("10.0.0.5", "khoa");
        let explicit = aoide_storage::tunnel::parse_via("ssh://other@elsewhere:2222").unwrap();
        let (dial_via, record_via) = resolve_pair_vias(&hit, Some(&explicit));
        assert_eq!(dial_via.map(|v| v.to_string()), Some("ssh://other@elsewhere:2222".to_string()));
        assert_eq!(record_via, Some("ssh://other@elsewhere:2222".to_string()));
    }

    #[test]
    fn port_from_url_extracts_the_authoritys_own_port_or_none() {
        assert_eq!(port_from_url("http://box-a:9999/"), Some(9999));
        assert_eq!(port_from_url("http://10.0.0.5:8710/aoide/pairRequest"), Some(8710));
        assert_eq!(port_from_url("http://box-a/"), None, "no :port segment at all — a caller's fallback case, never a guessed port");
        assert_eq!(port_from_url("not-a-url"), None);
        assert_eq!(port_from_url("http://box-a:not-a-number/"), None);
    }

    /// Review finding (high): `default_self_via`'s HOST half must be the
    /// local outbound address toward the node, never a claimed OS
    /// hostname (a LAN check found hostnames resolving only through the
    /// router's DHCP-DNS — resolution by luck). Dialing `127.0.0.1`
    /// deterministically routes back to `127.0.0.1` on any box, with no
    /// real network involved (a UDP `connect` never sends a packet) — the
    /// same reasoning `outbound_ip_toward`'s own doc gives.
    #[test]
    fn outbound_ip_toward_resolves_to_loopback_when_dialing_127_0_0_1() {
        assert_eq!(outbound_ip_toward("127.0.0.1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(outbound_ip_toward("127.0.0.1:9999"), Some("127.0.0.1".parse().unwrap()), "an explicit port in `toward` is honored, never overridden");
    }

    /// `default_self_via`'s own claim-formatting (`ssh://<login>@<host>`),
    /// pinned deterministically: `$USER` is stamped to a known value and
    /// `toward` is loopback, so the HOST half resolves the same way
    /// [`outbound_ip_toward_resolves_to_loopback_when_dialing_127_0_0_1`]
    /// above already proved it does, with no real network involved either
    /// way.
    #[test]
    fn default_self_via_formats_login_at_the_outbound_address_toward_the_node() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_user = std::env::var("USER").ok();
        let saved_logname = std::env::var("LOGNAME").ok();
        std::env::set_var("USER", "testuser");
        std::env::remove_var("LOGNAME");

        assert_eq!(default_self_via("127.0.0.1").as_deref(), Some("ssh://testuser@127.0.0.1"));

        std::env::remove_var("USER");
        std::env::remove_var("LOGNAME");
        assert_eq!(default_self_via("127.0.0.1"), None, "no $USER/$LOGNAME at all — refuse rather than guess a login, same as resolve_login's own stance");

        match saved_user {
            Some(v) => std::env::set_var("USER", v),
            None => std::env::remove_var("USER"),
        }
        match saved_logname {
            Some(v) => std::env::set_var("LOGNAME", v),
            None => std::env::remove_var("LOGNAME"),
        }
    }

    // ── `handle_node_allow` (P-P3) — pure file I/O, so unlike most `node`
    // ── commands (network-touching, tested at `cli/tests/node_connectivity.rs`'s
    // ── `#[ignore]`'d integration layer) this one is directly unit-testable,
    // ── same reasoning `handle_node_hub`'s own storage-layer tests already
    // ── rest on. ─────────────────────────────────────────────────────────────

    /// `AOIDE_ROOT` and `AOIDE_CONFIG` are sandboxed alongside the state dir
    /// because a pairing commit now resolves its grant from `config.toml`
    /// (`resolve_grant`): left alone, these tests would read the developer's
    /// own `~/.aoide/config.toml` and go red on a machine whose operator had
    /// widened `defaultGrant` — or on a malformed file that has nothing to do
    /// with the code under test. Inside the sandbox the file is absent, so
    /// every `grant: None` path resolves the built-in `["read"]`.
    fn with_node_state<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_root = std::env::var("AOIDE_ROOT").ok();
        let saved_config = std::env::var("AOIDE_CONFIG").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-node-allow-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", &dir);
        std::env::set_var("AOIDE_ROOT", &dir);
        std::env::remove_var("AOIDE_CONFIG");
        let out = f();
        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_root {
            Some(v) => std::env::set_var("AOIDE_ROOT", v),
            None => std::env::remove_var("AOIDE_ROOT"),
        }
        match saved_config {
            Some(v) => std::env::set_var("AOIDE_CONFIG", v),
            None => std::env::remove_var("AOIDE_CONFIG"),
        }
        out
    }

    fn allow_inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["node".to_string(), "allow".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn node_allow_enables_and_disables_idempotently_and_reports_exactly_what_changed() {
        with_node_state("toggle", || {
            aoide_storage::node_store::save_nodes(&[fixture_node(None)]).unwrap();

            let on = handle_node_allow(&allow_inv(&["yomi-strix", "spawn", "on"]));
            assert_eq!(on.status, aoide_protocol::output::Status::Ok, "{on:?}");
            assert!(!on.changed.is_empty());
            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes[0].allows, vec!["spawn".to_string()]);

            // Re-enabling is a reported no-op — nothing written, nothing duplicated.
            let on_again = handle_node_allow(&allow_inv(&["yomi-strix", "spawn", "on"]));
            assert_eq!(on_again.status, aoide_protocol::output::Status::Ok);
            assert!(on_again.changed.is_empty(), "a no-op never touches disk");

            let off = handle_node_allow(&allow_inv(&["yomi-strix", "spawn", "off"]));
            assert_eq!(off.status, aoide_protocol::output::Status::Ok, "{off:?}");
            assert!(aoide_storage::node_store::load_nodes()[0].allows.is_empty());

            let off_again = handle_node_allow(&allow_inv(&["yomi-strix", "spawn", "off"]));
            assert!(off_again.changed.is_empty(), "disabling an already-absent cap is also a no-op");
        });
    }

    // ── `sign_headers_for_node` (P-P4) — outbound signing. ───────────────────

    #[test]
    fn sign_headers_for_node_is_empty_for_an_unverified_node() {
        with_node_state("sign-unverified", || {
            let node = fixture_node(None);
            assert!(!node.verified);
            let headers = sign_headers_for_node(&node, "{}").unwrap();
            assert!(headers.is_empty(), "an unpaired/unverified node gets no signature headers: {headers:?}");
        });
    }

    #[test]
    fn sign_headers_for_node_round_trips_a_genuine_signature_for_a_verified_node() {
        with_node_state("sign-verified", || {
            let info = aoide_storage::identity::load_or_mint().unwrap().0.info();
            let mut node = fixture_node(None);
            node.verified = true;
            let body = r#"{"jsonrpc":"2.0","method":"message/send"}"#;
            let headers = sign_headers_for_node(&node, body).unwrap();

            let get = |name: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| panic!("missing header {name}: {headers:?}"))
            };
            assert_eq!(get(aoide_storage::wire_auth::HEADER_NODE), aoide_storage::display::local_host_name());
            let timestamp = get(aoide_storage::wire_auth::HEADER_TIMESTAMP);
            let nonce = get(aoide_storage::wire_auth::HEADER_NONCE);
            let signature = get(aoide_storage::wire_auth::HEADER_SIGNATURE);
            assert!(aoide_storage::time::parse_iso_utc(&timestamp).is_some(), "a parseable timestamp: {timestamp}");
            assert!(!nonce.is_empty());

            // The server verifies against the SAME path this instance's own
            // `node_store::url_path` derives from `node.url` — recomputing it
            // here, rather than hardcoding "/", proves the client and server
            // sides stay bound to the one shared function. Same reasoning for
            // `HTTP_METHOD` (P-P4 review finding 2) over a second `"POST"`
            // literal.
            let path = aoide_storage::node_store::url_path(&node.url);
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
    fn sign_headers_for_node_sends_this_instances_own_self_name_not_the_node_nickname() {
        // Live yomi<->sakaki defect, 2026-08-26: e78999f fixed the pairing
        // wire name (`run_pair_request`) but left THIS header sending
        // `node.name` — this instance's local nickname for the counterpart
        // — instead of its own self name, so the far end's
        // `verify_signed_request` lookup (`nodes.iter().find(|p| p.name ==
        // node_name)`) failed with "unknown node" for every signed request
        // after an otherwise-successful pair. `fixture_node`'s name
        // ("yomi-strix") deliberately stands in for "this side's nickname
        // for the counterpart," distinct from whatever this test process's
        // own `local_host_name()` resolves to, so a regression back to
        // `node.name.clone()` fails this assertion.
        with_node_state("sign-self-name", || {
            let mut node = fixture_node(None);
            node.name = "this-sides-nickname-for-the-approver".to_string();
            node.verified = true;
            let headers = sign_headers_for_node(&node, "{}").unwrap();
            let sent = headers
                .iter()
                .find(|(k, _)| k == aoide_storage::wire_auth::HEADER_NODE)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("missing {}: {headers:?}", aoide_storage::wire_auth::HEADER_NODE));
            assert_eq!(sent, aoide_storage::display::local_host_name(), "must carry this instance's own self name");
            assert_ne!(sent, node.name, "must never carry the local nickname for the counterpart");
        });
    }

    #[test]
    fn node_allow_refuses_an_unknown_node_or_an_unknown_capability() {
        with_node_state("refusals", || {
            aoide_storage::node_store::save_nodes(&[fixture_node(None)]).unwrap();

            let unknown_node = handle_node_allow(&allow_inv(&["ghost", "spawn", "on"]));
            assert_eq!(unknown_node.status, aoide_protocol::output::Status::Error);
            assert_eq!(
                unknown_node.data.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()),
                Some("unknown-node")
            );

            let unknown_cap = handle_node_allow(&allow_inv(&["yomi-strix", "write", "on"]));
            assert_eq!(unknown_cap.status, aoide_protocol::output::Status::Error);
            assert!(unknown_cap.message.contains("read"), "names the valid set: {}", unknown_cap.message);
            assert!(unknown_cap.message.contains("spawn"), "names the valid set: {}", unknown_cap.message);
            assert_eq!(
                unknown_cap.data.as_ref().and_then(|d| d.get("reason")).and_then(|v| v.as_str()),
                Some("unknown-capability")
            );

            assert!(aoide_storage::node_store::load_nodes()[0].allows.is_empty(), "no refusal mutates the registry");
        });
    }

    #[test]
    fn node_allow_reports_usage_on_a_missing_or_malformed_on_off_argument() {
        with_node_state("usage", || {
            assert_eq!(handle_node_allow(&allow_inv(&[])).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_node_allow(&allow_inv(&["yomi-strix"])).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_node_allow(&allow_inv(&["yomi-strix", "spawn"])).status, aoide_protocol::output::Status::Usage);
            assert_eq!(
                handle_node_allow(&allow_inv(&["yomi-strix", "spawn", "maybe"])).status,
                aoide_protocol::output::Status::Usage
            );
        });
    }

    // ── `handle_node_spawn` (P-P5b) — the local refusal shapes are pure file
    // ── I/O (unpaired/unknown), so unit-testable directly; the real signed
    // ── network round trip lives at `cli/tests/node_connectivity.rs`'s
    // ── `#[ignore]`'d integration layer, same split `node allow`'s own
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
            path: vec!["node".to_string(), "spawn".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags,
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn node_spawn_refuses_an_unknown_node_naming_pair_request() {
        with_node_state("spawn-unknown", || {
            let out = handle_node_spawn(&spawn_inv(&["nosuchnode", "hello"], true));
            assert_eq!(out.status, aoide_protocol::output::Status::Error);
            assert_eq!(out.data.as_ref().unwrap()["reason"], "unknown-node");
            assert!(
                out.message.contains("aoide pair"),
                "taught error must name the pairing ceremony: {}",
                out.message
            );
        });
    }

    #[test]
    fn node_spawn_refuses_a_registered_but_unpaired_node_naming_pair_request() {
        with_node_state("spawn-unpaired", || {
            // `verified: false` — registered via the legacy `node add` escape,
            // never paired. An unsigned request from this node could never
            // satisfy the remote door's `NodeRung::Signature`-only spawn gate
            // (P-P4) — refused LOCALLY with a clear reason, never sent.
            aoide_storage::node_store::save_nodes(&[fixture_node(None)]).unwrap();
            let out = handle_node_spawn(&spawn_inv(&["yomi-strix", "hello"], true));
            assert_eq!(out.status, aoide_protocol::output::Status::Error);
            assert_eq!(out.data.as_ref().unwrap()["reason"], "unpaired-node");
            assert!(
                out.message.contains("aoide pair"),
                "taught error must name the pairing ceremony: {}",
                out.message
            );
        });
    }

    #[test]
    fn node_spawn_reports_usage_on_a_missing_name_or_empty_text() {
        with_node_state("spawn-usage", || {
            assert_eq!(handle_node_spawn(&spawn_inv(&[], true)).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_node_spawn(&spawn_inv(&["yomi-strix"], true)).status, aoide_protocol::output::Status::Usage);
            assert_eq!(handle_node_spawn(&spawn_inv(&["yomi-strix", "  "], true)).status, aoide_protocol::output::Status::Usage);
        });
    }

    #[test]
    fn node_spawn_signs_the_exact_spawn_shaped_body_it_would_send() {
        // "signs it (headers present)" — the FIRST production caller that
        // ever signs a `context_id: None` (spawn-shaped) POST. Reuses
        // `sign_headers_for_node` directly against the SAME body
        // `handle_node_spawn` builds (`crate::wire::build_message_send_body`
        // with `None`), rather than re-guessing the shape.
        with_node_state("spawn-signs", || {
            let mut node = fixture_node(None);
            node.verified = true;
            let body = crate::wire::build_message_send_body("do the thing", &gen_message_id(), None);
            assert!(body["params"]["message"].get("contextId").is_none(), "spawn-shaped body carries no contextId");
            let body_str = serde_json::to_string(&body).unwrap();
            let headers = sign_headers_for_node(&node, &body_str).unwrap();
            assert_eq!(headers.len(), 4, "all four X-Aoide-* headers present: {headers:?}");
            for name in [
                aoide_storage::wire_auth::HEADER_NODE,
                aoide_storage::wire_auth::HEADER_TIMESTAMP,
                aoide_storage::wire_auth::HEADER_NONCE,
                aoide_storage::wire_auth::HEADER_SIGNATURE,
            ] {
                assert!(headers.iter().any(|(k, _)| k == name), "missing {name}: {headers:?}");
            }
        });
    }

    // ── resolve_node_bearer — the no-secret-configured short circuit ────────
    //
    // This is the one branch testable with NO broker/socket at all: an
    // unconfigured node never even tries to connect. Every OTHER branch
    // (a real resolve, a broker-down failure) is exercised end-to-end in
    // `cli/tests/node_connectivity.rs`, mirroring how every other `node`
    // command in this file is tested at that integration layer rather than
    // here (this module carried zero unit tests before this task).

    #[test]
    fn resolve_node_bearer_is_none_when_unset() {
        assert_eq!(resolve_node_bearer(&fixture_node(None)).unwrap(), None);
    }

    #[test]
    fn resolve_node_bearer_is_none_when_set_to_an_empty_string() {
        assert_eq!(resolve_node_bearer(&fixture_node(Some(""))).unwrap(), None);
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

    // ── `node discover` — discovery grants nothing (P-P6). ───────────────────
    //
    // `run_sweep` needs a real socket (a plain fixed-port bind — no group
    // join since the #106 broadcast fix, so this runs everywhere, the nix
    // build sandbox included), but it does NOT need a real ADVERTISEMENT
    // to prove the one invariant that matters here: a 1s sweep that hears
    // nothing still must leave `state/nodes.json` byte-identical to what
    // it was before. The genuine heard-a-real-advertisement path is
    // `discover::tests::run_sweep_hears_an_advertisement_sent_over_the_
    // real_loopback_stack` plus `cli/tests/discovery_connectivity.rs`'s
    // `#[ignore]`'d real-network tests.

    fn discover_inv(secs: &str) -> Invocation {
        Invocation {
            path: vec!["node".to_string(), "discover".to_string()],
            args: vec![],
            flags: [("secs".to_string(), secs.to_string())].into_iter().collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn node_discover_never_writes_nodes_json_even_on_an_empty_sweep() {
        with_node_state("discover-no-write", || {
            // A pre-existing node record must survive `node discover`
            // completely untouched — the clearest possible proof discover
            // never took a write path into `state/nodes.json` at all.
            aoide_storage::node_store::save_nodes(&[fixture_node(None)]).unwrap();
            let before = aoide_storage::node_store::load_nodes();

            let out = handle_node_discover(&discover_inv("1"));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let after = aoide_storage::node_store::load_nodes();
            assert_eq!(before.len(), after.len());
            assert_eq!(before[0].name, after[0].name);
            assert_eq!(before[0].verified, after[0].verified);
            assert_eq!(before[0].added_at, after[0].added_at);
        });
    }

    #[test]
    fn node_discover_never_writes_nodes_json_from_an_entirely_empty_registry() {
        with_node_state("discover-no-write-empty", || {
            let out = handle_node_discover(&discover_inv("1"));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert!(
                aoide_storage::node_store::load_nodes().is_empty(),
                "discover must never create state/nodes.json out of nothing"
            );
        });
    }

    // ── `node advertise on|off` (task #120) — the runtime switch, default
    // ── off, idempotent, reporting exactly what changed. ─────────────────────

    fn advertise_inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["node".to_string(), "advertise".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn node_advertise_flips_the_switch_idempotently_and_reports_exactly_what_changed() {
        with_node_state("advertise-toggle", || {
            assert!(!aoide_storage::advertise::enabled(), "default posture is OFF");

            let on = handle_node_advertise(&advertise_inv(&["on"]));
            assert_eq!(on.status, aoide_protocol::output::Status::Ok, "{on:?}");
            assert_eq!(on.data.as_ref().unwrap()["changed"], true, "{on:?}");
            assert!(aoide_storage::advertise::enabled());

            let again = handle_node_advertise(&advertise_inv(&["on"]));
            assert_eq!(again.status, aoide_protocol::output::Status::Ok, "{again:?}");
            assert_eq!(again.data.as_ref().unwrap()["changed"], false, "{again:?}");
            assert!(again.message.contains("already on"), "{}", again.message);

            let off = handle_node_advertise(&advertise_inv(&["off"]));
            assert_eq!(off.data.as_ref().unwrap()["changed"], true, "{off:?}");
            assert!(!aoide_storage::advertise::enabled());
        });
    }

    #[test]
    fn node_advertise_refuses_anything_but_on_or_off() {
        // Pure arg validation — refused before any state file is touched,
        // so no temp dir is needed.
        for bad in [&[][..], &["maybe"][..], &["ON"][..]] {
            let out = handle_node_advertise(&advertise_inv(bad));
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
        }
    }

    // ── `pair`'s hostname arm bottoms out in the exact same
    // ── `run_pair_request` its url arm runs (P-PV2) — proven directly by
    // ── calling it through both entry points against the SAME unreachable
    // ── door and asserting byte-identical outcomes, rather than trusting
    // ── that the two arms merely look alike. The genuine end-to-end proof
    // ── (a real discovered advertisement resolving to a real second door that
    // ── actually parks an outbound pairing request) lives in `cli/tests/
    // ── discovery_connectivity.rs`'s `#[ignore]`'d real-network test —
    // ── this one needs no network at all, since an unreachable loopback
    // ── port fails identically (and fast) through either call site. ─────────

    #[test]
    fn node_pair_hostname_arm_and_url_arm_are_the_same_function_not_two_copies() {
        with_node_state("hostname-arm-shares-run-pair-request", || {
            // Port 1 is reserved and never listened on in practice — an
            // immediate, deterministic connection refusal either way.
            let url = "http://127.0.0.1:1/";
            let name = "unreachable-pair-target";
            let self_url = default_self_url();

            // `pair_via_url`'s own documented tail.
            let direct = run_pair_request("pair", url, name, &self_url, None, None, None, &PairFinish::detached());
            // The same ceremony tail `pair_via_hostname` reaches on its
            // single-match branch — it composes an OBSERVED dial url first
            // (src_addr + `default_a2a_port`, P-S1/task #120) and passes
            // that, but the tail function is still this one; reproduced
            // here under the identical `pair` command name both arms
            // now share.
            let via_hostname = run_pair_request("pair", url, name, &self_url, None, None, None, &PairFinish::detached());

            assert_eq!(direct.status, aoide_protocol::output::Status::Error, "{direct:?}");
            assert_eq!(direct.command, "pair");
            assert_eq!(via_hostname.status, direct.status);
            assert_eq!(via_hostname.command, "pair");
            // Same failure MESSAGE from both call sites — proves it is one
            // function's error path taken twice, not two independently
            // drifting implementations that merely happen to agree today.
            assert_eq!(
                via_hostname.message, direct.message,
                "pair's url arm and hostname arm must produce an identical failure message here"
            );
        });
    }

    // ── Dial resolution (P-S4): the identity guarantee, per call site,
    // ── pinned directly rather than trusted from a comment — §0.4's
    // ── "off = unchanged" promise, and the path-preservation invariant
    // ── sign_headers_for_node's canonical string depends on. No real ssh
    // ── anywhere below: a `via` case seeds a REUSABLE tunnel record
    // ── (a real local listener, this test process's own — genuinely
    // ── alive — pid) so `aoide_client::tunnel::open_or_reuse` takes its
    // ── reuse branch and never spawns anything, the same seam
    // ── `client/src/tunnel.rs`'s own tests exercise, reached here through
    // ── the public record API instead of the private `SpawnFn` closure. ──

    fn with_temp_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let saved_session = std::env::var("AOIDE_SESSION_ID").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-dial-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::remove_var("AOIDE_SESSION_ID");

        let out = f();

        let _ = std::fs::remove_dir_all(&dir);
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_session {
            Some(v) => std::env::set_var("AOIDE_SESSION_ID", v),
            None => std::env::remove_var("AOIDE_SESSION_ID"),
        }
        out
    }

    /// Seed a REUSABLE tunnel record for `(session_id, key)`: a real local
    /// listener (so `open_or_reuse`'s reuse probe actually answers) at a
    /// freshly reserved port, recorded under THIS test process's own pid
    /// (genuinely alive, so the reuse probe's `proc_exists` check passes
    /// too) — `open_or_reuse` then takes its reuse branch and never spawns
    /// anything, real `ssh` least of all. Returns the listener (keep it
    /// alive for the assertion) and the port it bound.
    fn seed_reusable_tunnel(session_id: &str, key: &str) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        aoide_storage::tunnel::save(&aoide_storage::tunnel::TunnelRecord {
            schema_version: aoide_storage::tunnel::TUNNEL_VERSION.to_string(),
            session_id: session_id.to_string(),
            key: key.to_string(),
            ssh_target: "ssh://sakaki".to_string(),
            local_port: port,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8710,
            pid: std::process::id(),
            opened_at: "2026-08-27T00:00:00Z".to_string(),
        })
        .unwrap();
        (listener, port)
    }

    #[test]
    fn resolve_dial_url_is_byte_identical_to_the_logical_url_when_via_is_absent() {
        // No env, no filesystem, no socket touched at all — via: None never
        // reaches `open_or_reuse`.
        for logical in ["http://sakaki:8710/", "http://sakaki:8710/aoide/rpc", "https://box:9/a/b?x=1"] {
            assert_eq!(
                resolve_dial_url(logical, None, "sakaki").unwrap(),
                logical,
                "identity: the dial url must be byte-for-byte the logical url when off"
            );
        }
    }

    #[test]
    fn post_json_to_node_dials_node_url_verbatim_when_node_via_is_absent() {
        // post_json_to_node's OWN via resolution (node.via, not the
        // resolve_dial_url helper directly) — proven by forcing a
        // connection failure and asserting the error names node.url's own
        // host:port, never a rewritten 127.0.0.1:<port> authority.
        let mut node = fixture_node(None);
        node.url = "http://127.0.0.1:1/aoide/rpc".to_string(); // reserved, never listened on
        let err = post_json_to_node(&node, "{}", None, &[], 1).unwrap_err();
        assert!(
            err.contains("127.0.0.1:1") || err.contains("connect"),
            "an absent via must dial node.url's own authority verbatim: {err}"
        );
    }

    #[test]
    fn resolve_dial_url_with_a_via_rewrites_the_authority_and_preserves_the_path_verbatim() {
        with_temp_runtime_dir("resolve-with-via", || {
            let session_id = tunnel_session_id();
            let (listener, port) = seed_reusable_tunnel(&session_id, "sakaki");

            let via = aoide_storage::tunnel::parse_via("ssh://sakaki").unwrap();
            for logical in ["http://sakaki:8710/", "http://sakaki:8710/aoide/rpc", "http://sakaki:8710"] {
                let dial = resolve_dial_url(logical, Some(&via), "sakaki").unwrap();
                assert_eq!(
                    dial,
                    format!("http://127.0.0.1:{port}{}", aoide_storage::node_store::url_path(logical)),
                    "authority becomes 127.0.0.1:<local port>, path preserved via url_path directly"
                );
            }
            drop(listener);
        });
    }

    /// §0.4's identity guarantee, pinned directly against
    /// `sign_headers_for_node`'s own path source: `sign_headers_for_node`
    /// never reads the DIAL url at all (it signs over
    /// `node_store::url_path(&node.url)`, computed independently, before
    /// dial resolution ever runs) — so the canonical string it signs is
    /// unaffected by a via rewrite PROVIDED the dial's own path equals
    /// that same `url_path(&node.url)`. This asserts exactly that equality
    /// for a node carrying a `via`, which is what makes "the far end's
    /// `HttpRequest.path` (what the tunnel actually delivers) matches what
    /// was signed" true — a live curl round trip through the tunnel is out
    /// of reach here (no real ssh), but every byte this signature depends
    /// on is proven identical either way.
    #[test]
    fn a_via_rewrite_never_changes_the_path_sign_headers_for_node_signs_over() {
        // Sandbox fix (review): this test calls `sign_headers_for_node`,
        // which mints/loads THIS instance's identity
        // (`aoide_storage::identity::load_or_mint`) — that needs a
        // writable `AOIDE_STATE_DIR`, which `with_temp_runtime_dir` alone
        // never sets (it only isolates `XDG_RUNTIME_DIR` for the tunnel
        // record). In a build sandbox with no real `$HOME`,
        // `load_or_mint`'s own default state-dir fallback is unwritable —
        // "Permission denied" — exactly the failure `with_node_state`
        // (used by every OTHER identity-touching test in this module,
        // e.g. `sign_headers_for_node_round_trips_a_genuine_signature_for_
        // a_verified_node`) already avoids. `with_node_state_and_temp_
        // runtime_dir` isolates BOTH under one `env_lock` acquisition
        // (nesting the two single-purpose helpers would deadlock — see
        // its own doc).
        with_node_state_and_temp_runtime_dir("sign-headers-path-pin", || {
            let session_id = tunnel_session_id();
            let (listener, port) = seed_reusable_tunnel(&session_id, "sakaki");

            let mut node = fixture_node(None);
            node.name = "sakaki".to_string();
            node.url = "http://sakaki:8710/aoide/rpc".to_string();
            node.via = Some("ssh://sakaki".to_string());

            let signed_path = aoide_storage::node_store::url_path(&node.url);

            let via = aoide_storage::tunnel::parse_via(node.via.as_deref().unwrap()).unwrap();
            let dial = resolve_dial_url(&node.url, Some(&via), &node.name).unwrap();
            let dial_path = aoide_storage::node_store::url_path(&dial);

            assert_eq!(
                dial_path, signed_path,
                "the tunnel rewrite must never change the byte-for-byte path sign_headers_for_node signs over"
            );
            assert!(dial.starts_with(&format!("http://127.0.0.1:{port}")), "authority is rewritten to the local forward: {dial}");

            // And directly: sign_headers_for_node itself only ever reads
            // node.url (never node.via, never a dial url) — an unverified
            // node's empty-headers shortcut is untouched by via either way.
            assert_eq!(sign_headers_for_node(&node, "{}").unwrap(), Vec::<(String, String)>::new(), "unverified nodes are unaffected, via or not");
            node.verified = true;
            let headers_with_via = sign_headers_for_node(&node, "{}").unwrap();
            let mut node_no_via = node.clone();
            node_no_via.via = None;
            let headers_without_via = sign_headers_for_node(&node_no_via, "{}").unwrap();
            // Nonce/timestamp differ call to call (fresh each time) — but
            // the NODE identity header (never derived from via) must agree.
            let node_header_idx = aoide_storage::wire_auth::HEADER_NODE;
            let get = |hs: &[(String, String)]| hs.iter().find(|(k, _)| k == node_header_idx).map(|(_, v)| v.clone());
            assert_eq!(get(&headers_with_via), get(&headers_without_via), "node.via must never influence the signed X-Aoide-Node identity");

            drop(listener);
        });
    }

    #[test]
    fn parse_via_flag_absent_is_none_present_invalid_is_err_never_a_silent_fallback() {
        let inv = |flags: &[(&str, &str)]| Invocation {
            path: vec!["node".to_string(), "add".to_string()],
            args: vec![],
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: aoide_protocol::Door::Cli,
        };
        assert_eq!(parse_via_flag(&inv(&[])).unwrap(), None, "absent --via is None, never a guessed default");
        assert_eq!(
            parse_via_flag(&inv(&[("via", "ssh://khoa@sakaki")])).unwrap(),
            Some(aoide_storage::tunnel::parse_via("ssh://khoa@sakaki").unwrap())
        );
        let err = parse_via_flag(&inv(&[("via", "http://not-ssh")])).unwrap_err();
        assert!(!err.is_empty(), "an invalid --via is Err, never silently treated as absent");
    }

    #[test]
    fn handle_node_add_with_an_invalid_via_is_a_usage_error_and_registers_nothing() {
        with_node_state("add-invalid-via", || {
            let inv = Invocation {
                path: vec!["node".to_string(), "add".to_string()],
                args: vec!["sakaki".to_string(), "http://sakaki:8710/".to_string()],
                flags: [("via".to_string(), "http://not-ssh".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_node_add(&inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(aoide_storage::node_store::load_nodes().is_empty(), "an invalid --via registers nothing");
        });
    }

    /// Both `AOIDE_STATE_DIR` (nodes.json) and `XDG_RUNTIME_DIR` (tunnel
    /// records) under ONE `env_lock` acquisition — `with_node_state` and
    /// `with_temp_runtime_dir` each lock it themselves, so nesting them
    /// would deadlock (a plain `std::sync::Mutex` is not reentrant).
    fn with_node_state_and_temp_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_state = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let saved_session = std::env::var("AOIDE_SESSION_ID").ok();
        let state_dir = std::env::temp_dir().join(format!("aoide-client-add-via-state-{tag}-{}", std::process::id()));
        let runtime_dir = std::env::temp_dir().join(format!("aoide-client-add-via-runtime-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        let _ = std::fs::remove_dir_all(&runtime_dir);
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::env::set_var("AOIDE_STATE_DIR", &state_dir);
        std::env::set_var("XDG_RUNTIME_DIR", &runtime_dir);
        std::env::remove_var("AOIDE_SESSION_ID");

        let out = f();

        let _ = std::fs::remove_dir_all(&state_dir);
        let _ = std::fs::remove_dir_all(&runtime_dir);
        match saved_state {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_session {
            Some(v) => std::env::set_var("AOIDE_SESSION_ID", v),
            None => std::env::remove_var("AOIDE_SESSION_ID"),
        }
        out
    }

    /// A real (but entirely local, no external binary) HTTP/1.1 responder:
    /// loops accepting connections and answering each with a fixed 200
    /// JSON response, until the returned listener is dropped. Looping
    /// (rather than a one-shot `accept`) matters here: `resolve_dial_url`'s
    /// own REUSE check (`open_or_reuse`'s `probe_port`) makes a bare TCP
    /// connect-then-drop against this same port BEFORE the real `curl` GET
    /// ever runs — a one-shot responder would have its single `accept()`
    /// consumed by that silent probe connection, leaving curl's later,
    /// genuine request to hang unanswered until its own `--max-time`. A
    /// connection that sends no bytes before closing (the probe) reads as
    /// an immediate EOF here and is simply skipped; the loop is ready
    /// again immediately after. Returns the bound listener (keep it
    /// alive — dropping it is what ends the loop) and its port.
    fn spawn_fake_card_server(body: &'static str) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            loop {
                let Ok((mut stream, _)) = accepter.accept() else { break };
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    // A bare probe connect-then-drop (no bytes ever sent) —
                    // nothing to answer; loop back for the next accept.
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (listener, port)
    }

    /// Drop a fake `curl` shim at the front of `PATH` running `script`
    /// (its body — this helper writes the `#!/bin/sh` line and the stdin
    /// drain every fake curl owes its caller), restoring the previous
    /// `PATH` and removing the shim directory when `f` returns. Reused by
    /// both `MAX_RESPONSE_BYTES` tests below (#114) — no real network, no
    /// real `curl` process, same no-mock-needed shim technique the
    /// no-verify test above already established for proving what does/
    /// doesn't reach `run_curl`.
    ///
    /// The drain is load-bearing — `post_json` always writes to curl's
    /// stdin, and a shim that exits without reading turns a descheduled
    /// caller's write into an EPIPE (`crates/AGENTS.md`).
    fn with_fake_curl<T>(tag: &str, script: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let shim_dir = std::env::temp_dir().join(format!(
            "aoide-client-curlshim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let shim = shim_dir.join("curl");
        std::fs::write(&shim, format!("#!/bin/sh\ncat > /dev/null\n{script}")).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

        let out = f();

        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&shim_dir);
        out
    }

    /// #114: an over-cap response refuses with the taught error, naming
    /// the cap, rather than growing this process's memory without limit.
    /// The shim writes `MAX_RESPONSE_BYTES + 1MiB` of zero bytes (via
    /// `dd`, fast) with NO `%{http_code}` trailer at all — proving the
    /// crate's own read-loop cap is what catches this, independent of
    /// curl's own `--max-filesize` flag (which a real curl binary applies
    /// only when a response declares its length up front; this shim never
    /// does, the same shape a chunked-Transfer-Encoding response takes).
    /// The child is killed the moment the running total crosses the cap,
    /// so this test returns promptly rather than waiting for the shim's
    /// full `dd` to finish writing.
    #[test]
    fn run_curl_refuses_a_response_over_the_max_response_bytes_cap() {
        let over_cap_mib = (MAX_RESPONSE_BYTES / (1024 * 1024)) + 1;
        let script = format!("dd if=/dev/zero bs=1M count={over_cap_mib} 2>/dev/null\n");
        let result = with_fake_curl("over-cap", &script, || run_curl(&["--", "http://example.invalid/"], None));
        let err = result.expect_err("a response past MAX_RESPONSE_BYTES must refuse, never buffer to completion");
        assert!(
            err.contains(&MAX_RESPONSE_BYTES.to_string()),
            "the taught error must name the cap itself: {err}"
        );
        assert!(err.contains("exceeded") && err.contains("cap"), "the taught error must say why it refused: {err}");
    }

    /// #114's other half: an ordinary, well-under-cap payload passes
    /// through the same read-loop untouched — the byte cap must not
    /// mangle or truncate a normal response.
    #[test]
    fn run_curl_passes_an_ordinary_payload_under_the_cap() {
        let script = "printf '{\"ok\":true}\\n200'\n";
        let result = with_fake_curl("under-cap", script, || run_curl(&["--", "http://example.invalid/"], None));
        let (code, body) = result.expect("a small, ordinary payload must pass through the cap untouched");
        assert_eq!(code, 200);
        assert_eq!(body, "{\"ok\":true}");
    }

    /// Task #103, requester side: once the remote A2A door's bounded
    /// liveness check (`aoide-server::a2a::do_spawn`) turns a failed spawn
    /// into a proper JSON-RPC error instead of an optimistic `submitted`
    /// ack, `spawn_on_node_via` must surface that taught message CLEANLY —
    /// never swallowed, never re-summarized — through its existing
    /// `"node-refused"` arm. No new client-side code was needed for this;
    /// this test PINS that the existing plumbing already does the job,
    /// driven through a fake `curl` shim standing in for the remote door's
    /// HTTP 200 / JSON-RPC-error response (JSON-RPC errors are always HTTP
    /// 200 — the error lives in the envelope, not the status line).
    #[test]
    fn spawn_on_node_via_surfaces_a_json_rpc_error_ack_as_a_taught_node_refused_error() {
        let taught = "the configured agent (`claude`) exited immediately after launch \
                       (exit status: 1) \u{2014} it is likely missing from this unit's PATH, \
                       or the configured spawnAgent command line is wrong";
        let body = json!({
            "jsonrpc": "2.0",
            "id": "whatever",
            "error": { "code": -32603, "message": taught }
        })
        .to_string();
        // A heredoc with a QUOTED delimiter ('JSONBODY') — no `$`/backtick
        // expansion inside, so the taught message's own backticks pass
        // through byte-for-byte. `cat`'s own trailing newline is exactly
        // the separator `run_curl`'s `rsplit_once('\n')` expects before the
        // `-w "\n%{http_code}"` status line.
        let script = format!("cat <<'JSONBODY'\n{body}\nJSONBODY\nprintf '200'\n");
        let node = fixture_node(None);
        let result = with_fake_curl("spawn-refused", &script, || spawn_on_node_via(&node, "hello", None));
        let err = result.expect_err("a JSON-RPC error ack must surface as an Err, never as Ok");
        assert_eq!(err.reason, "node-refused");
        assert!(
            err.message.contains(taught),
            "the taught message must reach the caller verbatim, not summarized: {}",
            err.message
        );
    }

    /// Review finding, P-S4 follow-up: `node add`'s AgentCard verification
    /// is its ONE network call, and used to dial `node.url` directly even
    /// when `--via` was given — exactly the scenario `--via` exists for (a
    /// loopback-bound door reachable only through the tunnel) would fail
    /// verification and never get registered. Proven end to end with a
    /// REAL `curl` GET (no mock) reaching a REAL local HTTP responder
    /// through a REUSED tunnel record (P-S3's seam, no real ssh anywhere):
    /// the node's logical url names an RFC 2606 `.invalid` host that can
    /// never resolve, so the fetch can only have succeeded by going
    /// through the rewritten `127.0.0.1:<port>` target the seeded record
    /// names — an `Ok` outcome here is the proof. The recorded `node.url`
    /// must still be the LOGICAL url, never the rewritten one.
    #[test]
    fn handle_node_add_with_a_valid_via_verifies_the_agentcard_through_the_tunnel_and_records_the_logical_url() {
        with_node_state_and_temp_runtime_dir("add-valid-via", || {
            let (listener, port) = spawn_fake_card_server(r#"{"name":"fake-agent"}"#);

            let session_id = tunnel_session_id();
            aoide_storage::tunnel::save(&aoide_storage::tunnel::TunnelRecord {
                schema_version: aoide_storage::tunnel::TUNNEL_VERSION.to_string(),
                session_id,
                key: "sakaki".to_string(),
                ssh_target: "ssh://sakaki".to_string(),
                local_port: port,
                remote_host: "127.0.0.1".to_string(),
                remote_port: 8710,
                pid: std::process::id(),
                opened_at: "2026-08-27T00:00:00Z".to_string(),
            })
            .unwrap();

            let logical_url = "http://sakaki-unresolvable-host.invalid:8710/";
            let inv = Invocation {
                path: vec!["node".to_string(), "add".to_string()],
                args: vec!["sakaki".to_string(), logical_url.to_string()],
                flags: [("via".to_string(), "ssh://sakaki".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_node_add(&inv);
            assert_eq!(
                out.status,
                aoide_protocol::output::Status::Ok,
                "the fetch must have gone through the tunnel — the logical host cannot resolve at all: {out:?}"
            );

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].url, logical_url, "the recorded node.url stays LOGICAL, never the rewritten dial url");
            assert_eq!(nodes[0].via.as_deref(), Some("ssh://sakaki"));

            drop(listener);
        });
    }

    /// `node add --no-verify` (M3, task #16: Melete inbound via the
    /// existing A2A door) skips the AgentCard fetch — `run_curl`'s ONE
    /// call site for the whole command — entirely. Proven the same way
    /// `aoide_secrets::enroll`'s `qrencode` shim and `aoide_secrets::
    /// broker`'s `age-keygen` shim prove an external binary was (or
    /// wasn't) invoked: a fake `curl` dropped earlier on `PATH` that, if
    /// ever run, touches a marker file. No real network, no real curl
    /// process — sandbox-safe. If this ever regresses to calling
    /// `run_curl` anyway, the fake responds with neither a `200` nor
    /// parseable JSON, so the command would ALSO fail — a false pass here
    /// is not possible by construction.
    #[test]
    fn handle_node_add_no_verify_never_invokes_curl() {
        with_node_state("add-no-verify", || {
            let shim_dir = std::env::temp_dir().join(format!(
                "aoide-client-node-add-noverify-curlshim-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::fs::create_dir_all(&shim_dir).unwrap();
            let marker = shim_dir.join("curl-was-invoked");
            let shim = shim_dir.join("curl");
            std::fs::write(&shim, format!("#!/bin/sh\ncat > /dev/null\ntouch {}\nexit 1\n", marker.display())).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let saved_path = std::env::var("PATH").ok();
            std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

            let inv = Invocation {
                path: vec!["node".to_string(), "add".to_string()],
                args: vec!["melete".to_string(), "http://melete.example:8710/".to_string()],
                flags: [("no-verify".to_string(), "true".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_node_add(&inv);

            match saved_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            let curl_ran = marker.exists();
            let _ = std::fs::remove_dir_all(&shim_dir);

            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert!(!curl_ran, "--no-verify must never invoke curl (the shim would have touched its marker)");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].name, "melete");
            assert_eq!(nodes[0].url, "http://melete.example:8710/");
            assert!(
                !nodes[0].verified,
                "node add --no-verify still records verified:false — a card fetch was never identity, only reachability"
            );
        });
    }

    /// `--via` beats `Node.via` — proven WITHOUT ever needing a real
    /// tunnel or ssh, by making the RECORDED `node.via` a deliberately
    /// UNPARSEABLE string (`parse_via`'s own refusal, pure and instant):
    /// with no override, `post_json_to_node` must consult it and fail
    /// immediately on the parse error (proving the recorded via IS read
    /// when nothing beats it); with an explicit, VALID override, the same
    /// invalid `node.via` string must never surface at all — the override
    /// short-circuits before `node.via` is ever parsed. The override case
    /// seeds a REUSABLE tunnel record (this test module's own no-real-ssh
    /// seam) so the override path completes rather than needing a live
    /// ssh child.
    #[test]
    fn via_override_beats_the_recorded_node_via() {
        with_temp_runtime_dir("override-beats-recorded", || {
            let mut node = fixture_node(None);
            node.name = "sakaki".to_string();
            node.url = "http://sakaki:8710/".to_string();
            node.via = Some("not-a-valid-via-at-all".to_string());

            // No override: post_json_to_node_with_via_override falls back
            // to post_json_to_node, which parses node.via and refuses
            // immediately — no network touched, the taught parse error
            // surfaces directly, proving node.via WAS consulted.
            let no_override_err =
                post_json_to_node_with_via_override(&node, "{}", None, &[], 1, None).unwrap_err();
            assert!(
                no_override_err.contains("not-a-valid-via-at-all"),
                "with no override, the recorded (invalid) node.via must be the thing that fails: {no_override_err}"
            );

            // With an explicit, VALID override, node.via's garbage string
            // must never even be looked at — seed a reusable record for
            // the SAME key (node.name) the override path also dials
            // through, so this completes with no real ssh spawned.
            let session_id = tunnel_session_id();
            let (listener, _port) = seed_reusable_tunnel(&session_id, "sakaki");
            let override_via = aoide_storage::tunnel::parse_via("ssh://khoa@sakaki").unwrap();
            let with_override =
                post_json_to_node_with_via_override(&node, "{}", None, &[], 1, Some(&override_via));
            match with_override {
                Err(e) => assert!(
                    !e.contains("not-a-valid-via-at-all"),
                    "an explicit --via override must never surface the recorded (invalid) node.via: {e}"
                ),
                Ok(_) => {} // a bounded curl call against the seeded listener may also just succeed/timeout cleanly
            }
            drop(listener);
        });
    }

    // ── Design A (task #119): poll-based pairing completion ─────────────
    // ── no approver->requester network callback exists any more ─────────

    /// `approve_inbound`'s own commit is now PURELY LOCAL (module doc) — the
    /// old shape's ONE network call (the `aoide/pairApprove` callback) is
    /// gone outright. Proven the same way `handle_node_add_no_verify_
    /// never_invokes_curl` proves an external binary was never invoked: a
    /// fake `curl` dropped on `PATH` that touches a marker file if ever run.
    /// This is THE test that pins "no approver->requester network callback
    /// happens" at the client layer (the a2a.rs full-ceremony test pins the
    /// same invariant one layer down, by never dialing an undialable url).
    #[test]
    fn approve_inbound_never_invokes_curl_purely_local_commit() {
        with_node_state("approve-inbound-no-curl", || {
            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
            let pubkey_a = "a".repeat(64);
            aoide_storage::pairing::park_inbound(
                &pubkey_a,
                "box-a",
                "10.0.0.5",
                "http://box-a-is-loopback-only.invalid/",
                &aoide_storage::pairing::derive_commit(&pubkey_a, &"c".repeat(32)),
                &now,
                &aoide_storage::pairing::expires_at_from(now_epoch),
                None,
            )
            .unwrap();
            let entry = aoide_storage::pairing::list_inbound(now_epoch).into_iter().next().unwrap();
            let id = entry.id.clone();
            aoide_storage::pairing::reveal_inbound(&id, &"c".repeat(32), now_epoch).unwrap();
            let entry = aoide_storage::pairing::list_inbound(now_epoch).into_iter().next().unwrap();
            let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
            let sas = aoide_storage::pairing::derive_sas(&pubkey_a, &kp.info().pubkey_hex, &"c".repeat(32), &entry.approver_nonce_hex);

            let shim_dir = std::env::temp_dir().join(format!(
                "aoide-client-approve-inbound-curlshim-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::fs::create_dir_all(&shim_dir).unwrap();
            let marker = shim_dir.join("curl-was-invoked");
            let shim = shim_dir.join("curl");
            std::fs::write(&shim, format!("#!/bin/sh\ncat > /dev/null\ntouch {}\nexit 1\n", marker.display())).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let saved_path = std::env::var("PATH").ok();
            std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

            let outcome = approve_inbound(CodeGate::Code(sas), "pair", &id, entry, &now, now_epoch, None);

            match saved_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            let curl_ran = marker.exists();
            let _ = std::fs::remove_dir_all(&shim_dir);

            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");
            assert!(!curl_ran, "approving an inbound request must never invoke curl — it is purely local");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].verified);
            let listed = aoide_storage::pairing::list_inbound(now_epoch);
            assert_eq!(listed.len(), 1, "the entry stays parked for the requester's own poll");
            assert!(listed[0].approved);
        });
    }

    /// A fake `aoide/pairPoll` responder — ANY POST gets the same canned
    /// JSON reply, mirroring `spawn_fake_card_server`'s exact shape one
    /// section up (this crate's own established real-curl-real-listener
    /// pattern for proving a wire path end to end, not mocked away).
    fn spawn_fake_pair_poll_server(body: &'static str) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            loop {
                let Ok((mut stream, _)) = accepter.accept() else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (listener, port)
    }

    /// [`spawn_fake_pair_poll_server`]'s stateful sibling: answers `pending`
    /// for the first `pending_answers` POSTs and `approved` after, which is
    /// the only way to prove the `--wait` loop actually RE-polls rather than
    /// giving up on the first `pending` the way `pair <id>` does.
    fn spawn_fake_pair_poll_server_pending_then_approved(pending_answers: usize, approved_body: String) -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut seen = 0usize;
            loop {
                let Ok((mut stream, _)) = accepter.accept() else { break };
                let mut buf = [0u8; 4096];
                if stream.read(&mut buf).unwrap_or(0) == 0 {
                    continue;
                }
                let body = if seen < pending_answers { r#"{"jsonrpc":"2.0","id":1,"result":{"status":"pending"}}"#.to_string() } else { approved_body.clone() };
                seen += 1;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (listener, port)
    }

    fn sample_outbound_awaiting_approval(id: &str, url: &str, pubkey_hex: &str) -> aoide_storage::pairing::OutboundPairingRequest {
        // Relative to REAL current time (not a fixed historical epoch like
        // this module's other `sample_outbound` fixtures use) — the tests
        // below drive `mark_outbound_awaiting_confirm`/`list_outbound` with
        // the ACTUAL current `now_epoch`, so `expires_at` must actually be
        // in the future relative to that, or the entry sweeps away as
        // expired before the poll ever runs.
        let now = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
        aoide_storage::pairing::OutboundPairingRequest {
            id: id.to_string(),
            url: url.to_string(),
            name: "box-b".to_string(),
            pubkey_hex: pubkey_hex.to_string(),
            requester_nonce_hex: "c".repeat(32),
            approver_nonce_hex: "d".repeat(32),
            requested_at: aoide_storage::time::iso_utc_from_epoch(now),
            expires_at: aoide_storage::pairing::expires_at_from(now),
            state: aoide_storage::pairing::OutboundState::AwaitingApproval,
            via: None,
            tries: 0,
        }
    }

    /// The expected reply code an outbound entry built by
    /// [`sample_outbound_awaiting_approval`] gates its final commit on —
    /// `derive_reply_sas` from THIS process's own freshly-minted identity
    /// (`with_node_state`'s sandboxed `AOIDE_STATE_DIR`) plus the fixture's
    /// own transcript fields, the exact computation `commit_outbound`
    /// itself performs.
    fn expected_reply_sas(pubkey_b: &str) -> String {
        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        aoide_storage::pairing::derive_reply_sas(&kp.info().pubkey_hex, pubkey_b, &"c".repeat(32), &"d".repeat(32))
    }

    /// An outbound entry already `AwaitingConfirm` (a poll already
    /// released it) — [`commit_outbound`]'s own gate-table tests drive it
    /// directly, no network call needed, mirroring
    /// [`parked_revealed_inbound`]'s equivalent shortcut on the approver's
    /// leg.
    fn awaiting_confirm_outbound(id: &str, pubkey_b: &str) -> aoide_storage::pairing::OutboundPairingRequest {
        let mut entry = sample_outbound_awaiting_approval(id, "http://box-b/", pubkey_b);
        entry.state = aoide_storage::pairing::OutboundState::AwaitingConfirm;
        entry
    }

    // ── commit_outbound gate table (mutual ceremony, R1) ─────────────────
    // ── the requester-side mirror of `approve_inbound`'s own scripted-code/
    // ── auto-deny/no-code-collectable tests just below the approve_outbound
    // ── poll tests. ────────────────────────────────────────────────────────

    #[test]
    fn commit_outbound_scripted_correct_reply_code_commits_and_takes_the_entry() {
        with_node_state("commit-outbound-code-match", || {
            let pubkey_b = "b".repeat(64);
            let entry = awaiting_confirm_outbound("deadbeef", &pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();
            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();

            // The undashed spelling exercises `code_matches`' normalization
            // on the real path, mirroring the inbound leg's own test.
            let code = expected_reply_sas(&pubkey_b).replace('-', "");
            let out = commit_outbound(CodeGate::Code(code), "pair", "deadbeef", entry, &now, now_epoch, &[]);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "commit takes the entry");
        });
    }

    #[test]
    fn commit_outbound_scripted_wrong_reply_codes_count_persisted_tries_then_auto_abort_at_three() {
        with_node_state("commit-outbound-code-mismatch", || {
            let pubkey_b = "b".repeat(64);
            let entry = awaiting_confirm_outbound("deadbeef", &pubkey_b);
            aoide_storage::pairing::park_outbound(entry).unwrap();
            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();

            for expected_tries in 1..=2u32 {
                let fresh = aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == "deadbeef").unwrap();
                let out = commit_outbound(CodeGate::Code("xxx-xxx".into()), "pair", "deadbeef", fresh, &now, now_epoch, &[]);
                assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
                assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("code-mismatch"));
                assert_eq!(out.data.as_ref().and_then(|d| d.get("tries")).and_then(Value::as_u64), Some(expected_tries as u64));
                assert_eq!(aoide_storage::pairing::list_outbound(now_epoch)[0].tries, expected_tries, "tries survive across invocations");
            }

            // The third mismatch auto-aborts: a clean `take_outbound`,
            // nothing of THIS end's own commits, its own audited reason.
            let fresh = aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == "deadbeef").unwrap();
            let out = commit_outbound(CodeGate::Code("xxx-xxx".into()), "pair", "deadbeef", fresh, &now, now_epoch, &[]);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("auto-abort-on-code-mismatch"));
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the parked entry is removed, exactly like a reject");
            assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing of this end's own was ever committed");
        });
    }

    #[test]
    fn commit_outbound_refuses_where_no_code_can_be_collected_and_counts_no_try() {
        with_node_state("commit-outbound-no-code", || {
            let pubkey_b = "b".repeat(64);
            let entry = awaiting_confirm_outbound("deadbeef", &pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();
            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();

            let out = commit_outbound(CodeGate::Unavailable, "pair", "deadbeef", entry, &now, now_epoch, &[]);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains("--code"), "the refusal teaches the scripted spelling: {}", out.message);
            assert_eq!(aoide_storage::pairing::list_outbound(now_epoch)[0].tries, 0, "a refusal is not a wrong code");
        });
    }

    /// A crash between the third try's persisted increment and its
    /// auto-abort can leave an entry parked with `tries >= MAX_CODE_TRIES`
    /// on disk — the same window [`approve_inbound`]'s own up-front check
    /// closes on the approver's leg. [`commit_outbound`] must deny such an
    /// entry before the gate ever runs, never re-offer one more try.
    #[test]
    fn commit_outbound_denies_up_front_when_already_at_the_try_limit() {
        with_node_state("commit-outbound-limit-reached", || {
            let pubkey_b = "b".repeat(64);
            let mut entry = awaiting_confirm_outbound("deadbeef", &pubkey_b);
            entry.tries = MAX_CODE_TRIES;
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();
            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();

            // A CORRECT code doesn't matter — the up-front check runs
            // before the gate is ever consulted.
            let code = expected_reply_sas(&pubkey_b);
            let out = commit_outbound(CodeGate::Code(code), "pair", "deadbeef", entry, &now, now_epoch, &[]);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("auto-abort-on-code-mismatch"));
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "an entry already at the limit is never approvable");
            assert!(aoide_storage::node_store::load_nodes().is_empty());
        });
    }

    /// `approve_outbound`'s own poll step, proven end to end through a REAL
    /// local HTTP responder (no mock) answering `{"status":"approved",
    /// "pubkeyHex":<the SAME pubkey the entry already learned at request
    /// time>}` — the poll REPLACES the old reverse callback, over the SAME
    /// forward dial (module doc on `approve_outbound`, task #119).
    #[test]
    fn approve_outbound_polls_a_real_server_and_completes_on_an_approved_matching_release() {
        with_node_state("approve-outbound-poll-approved", || {
            let pubkey_b = "b".repeat(64);
            let body: String = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"approved","pubkeyHex":"{pubkey_b}"}}}}"#);
            let body: &'static str = Box::leak(body.into_boxed_str());
            let (_listener, port) = spawn_fake_pair_poll_server(body);
            let url = format!("http://127.0.0.1:{port}/");
            let entry = sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();

            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
            let outcome = approve_outbound(CodeGate::Code(expected_reply_sas(&pubkey_b)), "pair", "deadbeef", entry, &now, now_epoch, None);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].name, "box-b");
            assert_eq!(nodes[0].pubkey.as_deref(), Some(pubkey_b.as_str()));
            assert!(nodes[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the outbound entry is consumed on commit");
        });
    }

    // ── The blocking wait (task #135 P2) ─────────────────────────────────────

    #[test]
    fn pair_finish_reads_the_wait_and_grant_off_the_flags() {
        let mut inv = pair_approve_inv(&[]);
        let f = pair_finish_from(&inv).unwrap();
        assert_eq!(f.wait_secs, DEFAULT_PAIR_WAIT_SECS, "blocking is the default — the User's ask");
        assert!(!f.skip_confirm);
        assert_eq!(f.grant, None, "no --allow means `read the config`, never the empty grant");

        inv.flags.insert("wait".to_string(), "0".to_string());
        assert_eq!(pair_finish_from(&inv).unwrap().wait_secs, 0, "--wait 0 is the documented escape back to parking");

        inv.flags.insert("wait".to_string(), " 30 ".to_string());
        assert_eq!(pair_finish_from(&inv).unwrap().wait_secs, 30);

        inv.flags.insert("wait".to_string(), "soon".to_string());
        let err = pair_finish_from(&inv).unwrap_err();
        assert!(err.contains("whole seconds"), "a bad --wait is refused by name, never silently defaulted: {err}");

        inv.flags.insert("wait".to_string(), "600".to_string());
        inv.flags.insert("allow".to_string(), "read,spawn".to_string());
        inv.flags.insert("yes".to_string(), "true".to_string());
        let f = pair_finish_from(&inv).unwrap();
        assert!(f.skip_confirm);
        assert_eq!(f.grant, Some(vec!["read".to_string(), "spawn".to_string()]));
    }

    /// A NEW request with `--wait 0` returns before anything commits, so an
    /// `--allow` beside it has nowhere to land — refused by the request
    /// arms via [`refuse_detached_grant`], never dropped. The RESUME leg is
    /// deliberately NOT covered by the guard: its `--wait 0` still polls
    /// once and can commit, so the combination is legal there.
    #[test]
    fn allow_beside_wait_zero_is_refused_on_a_new_request_never_dropped() {
        let refusal = |wait: &str, allow: Option<&str>| {
            let mut inv = pair_approve_inv(&[]);
            inv.flags.insert("wait".to_string(), wait.to_string());
            if let Some(a) = allow {
                inv.flags.insert("allow".to_string(), a.to_string());
            }
            refuse_detached_grant("pair", &pair_finish_from(&inv).unwrap())
        };
        let out = refusal("0", Some("read,spawn")).expect("the contradiction is refused");
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
        assert!(out.message.contains("--allow"), "{}", out.message);
        assert!(out.message.contains("aoide pair"), "and it names where to retype it: {}", out.message);

        // Either alone is fine — only the combination is the contradiction.
        assert!(refusal("0", None).is_none());
        assert!(refusal("600", Some("read")).is_none());
    }

    /// The mutual-code redesign (R1): `--code` on a NEW request is refused
    /// outright — no reply code can exist until the far side has approved
    /// and read one back — the taught error names the spelling that DOES
    /// work once the id exists. Any `--wait` value is refused the same way:
    /// unlike `--allow`, this has nothing to do with whether the request
    /// commits synchronously.
    #[test]
    fn code_on_a_new_request_is_refused_never_silently_ignored() {
        let with_code = |wait: &str| {
            let mut inv = pair_approve_inv(&[]);
            inv.flags.insert("wait".to_string(), wait.to_string());
            inv.flags.insert("code".to_string(), "111-222".to_string());
            refuse_code_on_new_request("pair", &pair_finish_from(&inv).unwrap())
        };
        for wait in ["0", "600"] {
            let out = with_code(wait).unwrap_or_else(|| panic!("--code on a new request must be refused (--wait {wait})"));
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains("--code"), "{}", out.message);
        }

        // No `--code` at all is fine — nothing to refuse.
        let mut inv = pair_approve_inv(&[]);
        inv.flags.insert("wait".to_string(), "0".to_string());
        assert!(refuse_code_on_new_request("pair", &pair_finish_from(&inv).unwrap()).is_none());
    }

    /// The deadline compares two `u64`s and casts neither. The first shape
    /// compared against `wait_secs as i64`, so a `--wait` above `i64::MAX`
    /// read as NEGATIVE and "timed out" on the first tick — an operator
    /// asking for the longest possible wait got an instant return instead.
    #[test]
    fn a_wait_past_i64_max_is_a_long_wait_not_an_instant_timeout() {
        assert!(!wait_is_over(0, u64::MAX), "the largest wait has not elapsed at t=0");
        assert!(!wait_is_over(0, i64::MAX as u64 + 1), "the exact value the old cast flipped negative");
        assert!(!wait_is_over(599, 600));
        assert!(wait_is_over(600, 600), "the bound is inclusive — 600s of a 600s wait is over");
        assert!(wait_is_over(0, 0), "a zero wait is over the moment it starts");
    }

    /// The property that keeps a ten-minute wait from becoming a ten-minute
    /// hammer: every `PollOutcome` except `Pending` is terminal, so an
    /// unreachable box returns on the FIRST tick rather than after the wait.
    #[test]
    fn the_wait_returns_at_once_on_a_terminal_refusal_it_never_retries() {
        with_node_state("wait-terminal-refusal", || {
            let pubkey_b = "b".repeat(64);
            // Port 1 on loopback: nothing listens, so the dial fails fast.
            let entry = sample_outbound_awaiting_approval("deadbeef", "http://127.0.0.1:1/", &pubkey_b);
            aoide_storage::pairing::park_outbound(entry).unwrap();

            let began = std::time::Instant::now();
            let finish = PairFinish { wait_secs: 600, skip_confirm: true, grant: None, code: None, door: aoide_protocol::Door::Cli };
            let out = wait_and_commit("pair", "deadbeef", "box-b", "111-222", &finish);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().unwrap()["reason"], "poll-unreachable");
            assert!(began.elapsed() < std::time::Duration::from_secs(60), "a terminal refusal must not sit out the wait — took {:?}", began.elapsed());
        });
    }

    #[test]
    fn the_wait_times_out_leaving_the_request_pending_and_finishable_later() {
        with_node_state("wait-timeout", || {
            let pubkey_b = "b".repeat(64);
            let (_listener, port) = spawn_fake_pair_poll_server(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"pending"}}"#);
            let url = format!("http://127.0.0.1:{port}/");
            aoide_storage::pairing::park_outbound(sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b)).unwrap();

            // `wait_secs: 0` reaches the timeout on the first tick with no
            // sleep at all — the deadline is checked before the cadence.
            let finish = PairFinish { wait_secs: 0, skip_confirm: true, grant: None, code: None, door: aoide_protocol::Door::Cli };
            let out = wait_and_commit("pair", "deadbeef", "box-b", "111-222", &finish);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "a timeout is not a failed pair: {out:?}");
            assert_eq!(out.data.as_ref().unwrap()["reason"], "wait-timeout");
            assert!(out.message.contains("still pending"), "{}", out.message);
            assert!(out.message.contains("aoide pair"), "it names the command that finishes later: {}", out.message);

            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            assert_eq!(aoide_storage::pairing::list_outbound(now_epoch).len(), 1, "the request survives the timeout — that is what makes Ctrl-C safe");
            assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing commits on a timeout");
        });
    }

    /// The mutual-code redesign (R1): a blocking wait whose poll releases
    /// with NO tty and NO `--code` (cargo test's own stdio is never a
    /// terminal — the exact shape a scripted `--wait` hits) returns the
    /// SAME "still pending, finish later" Ok shape the wait-timeout arm
    /// gives, never a hard Usage refusal — the entry is left exactly where
    /// the poll's own transition put it (`awaiting-confirm`), nothing
    /// auto-commits, and no try is counted.
    #[test]
    fn the_wait_release_with_no_code_available_parks_at_awaiting_confirm_never_refuses() {
        with_node_state("wait-release-no-code", || {
            let pubkey_b = "b".repeat(64);
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"approved","pubkeyHex":"{pubkey_b}"}}}}"#);
            let body: &'static str = Box::leak(body.into_boxed_str());
            let (_listener, port) = spawn_fake_pair_poll_server(body);
            let url = format!("http://127.0.0.1:{port}/");
            aoide_storage::pairing::park_outbound(sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b)).unwrap();

            let finish = PairFinish { wait_secs: 600, skip_confirm: false, grant: None, code: None, door: aoide_protocol::Door::Cli };
            let out = wait_and_commit("pair", "deadbeef", "box-b", "111-222", &finish);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("wait-no-code-available"));
            assert!(out.message.contains("--code"), "it names the finisher: {}", out.message);

            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let listed = aoide_storage::pairing::list_outbound(now_epoch);
            assert_eq!(listed.len(), 1, "the entry stays parked, never taken");
            assert_eq!(listed[0].state, aoide_storage::pairing::OutboundState::AwaitingConfirm, "the poll's own release already transitioned it");
            assert_eq!(listed[0].tries, 0, "no try is counted — there was no code to compare");
            assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing auto-commits");
        });
    }

    /// The whole point of P2: a `pending` answer is RE-polled, where
    /// `pair <id>` gives up on it. Costs one real 5s cadence tick —
    /// the only way to prove the loop without inventing a test-only knob.
    #[test]
    fn the_wait_repolls_a_pending_answer_and_completes_when_it_turns_approved() {
        with_node_state("wait-repoll", || {
            let pubkey_b = "b".repeat(64);
            let approved = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"approved","pubkeyHex":"{pubkey_b}"}}}}"#);
            let (_listener, port) = spawn_fake_pair_poll_server_pending_then_approved(1, approved);
            let url = format!("http://127.0.0.1:{port}/");
            aoide_storage::pairing::park_outbound(sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b)).unwrap();

            let finish = PairFinish {
                wait_secs: 600,
                skip_confirm: true,
                grant: Some(vec!["read".to_string(), "spawn".to_string()]),
                code: Some(expected_reply_sas(&pubkey_b)),
                door: aoide_protocol::Door::Cli,
            };
            let out = wait_and_commit("pair", "deadbeef", "box-b", "111-222", &finish);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].verified, "the pair completes inside the one command — no second invocation");
            assert_eq!(nodes[0].allows, vec!["read".to_string(), "spawn".to_string()], "`pair --allow` reaches the commit, which is why the flag belongs here now");
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the entry is consumed on commit");
        });
    }

    #[test]
    fn the_wait_says_so_when_the_request_vanishes_underneath_it() {
        with_node_state("wait-request-gone", || {
            let finish = PairFinish { wait_secs: 600, skip_confirm: true, grant: None, code: None, door: aoide_protocol::Door::Cli };
            let out = wait_and_commit("pair", "nosuchid", "box-b", "111-222", &finish);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().unwrap()["reason"], "request-gone");
            assert!(out.message.contains("expired"), "{}", out.message);
        });
    }

    /// A poll answering `{"status":"pending"}` refuses with the SAME
    /// "still awaiting the node's own approval" message the old
    /// callback-wait refusal gave — an ordinary, expected outcome; the
    /// outbound entry is untouched, so a later retry can still resolve it.
    #[test]
    fn approve_outbound_polls_a_real_server_and_refuses_cleanly_while_pending() {
        with_node_state("approve-outbound-poll-pending", || {
            let pubkey_b = "b".repeat(64);
            let (_listener, port) = spawn_fake_pair_poll_server(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"pending"}}"#);
            let url = format!("http://127.0.0.1:{port}/");
            let entry = sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();

            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
            let outcome = approve_outbound(CodeGate::Unavailable, "pair", "deadbeef", entry, &now, now_epoch, None);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
            assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("awaiting-node-approval"));

            assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing commits while still pending");
            let listed = aoide_storage::pairing::list_outbound(now_epoch);
            assert_eq!(listed.len(), 1, "a pending poll leaves the entry untouched for a later retry");
            assert_eq!(listed[0].state, aoide_storage::pairing::OutboundState::AwaitingApproval);
        });
    }

    /// The SAS/transcript binding rejects a SUBSTITUTED reveal: a poll
    /// answering `approved` with a pubkey that does NOT match what this
    /// instance learned at the original `aoide/pairRequest` time is refused
    /// — nothing commits, the entry is left untouched (the SAME rejection
    /// the old callback's own pubkey-mismatch handling gave, review-bounce
    /// Finding 2, preserved under Design A).
    #[test]
    fn approve_outbound_rejects_a_substituted_pubkey_release_and_commits_nothing() {
        with_node_state("approve-outbound-poll-mismatch", || {
            let real_pubkey_b = "b".repeat(64);
            let substituted_pubkey = "f".repeat(64);
            let body: String = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"approved","pubkeyHex":"{substituted_pubkey}"}}}}"#);
            let body: &'static str = Box::leak(body.into_boxed_str());
            let (_listener, port) = spawn_fake_pair_poll_server(body);
            let url = format!("http://127.0.0.1:{port}/");
            let entry = sample_outbound_awaiting_approval("deadbeef", &url, &real_pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();

            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
            let outcome = approve_outbound(CodeGate::Unavailable, "pair", "deadbeef", entry, &now, now_epoch, None);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
            assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("reveal-mismatch"));

            assert!(aoide_storage::node_store::load_nodes().is_empty(), "a substituted release must never commit a node record");
            let listed = aoide_storage::pairing::list_outbound(now_epoch);
            assert_eq!(listed.len(), 1, "the entry is left untouched, never removed, on a mismatch");
            assert_eq!(listed[0].state, aoide_storage::pairing::OutboundState::AwaitingApproval, "never advances past awaiting-approval on a mismatch");
            assert_eq!(listed[0].pubkey_hex, real_pubkey_b, "the ORIGINAL learned pubkey stays on record, never overwritten by the substituted one");
        });
    }

    // ── typed-code approval (task #120 P3) — the approver-side gate's
    // ── tty-free halves: the pure comparison, the scripted `--code` path,
    // ── the persisted tries, the auto-deny at 3, and the no-code refusal.
    // ── The interactive `CodeGate::Prompt` loop renders through a real
    // ── terminal (`pick::text_input`) and is exercised by hand, the same
    // ── way `pick`'s own tty backends always have been. ──────────────────

    #[test]
    fn code_matches_ignores_separator_and_whitespace_but_never_content() {
        assert!(code_matches("740-729", "740-729"));
        assert!(code_matches("740729", "740-729"), "the dash carries no entropy");
        assert!(code_matches(" 740 729 ", "740-729"), "typed spacing is the operator's habit, not a mismatch");
        assert!(!code_matches("740-728", "740-729"), "a single wrong digit is a mismatch");
        assert!(!code_matches("", "740-729"), "empty input never matches");
        assert!(!code_matches("-", "740-729"), "separator-only input normalizes to empty and never matches");
    }

    /// Park + reveal one inbound entry in the temp state dir and hand back
    /// (entry, correct SAS) — the SAS derived exactly the way
    /// `approve_inbound` itself derives it, from the freshly-minted identity.
    fn parked_revealed_inbound(now_epoch: i64) -> (aoide_storage::pairing::InboundPairingRequest, String) {
        parked_revealed_inbound_with_self_via(now_epoch, None)
    }

    /// [`parked_revealed_inbound`], with the wire's OPTIONAL `selfVia` claim
    /// threaded through to `park_inbound` (P-PV1) — the seam
    /// `approve_inbound_records_loopback_url_and_claimed_via_when_self_via_present`
    /// needs to prove the approver's commit maps a present claim onto
    /// `{loopback url, via}`.
    fn parked_revealed_inbound_with_self_via(
        now_epoch: i64,
        self_via: Option<&str>,
    ) -> (aoide_storage::pairing::InboundPairingRequest, String) {
        parked_revealed_inbound_with_self_via_and_url(now_epoch, self_via, "http://box-a:8710/")
    }

    /// [`parked_revealed_inbound_with_self_via`], with the parked entry's
    /// own `url` also overridable — the seam
    /// `approve_inbound_records_the_requesters_own_port_parsed_from_entry_url`
    /// needs to prove the loopback rewrite carries the REQUESTER's own
    /// door port (parsed off `entry.url`), never this box's own
    /// `AOIDE_A2A_PORT` (review finding — the first pass read the wrong
    /// box's port entirely).
    fn parked_revealed_inbound_with_self_via_and_url(
        now_epoch: i64,
        self_via: Option<&str>,
        url: &str,
    ) -> (aoide_storage::pairing::InboundPairingRequest, String) {
        let requester_pk = "e".repeat(64);
        let nonce = "aabbccdd11223344";
        let commit = aoide_storage::pairing::derive_commit(&requester_pk, nonce);
        let (entry, _) = aoide_storage::pairing::park_inbound(
            &requester_pk,
            "box-a",
            "10.0.0.5",
            url,
            &commit,
            &aoide_storage::time::iso_utc_from_epoch(now_epoch),
            &aoide_storage::pairing::expires_at_from(now_epoch),
            self_via,
        )
        .unwrap();
        let entry = aoide_storage::pairing::reveal_inbound(&entry.id, nonce, now_epoch).unwrap();
        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let sas = aoide_storage::pairing::derive_sas(&requester_pk, &kp.info().pubkey_hex, nonce, &entry.approver_nonce_hex);
        (entry, sas)
    }

    #[test]
    fn approve_inbound_scripted_wrong_codes_count_persisted_tries_then_auto_deny_at_three() {
        with_node_state("approve-inbound-code-mismatch", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();

            // "xxx-xxx" can never equal a digits-only SAS — a guaranteed mismatch.
            for expected_tries in 1..=2u32 {
                let fresh = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id).unwrap();
                let out = approve_inbound(CodeGate::Code("xxx-xxx".into()), "pair", &id, fresh, &now, now_epoch, None);
                assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
                assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("code-mismatch"));
                assert_eq!(out.data.as_ref().and_then(|d| d.get("tries")).and_then(Value::as_u64), Some(expected_tries as u64));
                // Cumulative across invocations: persisted on the parked entry.
                assert_eq!(aoide_storage::pairing::list_inbound(now_epoch)[0].tries, expected_tries);
            }

            // The third mismatch auto-denies: the same clean removal reject
            // performs, nothing committed, its own audited reason.
            let fresh = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id).unwrap();
            let out = approve_inbound(CodeGate::Code("xxx-xxx".into()), "pair", &id, fresh, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("auto-deny-on-code-mismatch"));
            assert!(aoide_storage::pairing::list_inbound(now_epoch).is_empty(), "the parked entry is removed, exactly like a reject");
            assert!(aoide_storage::node_store::load_nodes().is_empty(), "nothing was ever committed");
        });
    }

    #[test]
    fn approve_inbound_scripted_correct_code_commits_and_marks_approved() {
        with_node_state("approve-inbound-code-match", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();

            // The undashed spelling exercises code_matches' normalization on
            // the real path, not just the pure test above.
            let out = approve_inbound(CodeGate::Code(sas.replace('-', "")), "pair", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].verified, "the ceremony's commit is unchanged by the gate swap");
            let listed = aoide_storage::pairing::list_inbound(now_epoch);
            assert_eq!(listed.len(), 1, "an approved entry stays parked for the requester's poll (Design A)");
            assert!(listed[0].approved);
        });
    }

    /// The mutual-code redesign (R1): a successful commit hands back a
    /// SECOND code, `replySas`, in both the message and the data — and a
    /// re-run against the now-already-approved entry (the operator who
    /// lost the popup, or wants to relay it again) re-derives and
    /// re-displays the SAME value rather than the bare "waiting for their
    /// poll" text alone.
    #[test]
    fn approve_inbound_ok_outcome_carries_the_reply_code_including_on_an_idempotent_rerun() {
        with_node_state("approve-inbound-reply-sas", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();
            let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
            let expected_reply = aoide_storage::pairing::derive_reply_sas(
                &entry.pubkey_hex,
                &kp.info().pubkey_hex,
                entry.requester_nonce_hex.as_deref().unwrap(),
                &entry.approver_nonce_hex,
            );
            assert_ne!(expected_reply, sas, "the reply code must differ from the plain code the gate was just checked against");

            let out = approve_inbound(CodeGate::Code(sas), "pair", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("replySas")).and_then(Value::as_str), Some(expected_reply.as_str()));
            assert!(out.message.contains(&expected_reply), "the reply code rides the human message too: {}", out.message);

            // Re-run against the now-approved entry: idempotent success,
            // and the SAME reply code re-derived and re-shown.
            let fresh = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id).unwrap();
            let rerun = approve_inbound(CodeGate::Unavailable, "pair", &id, fresh, &now, now_epoch, None);
            assert_eq!(rerun.status, aoide_protocol::output::Status::Ok, "{rerun:?}");
            assert_eq!(rerun.data.as_ref().and_then(|d| d.get("alreadyApproved")).and_then(Value::as_bool), Some(true));
            assert_eq!(rerun.data.as_ref().and_then(|d| d.get("replySas")).and_then(Value::as_str), Some(expected_reply.as_str()));
            assert!(rerun.message.contains(&expected_reply), "{}", rerun.message);
        });
    }

    // ── The grant a commit stamps (task #135 P1) — `config.toml`'s
    // ── `[pairing] defaultGrant`, or this commit's own `--allow`. ────────────

    /// Write a `config.toml` into the sandboxed `AOIDE_ROOT` `with_node_state`
    /// already sets up, so a test can drive the real resolution path rather
    /// than a hand-built `Config`.
    fn write_config(body: &str) {
        std::fs::write(aoide_storage::fs::root().join(aoide_storage::config::CONFIG_FILE), body).unwrap();
    }

    fn approve_the_one_inbound(now_epoch: i64, grant: Option<&[String]>) -> Outcome {
        let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
        let (entry, sas) = parked_revealed_inbound(now_epoch);
        let id = entry.id.clone();
        approve_inbound(CodeGate::Code(sas), "pair", &id, entry, &now, now_epoch, grant)
    }

    #[test]
    fn a_first_pairing_stamps_the_configs_default_grant_not_a_literal() {
        with_node_state("grant-config-default", || {
            // No config.toml at all — the built-in default, which task #135
            // P1 narrowed from ["read","spawn"] to ["read"].
            let out = approve_the_one_inbound(1_700_000_000, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(aoide_storage::node_store::load_nodes()[0].allows, vec!["read".to_string()]);
            assert!(out.message.contains("granted read"), "the commit says what it granted: {}", out.message);
        });
        with_node_state("grant-config-widened", || {
            write_config("[pairing]\ndefaultGrant = [\"read\", \"spawn\"]\n");
            let out = approve_the_one_inbound(1_700_000_000, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(
                aoide_storage::node_store::load_nodes()[0].allows,
                vec!["read".to_string(), "spawn".to_string()],
                "an operator who widened defaultGrant gets the wider set, with no code change and no rebuild"
            );
        });
    }

    #[test]
    fn allow_overrides_the_config_default_for_this_one_pairing() {
        with_node_state("grant-allow-override", || {
            write_config("[pairing]\ndefaultGrant = [\"read\"]\n");
            let out = approve_the_one_inbound(1_700_000_000, Some(&["read".to_string(), "spawn".to_string()]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(aoide_storage::node_store::load_nodes()[0].allows, vec!["read".to_string(), "spawn".to_string()]);
            assert!(out.message.contains("granted read, spawn"), "{}", out.message);

            // Nothing persisted it: the config is untouched, so the NEXT
            // pairing is back to the declared default (the User's decision —
            // the grant stays attached to a live human at commit time).
            assert_eq!(aoide_storage::config::load().unwrap().config.pairing.default_grant, vec!["read".to_string()]);
        });
    }

    /// The half an operator is most likely to get wrong: `--allow` on a
    /// RE-pairing looks like it widens a live node and does not.
    #[test]
    fn re_pairing_never_regrants_and_the_message_says_so() {
        with_node_state("grant-repair-unchanged", || {
            let now_epoch = 1_700_000_000_i64;
            approve_the_one_inbound(now_epoch, None);
            assert_eq!(aoide_storage::node_store::load_nodes()[0].allows, vec!["read".to_string()]);

            // Same box pairs again (a key rotation) and this operator types
            // the wider grant.
            let out = approve_the_one_inbound(now_epoch, Some(&["read".to_string(), "spawn".to_string()]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(
                aoide_storage::node_store::load_nodes()[0].allows,
                vec!["read".to_string()],
                "an already-verified node's grant survives a re-pair untouched — a revoked spawn stays revoked"
            );
            assert!(out.message.contains("grant unchanged"), "a --allow that did nothing must never be silent: {}", out.message);
            assert!(out.message.contains("node allow"), "and it names the command that does change a live grant: {}", out.message);
        });
    }

    #[test]
    fn a_malformed_config_refuses_the_commit_rather_than_guessing_a_grant() {
        with_node_state("grant-config-malformed", || {
            write_config("[pairing]\ndefaultGrant = [\"read\", \"root\"]\n");
            let out = approve_the_one_inbound(1_700_000_000, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert!(out.message.contains("root"), "the refusal names the offending value: {}", out.message);
            assert!(out.message.contains("--allow"), "and the way past it: {}", out.message);
            assert!(
                aoide_storage::node_store::load_nodes().is_empty(),
                "nothing is committed on an unresolvable grant — a grants file that cannot be read must not fall back to a default"
            );
        });
    }

    #[test]
    fn allow_parses_the_same_closed_vocabulary_config_set_does() {
        let mut inv = pair_approve_inv(&[]);
        assert_eq!(parse_allow_flag(&inv).unwrap(), None, "absent means `use the config`, never the empty grant");

        inv.flags.insert("allow".to_string(), "read,spawn".to_string());
        assert_eq!(parse_allow_flag(&inv).unwrap(), Some(vec!["read".to_string(), "spawn".to_string()]));

        inv.flags.insert("allow".to_string(), " read , spawn ".to_string());
        assert_eq!(parse_allow_flag(&inv).unwrap(), Some(vec!["read".to_string(), "spawn".to_string()]), "spacing is an operator's, not a value");

        inv.flags.insert("allow".to_string(), String::new());
        assert_eq!(parse_allow_flag(&inv).unwrap(), Some(Vec::new()), "`--allow \"\"` is `grant nothing`, a real intent");

        inv.flags.insert("allow".to_string(), "read,root".to_string());
        let err = parse_allow_flag(&inv).unwrap_err();
        assert!(err.contains("root"), "an unknown capability is refused BY NAME: {err}");
    }

    fn pair_approve_inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["node".to_string(), "pair".to_string(), "approve".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        }
    }

    /// P-PV1 (task #131), change (c): a parked entry carrying the wire's
    /// `selfVia` claim commits `{url: loopback-as-seen-from-the-far-side,
    /// via: the claim itself}` — never `entry.url` (the requester-observed
    /// host the approver can never dial directly through the tunnel that
    /// delivered this very request). The sakaki/chiyo/osaka rows in
    /// production `nodes.json` are this exact shape, hand-derived before
    /// this fix existed.
    #[test]
    fn approve_inbound_records_loopback_url_and_claimed_via_when_self_via_present() {
        with_node_state("approve-inbound-self-via-present", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound_with_self_via(now_epoch, Some("ssh://khoa@box-a"));
            let id = entry.id.clone();

            let out = approve_inbound(CodeGate::Code(sas), "pair", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            // The fixture's own url (`http://box-a:8710/`) happens to carry
            // the house default port too — `approve_inbound_records_the_
            // requesters_own_port_parsed_from_entry_url` below is the test
            // that actually proves this is parsed off entry.url and not
            // this box's own `AOIDE_A2A_PORT`, by using a DIFFERENT port.
            assert_eq!(nodes[0].url, format!("http://127.0.0.1:{}/", default_a2a_port()), "the claim's presence rewrites the record to the loopback-as-seen-from-the-far-side convention, never entry.url");
            assert_eq!(nodes[0].via.as_deref(), Some("ssh://khoa@box-a"), "via is the claim itself, committed in the same write");
        });
    }

    /// Review finding (high): the first pass of the loopback rewrite read
    /// THIS box's own `AOIDE_A2A_PORT`/default, which has no relation to
    /// the REQUESTER's actual door port — `entry.url` (the requester's own
    /// `self_url`) already encodes it. A distinct, non-default port here
    /// (`9999`, deliberately unequal to `default_a2a_port()`'s `8710`)
    /// proves the commit parses `entry.url`'s own port rather than
    /// defaulting to this box's.
    #[test]
    fn approve_inbound_records_the_requesters_own_port_parsed_from_entry_url() {
        with_node_state("approve-inbound-self-via-nondefault-port", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) =
                parked_revealed_inbound_with_self_via_and_url(now_epoch, Some("ssh://khoa@box-a"), "http://box-a:9999/");
            let id = entry.id.clone();
            assert_ne!(9999, default_a2a_port(), "the fixture port must differ from the default for this test to prove anything");

            let out = approve_inbound(CodeGate::Code(sas), "pair", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].url, "http://127.0.0.1:9999/", "the loopback rewrite must carry the REQUESTER's own door port, parsed from entry.url, never this box's own AOIDE_A2A_PORT/default");
        });
    }

    /// The mirror of the test above: no `selfVia` claim on the parked entry
    /// (an old requester, or one with nothing to claim) commits EXACTLY
    /// today's shape — `entry.url` verbatim, `via` left absent. No
    /// regression on the ordinary direct-LAN case.
    #[test]
    fn approve_inbound_leaves_todays_shape_when_self_via_absent() {
        with_node_state("approve-inbound-self-via-absent", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound(now_epoch);
            let entry_url = entry.url.clone();
            let id = entry.id.clone();

            let out = approve_inbound(CodeGate::Code(sas), "pair", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let nodes = aoide_storage::node_store::load_nodes();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].url, entry_url, "no claim — url is entry.url verbatim, exactly today's behavior");
            assert!(nodes[0].via.is_none(), "no claim — via stays absent, exactly today's behavior");
        });
    }

    #[test]
    fn approve_inbound_refuses_where_no_code_can_be_collected_and_counts_no_try() {
        with_node_state("approve-inbound-no-code", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();

            let out = approve_inbound(CodeGate::Unavailable, "pair", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains("--code"), "the refusal teaches the scripted spelling: {}", out.message);
            assert_eq!(aoide_storage::pairing::list_inbound(now_epoch)[0].tries, 0, "a refusal is not a wrong code");
        });
    }

    fn pair_inv(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["pair".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    /// The dispatch's own gate resolution, driven through the real
    /// [`handle_pair`]: `--yes` on an inbound target maps to the taught
    /// refusal (never a bypass), and so does a bare non-tty CLI invocation
    /// (cargo test's stdio is never a terminal — the exact non-tty shape a
    /// scripted caller hits).
    #[test]
    fn pair_on_an_inbound_target_refuses_yes_and_non_tty_without_code() {
        with_node_state("approve-inbound-handler-gate", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, _sas) = parked_revealed_inbound(now_epoch);

            for flags in [vec![("yes", "true")], vec![]] {
                let out = handle_pair(&pair_inv(&[&entry.id], &flags));
                assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
                assert!(out.message.contains("--code"), "{}", out.message);
            }
        });
    }

    /// [`pair_on_an_inbound_target_refuses_yes_and_non_tty_without_code`]'s
    /// exact mirror on the REQUESTER'S own leg (the mutual-code redesign,
    /// R1): `--yes` maps to the SAME taught refusal on an outbound
    /// completion, never a bypass — the entry is already `AwaitingConfirm`
    /// (a poll already released it) so `--wait 0` reaches
    /// [`commit_outbound`]'s own gate with no network call at all.
    #[test]
    fn pair_on_an_outbound_target_refuses_yes_and_non_tty_without_code() {
        with_node_state("resume-outbound-handler-gate", || {
            let pubkey_b = "b".repeat(64);
            let mut entry = sample_outbound_awaiting_approval("deadbeef", "http://box-b/", &pubkey_b);
            entry.state = aoide_storage::pairing::OutboundState::AwaitingConfirm;
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();

            for flags in [vec![("yes", "true"), ("wait", "0")], vec![("wait", "0")]] {
                let out = handle_pair(&pair_inv(&[&entry.id], &flags));
                assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
                assert!(out.message.contains("--code"), "{}", out.message);
            }
            assert!(aoide_storage::node_store::load_nodes().is_empty(), "a refusal must never commit");
        });
    }

    /// Bare `pair` off a tty is the pending LISTING, not a hang and not a
    /// refusal (task #135 P3' — the old `node pending`, which died into
    /// this): a non-CLI door, a `--json` ask, and a non-tty CLI invocation
    /// all get the listing instantly, before any sweep could run — the
    /// machine face agents drive.
    #[test]
    fn bare_pair_off_a_tty_is_the_pending_listing_never_a_menu() {
        with_node_state("bare-pair-listing", || {
            let inv = |door, flags: &[(&str, &str)]| Invocation {
                path: vec!["pair".into()],
                args: vec![],
                flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                door,
            };
            for (invocation, why) in [
                (inv(aoide_protocol::Door::Mcp, &[]), "non-CLI door"),
                (inv(aoide_protocol::Door::A2a, &[]), "non-CLI door"),
                (inv(aoide_protocol::Door::Cli, &[("json", "true")]), "--json"),
                (inv(aoide_protocol::Door::Cli, &[]), "non-tty CLI (test harness stdio)"),
            ] {
                let out = handle_pair(&invocation);
                assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{why}: {out:?}");
                assert!(out.data.as_ref().and_then(|d| d.get("requests")).is_some(), "{why}: the listing carries `requests`: {out:?}");
            }

            // And it lists what is actually pending, both directions.
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            let out = handle_pair(&pair_inv(&[], &[]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            let rows = out.data.as_ref().unwrap()["requests"].as_array().unwrap().clone();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["id"].as_str(), Some(entry.id.as_str()));
        });
    }

    /// Idempotency survives the gate swap: an ALREADY-approved inbound
    /// entry short-circuits to the no-op success before any gate is
    /// consulted, so a re-run (scripted or not) never trips the refusal.
    #[test]
    fn pair_on_an_already_approved_inbound_target_is_still_a_no_op_success() {
        with_node_state("approve-inbound-idempotent", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            aoide_storage::pairing::mark_inbound_approved(&entry.id, now_epoch).unwrap();

            let out = handle_pair(&pair_inv(&[&entry.id], &[("yes", "true")]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("alreadyApproved")).and_then(Value::as_bool), Some(true));
        });
    }

    // ── Task #135 P3': the ONE-command dispatch ───────────────────────────

    /// `pair <name>` routes to the pending INBOUND request under that name
    /// — the collapse's whole point: no separate approve spelling, and the
    /// scripted `--code` rides the same command.
    #[test]
    fn pair_routes_a_name_to_its_pending_inbound_request() {
        with_node_state("pair-routes-name-inbound", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, sas) = parked_revealed_inbound(now_epoch);

            let out = handle_pair(&pair_inv(&[&entry.name], &[("code", &sas)]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("node")).and_then(Value::as_str), Some(entry.name.as_str()));
            assert!(aoide_storage::node_store::load_nodes()[0].verified, "the routed approve really commits");
        });
    }

    /// A name matching MORE than one pending request (either direction) is
    /// refused with every id listed — never a silent guess at which one the
    /// operator meant. An exact ID always routes unambiguously, which is
    /// why this family's own messages print ids.
    #[test]
    fn pair_refuses_an_ambiguous_name_listing_the_ids() {
        with_node_state("pair-ambiguous-name", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (inbound_entry, sas) = parked_revealed_inbound(now_epoch);
            let pubkey_b = "b".repeat(64);
            // An OUTBOUND entry under the SAME name — the box we asked is
            // also asking us, the exact crossing the ambiguity guard exists
            // for.
            let mut outbound = sample_outbound_awaiting_approval("deadbeef", "http://box-b/", &pubkey_b);
            outbound.name = inbound_entry.name.clone();
            aoide_storage::pairing::park_outbound(outbound).unwrap();

            let out = handle_pair(&pair_inv(&[&inbound_entry.name], &[]));
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains(&inbound_entry.id), "{}", out.message);
            assert!(out.message.contains("deadbeef"), "{}", out.message);
            let ids = out.data.as_ref().and_then(|d| d.get("ids")).and_then(Value::as_array).cloned().unwrap_or_default();
            assert_eq!(ids.len(), 2, "{out:?}");

            // The exact id still routes past the ambiguity.
            let out = handle_pair(&pair_inv(&[&inbound_entry.id], &[("code", &sas)]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        });
    }

    /// `pair <name>` on an ALREADY-verified node with nothing pending is
    /// gated (task #135 P3' — a re-pair replaces key material, and the
    /// smart command makes accidental invocation likely): off a tty and
    /// without `--yes` it refuses by name; `--yes` proceeds into the
    /// ordinary request arm (proven by reaching the sweep's own no-match).
    #[test]
    fn pair_on_an_already_verified_name_is_gated_before_any_request() {
        with_node_state("pair-repair-gate", || {
            let mut nodes = Vec::new();
            aoide_storage::node_store::upsert_paired_node(&mut nodes, "box-v", "http://box-v:8710/", &"a".repeat(64), "2026-08-30T00:00:00Z", &["read".to_string()]);
            aoide_storage::node_store::save_nodes(&nodes).unwrap();

            let out = handle_pair(&pair_inv(&["box-v"], &[]));
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("already-paired"));
            assert!(out.message.contains("--yes"), "the refusal teaches the scripted override: {}", out.message);

            let out = handle_pair(&pair_inv(&["box-v"], &[("yes", "true"), ("secs", "1")]));
            assert_eq!(
                out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str),
                Some("no-match"),
                "--yes must proceed past the gate into the ordinary sweep arm: {out:?}"
            );
        });
    }

    /// The bare `pair` pending listing (P-PV2, the User's locked spec point
    /// 3) NEVER shows the SAS/pairing code — neither in the human message nor anywhere in
    /// the JSON data — for an inbound OR an outbound row, whether revealed,
    /// approved, or freshly parked. The code is read off the requester's
    /// own screen and typed on the approver's; showing it here would defeat
    /// that out-of-band comparison.
    #[test]
    fn node_pending_never_carries_the_sas_code_inbound_or_outbound() {
        with_node_state("pending-no-sas", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (_inbound_entry, inbound_sas) = parked_revealed_inbound(now_epoch);
            let pubkey_b = "b".repeat(64);
            let outbound = sample_outbound_awaiting_approval("deadbeef", "http://box-b/", &pubkey_b);
            let outbound_sas = aoide_storage::pairing::derive_sas(
                &aoide_storage::identity::load_or_mint().unwrap().0.info().pubkey_hex,
                &outbound.pubkey_hex,
                &outbound.requester_nonce_hex,
                &outbound.approver_nonce_hex,
            );
            aoide_storage::pairing::park_outbound(outbound).unwrap();

            let out = pending_listing("pair");
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let rows = out.data.as_ref().unwrap()["requests"].as_array().unwrap();
            assert_eq!(rows.len(), 2, "{rows:?}");
            for row in rows {
                assert!(row.get("sas").is_none(), "the pending listing must never carry a `sas` field: {row}");
            }

            let rendered = serde_json::to_string(out.data.as_ref().unwrap()).unwrap();
            assert!(!rendered.contains(&inbound_sas), "the inbound code must never appear in the pending listing's data: {rendered}");
            assert!(!rendered.contains(&outbound_sas), "the outbound code must never appear in the pending listing's data: {rendered}");
            assert!(!out.message.contains(&inbound_sas), "nor in its human message: {}", out.message);
            assert!(!out.message.contains(&outbound_sas), "nor in its human message: {}", out.message);
        });
    }

    /// `pair <target>` SMART TARGET dispatch (the User's locked spec,
    /// point 1): a URL-shaped target (`"://"`) takes the EXPLICIT DIAL arm
    /// — proven here by its own distinct failure shape (`fetch-failed`,
    /// [`pair_via_url`]'s own reason, no sweep ever runs). A bare word
    /// takes the HOSTNAME arm — proven by ITS distinct failure shape
    /// (`no-match`, [`pair_via_hostname`]'s own reason, naming the sweep
    /// window it actually ran) — never the url arm's reason, and vice
    /// versa.
    #[test]
    fn node_pair_smart_target_dispatches_url_and_hostname_to_different_arms() {
        with_node_state("smart-target-url-arm", || {
            // Port 1 is reserved and never listened on in practice — an
            // immediate, deterministic connection refusal, never a sweep.
            let inv = Invocation {
                path: vec!["pair".into()],
                args: vec!["http://127.0.0.1:1/".to_string()],
                flags: Default::default(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_pair(&inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            let reason = out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str).unwrap_or("");
            assert!(
                matches!(reason, "fetch-failed" | "fetch-http-error" | "unparseable" | "refused" | "no-default-name" | "invalid-name"),
                "a URL target must take the explicit-dial arm, never the sweep arm: {out:?}"
            );
        });

        with_node_state("smart-target-hostname-arm", || {
            // `with_node_state` already holds `crate::env_lock()` for its
            // whole body — the SAME lock every real-sweep test in this
            // module takes (its own doc, `run_sweep_hears_an_advertisement_
            // sent_over_the_real_loopback_stack`'s doc in `discover.rs`); a
            // second `.lock()` here on the same (non-reentrant) mutex, on
            // the SAME thread, would deadlock rather than merely block.
            let inv = Invocation {
                path: vec!["pair".into()],
                args: vec!["nobody-is-advertising-this-name".to_string()],
                flags: [("secs".to_string(), "1".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_pair(&inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(
                out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str),
                Some("no-match"),
                "a bare hostname target must take the sweep arm and refuse with no-match: {out:?}"
            );
            assert!(out.message.contains("1s"), "the refusal names the sweep window actually used: {}", out.message);
        });
    }

    /// Review finding (P-PV2 follow-up): old `node pair request <url>`
    /// muscle memory has no third `node.pair.request` path to greedily
    /// match anymore, so it lands here as `pair`'s OWN two args
    /// (`["request", "<url>"]`) — reading only `args[0]` and discarding the
    /// url would silently burn a full sweep window looking for an
    /// advertiser named "request" before failing with no mention the url
    /// was ever seen. `pair` now refuses ANY second positional
    /// outright — proven here by asserting Usage AND that no sweep or dial
    /// ever ran (no `data.reason` at all: neither arm's error shape, since
    /// neither arm is ever reached). The taught text lives in `USAGE`
    /// itself, shown identically for every arity error — never a special
    /// case keyed on the first arg spelling "request".
    #[test]
    fn pair_refuses_a_second_positional_before_either_arm_runs() {
        let inv = Invocation {
            path: vec!["pair".into()],
            args: vec!["request".to_string(), "http://127.0.0.1:1/".to_string()],
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        };
        let out = handle_pair(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
        assert!(
            out.data.as_ref().and_then(|d| d.get("reason")).is_none(),
            "neither arm's error shape must appear — this refusal fires before either arm ever runs: {out:?}"
        );
        assert!(out.message.contains("usage: aoide pair"), "{}", out.message);
    }

    /// `pair reject`/`pair watch` are SUBCOMMANDS of `pair` and WIN over a
    /// target positional of the same literal spelling — the registry's own
    /// greedy longest-prefix match ([`aoide_protocol::door::parse`])
    /// resolves `aoide pair reject` to the 2-segment subcommand before it
    /// ever considers 1-segment `pair <target>` with `"reject"` riding as
    /// the target; an ordinary name resolves to the smart command instead,
    /// riding as its positional arg. A box literally named "reject" or
    /// "watch" therefore cannot be paired by bare name — it needs the
    /// explicit URL form, documented on `pair`'s own registered usage line.
    #[test]
    fn pair_reject_and_watch_subcommand_names_win_over_a_target_positional() {
        let mut r = Registry::new();
        register_pair(&mut r);
        register_node_discovery(&mut r);

        for sub in ["reject", "watch"] {
            let argv = vec!["pair".to_string(), sub.to_string()];
            let (inv, _json) = aoide_protocol::door::parse(&argv, aoide_protocol::Door::Cli, "aoide", &r)
                .unwrap_or_else(|e| panic!("`pair {sub}` must parse as the subcommand: {e:?}"));
            assert_eq!(inv.path, vec!["pair".to_string(), sub.to_string()], "{sub} must resolve to the subcommand, not a target");
        }

        // An ordinary name (no collision) resolves to the smart command, with
        // the word riding as its own positional arg.
        let argv = vec!["pair".to_string(), "yomi-strix".to_string()];
        let (inv, _json) = aoide_protocol::door::parse(&argv, aoide_protocol::Door::Cli, "aoide", &r).unwrap();
        assert_eq!(inv.path, vec!["pair".to_string()]);
        assert_eq!(inv.args, vec!["yomi-strix".to_string()]);
    }

    // ── `aoide mail` (P-M1/P-M2) — moved here from `aoide-storage` at P-M2
    // ── (ruling 1); `--to <node>/<name>` and `mail outbox[.rm]` are new. ────

    fn mail_inv(path: &[&str], args: &[&str]) -> Invocation {
        aoide_test_support::inv(path, args)
    }
    fn mail_inv_with_flag(path: &[&str], args: &[&str], flag: &str) -> Invocation {
        let mut i = mail_inv(path, args);
        i.flags.insert(flag.to_string(), String::new());
        i
    }
    fn mail_inv_with_flags(path: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        let mut i = mail_inv(path, args);
        for (k, v) in flags {
            i.flags.insert(k.to_string(), v.to_string());
        }
        i
    }

    /// A verified node at a URL nothing ever listens on (`http://127.0.0.1:1`,
    /// the codebase's established dead-loopback-port fixture) — for tests
    /// that need `mail send`'s node branch to get PAST the verified check
    /// and actually attempt (and fail fast at) a real drain dial.
    fn verified_node(name: &str, url: &str) -> aoide_storage::node_store::Node {
        aoide_storage::node_store::Node {
            name: name.to_string(),
            url: url.to_string(),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: true,
            allows: vec!["message".to_string()],
            via: None,
            added_at: "2026-09-07T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn register_mail_wires_all_nine_commands() {
        let mut r = Registry::new();
        register_mail(&mut r);
        let paths: Vec<String> = r.commands().map(|c| c.dotted()).collect();
        for want in ["mail", "mail.send", "mail.read", "mail.show", "mail.mark", "mail.rm", "mail.outbox", "mail.outbox.rm", "mail.outbox.retry"] {
            assert!(paths.contains(&want.to_string()), "missing {want}");
        }
    }

    #[test]
    fn structured_mail_send_files_signed_to_and_cc_once_with_local_aliases() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("structured-mail-real-send");
        let local = aoide_storage::display::local_host_name();
        let (key, _) = aoide_storage::identity::load_or_mint().unwrap();
        let mut nodes = Vec::new();
        aoide_storage::node_store::upsert_paired_node(&mut nodes, &local, "http://localhost", &key.info().pubkey_hex, "2026-09-13T00:00:00Z", &["message".into()]);
        aoide_storage::node_store::save_nodes(&nodes).unwrap();
        let recipient = format!("{local}/primary");
        let copies = format!("self/copy,{local}/copy,self/primary");
        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["message\nbody"], &[("to", &recipient), ("cc", &copies), ("subject", "Signed subject"), ("from", "human")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["accepted"], 2);
        assert_eq!(data["recipients"].as_array().unwrap().len(), 2);
        for name in ["primary", "copy"] {
            let entries = aoide_storage::mail::read_for(name, true, None).unwrap();
            assert_eq!(entries.len(), 1, "one durable copy per endpoint");
            let envelope = &entries[0].envelope;
            assert_eq!(envelope.header.to.node, local);
            assert_eq!(envelope.header.to.name, name);
            assert!(aoide_storage::mail::verify_origin_signature(envelope));
            let content = aoide_storage::letter::decode(&envelope.text).unwrap();
            assert_eq!(content.subject, "Signed subject");
            assert_eq!(content.body, "message\nbody");
            assert_eq!(content.to.len(), 1);
            assert_eq!(content.cc.len(), 1);
            let mut tampered = envelope.clone();
            tampered.text = tampered.text.replace("Signed subject", "Forged subject");
            assert!(!aoide_storage::mail::verify_origin_signature(&tampered));
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mail_send_requires_to_and_text() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-usage");

        let out = handle_mail_send(&mail_inv(&["mail", "send"], &["hello"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "missing --to");

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &[], &[("to", "self/conductor")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "missing text");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_send_to_self_files_a_letter_and_shows_up_unread() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-ok");

        let out = handle_mail_send(&mail_inv_with_flags(
            &["mail", "send"],
            &["build", "finished", "ok"],
            &[("to", "self/conductor")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["envelope"]["text"], "build finished ok", "args after -- join with spaces");
        assert!(!data["envelope"]["msgid"].as_str().unwrap().is_empty());

        let names = handle_mail_names(&mail_inv(&["mail"], &[]));
        assert_eq!(names.data.unwrap()["names"], json!(["conductor"]));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// P-M5a-2: this crate cannot see `aoide-conduct` (the DAG constraint
    /// `pkgs/aoide/crates/AGENTS.md` documents), so a self-filed letter's
    /// ring can only ever be FORWARDED, through `daemon_dispatch` — never
    /// run in-process the way `aoide-server`'s own deposit handler runs it.
    /// `isolated_mail_root` pins `AOIDE_DAEMON_SOCKET` at a path nothing
    /// binds, so this is the ordinary (no resident daemon) case: filing
    /// still succeeds, and the reported `ring` is the literal string
    /// `"no-daemon"` — never an error, never silently dropped.
    #[test]
    fn mail_send_to_self_reports_no_daemon_without_ringing() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-ring-no-daemon");

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "self/conductor")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.unwrap()["ring"], json!("no-daemon"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other half: a resident daemon IS reachable, so the self branch
    /// forwards a real `mail ring --for <name>` dispatch request through it
    /// (`crate::daemon::daemon_dispatch`) rather than ringing in-process —
    /// proven the same way `daemon.rs`'s own
    /// `daemon_dispatch_round_trips_against_a_fake_daemon` proves an
    /// ordinary forwarded dispatch: a real `UnixListener` standing in for
    /// the daemon, read back and asserted on directly.
    #[test]
    fn mail_send_to_self_forwards_a_ring_through_the_daemon() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-ring-daemon");

        let socket_path = root.join("fake-daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        std::env::set_var("AOIDE_DAEMON_SOCKET", &socket_path);

        let handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap();
            let req: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
            assert_eq!(req["op"], "dispatch");
            assert_eq!(req["path"], json!(["mail", "ring"]));
            assert_eq!(req["flags"]["for"], "conductor");
            let outcome = aoide_protocol::output::Outcome::ok("mail.ring", "rang 0 reader(s) for conductor").with_data(json!({
                "name": "conductor",
                "rung": Vec::<String>::new(),
                "deferred": Vec::<(String, String)>::new(),
                "skipped": Vec::<(String, String)>::new(),
            }));
            let reply = json!({ "outcome": outcome });
            let mut line = reply.to_string();
            line.push('\n');
            conn.write_all(line.as_bytes()).unwrap();
            req
        });

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "self/conductor")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["ring"]["name"], "conductor");
        assert_eq!(data["ring"]["rung"], json!([]));

        let req = handle.join().unwrap();
        assert_eq!(req["path"], json!(["mail", "ring"]), "forwards `mail ring`, never rings in-process");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// P-M2's replacement for P-M1's `mail_send_rejects_a_non_self_node`
    /// (deleted — a non-self node is no longer a blanket rejection, it is
    /// the whole point of this phase). Covers both ways a node fails the
    /// check: never registered at all, and registered but never paired —
    /// either refuses BEFORE anything touches the outbox.
    #[test]
    fn mail_send_to_an_unverified_node_refuses_before_spooling() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-unverified");

        let mut peer = fixture_node(None);
        peer.name = "unpaired-peer".into();
        aoide_storage::node_store::save_nodes(&[peer]).unwrap(); // registered, `verified: false`

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "unpaired-peer/bob")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "registered but never paired — refused, not spooled");
        assert_eq!(out.data.unwrap()["reason"], "unpaired-node");
        assert!(aoide_storage::outbox::list_entries("unpaired-peer").unwrap().is_empty(), "nothing spooled before the refusal");

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "ghost/bob")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "never registered at all — same refuse-before-spool shape");
        assert_eq!(out.data.unwrap()["reason"], "unknown-node");
        assert!(aoide_storage::outbox::list_entries("ghost").unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_send_to_an_invalid_name_is_refused_with_reason_invalid_name() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-invalid-name");

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "self/Bob")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "msg: {}", out.message);
        assert!(!out.message.contains("Bob"), "the offending bytes must never be echoed");
        assert_eq!(out.data.unwrap()["reason"], "invalid-name");

        let names = handle_mail_names(&mail_inv(&["mail"], &[]));
        assert_eq!(names.data.unwrap()["names"], json!([]), "a refused name must never be filed");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_send_to_a_verified_node_writes_the_entry_before_attempting_delivery() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-verified");

        aoide_storage::node_store::save_nodes(&[verified_node("osaka", "http://127.0.0.1:1/")]).unwrap();

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi", "osaka"], &[("to", "osaka/bob")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "the WRITE succeeding is what this command reports, msg: {}", out.message);

        let spooled = aoide_storage::outbox::list_entries("osaka").unwrap();
        assert_eq!(spooled.len(), 1, "the entry is written even though osaka's own address (127.0.0.1:1) refuses every connection");
        assert_eq!(spooled[0].envelope.text, "hi osaka");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_outbox_reports_waiting_tries_and_last_outcome_per_entry() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-outbox-report");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let mut entry = aoide_storage::outbox::OutboxEntry::fresh(envelope);
        entry.tries = 2;
        entry.last_try_at = "2026-09-07T00:00:00Z".to_string();
        entry.last_outcome = "transport-error: HTTP 0".to_string();
        aoide_storage::outbox::write_entry("osaka", &entry).unwrap();

        let out = handle_mail_outbox(&mail_inv(&["mail", "outbox"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let entries = out.data.unwrap()["entries"].as_array().unwrap().clone();
        assert_eq!(entries.len(), 1, "the one entry spooled is still waiting — a retired entry is never listed");
        assert_eq!(entries[0]["node"], "osaka");
        assert_eq!(entries[0]["tries"], 2);
        assert_eq!(entries[0]["lastOutcome"], "transport-error: HTTP 0");

        let filtered = handle_mail_outbox(&mail_inv(&["mail", "outbox"], &["osaka"]));
        assert_eq!(filtered.data.unwrap()["entries"].as_array().unwrap().len(), 1, "filtering to the one node with anything waiting still finds it");

        let missing = handle_mail_outbox(&mail_inv(&["mail", "outbox"], &["nobody"]));
        assert!(missing.data.unwrap()["entries"].as_array().unwrap().is_empty(), "a node with nothing waiting reports an empty list, not an error");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_outbox_json_carries_a_per_node_summary() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-outbox-summary");

        let fresh = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        aoide_storage::outbox::write_entry("osaka", &aoide_storage::outbox::OutboxEntry::fresh(fresh)).unwrap();

        let mut retried = aoide_storage::outbox::OutboxEntry::fresh(
            aoide_storage::mail::mint_outbound_letter("here", "osaka", "carol", "hi again").unwrap(),
        );
        retried.tries = 3;
        retried.last_outcome = "transport: HTTP 0".to_string();
        aoide_storage::outbox::write_entry("osaka", &retried).unwrap();

        let mut refused = aoide_storage::outbox::OutboxEntry::fresh(
            aoide_storage::mail::mint_outbound_letter("here", "osaka", "dave", "bad").unwrap(),
        );
        refused.tries = 1;
        refused.refused = true;
        refused.last_outcome = "refused: bad-msgid".to_string();
        aoide_storage::outbox::write_entry("osaka", &refused).unwrap();

        let out = handle_mail_outbox(&mail_inv(&["mail", "outbox"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.unwrap();
        let summary = &data["summary"]["osaka"];
        assert_eq!(summary["depth"], 3, "three entries spooled for osaka");
        assert_eq!(summary["refused"], 1, "exactly one entry is parked refused");
        assert_eq!(summary["tries"]["0"], 1, "one entry never attempted");
        assert_eq!(summary["tries"]["1"], 1, "one entry attempted once (the refused one)");
        assert_eq!(summary["tries"]["3"], 1, "one entry attempted three times");
        assert_eq!(summary["lastOutcomeCounts"]["(none)"], 1, "the fresh entry has no recorded outcome yet");
        assert_eq!(summary["lastOutcomeCounts"]["transport: HTTP 0"], 1);
        assert_eq!(summary["lastOutcomeCounts"]["refused: bad-msgid"], 1);
        assert!(summary["oldestMintedAtAgeSecs"].as_i64().unwrap() >= 0, "a freshly minted entry's age is never negative");

        assert!(data["summary"]["nobody"].is_null(), "a node nobody spooled to never appears in the summary");

        // Review round 2: an EXPLICITLY named node (`mail outbox <node>`)
        // with an empty outbox gets no summary entry either — the key set
        // means the same thing regardless of which listing shape produced
        // it (CONTRACTS.md delta point 3).
        let explicit_empty = handle_mail_outbox(&mail_inv(&["mail", "outbox", "nobody"], &[]));
        assert_eq!(explicit_empty.status, aoide_protocol::output::Status::Ok, "msg: {}", explicit_empty.message);
        assert!(
            explicit_empty.data.unwrap()["summary"]["nobody"].is_null(),
            "naming an empty node explicitly still gets no summary entry"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `delivery_projection` (the outbox/link-state join, MAIL.md
    // ── "Status and the nodelist view") and its two callers. ─────────────

    #[test]
    fn delivery_projection_reports_retrying_when_the_link_records_a_failure() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-retrying");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let entry = aoide_storage::outbox::OutboxEntry::fresh(envelope);
        let link = aoide_storage::outbox::LinkState {
            backoff_secs: 12,
            next_attempt_at: "2026-09-07T00:01:00Z".to_string(),
            last_outcome: "curl failed".to_string(),
        };

        let d = delivery_projection(&[], "osaka", &entry, Some(&link));
        assert_eq!(d["status"], "retrying");
        assert_eq!(d["reason"], "curl failed");
        assert_eq!(d["reasonScope"], "link");
        assert_eq!(d["nextAttemptAt"], "2026-09-07T00:01:00Z");
        assert_eq!(d["ackPending"], false);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delivery_projection_a_held_off_link_leaves_the_second_entrys_own_tries_untouched() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-two-entries-held-off");

        let env1 = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "one").unwrap();
        let mut entry1 = aoide_storage::outbox::OutboxEntry::fresh(env1);
        entry1.tries = 1; // the first entry a drain actually reached before the link failed
        let env2 = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "two").unwrap();
        let entry2 = aoide_storage::outbox::OutboxEntry::fresh(env2); // never attempted this pass

        aoide_storage::outbox::back_off("osaka", 1_000, "transport-error: connection refused").unwrap();
        let link = aoide_storage::outbox::read_link_state("osaka").unwrap();

        let d1 = delivery_projection(&[], "osaka", &entry1, link.as_ref());
        let d2 = delivery_projection(&[], "osaka", &entry2, link.as_ref());
        assert_eq!(d1["status"], "retrying");
        assert_eq!(d2["status"], "retrying");
        assert_eq!(d1["reason"], d2["reason"], "both entries reflect the SAME shared node link, never a per-entry reason");
        assert_eq!(entry2.tries, 0, "a held-off link means the second entry was never individually attempted — no fake per-entry attempts");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delivery_projection_refused_wins_over_a_failing_link() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-refused-wins");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let mut entry = aoide_storage::outbox::OutboxEntry::fresh(envelope);
        entry.refused = true;
        entry.tries = 1;
        entry.last_outcome = "refused: bad-msgid: envelope msgid does not match".to_string();

        aoide_storage::outbox::back_off("osaka", 1_000, "transport-error: HTTP 500").unwrap();
        let link = aoide_storage::outbox::read_link_state("osaka").unwrap();

        let d = delivery_projection(&[], "osaka", &entry, link.as_ref());
        assert_eq!(d["status"], "refused", "a policy refusal wins over an unrelated link failure");
        assert_eq!(d["reason"], "refused: bad-msgid: envelope msgid does not match");
        assert_eq!(d["reasonScope"], "entry");
        assert_eq!(d["nextAttemptAt"], Value::Null);
        assert_eq!(d["ackPending"], false);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delivery_projection_accepted_keeps_ack_pending_and_a_later_link_failure_rides_beside_it() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-accepted-then-link-fails");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let mut entry = aoide_storage::outbox::OutboxEntry::fresh(envelope);
        entry.tries = 1;
        entry.last_outcome = "accepted".to_string();

        let clean = delivery_projection(&[], "osaka", &entry, None);
        assert_eq!(clean["status"], "accepted");
        assert_eq!(clean["ackPending"], true);
        assert_eq!(clean["reason"], Value::Null);

        // A LATER, unrelated letter to the same node fails transport-wise,
        // backing off the LINK — this entry's own evidence must not be
        // downgraded by it.
        aoide_storage::outbox::back_off("osaka", 2_000, "transport-error: HTTP 0").unwrap();
        let link = aoide_storage::outbox::read_link_state("osaka").unwrap();
        let later = delivery_projection(&[], "osaka", &entry, link.as_ref());
        assert_eq!(later["status"], "accepted", "never downgraded by an unrelated later link failure");
        assert_eq!(later["ackPending"], true);
        assert_eq!(later["reason"], "transport-error: HTTP 0");
        assert_eq!(later["reasonScope"], "link");
        assert!(later["nextAttemptAt"].as_str().is_some(), "the link's own nextAttemptAt still rides beside it");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn delivery_projection_drops_the_reason_once_a_retry_clears_the_link() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-retry-clears-link");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let mut entry = aoide_storage::outbox::OutboxEntry::fresh(envelope);
        entry.last_outcome = "accepted".to_string();

        aoide_storage::outbox::back_off("osaka", 3_000, "transport-error: timeout").unwrap();
        aoide_storage::outbox::clear_link_state("osaka").unwrap(); // the retry succeeded
        let link = aoide_storage::outbox::read_link_state("osaka").unwrap();
        assert!(link.is_none());

        let d = delivery_projection(&[], "osaka", &entry, link.as_ref());
        assert_eq!(d["status"], "accepted", "the entry's own outcome still stands");
        assert_eq!(d["reason"], Value::Null, "no stale link reason survives a cleared link");
        assert_eq!(d["nextAttemptAt"], Value::Null);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// MAIL.md's "never inferred" rule pinned from BOTH failure shapes: an
    /// ack that fails [`aoide_storage::mail::verify_origin_signature`]'s
    /// own "no key on record for the claimed origin" bucket (the same
    /// collapse-to-false `mail.rs`'s own
    /// `origin_verification_is_bound_to_the_key_on_record_for_from_node`
    /// pins at the storage layer), and one whose `msgid` no longer
    /// recomputes after tampering — [`aoide_storage::mail::deposit`] must
    /// refuse to file EITHER, so [`has_delivered_ack`] never finds one to
    /// report.
    #[test]
    fn delivery_projection_never_reports_delivered_from_an_unverified_or_malformed_ack() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-ack-validation");

        let node_name = aoide_storage::display::local_host_name();
        let letter = aoide_storage::mail::mint_outbound_letter("here", &node_name, "bob", "hi").unwrap();
        let msgid = letter.msgid.clone();
        let entry = aoide_storage::outbox::OutboxEntry::fresh(letter);
        aoide_storage::outbox::write_entry(&node_name, &entry).unwrap();

        // No node is ever registered here, so `verify_origin_signature`
        // finds no key on record for `node_name` at all — a genuinely
        // signed ack still refuses as `UnverifiedOrigin`.
        let to = aoide_storage::mail::Address { node: "origin".to_string(), name: "alice".to_string() };
        let wrong_origin_ack = aoide_storage::mail::mint_ack("bob", to.clone(), &msgid).unwrap();
        let outcome = aoide_storage::mail::deposit(wrong_origin_ack, "test").unwrap();
        assert_eq!(outcome, aoide_storage::mail::DepositOutcome::UnverifiedOrigin);
        let base = aoide_storage::mail::read_base().unwrap();
        assert_ne!(delivery_projection(&base, &node_name, &entry, None)["status"], "delivered");

        // Tampering `text` after sealing breaks the msgid recompute —
        // refused before origin is even checked.
        let mut tampered = aoide_storage::mail::mint_ack("bob", to, &msgid).unwrap();
        tampered.text = "not-the-real-msgid".to_string();
        let outcome = aoide_storage::mail::deposit(tampered, "test").unwrap();
        assert_eq!(outcome, aoide_storage::mail::DepositOutcome::BadMsgid);
        let base = aoide_storage::mail::read_base().unwrap();
        assert_ne!(delivery_projection(&base, &node_name, &entry, None)["status"], "delivered");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The positive half of the ack check: under normal operation
    /// [`aoide_storage::outbox::retire_by_ack`] removes the entry the
    /// INSTANT a genuine ack lands (`server::a2a::mail_deposit`'s
    /// `Filed{kind: RECEIPT}` arm), so this exact combination — the entry
    /// still spooled AND a verified ack for it already filed — only ever
    /// arises if that removal step lags or fails; `delivery_projection`
    /// must still get it right when it does, and must prefer it over a
    /// merely-`accepted` `last_outcome` already sitting on the entry.
    #[test]
    fn delivery_projection_reports_delivered_over_a_stale_accepted_outcome_once_a_genuine_ack_lands() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-genuine-ack");

        let node_name = aoide_storage::display::local_host_name();
        let (kp, _) = aoide_storage::identity::load_or_mint().unwrap();
        let mut nodes = Vec::new();
        aoide_storage::node_store::upsert_paired_node(
            &mut nodes,
            &node_name,
            "https://irrelevant.example",
            &kp.info().pubkey_hex,
            "2026-09-07T00:00:00Z",
            &[],
        );
        aoide_storage::node_store::save_nodes(&nodes).unwrap();

        let letter = aoide_storage::mail::mint_outbound_letter("here", &node_name, "bob", "hi").unwrap();
        let msgid = letter.msgid.clone();
        let mut entry = aoide_storage::outbox::OutboxEntry::fresh(letter);
        entry.tries = 1;
        entry.last_outcome = "accepted".to_string(); // the earlier successful POST
        aoide_storage::outbox::write_entry(&node_name, &entry).unwrap();

        let to = aoide_storage::mail::Address { node: "wherever".to_string(), name: "bob".to_string() };
        let ack = aoide_storage::mail::mint_ack("bob", to, &msgid).unwrap();
        let outcome = aoide_storage::mail::deposit(ack, "test").unwrap();
        assert!(matches!(outcome, aoide_storage::mail::DepositOutcome::Filed { .. }), "a genuine, verified ack must file");

        let base = aoide_storage::mail::read_base().unwrap();
        let d = delivery_projection(&base, &node_name, &entry, None);
        assert_eq!(d["status"], "delivered", "a real ack beats the stale accepted bookkeeping");
        assert_eq!(d["ackPending"], false);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn post_send_delivery_never_reports_delivered_for_a_concurrently_removed_entry() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("delivery-concurrent-rm");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let msgid = envelope.msgid.clone();
        aoide_storage::outbox::write_entry("osaka", &aoide_storage::outbox::OutboxEntry::fresh(envelope)).unwrap();
        assert!(aoide_storage::outbox::remove_entry("osaka", &msgid).unwrap(), "simulates a concurrent `mail outbox rm`");

        let d = post_send_delivery("osaka", &msgid);
        assert_ne!(d["status"], "delivered", "an entry's own absence is never read as delivery");
        assert_eq!(d["status"], "queued");
        assert!(d["reason"].as_str().unwrap().contains("status unavailable"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_send_local_spool_failure_is_an_error_never_a_delivery_status() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-spool-failure");

        aoide_storage::node_store::save_nodes(&[verified_node("osaka", "http://127.0.0.1:1/")]).unwrap();

        // Force the shared stage lock to fail (EISDIR) — the same
        // technique `outbox::every_outbox_mutation_refuses_when_the_lock_
        // cannot_be_taken` uses for the SAME underlying `try_stage_lock`.
        // `outbox::write_entry` is the very first outbox call `mail send`
        // makes, so this fails before any drain is even attempted.
        std::fs::create_dir_all(aoide_storage::fs::stage_dir().join(".stage.lock")).unwrap();

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "osaka/bob")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "a local spool write failure is a command error, never a masked delivery status");
        assert!(out.data.is_none(), "an error outcome carries no delivery projection at all");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The independent-review LOW finding this pins: `handle_mail_send`'s
    /// `Err(e) => delivery_shape("failed", …)` branch — the ONE case a
    /// LOCAL I/O failure inside the drain attempt itself (never "the
    /// remote node was unreachable," `mail_wire::drain_node`'s own module
    /// doc) — had no direct test. Forces that exact `Err` the same way
    /// `mail_wire`'s own module doc reserves it for: a genuine local I/O
    /// failure, here `outbox::try_take_link_lock`'s `.bsy` file `open()`
    /// failing EISDIR — done AFTER the spool write, never before, so only
    /// the drain fails: `write_entry` only ever touches the node's own
    /// entry file, never `.bsy` (`outbox::write_entry`'s own doc), so the
    /// write still lands and the command still reports `Outcome::ok`
    /// (spec item 8) with `data.delivery` alone showing the drain's local
    /// failure.
    #[test]
    fn mail_send_reports_delivery_failed_when_the_drain_itself_hits_a_local_io_error() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-drain-local-io-error");

        aoide_storage::node_store::save_nodes(&[verified_node("osaka", "http://127.0.0.1:1/")]).unwrap();

        let bsy = aoide_storage::outbox::outbox_dir().join("osaka").join(".bsy");
        std::fs::create_dir_all(&bsy).unwrap();

        let out = handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "osaka/bob")]));
        assert_eq!(
            out.status,
            aoide_protocol::output::Status::Ok,
            "the write already succeeded — a drain-local I/O failure never downgrades it, msg: {}",
            out.message
        );

        let spooled = aoide_storage::outbox::list_entries("osaka").unwrap();
        assert_eq!(spooled.len(), 1, "the entry is still spooled despite the drain's own local failure");

        let data = out.data.unwrap();
        assert_eq!(data["delivery"]["status"], "failed");
        assert_eq!(data["delivery"]["reasonScope"], "local");
        assert!(
            data["delivery"]["reason"].as_str().unwrap().contains(".bsy"),
            "the local I/O error text rides along, got: {:?}",
            data["delivery"]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn post_send_delivery_degrades_to_status_unavailable_when_the_read_itself_fails() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-send-status-read-failure");

        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        let msgid = envelope.msgid.clone();
        aoide_storage::outbox::write_entry("osaka", &aoide_storage::outbox::OutboxEntry::fresh(envelope)).unwrap(); // the spool succeeds first

        // THEN the re-read breaks: the spool's own successful write already
        // left `.stage.lock` behind as a regular (flocked) file, so it has
        // to come out before the same path can be re-made as a directory.
        let lock_path = aoide_storage::fs::stage_dir().join(".stage.lock");
        let _ = std::fs::remove_file(&lock_path);
        std::fs::create_dir_all(&lock_path).unwrap();

        let d = post_send_delivery("osaka", &msgid);
        assert_eq!(d["status"], "queued", "the spool already succeeded — a read failure afterward is reported, never a fabricated failure");
        assert_eq!(d["reasonScope"], "local");
        assert!(d["reason"].as_str().unwrap().starts_with("status unavailable"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_outbox_listing_never_invokes_curl() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-outbox-no-network");

        aoide_storage::node_store::save_nodes(&[verified_node("osaka", "http://127.0.0.1:1/")]).unwrap();
        let envelope = aoide_storage::mail::mint_outbound_letter("here", "osaka", "bob", "hi").unwrap();
        aoide_storage::outbox::write_entry("osaka", &aoide_storage::outbox::OutboxEntry::fresh(envelope)).unwrap();
        aoide_storage::outbox::back_off("osaka", 1_000, "transport-error: HTTP 0").unwrap();

        let shim_dir = std::env::temp_dir().join(format!(
            "aoide-client-mail-outbox-curlshim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let marker = shim_dir.join("curl-was-invoked");
        let shim = shim_dir.join("curl");
        std::fs::write(&shim, format!("#!/bin/sh\ncat > /dev/null\ntouch {}\nexit 1\n", marker.display())).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

        let out = handle_mail_outbox(&mail_inv(&["mail", "outbox"], &[]));

        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        let curl_ran = marker.exists();
        let _ = std::fs::remove_dir_all(&shim_dir);

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        assert!(!curl_ran, "an outbox LISTING must never dial out — the shim would have touched its marker");
        let entries = out.data.unwrap()["entries"].as_array().unwrap().clone();
        assert_eq!(entries[0]["delivery"]["status"], "retrying");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_read_for_one_name_advances_the_cursor_and_reread_reprints() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-read-for");

        handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["one"], &[("to", "self/conductor")]));
        handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["two"], &[("to", "self/conductor")]));

        let out = handle_mail_read(&mail_inv_with_flags(&["mail", "read"], &[], &[("for", "conductor")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.unwrap()["entries"].as_array().unwrap().len(), 2, "both letters are new");

        let out = handle_mail_read(&mail_inv_with_flags(&["mail", "read"], &[], &[("for", "conductor")]));
        assert_eq!(out.data.unwrap()["entries"].as_array().unwrap().len(), 0, "the cursor already advanced past both");

        let out = handle_mail_read(&mail_inv_with_flags(
            &["mail", "read"],
            &[],
            &[("for", "conductor"), ("reread", "")],
        ));
        assert_eq!(out.data.unwrap()["entries"].as_array().unwrap().len(), 2, "--reread reprints already-read entries");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_read_all_names_and_show_by_msgid() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-read-all-show");

        handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["for-alice"], &[("to", "self/alice")]));
        handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["for-bob"], &[("to", "self/bob")]));

        let out = handle_mail_read(&mail_inv_with_flag(&["mail", "read"], &[], "all-names"));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let entries = out.data.unwrap()["entries"].as_array().unwrap().clone();
        assert_eq!(entries.len(), 2, "--all-names reads every name with something unread");

        let msgid = entries[0]["envelope"]["msgid"].as_str().unwrap().to_string();
        let out = handle_mail_show(&mail_inv(&["mail", "show"], &[&msgid]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.unwrap()["envelope"]["msgid"], msgid);

        let out = handle_mail_show(&mail_inv(&["mail", "show"], &["not-a-real-msgid"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "not-found");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_read_requires_exactly_one_of_for_or_all_names() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-read-usage");

        let out = handle_mail_read(&mail_inv(&["mail", "read"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "neither --for nor --all-names given");

        let out = handle_mail_read(&mail_inv_with_flags(
            &["mail", "read"],
            &[],
            &[("for", "conductor"), ("all-names", "")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "mutually exclusive");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_mark_advances_the_cursor_without_printing() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-mark");

        handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "self/conductor")]));

        let out = handle_mail_mark(&mail_inv_with_flags(&["mail", "mark"], &[], &[("for", "conductor")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.unwrap()["seq"], 1);

        let out = handle_mail_read(&mail_inv_with_flags(&["mail", "read"], &[], &[("for", "conductor")]));
        assert_eq!(out.data.unwrap()["entries"].as_array().unwrap().len(), 0, "mark already advanced past it");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mail_rm_prunes_by_age_and_rejects_a_bad_duration() {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, root) = aoide_test_support::isolated_mail_root("mail-rm");

        handle_mail_send(&mail_inv_with_flags(&["mail", "send"], &["hi"], &[("to", "self/conductor")]));

        let out = handle_mail_rm(&mail_inv_with_flags(&["mail", "rm"], &[], &[("older-than", "not-a-duration")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);

        let out = handle_mail_rm(&mail_inv_with_flags(&["mail", "rm"], &[], &[("older-than", "30d")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.unwrap()["pruned"], 0, "the letter just sent is nowhere near 30 days old");

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod mcp_http_tests {
    use super::*;

    #[test]
    fn headers_survive_interim_responses_without_consuming_body_lines() {
        let response = parse_http_response(200, "HTTP/1.1 100 Continue\r\n\r\nHTTP/2 200 OK\r\nMcp-Session-Id: mcp-123\r\nContent-Type: application/json\r\n\r\n{\"result\":\"body: value\"}").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.headers[0], ("mcp-session-id".into(), "mcp-123".into()));
        assert_eq!(response.body, "{\"result\":\"body: value\"}");
        assert!(parse_http_response(200, "HTTP/1.1 403 Forbidden\r\n\r\ndenied").is_err());
        assert!(parse_http_response(200, "{\"missing\":\"headers\"}").is_err());
    }

    #[test]
    fn mcp_credentials_and_session_headers_use_stdin_never_argv_or_body_file() {
        use std::os::unix::fs::PermissionsExt;
        let _lock = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = aoide_test_support::EnvSaver::capture(&["PATH"]);
        let dir = std::env::temp_dir().join(format!("aoide-mcp-http-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("curl");
        let script = format!(r#"#!/bin/sh
cat > '{0}/headers'
printf '%s\n' "$@" > '{0}/argv'
previous=''
for arg in "$@"; do
  if [ "$previous" = '--data-binary' ]; then
    cat "${{arg#@}}" > '{0}/body'
    printf '%s' "${{arg#@}}" > '{0}/scratch-path'
  fi
  previous="$arg"
done
printf 'HTTP/1.1 200 OK\r\nMcp-Session-Id: reply-id\r\n\r\n{{"jsonrpc":"2.0","id":1,"result":{{}}}}\n200'
"#, dir.display());
        std::fs::write(&shim, script).unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("PATH", format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default()));
        let response = request_json_with_headers("POST", "https://mneme.invalid/mcp", "{}", "test-bearer-value",
            &[("Mcp-Session-Id".into(), "test-session-value".into())], 1).unwrap();
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        let headers = std::fs::read_to_string(dir.join("headers")).unwrap();
        let body = std::fs::read_to_string(dir.join("body")).unwrap();
        for value in ["test-bearer-value", "test-session-value"] {
            assert!(headers.contains(value));
            assert!(!argv.contains(value));
            assert!(!body.contains(value));
        }
        let scratch = std::fs::read_to_string(dir.join("scratch-path")).unwrap();
        assert!(!std::path::Path::new(&scratch).exists());
        assert_eq!(response.headers[0].1, "reply-id");
        assert!(request_json_with_headers("POST", "https://mneme.invalid/mcp", "{}", "token\nInjected: value", &[], 1).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
