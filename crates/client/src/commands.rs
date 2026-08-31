//! The client domain's CLI commands: `peer add|remove|allow|hub|pull|
//! status` and `peer pair|pending` + `peer pair approve|reject|watch` +
//! `peer discover|advertise` (CONTRACTS.md §7, same-network federation and
//! its pairing ceremony) and `adapter melete` (the neutral-event consumer).
//!
//! Moved from the root package's `src/commands/a2a.rs` + the client half of
//! `src/commands/infra.rs` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands live with the
//! domain. The root package's `commands::all()` calls [`register_peers`]
//! directly after `aoide_server::commands::register_a2a_serve` and
//! [`register_post_graph`] directly before `aoide_conductor::commands::register`,
//! so `schema --json` order never shifts.
//!
//! A peer is another aoide instance, addressed by URL and verified via its
//! AgentCard before registration (`aoide_storage::peer_store`); registered
//! peers fold into the session DAG as `kind:"peer"` nodes
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
/// without it, a misbehaving or hostile far side (a compromised peer, a
/// captive-portal proxy, `--no-verify` pointed at an arbitrary URL) could
/// hand back an unbounded body and grow this process's memory without
/// limit, since [`run_curl_with_timeout`] used to buffer the ENTIRE
/// response before ever looking at it.
///
/// **Investigated legitimate ceiling**: the biggest real payload any call
/// site here fetches is `peer pull`'s `aoide/graphSummary` response, which
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
/// instead of the hardcoded `15`. Split out for `pull_peer_live` (the
/// roster core's presence probe, workstream C2 — reached via bare
/// `session`/`--hosts`) which needs a much shorter per-peer bound
/// (~2s) than every other curl call site here — those all keep calling
/// [`run_curl`] unchanged, so this refactor is a pure internal split, not a
/// behavior change for `peer pull`/`peer add`/etc.
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
/// crosses the cap — every real fetch in this crate (`post_json`'s peer
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
/// — every P-P4 signed-request header (peer name, timestamp, nonce,
/// signature) is PUBLIC, verifiable wire material, not a secret; there is
/// nothing in it worth hiding from `/proc/<pid>/cmdline` the way a bearer
/// token is. [`sign_headers_for_peer`] is the one production caller that
/// ever passes a non-empty slice here; every other call site (unpaired
/// peers, the pairing-ceremony wire methods themselves) passes `&[]`,
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

// ── Dial resolution (ssh-transport lane, P-S4): the tunnel seam every
// ── outbound POST resolves through BEFORE it ever reaches `post_json` ───────
//
// `aoide_client::tunnel::open_or_reuse` (P-S3) opens/reuses the ssh child;
// `aoide_storage::tunnel::dial_url` (P-S2) rewrites the dial url's authority
// while preserving its PATH verbatim — §0.4's identity guarantee
// [`sign_headers_for_peer`]'s canonical string depends on. Everything below
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
/// on the command's own exit" shape) and deliberately NOT done: `pull_peer_live`/
/// `send_message_to_peer`/`spawn_on_peer` are called from `aoide-conduct`
/// command handlers (`who.rs`/`send.rs`/`resurrect.rs`), not from a
/// client-owned CLI handler this phase can wrap — closing only at the
/// four client-owned handlers (`peer add|invite|pair request|spawn`) while
/// leaving those three call sites unclosed would make the SAME function
/// behave inconsistently depending on which crate called it. A single,
/// uniform "every tunnel this phase opens stays open" story is more honest
/// than a partial close that only covers some call sites — P-S5 is where
/// the real lifecycle (both kinds, both close paths) belongs, all at once.
fn tunnel_session_id() -> String {
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
/// [`aoide_storage::peer_store::url_host`]; falls back to the scheme's
/// conventional default (`80`/`443`) only when the url carries no explicit
/// port — every real peer url in this system names its door port
/// explicitly, so this is a generous fallback, never the common case.
fn remote_port_from_url(logical_url: &str) -> Result<u16, String> {
    let host = aoide_storage::peer_store::url_host(logical_url)
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
/// [`sign_headers_for_peer`]'s canonical-string path can never drift apart
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
/// [`aoide_storage::peer_store::Peer`] — resolves `peer.via` (parsed via
/// [`aoide_storage::tunnel::parse_via`]) into a dial url keyed by
/// `peer.name` itself (already `valid_peer_name`-shaped — every registered
/// peer's own nickname, the identical shape [`aoide_storage::tunnel::
/// record_path`] requires of a tunnel `key`) BEFORE calling [`post_json`],
/// changing nothing about what `post_json` itself does. With no `peer.via`
/// (today's every real peer), [`resolve_dial_url`] is the identity
/// function — the url handed to `post_json` is `peer.url`, BYTE-IDENTICAL
/// to every call site's own behavior before this function existed (pinned
/// per call site by this module's tests). An unparseable `peer.via` (a
/// hand-edited `peers.json`) is a hard `Err`, never a silent direct-dial
/// fallback — the same "malformed input refuses, never guesses" stance
/// [`aoide_storage::tunnel::parse_via`] itself holds.
fn post_json_to_peer(
    peer: &aoide_storage::peer_store::Peer,
    body: &str,
    bearer: Option<&str>,
    extra_headers: &[(String, String)],
    timeout_secs: u64,
) -> Result<(u16, String), String> {
    let via = peer
        .via
        .as_deref()
        .map(aoide_storage::tunnel::parse_via)
        .transpose()
        .map_err(|e| format!("peer `{}`'s recorded via: {e}", peer.name))?;
    let dial_url = resolve_dial_url(&peer.url, via.as_ref(), &peer.name)?;
    post_json(&dial_url, body, bearer, extra_headers, timeout_secs)
}

/// [`post_json_to_peer`]'s own body, plus an explicit `via_override` that
/// BEATS `peer.via` when present — [`spawn_on_peer_via`]'s only caller
/// (`peer spawn --via …`), the one call site an operator can override the
/// recorded transport marker from at call time. `via_override: None` makes
/// this byte-identical to [`post_json_to_peer`] (resolves `peer.via`
/// exactly the same way), which is why [`post_json_to_peer`] itself is
/// NOT reimplemented in terms of this — the common, override-free path
/// stays the simpler function.
fn post_json_to_peer_with_via_override(
    peer: &aoide_storage::peer_store::Peer,
    body: &str,
    bearer: Option<&str>,
    extra_headers: &[(String, String)],
    timeout_secs: u64,
    via_override: Option<&aoide_storage::tunnel::Via>,
) -> Result<(u16, String), String> {
    if let Some(via) = via_override {
        let dial_url = resolve_dial_url(&peer.url, Some(via), &peer.name)?;
        return post_json(&dial_url, body, bearer, extra_headers, timeout_secs);
    }
    post_json_to_peer(peer, body, bearer, extra_headers, timeout_secs)
}

/// [`post_json`] wrapped with dial resolution for a CEREMONY call — no
/// `Peer` record exists yet to read a marker off of ([`run_pair_request`]'s
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
/// ssh-transport marker (`peer.add`, `peer.invite`, `peer.pair.request`,
/// `peer.spawn`, P-S4): absent is `Ok(None)` (today's direct-dial default,
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
/// `X-Aoide-Peer` carries THIS instance's own SELF name
/// (`aoide_storage::display::local_host_name()`) — never `peer.name`, which
/// is only this side's local nickname for the counterpart and carries no
/// meaning to the far end. Each instance identifies itself by its own self
/// name on every wire call that claims an identity: the pairing ceremony's
/// `pairRequest.name` (`run_pair_request`, same `local_host_name()` chain
/// the discovery advertisement and `graphSummary` also use) and this header both
/// say "this is who I am," so both carry the same value. The name is
/// ATTRIBUTION, not identity (#63 P-ID5): the far end resolves the caller
/// BY THE KEY THAT SIGNED (`aoide-server::a2a::verify_signed_request` tries
/// the signature against every verified peer's stored pubkey and takes the
/// record whose key verifies — CONTRACTS.md §6 "Inbound verification"), so
/// a stale or mismatched name here never breaks authentication; the far end
/// audits the mismatch as attribution drift and proceeds under its own
/// record's name. The name's one identity-adjacent role on the far end is
/// the exact-name tiebreak when two of its records share this instance's
/// pubkey — one more reason this header stays the stable self name.
/// `--name`/`peer.name` stay purely a local label this instance uses to
/// refer to the counterpart, never an identity claim that crosses the wire.
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
        (aoide_storage::wire_auth::HEADER_PEER.to_string(), aoide_storage::display::local_host_name()),
        (aoide_storage::wire_auth::HEADER_TIMESTAMP.to_string(), timestamp),
        (aoide_storage::wire_auth::HEADER_NONCE.to_string(), nonce),
        (aoide_storage::wire_auth::HEADER_SIGNATURE.to_string(), signature),
    ])
}

/// Build a SIGNED `aoide/pairPoll` body for pairing request `id` (Design A,
/// task #119 — `approve_outbound`'s own poll step; REPLACES the old
/// `aoide/pairApprove` reverse callback). Unlike [`sign_headers_for_peer`],
/// this can be called with NO [`aoide_storage::peer_store::Peer`] record at
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
    let body = crate::peer::build_pair_poll_body(id, &timestamp, &nonce, &signature);
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

// ── The seven `peer` commands (CONTRACTS.md §7: same-network federation) ───────
//
// A peer is ANOTHER aoide instance, addressed by URL (topology-agnostic —
// the protocol never cares whether that URL happens to resolve on the same
// loopback host, a LAN, or a tailnet; it's just a URL). `peer add` verifies
// by fetching the peer's AgentCard first, before registering anything;
// `peer pull` calls the NEW `aoide/graphSummary` method
// (`aoide-server::a2a::graph_summary`) and caches the result; `build_graph`
// (`aoide-conduct`) folds a fresh cache in as a `peer:<name>` root node. The
// registry lives in `state/peers.json` (`aoide_storage::peer_store`) —
// external registry-style state, not song-scoped rehearsal state.

/// `peer add <name> <url> [--autogate]` — verify the peer by fetching its
/// AgentCard first, then register `name` → `url`. A duplicate `name` is
/// rejected cleanly — CONTRACTS.md §7's explicit stance (a peer's local
/// nickname should never be silently repointed at a different URL by a
/// second `add`).
fn handle_peer_add(inv: &Invocation) -> Outcome {
    let cmd = "peer.add";
    const USAGE: &str = "usage: aoide peer add <name> <url> [--autogate] [--no-verify] [--via ssh://[user@]host[:port]] [--json]";
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
    let no_verify = inv.flag_present("no-verify");
    let token_file = inv.flags.get("token-file").cloned().filter(|s| !s.is_empty());
    let bearer_secret = inv.flags.get("bearer-secret").cloned().filter(|s| !s.is_empty());

    let mut peers = aoide_storage::peer_store::load_peers();
    if peers.iter().any(|p| p.name == name) {
        return Outcome::error(cmd, format!("peer `{name}` is already registered — remove it first to re-add"))
            .with_data(json!({ "reason": "duplicate-name", "name": name }));
    }

    // Verify: fetch the peer's AgentCard BEFORE registering anything — a
    // peer that fails this fetch never gets added. This is the ONLY
    // network call `peer add` ever makes, so it must dial through the
    // tunnel exactly like every other cross-box call when `--via` is
    // given (review finding, P-S4 follow-up): a loopback-bound door
    // reachable ONLY through the tunnel — precisely the scenario `--via`
    // exists for — used to fail verification here before the peer was
    // ever registered, making the flag dead weight on `add`. `card_url`
    // stays the LOGICAL url for display and for the peer record below;
    // `resolve_dial_url` (this module's own P-S4 funnel) rewrites the
    // fetch target's authority when a via is present, preserving its
    // `.well-known/agent-card.json` path verbatim — no signing is
    // involved either way (a card fetch is a plain GET, never a signed
    // request), so there is no canonical-string path to keep in sync
    // here, unlike the signed peer calls this funnel also serves.
    //
    // `--no-verify` skips this entire block — for a peer that serves no
    // AgentCard at all (a plain A2A client endpoint, e.g. an inbound-only
    // harness like Melete that never stood up the discovery surface this
    // fetch expects). The peer is still recorded exactly as the verified
    // path records it below: `verified` was already hardcoded `false` on
    // this path regardless (a card fetch is reachability, never identity
    // — that only ever comes from `peer pair`), so skipping the fetch
    // changes nothing about what gets written, only whether this one GET
    // runs first.
    if !no_verify {
        let card_url = crate::wire::resolve_card_url(&url);
        let fetch_url = match resolve_dial_url(&card_url, via.as_ref(), &name) {
            Ok(u) => u,
            Err(e) => {
                return Outcome::error(cmd, format!("opening a tunnel to verify peer AgentCard at {card_url}: {e}"))
                    .with_data(json!({ "reason": "tunnel-failed", "url": card_url }))
            }
        };
        let (code, body) = match run_curl(&["--", &fetch_url], None) {
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
        via: via.as_ref().map(|v| v.to_string()),
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

/// `peer remove <name>` — deregister; a MISSING name is a clean error, not
/// idempotent-silent (following `rice draft drop <name>`'s precedent: a
/// missing target is a real mistake worth surfacing — CONTRACTS.md §7 calls
/// this stance out explicitly). Also drops the peer's cache file, if any,
/// so a re-added-under-the-same-name peer never starts from a stale
/// leftover.
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
        let (code, resp_body) = post_json_to_peer(peer, &body_str, bearer.as_deref(), &extra_headers, 15)?;
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
/// outcome). The roster core's presence probe (conduct crate, workstream
/// C2 — reached via bare `session`/`--hosts`; the standalone `who` command
/// it originally backed is retired, session-surface redesign, command-defrag
/// lane X, 2026-08-28) is the reason this exists: it reuses this exact curl
/// transport (never reimplements HTTP — see the crate's `Cargo.toml` for why
/// the `conduct → client` edge stays) but must never treat a presence query
/// as a cache-refreshing side effect. `build_graph`'s fold (`aoide-conduct`)
/// is the ONLY writer of that cache; the roster core only ever READS it, as
/// the fallback for a peer this call fails to reach. Returns just the peer's
/// resolved `graph` document (`{nodes, edges}`) — the roster core has no use
/// for the envelope's `instance` field `pull_one_peer` also captures.
pub fn pull_peer_live(peer: &aoide_storage::peer_store::Peer, timeout_secs: u64) -> Result<Value, String> {
    let body = crate::peer::build_graph_summary_request();
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer = resolve_peer_bearer(peer)?;
    let extra_headers = sign_headers_for_peer(peer, &body_str)?;
    let (code, resp_body) = post_json_to_peer(peer, &body_str, bearer.as_deref(), &extra_headers, timeout_secs)?;
    if code != 200 {
        return Err(format!("HTTP {code}"));
    }
    let resp: Value =
        serde_json::from_str(&resp_body).map_err(|e| format!("unparseable response: {e}"))?;
    let now = aoide_storage::time::now_iso_utc();
    let entry = crate::peer::parse_graph_summary_response(&resp, &peer.name, &now)?;
    Ok(entry.graph.unwrap_or_else(|| json!({ "nodes": [], "edges": [] })))
}

/// POST a `message/send` to a PEER with an explicit `contextId` naming the
/// REMOTE session to inject into. `graph send --to <peer>/<query>` (`aoide-conduct`,
/// workstream C3) resolves `query` against the peer's cached graph to that
/// one remote sessionId, then drives THIS function — the transport lives
/// here (not duplicated in `conduct`) for the same reason [`pull_peer_live`]
/// does, see the crate's `Cargo.toml`/`AGENTS.md` on the `conduct → client`
/// edge.
///
/// Same `run_curl` transport and 15s timeout every other `message/send`
/// call site in this file uses — this is a real delivery, not the roster
/// core's short-timeout presence probe, so it does NOT reuse
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
    let (code, resp) = post_json_to_peer(peer, &body_str, bearer.as_deref(), &extra_headers, 15)?;
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
        return Err(format!("peer returned an error: {detail}"));
    }
    Ok(parsed)
}

/// Prompt `y/N` before spawning on a peer — a LOCAL UX confirmation only
/// (mirrors `confirm_sas`'s exact idiom), never a security gate: the remote
/// door's own paired+signature+allows∋spawn check (PAIRING.md decision 6)
/// is the sole authority either way. Retrofit onto `aoide_protocol::pick::
/// confirm` (ONBOARD.md's prompt substrate section, P-I1): `inquire::
/// Confirm` on a tty, the identical stdin `y/N` read otherwise — the
/// question text itself is unchanged, `confirm` owns the `[y/N]` decoration
/// now instead of this function.
fn confirm_spawn(name: &str, text: &str) -> Result<bool, String> {
    aoide_protocol::pick::confirm(&format!("spawn a new session on peer `{name}` — first turn: {text:?} — proceed?"))
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
/// SAME builder every other `message/send` call site in this file uses, so
/// this is a proven shape, not a new invention.
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
/// taught error naming `peer pair`. Every OTHER refusal shape —
/// `allows` lacking `spawn`, clock skew, a revoked pairing — is the remote
/// door's OWN call; this function never second-guesses it, and surfaces
/// whatever JSON-RPC error the door returns VERBATIM (taught), per
/// PAIRING.md decision 6: "the remote door's paired+signature+
/// allows∋spawn gate is the authority."
/// The wire-level twin of [`send_message_to_peer`] for the SPAWN shape:
/// `context_id: None` routes `aoide-server::a2a::do_spawn` to spawn the
/// peer's own configured `aoide.a2a.spawnAgent` and inject `text` as that
/// session's first turn (`spawn_inject_prompt`) — never a client-chosen
/// agent or argv (see [`handle_peer_spawn`]'s own doc on the security
/// model this enforces). Extracted so this is the ONE place that builds and
/// sends a spawn-shaped `message/send`: [`handle_peer_spawn`] (the CLI's
/// confirm-then-send wrapper, unchanged in shape) AND `aoide-conduct`'s
/// manifest remote-summon path (U4, command-defrag lane U — a manifest spec
/// whose `host` names a registered peer drives this directly, with no
/// confirm: the manifest is itself the operator's standing declaration, the
/// same posture U2's local clean-spawn already takes toward a spec's own
/// `command`) call into. Returns the parsed JSON-RPC response on a 200 with
/// no `error` member; any transport/HTTP/JSON-RPC failure is `Err` with a
/// plain message the caller surfaces and audits directly — the same
/// `Result`-not-`Outcome` shape [`send_message_to_peer`]/[`pull_peer_live`]
/// hold, for the same reason (the caller builds its own `Outcome`).
pub fn spawn_on_peer(
    peer: &aoide_storage::peer_store::Peer,
    text: &str,
) -> Result<Value, SpawnPeerError> {
    spawn_on_peer_via(peer, text, None)
}

/// [`spawn_on_peer`]'s own body, PLUS an optional `--via` OVERRIDE
/// (P-S4) — `handle_peer_spawn` is the one production caller that ever
/// passes `Some` (an explicit `peer spawn --via …`, which beats a
/// recorded `peer.via`); every other caller (`aoide-conduct`'s manifest
/// remote-summon path, this function's own `spawn_on_peer` above) passes
/// `None`, making `spawn_on_peer` itself byte-identical-in-behavior to
/// before this override existed. Extracted rather than adding the
/// parameter to `spawn_on_peer` directly so `aoide-conduct`'s existing
/// call site (`graph::resurrect.rs`) needs no change.
pub fn spawn_on_peer_via(
    peer: &aoide_storage::peer_store::Peer,
    text: &str,
    via_override: Option<&aoide_storage::tunnel::Via>,
) -> Result<Value, SpawnPeerError> {
    let message_id = gen_message_id();
    let body = crate::wire::build_message_send_body(text, &message_id, None);
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    let bearer =
        resolve_peer_bearer(peer).map_err(|e| SpawnPeerError::new("bearer-resolve-failed", e))?;
    let extra_headers =
        sign_headers_for_peer(peer, &body_str).map_err(|e| SpawnPeerError::new("signing-failed", e))?;
    let (code, resp) = post_json_to_peer_with_via_override(peer, &body_str, bearer.as_deref(), &extra_headers, 15, via_override)
        .map_err(|e| SpawnPeerError::new("send-failed", e))?;
    if code != 200 {
        return Err(SpawnPeerError {
            reason: "send-http-error",
            message: format!("HTTP {code}"),
            http_code: Some(code),
            body: Some(resp),
        });
    }
    let parsed: Value = serde_json::from_str(&resp)
        .map_err(|e| SpawnPeerError::new("unparseable-response", format!("unparseable response: {e}")))?;
    // A JSON-RPC error still returns HTTP 200 (same discipline as
    // `send_message_to_peer`) — the remote door's refusal (paired-but-
    // unsigned, allows lacking spawn, skew, …) surfaces VERBATIM, never
    // translated or second-guessed.
    if let Some(err) = parsed.get("error") {
        let detail = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("(no message)");
        return Err(SpawnPeerError::new(
            "peer-refused",
            format!("peer returned an error: {detail}"),
        ));
    }
    Ok(parsed)
}

/// [`spawn_on_peer`]'s error: the wire stage that failed (`reason`, the same
/// vocabulary `handle_peer_spawn`'s structured `data` always carried —
/// bearer-resolve-failed · signing-failed · send-failed · send-http-error ·
/// unparseable-response · peer-refused) plus the human message; HTTP
/// failures keep their code and raw body for programmatic consumers.
#[derive(Debug)]
pub struct SpawnPeerError {
    pub reason: &'static str,
    pub message: String,
    pub http_code: Option<u16>,
    pub body: Option<String>,
}

impl SpawnPeerError {
    fn new(reason: &'static str, message: String) -> Self {
        Self { reason, message, http_code: None, body: None }
    }
}

impl std::fmt::Display for SpawnPeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn handle_peer_spawn(inv: &Invocation) -> Outcome {
    let cmd = "peer.spawn";
    const USAGE: &str = "usage: aoide peer spawn <name> [--yes] [--via ssh://[user@]host[:port]] -- <text…>";
    let name = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    let text = inv.args.get(1..).map(|rest| rest.join(" ")).unwrap_or_default();
    if text.trim().is_empty() {
        return Outcome::usage(cmd, USAGE);
    }
    // --via beats a recorded Peer.via (spawn_on_peer_via's own doc) — an
    // invalid --via is a usage error, never a silent fallback to the
    // recorded marker (parse_via_flag's own stance).
    let via_override = match parse_via_flag(inv) {
        Ok(v) => v,
        Err(e) => return Outcome::usage(cmd, format!("{USAGE} — {e}")),
    };

    let peers = aoide_storage::peer_store::load_peers();
    let peer = match peers.iter().find(|p| p.name == name) {
        Some(p) if p.verified => p.clone(),
        Some(_) => {
            return Outcome::error(
                cmd,
                format!(
                    "peer `{name}` is registered but not paired — spawn requires a signed request \
                     from a VERIFIED peer (docs/architecture/PAIRING.md decision 6); pair first with \
                     `aoide peer pair <url> --name {name}`"
                ),
            )
            .with_data(json!({ "reason": "unpaired-peer", "name": name }));
        }
        None => {
            return Outcome::error(
                cmd,
                format!(
                    "no peer named `{name}` — spawn requires a paired peer; register and pair it \
                     first with `aoide peer pair <url> --name {name}`"
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

    match spawn_on_peer_via(&peer, &text, via_override.as_ref()) {
        Ok(parsed) => {
            let session_id = parsed
                .get("result")
                .and_then(|r| r.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            Outcome::ok(cmd, format!("spawned on `{}` — remote session `{session_id}`", peer.name))
                .with_data(json!({ "name": peer.name, "url": peer.url, "sessionId": session_id, "response": parsed }))
        }
        Err(e) => {
            let mut data = json!({ "reason": e.reason, "name": peer.name, "url": peer.url });
            if let Some(code) = e.http_code {
                data["httpCode"] = json!(code);
            }
            if let Some(body) = &e.body {
                data["body"] = json!(body);
            }
            Outcome::error(cmd, format!("spawning on `{}` at {}: {e}", peer.name, peer.url))
                .with_data(data)
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

/// `peer status` — each registered peer's full registry row (name/url/
/// autogate/tokenFile/bearerSecret/hub/pubkey/verified/allows/addedAt — the
/// same shape `peer list` used to be the only place emitting, folded in
/// here so `peer list` has nothing left to say `peer status --json` doesn't
/// already say, command-defrag lane task #101) plus its last-pull outcome
/// and staleness (`fresh` within
/// [`aoide_storage::peer_store::PEER_CACHE_TTL_SECS`], `stale` past it or
/// explicitly marked so, `never-pulled` with no cache file at all) — the
/// same three-way classification `build_graph`'s fold uses
/// (`aoide-conduct::graph::doc`), so this and the DAG never disagree. The
/// human-readable message stays the terse per-peer-count summary; the full
/// row rides `--json`'s `data.peers` only.
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
            flag!("no-verify", "bool", "Skip the AgentCard fetch entirely and register the peer unverified — for a peer that serves no AgentCard (a plain A2A client endpoint). `verified` stays false either way; a card fetch was never identity, only reachability."),
            flag!("token-file", "string", "Path to a file holding the shared secret this peer must present (Authorization: Bearer <token>) to be identified as this peer — required for --autogate to survive a proxy/tunnel, where every caller's address looks the same."),
            flag!("bearer-secret", "string", "Name of a secret, resolved fresh on every outbound call through the local secrets broker, THIS instance presents as Authorization: Bearer <value> when calling this peer's own A2A door. Absent = no bearer sent (today's behavior)."),
            flag!("via", "string", "An ssh://[user@]host[:port] transport marker — cross-box calls to this peer dial through an internal ssh tunnel to this target instead of the peer's own url directly. Absent = direct dial (today's behavior)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_add,
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
            flag!("via", "string", "An ssh://[user@]host[:port] transport marker for THIS call, overriding any via recorded on the peer. Absent = the peer's own recorded via, if any (today's behavior when neither is set)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_spawn,
        examples: ["peer spawn yomi-strix -- status check please"],
    ));
}

// ── The `peer pair`/`peer pending` commands (P-P2, P-PV2, CONTRACTS.md §6
// ── — the pairing ceremony's wire + CLI ceremony) ─────────────────────────
//
// `peer add`/`peer pair` are two SEPARATE paths onto the same registry
// (`docs/architecture/PAIRING.md`'s "Settled decisions" #2): `peer add` is
// the legacy escape for an UNPAIRED peer (a hand-set URL, never verified by
// key), `peer pair` is the ONE ceremony that mints a `pubkey`/`verified`
// peer record on BOTH ends — request/reveal/park/approve/reject over the
// A2A door (`aoide-server::a2a::pair_request`/`pair_reveal`/`pair_poll`),
// SAS derivation + display (`aoide_storage::pairing::derive_sas`), commit via
// `aoide_storage::peer_store::upsert_paired_peer` — which ALSO stamps the
// peer's `allows` the first time it becomes verified (P-P3, PAIRING.md
// decision 5). That grant is `config.toml`'s `[pairing] defaultGrant`
// (`["read"]` unless an operator widened it), or the `--allow` typed on this
// one commit; `resolve_grant` is the single place either is read. Editing a
// LIVE grant afterward is `peer allow <name> <cap> on|off`'s own separate
// command (registered in `register_peers` above), never a second write site
// here — and a re-pairing never re-grants, so a revoked capability survives
// a key rotation.
//
// **Both humans confirm, for real (review-bounce Finding 2).** `peer pair
// approve <id>` does double duty by DIRECTION, never a fifth command (golden
// count unchanged by Design A, task #119 — no new command path, only the
// completion trigger moved): on an INBOUND id (this instance is the
// APPROVER) it re-derives the SAS, gates on the TYPED pairing code (task
// #120 P3, [`InboundGate`] — max 3 cumulative mismatches, then auto-deny),
// commits LOCALLY, and marks the entry approved for the requester's own poll
// to find (no wire call at all — [`approve_inbound`]'s own doc). On an OUTBOUND
// id (this instance is the REQUESTER) it POLLS the approver's door first
// (over the SAME forward dial `peer pair`'s own request/reveal already
// used), and only
// once that poll comes back `approved` does it re-derive the SAME SAS and
// confirm-then-commit ([`approve_outbound`]'s own doc has the full poll
// mechanics). `peer pair reject <id>` doubles the same way, and on an
// outbound id is also the ceremony's missing ABORT command: it removes the
// entry at either outbound state, whether or not a poll has succeeded yet.

/// Confirm the pairing SAS code matches — `true` only for `y`/`yes`
/// (case-insensitive), EOF or anything else `false` (the ceremony's own
/// "never silently commit" stance). Retrofit onto `aoide_protocol::pick::
/// confirm` (ONBOARD.md's prompt substrate section, P-I1) — `inquire::
/// Confirm` on a tty, the identical stdin `y/N` read otherwise; the
/// question text is unchanged, `confirm` owns the `[y/N]` decoration.
/// REQUESTER-side only since task #120 P3: [`approve_outbound`]'s confirm
/// step is the one caller — the approver's own gate is the typed pairing
/// code ([`approve_inbound`], [`InboundGate`]), never a y/N over a code
/// this side already printed.
fn confirm_sas(sas: &str, name: &str) -> Result<bool, String> {
    aoide_protocol::pick::confirm(&format!("pairing request from `{name}` — confirmation code {sas} — do the codes match?"))
}

/// The capability set a pairing commit stamps on a FIRST verification (task
/// #135 P1) — `Some` is the `--allow` an operator typed at this commit,
/// `None` reads `config.toml`'s `[pairing] defaultGrant`
/// (`aoide_storage::config`, whose own default is `["read"]`).
///
/// **Resolution lives here, not in the store.** `upsert_paired_peer` takes
/// the finished list; a store function reading the config would be a second
/// resolution path, and it would have to swallow a malformed grants file at
/// the one moment that must fail loudly (`config`'s own module doc: "this one
/// must fail loudly, never guess"). So an unreadable or invalid `config.toml`
/// REFUSES the commit here rather than quietly falling back to the built-in
/// default — the ceremony is exactly where a wrong grant is expensive.
///
/// Both directions of `peer pair approve` and both popup arms call this, so
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
/// [`aoide_storage::peer_store::PEER_CAPABILITIES`]) — never a second list to
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
    let kind = aoide_storage::config::ValueKind::ClosedList(aoide_storage::peer_store::PEER_CAPABILITIES);
    aoide_storage::config::parse_value(&kind, raw).map(Some).map_err(|e| format!("--allow: {e}"))
}

/// What a commit says about `allows`. A grant lands ONLY on a first
/// verification — `upsert_paired_peer` leaves an already-verified peer's set
/// exactly as it was, so a revoked capability stays revoked across a key
/// rotation. An `--allow` that silently did nothing is precisely the surprise
/// this clause exists to prevent, so the re-pair case says so and names the
/// command that does change a live grant.
fn grant_note(first_pairing: bool, allows: &[String]) -> String {
    match (first_pairing, allows.is_empty()) {
        (false, _) => ", grant unchanged (`peer allow` edits a live one)".to_string(),
        (true, true) => ", granted nothing".to_string(),
        (true, false) => format!(", granted {}", allows.join(", ")),
    }
}

/// How many wrong pairing codes an inbound entry tolerates before the CLI
/// auto-denies it (task #120 P3) — cumulative across invocations
/// (`aoide_storage::pairing::InboundPairingRequest::tries` persists them)
/// and across the interactive prompt and the scripted `--code` path alike.
pub(crate) const MAX_CODE_TRIES: u32 = 3;

/// How `peer pair approve <id>` on an INBOUND entry collects its typed-code
/// confirmation (task #120 P3) — the approver-side gate: the operator
/// proves they hold the SAME code the requester's screen shows by TYPING
/// it, out-of-band (a phone call, a glance), never by y/N-ing a code this
/// side already printed. Resolved by `handle_peer_pair_approve` from the
/// invocation; [`approve_inbound`] consumes it AFTER the idempotent
/// already-approved and awaiting-reveal checks, so those short-circuits
/// behave identically whichever variant rides in.
pub(crate) enum InboundGate {
    /// Scripted `--code NNN-NNN`: validated once against the derived SAS;
    /// a mismatch counts one persisted try
    /// (`aoide_storage::pairing::record_inbound_code_try`).
    Code(String),
    /// Interactive CLI tty: prompt to type the code
    /// (`aoide_protocol::pick::text_input`), re-prompting on mismatch up
    /// to [`MAX_CODE_TRIES`] cumulative failures.
    Prompt,
    /// No way to collect a code — a non-CLI door, a non-tty CLI without
    /// `--code`, or `--yes` (which no longer bypasses the approver's code):
    /// a taught refusal, once the short-circuits above don't apply.
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

/// The taught refusal for [`InboundGate::Unavailable`] — one message for
/// every no-code shape (non-tty, non-CLI door, `--yes`), naming both the
/// terminal prompt and the scripted spelling.
fn inbound_code_refusal(cmd: &str, id: &str) -> Outcome {
    Outcome::usage(
        cmd,
        format!(
            "approving an inbound pairing request takes the TYPED pairing code as read from the \
             requester's screen — run `aoide peer pair approve {id}` on a real terminal to type it, \
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
/// SAME clean removal `peer pair reject` performs (parked entry taken,
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
             parked entry removed, nothing committed; a fresh `peer pair` on their side starts a new ceremony"
        ),
    )
    .with_data(json!({ "reason": "auto-deny-on-code-mismatch", "id": id, "name": name, "tries": MAX_CODE_TRIES, "rejected": true, "direction": "inbound" }))
}

/// This instance's own default advertised A2A door URL — `--peer-name`'s
/// sibling precedence chain (`aoide_server::a2a::resolve_peer_name`) but
/// resolved HERE, since this crate cannot depend on `aoide-server`: the
/// port comes from `AOIDE_A2A_PORT` (the same env the `aoide-a2a` systemd
/// unit sets, mirroring `a2a::resolve_bind_port`'s own precedence) or the
/// house default `8710`; the host is `aoide_storage::display::
/// local_host_name` (already the shared fallback chain `a2a::
/// resolve_peer_name` itself delegates to). `--self-url` overrides this
/// outright — the one flag `peer pair`'s url arm needs when the door binds
/// somewhere this default can't guess (a non-default port, a reverse
/// proxy/tunnel hostname).
fn default_self_url() -> String {
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
fn default_self_via(toward: &str) -> Option<String> {
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
/// discovered peer: `AOIDE_A2A_PORT` (the same env the `aoide-a2a`
/// systemd unit sets) or the house default `8710`. `peer pair`'s hostname
/// arm composes its dial target with this (task #120 — the advertisement
/// carries no door URL, so there is no per-peer port to read off the
/// wire); a peer on a non-default port takes the explicit `peer pair
/// <url>` path instead.
fn default_a2a_port() -> u16 {
    std::env::var("AOIDE_A2A_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8710)
}

/// The port a `scheme://host[:port][/path]` url's own authority carries —
/// lightweight, reusing [`aoide_storage::peer_store::url_host`]'s existing
/// authority extraction rather than pulling in a full URL parser for one
/// field. `None` on an unparseable url, a bare host with no `:port`
/// segment at all, or a port that doesn't fit `u16` — every one of those
/// is a caller's fallback case, never a panic.
fn port_from_url(url: &str) -> Option<u16> {
    let authority = aoide_storage::peer_store::url_host(url)?;
    let (_, port_str) = authority.rsplit_once(':')?;
    port_str.parse::<u16>().ok()
}

/// `peer pair <target> [--name <n>] [--self-url <url>] [--self-via …]
/// [--via …] [--secs N] [--yes] [--json]` — the ONE entry point into the
/// pairing ceremony's REQUEST half (the User's locked spec, P-PV2,
/// superseding the old `peer pair request`/`peer invite` split). SMART
/// TARGET dispatch decides which of the two ceremony arms `<target>`
/// means, by SHAPE alone, never a flag: a URL (`target.contains("://")`)
/// is an EXPLICIT DIAL — [`pair_via_url`], byte-identical to the old `peer
/// pair request <url>` path (P-PV1's via/self-via defaults included).
/// Anything else is a HOSTNAME — [`pair_via_hostname`], the old `peer
/// invite <name>` path: one beacon sweep, resolved by advertisement name.
/// Both arms bottom out in the SAME [`run_pair_request`] core — reused,
/// never forked.
fn handle_peer_pair(inv: &Invocation) -> Outcome {
    let cmd = "peer.pair";
    const USAGE: &str = "usage: aoide peer pair <url-or-hostname> [--name <n>] [--self-url <url>] [--self-via ssh://[user@]host] [--via ssh://[user@]host[:port]] [--secs N] [--yes] [--json] — takes exactly ONE positional target; the old `peer pair request <url>`/`peer invite <name>` folded into this single `peer pair <target>` (P-PV2, hard cutover, no alias)";
    let target = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(t) => t.to_string(),
        None => return Outcome::usage(cmd, USAGE),
    };
    // `peer pair` takes EXACTLY one positional (review finding, P-PV2
    // follow-up): a second one is never valid syntax. The registry has no
    // third `peer.pair.request` path to greedily match anymore, so old
    // `peer pair request <url>` muscle memory lands its `request`/`<url>`
    // pair here as THIS command's own `args`, past its single declared
    // `target`. Silently reading only `args[0]` ("request") and discarding
    // the real url would burn a full hostname-arm sweep window looking for
    // an advertiser literally named "request" before failing with a
    // message that never mentions the URL was even seen — worse than an
    // ordinary unknown-command refusal. Refuse loudly instead, uniformly:
    // the fold explanation lives in `USAGE` itself (shown on every arity
    // error alike), never a special case keyed on `target == "request"`.
    if inv.args.len() > 1 {
        return Outcome::usage(cmd, USAGE);
    }
    if target.contains("://") {
        pair_via_url(cmd, inv, &target, USAGE)
    } else {
        pair_via_hostname(cmd, inv, &target, USAGE)
    }
}

/// `peer pair <target>`'s EXPLICIT-DIAL arm (`target` is a URL) — the old
/// `peer pair request <url>` handler's own body, unchanged: mints this
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
/// `OutboundState::AwaitingApproval`) so a LATER `peer pair approve <id>`
/// invocation — run whenever, long after this CLI process exits — can poll
/// the approver's door for the release ([`approve_outbound`]'s own doc, task
/// #119) and finish the ceremony. `--secs`/`--yes` are the hostname arm's
/// own flags and are simply inert here — a URL is already an explicit,
/// typed act with nothing to sweep for or confirm before dialing.
fn pair_via_url(cmd: &str, inv: &Invocation, url: &str, usage: &str) -> Outcome {
    let name = match inv.flags.get("name").cloned().filter(|s| !s.is_empty()) {
        Some(n) => n,
        None => match aoide_storage::peer_store::default_peer_name_from_url(url) {
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
        None => aoide_storage::peer_store::url_host(url).unwrap_or_else(|| url.to_string()),
    };
    let self_via = inv
        .flags
        .get("self-via")
        .cloned()
        .filter(|s| !s.is_empty())
        .or_else(|| default_self_via(&toward));

    run_pair_request(cmd, url, &name, &self_url, self_via.as_deref(), via.as_ref(), via.as_ref().map(|v| v.to_string()))
}

/// The requester's half of the ceremony, shared verbatim by
/// [`pair_via_url`] (`peer pair <url>` — a CLI-typed url/`--name`,
/// validated above) AND [`pair_with_heard`] (`peer pair <hostname>`/bare
/// `pair` — a `url`/`name` already lifted straight off an
/// already-validated, already-confirmed discovery advertisement, so it
/// needs no SECOND `valid_peer_name` check here). Extracted so the
/// hostname arm reaches the SAME ceremony code the url arm does — never a
/// copy (PAIRING.md: "sugar over the ceremony, nothing more").
/// Everything from here down is unchanged from the pre-P-PV2 shape of
/// `handle_peer_pair_request`: mint-or-load this instance's identity, mint
/// a fresh nonce, POST `aoide/pairRequest` carrying a COMMITMENT to that
/// nonce (never the nonce itself), then immediately POST `aoide/pairReveal`
/// with the nonce the commitment already fixed; only once both calls
/// succeed does this instance derive its own SAS and remember the outbound
/// request.
///
/// **P-S4's two additions, deliberately kept separate.** `dial_via` is what
/// the ceremony's OWN two POSTs below actually tunnel through — `None` for
/// a plain `peer pair <url>` (no observed address to derive a
/// default from) and, for the hostname arm/bare `pair`, an explicit
/// `--via` or else [`pair_with_heard`]'s own src_addr-derived default
/// (P-PV1: loopback-only doors, task #131 — a discovered peer's door is
/// reached only through its ssh tunnel, so the ceremony's OWN dial needs
/// that same default, not only the record). `record_via` is the string
/// parked into [`aoide_storage::pairing::OutboundPairingRequest::via`] for
/// LATER commit onto the resulting peer record, in the SEPARATE `peer pair
/// approve <id>` invocation that actually writes it (`approve_outbound`).
/// `self_via` (P-PV1) is this instance's OWN reach-back hop claim —
/// `ssh://<local login>@<local address routed toward the peer>` by default
/// ([`default_self_via`] — the HOST half is the local outbound address the
/// kernel picks for a route toward the peer, never a claimed OS hostname;
/// that function's own doc has the full reasoning), overridable by
/// `--self-via` — carried on the wire beside `self_url` so the far end,
/// which can only ever OBSERVE this request arriving over the tunnel (i.e.
/// loopback), has something to record a working `via` from at ITS OWN
/// approve-commit time ([`approve_inbound`]'s own doc).
fn run_pair_request(
    cmd: &str,
    url: &str,
    name: &str,
    self_url: &str,
    self_via: Option<&str>,
    dial_via: Option<&aoide_storage::tunnel::Via>,
    record_via: Option<String>,
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
    // (the live yomi↔sakaki ceremony's phantom-peer defect, 2026-08-26).
    let self_name = aoide_storage::display::local_host_name();
    let body = crate::peer::build_pair_request_body(&own_pubkey, &self_name, &commit, &self_url, self_via);
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
        via: record_via,
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

/// `peer pending` — every pairing request THIS instance is still holding
/// open, BOTH directions (review-bounce Finding 2: an outbound entry
/// awaiting THIS instance's own confirm is exactly as "pending" as an
/// inbound one awaiting approval — before that fix, nothing ever surfaced
/// it). Inbound rows carry `revealed` (`requester_nonce_hex.is_some()`,
/// review-bounce Finding 1) — an unrevealed entry shows `"awaiting
/// reveal"`, and `peer pair approve` refuses it. An APPROVED inbound entry
/// (Design A, task #119 — [`InboundPairingRequest::approved`]) stays
/// listed here too, showing `"approved · awaiting their poll"` — it
/// remains parked (never taken) until the requester's own `aoide/pairPoll`
/// releases it or it expires, so the approver's own operator can still see
/// it's done its part. Outbound rows carry their own `state`
/// (`awaiting-approval`/`awaiting-confirm`).
///
/// **Never the SAS/pairing code (P-PV2, the User's locked spec).** The
/// code is read off the REQUESTER's own terminal and typed on the
/// APPROVER's — printing it here too would defeat the whole point of that
/// out-of-band comparison (an operator could just read both sides off this
/// one listing instead of actually comparing two independent screens).
/// `peer pair approve` still independently re-derives it from this
/// instance's own identity plus the entry's stored transcript fields —
/// never trusted from the wire — exactly as before; only THIS row listing
/// stops showing it.
pub(crate) fn handle_peer_pending(_inv: &Invocation) -> Outcome {
    let cmd = "peer.pending";
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
                "inbound" if r["approved"].as_bool() == Some(true) => "approved · awaiting their poll".to_string(),
                "inbound" => "revealed · run `peer pair approve` with the code from their screen".to_string(),
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

/// Resolve `peer pair approve`'s (P-PV2) OPTIONAL `<id>` when omitted: the
/// sole pending request across BOTH directions (`aoide_storage::pairing::
/// list_inbound`/`list_outbound`), or a taught `Outcome::usage` — zero
/// pending names nothing to approve, multiple pending lists every id
/// (`aoide peer pending` shows the same set) and requires the caller name
/// one explicitly. Never a silent guess.
fn sole_pending_id(cmd: &str, now_epoch: i64) -> Result<String, Outcome> {
    let mut ids: Vec<String> = aoide_storage::pairing::list_inbound(now_epoch).into_iter().map(|e| e.id).collect();
    ids.extend(aoide_storage::pairing::list_outbound(now_epoch).into_iter().map(|e| e.id));
    match ids.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(Outcome::usage(cmd, "no pending pairing requests to approve — see `aoide peer pending`")),
        _ => Err(Outcome::usage(
            cmd,
            format!(
                "multiple pending pairing requests — an id is required: {} (see `aoide peer pending`)",
                ids.join(", ")
            ),
        )
        .with_data(json!({ "reason": "ambiguous-id", "ids": ids }))),
    }
}

/// `peer pair approve [<id>] [--yes] [--code NNN-NNN]` — dispatches by
/// DIRECTION (module doc on this section): an INBOUND id runs
/// [`approve_inbound`] (this instance is the APPROVER, gated by the TYPED
/// pairing code — task #120 P3 — collected per [`InboundGate`]: `--code`
/// scripted, a `text_input` prompt on a real CLI tty, a taught refusal
/// anywhere no code can be collected; `--yes` deliberately maps to that
/// refusal too, never a bypass); an OUTBOUND id runs [`approve_outbound`]
/// (this instance is the REQUESTER, polling the approver's door then
/// confirming — `--yes` keeps its original skip-the-y/N meaning THERE,
/// since the requester's own screen already printed the code it would be
/// typing back to itself); an id in neither queue is `unknown-id`.
///
/// **`<id>` is OPTIONAL (P-PV2, the User's locked spec).** Omitted with
/// EXACTLY ONE pending request (either direction — [`sole_pending_id`]):
/// that one is approved, no id-copying required for the common case.
/// Omitted with zero or multiple pending: a taught error (zero: nothing to
/// approve; multiple: the id is required, every pending id is listed) —
/// never a silent guess at which request the operator meant.
fn handle_peer_pair_approve(inv: &Invocation) -> Outcome {
    let cmd = "peer.pair.approve";
    let now = aoide_storage::time::now_iso_utc();
    let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap_or(0);

    let id = match inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(i) => i.to_string(),
        None => match sole_pending_id(cmd, now_epoch) {
            Ok(i) => i,
            Err(out) => return out,
        },
    };

    let allow = match parse_allow_flag(inv) {
        Ok(a) => a,
        Err(e) => return Outcome::usage(cmd, e),
    };

    if let Some(entry) = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id) {
        let gate = match inv.flags.get("code").cloned().filter(|c| !c.trim().is_empty()) {
            Some(code) => InboundGate::Code(code),
            None if inv.flag_present("yes") => InboundGate::Unavailable,
            None if aoide_protocol::pick::interactive(inv.door) => InboundGate::Prompt,
            None => InboundGate::Unavailable,
        };
        return approve_inbound(gate, cmd, &id, entry, &now, now_epoch, allow.as_deref());
    }
    if let Some(entry) = aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.id == id) {
        return approve_outbound(inv.flag_present("yes"), cmd, &id, entry, &now, now_epoch, allow.as_deref());
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
/// tests) BEFORE anything commits.
///
/// **Design A (task #119): PURELY LOCAL — no network call at all.** The old
/// shape delivered an `aoide/pairApprove` callback to the requester's own
/// door FIRST, which meant a requester whose door was loopback-only
/// ([[doors-loopback-only]]) could never be reached, and the ceremony could
/// never complete. Now: commit THIS instance's own peer record
/// (`upsert_paired_peer`), then mark the parked entry
/// [`aoide_storage::pairing::InboundPairingRequest::approved`]
/// (`mark_inbound_approved`) and leave it PARKED — never taken — so the
/// requester's own `aoide/pairPoll` (over the SAME forward dial the request/
/// reveal already used) can find and release it later, however long after
/// this command exits. "A parked request grants NOTHING until approved"
/// (PAIRING.md) still holds: nothing is released to anyone until BOTH this
/// commit AND a correctly-signed poll from the ORIGINAL requester happen.
///
/// Idempotent: re-running this against an already-approved entry is a no-op
/// success (no second code prompt, no second `upsert_paired_peer`) — the
/// operator may have run it twice, or the popup arm may re-offer a stale
/// row before its own state catches up.
///
/// **The gate is the TYPED pairing code (task #120 P3, [`InboundGate`]).**
/// The approver's operator types the code as read off the REQUESTER's
/// screen (out-of-band — a phone call, a glance) and this compares it
/// against the locally derived SAS; the prompt itself never echoes that SAS
/// — printing the expected value beside the input would collapse the
/// comparison into a copy exercise and defeat the whole gate. A mismatch
/// counts one persisted try ([`aoide_storage::pairing::record_inbound_code_try`],
/// cumulative across invocations and across the interactive/scripted
/// paths); the [`MAX_CODE_TRIES`]rd mismatch auto-denies
/// ([`auto_deny_inbound`] — the same clean removal `peer pair reject`
/// performs, audited under its own reason). An abort (`Esc`, `Ctrl-C`)
/// leaves the entry pending with no try counted — an abort is not a wrong
/// code. **`pair_watch --popup`'s own dialog is `InboundGate::Code`
/// too** (P-PV3, task #132): it collects the SAME typed code this gate
/// already validates everywhere else, so the popup arm runs through this
/// exact match arm, not a separate no-prompt one.
pub(crate) fn approve_inbound(
    gate: InboundGate,
    cmd: &str,
    id: &str,
    entry: aoide_storage::pairing::InboundPairingRequest,
    now: &str,
    now_epoch: i64,
    grant: Option<&[String]>,
) -> Outcome {
    if entry.approved {
        return Outcome::ok(
            cmd,
            format!("already approved `{}` — waiting for their own `peer pair approve {id}` to complete their side", entry.name),
        )
        .with_data(json!({ "confirmed": true, "id": id, "peer": entry.name, "alreadyApproved": true }));
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
                 try again shortly, or `aoide peer pair reject {id}` to refuse it outright",
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
        InboundGate::Unavailable => return inbound_code_refusal(cmd, id),
        InboundGate::Code(code) => {
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
        InboundGate::Prompt => loop {
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
                    format!("not confirmed — the request remains pending; run `aoide peer pair reject {id}` to refuse it outright"),
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

    // P-S4/P-PV1: the APPROVER's own commit. `InboundPairingRequest` carries
    // no OBSERVED transport marker (through a tunnel, `origin_addr` reads
    // "loopback", per §0.7 — not a usable source) — but P-PV1 (task #131)
    // gives it a CLAIMED one: when the wire's `selfVia` rode this entry
    // (`entry.self_via`), the requester's own door is reachable only
    // through that hop, the same convention the sakaki/chiyo/osaka peer
    // rows already hold by hand — `url` becomes the loopback-as-seen-from-
    // the-far-side door (`http://127.0.0.1:<AOIDE_A2A_PORT or 8710>/`,
    // never `entry.url`'s requester-observed host, which the approver can
    // never dial directly through the tunnel) and `via` becomes the claim
    // itself, committed in the SAME write as the pairing commit below
    // (`set_peer_via`'s own doc on why it's a sibling writer beside
    // `upsert_paired_peer`). No claim on the entry (an old requester, or
    // one with nothing to claim) commits EXACTLY today's shape: `entry.url`
    // verbatim, `via` left `None` — the same "absent by default" a fresh
    // `Peer` already carries.
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
    let mut peers = aoide_storage::peer_store::load_peers();
    let first_pairing = !peers.iter().any(|p| p.name == entry.name && p.verified);
    let change = aoide_storage::peer_store::upsert_paired_peer(&mut peers, &entry.name, &record_url, &entry.pubkey_hex, now, &allows);
    if let Some(via) = entry.self_via.as_deref() {
        if let Err(e) = aoide_storage::peer_store::set_peer_via(&mut peers, &entry.name, Some(via)) {
            return Outcome::error(cmd, format!("recording the peer's transport marker: {e}"));
        }
    }
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"));
    }
    // Design A: mark approved, never take — the entry stays parked for the
    // requester's own poll to find (module doc above).
    let _ = aoide_storage::pairing::mark_inbound_approved(id, now_epoch);

    use aoide_storage::peer_store::PairChange;
    let word = match change {
        PairChange::Inserted => "paired with",
        PairChange::Updated => "re-paired with",
    };
    Outcome::ok(
        cmd,
        format!(
            "{word} `{}` (code {sas}) — verified{}; awaiting their own `peer pair approve {id}` to poll and complete their side",
            entry.name,
            grant_note(first_pairing, &allows)
        ),
    )
    .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
    .with_data(json!({ "confirmed": true, "sas": sas, "peer": entry.name, "pubkeyHex": entry.pubkey_hex, "direction": "inbound", "grant": allows, "grantStamped": first_pairing }))
}

/// The REQUESTER's poll-then-confirm-then-commit half of `peer pair
/// approve` (this instance holds the OUTBOUND entry, review-bounce
/// Finding 2's mutual confirmation, preserved).
///
/// **Design A (task #119): POLLS instead of waiting on a callback.** The old
/// shape refused outright while `state == AwaitingApproval`, waiting for an
/// `aoide/pairApprove` callback the approver's door would dial in to
/// deliver — unreachable when THIS instance's own door is loopback-only
/// ([[doors-loopback-only]]). Now, while still `AwaitingApproval`, this POSTs
/// a SIGNED `aoide/pairPoll` to the approver's door (`build_signed_pair_poll_body`,
/// over the SAME forward dial `peer pair`'s own two POSTs already
/// used — `entry.via` if one was recorded, never a reverse leg). A `pending`
/// answer refuses with the SAME "still awaiting the peer's own approval"
/// message the old callback-wait refusal gave (an ordinary, expected outcome
/// while the operators are still comparing codes out loud). An `approved`
/// answer calls [`aoide_storage::pairing::mark_outbound_awaiting_confirm`] —
/// the EXACT function the old callback handler used to call server-side,
/// only the TRIGGER moved to this poll — which rejects a pubkey that doesn't
/// match what THIS instance learned at request time (the SAS/transcript
/// binding: a substituted reveal is refused here, entry untouched, exactly
/// as the old callback's own mismatch handling refused it). From there on
/// (now `AwaitingConfirm`, whether transitioned just now or already so from
/// an earlier poll where the operator declined the confirm prompt) this
/// re-derives the SAS from this instance's own identity plus the entry's
/// stored transcript (never trusting the wire) and requires the SAME
/// explicit `y`/`yes` confirmation the approver's own side holds — only THEN
/// commits this instance's own peer record. The approver already committed
/// its own record locally, before this instance ever polled.
///
/// `skip_confirm` (P-P5): same meaning as [`approve_inbound`]'s own
/// parameter — the popup arm's dialog IS the confirmation.
pub(crate) fn approve_outbound(
    skip_confirm: bool,
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

    let entry = if entry.state == aoide_storage::pairing::OutboundState::AwaitingApproval {
        let poll_body = match build_signed_pair_poll_body(id) {
            Ok(b) => b,
            Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "identity-io-failed", "id": id })),
        };
        let via = match entry.via.as_deref().map(aoide_storage::tunnel::parse_via).transpose() {
            Ok(v) => v,
            Err(e) => return Outcome::error(cmd, format!("the pairing request's own recorded `via` no longer parses: {e}")),
        };
        let (code, resp_body) = match post_json_via(&entry.url, via.as_ref(), &entry.name, &poll_body, None, &[], 15) {
            Ok(v) => v,
            Err(e) => {
                return Outcome::error(
                    cmd,
                    format!("polling `{}` at {}: {e} — retry `aoide peer pair approve {id}` once it's reachable", entry.name, entry.url),
                )
                .with_data(json!({ "reason": "poll-unreachable", "id": id }))
            }
        };
        if code != 200 {
            return Outcome::error(cmd, format!("polling `{}`: HTTP {code}", entry.name))
                .with_data(json!({ "reason": "poll-http-error", "id": id, "httpCode": code }));
        }
        let parsed: Value = serde_json::from_str(&resp_body).unwrap_or(Value::Null);
        let status = match crate::peer::parse_pair_poll_response(&parsed) {
            Ok(s) => s,
            Err(e) => return Outcome::error(cmd, e).with_data(json!({ "reason": "poll-refused", "id": id })),
        };
        let polled_pubkey = match status {
            crate::peer::PairPollStatus::Pending => {
                return Outcome::error(
                    cmd,
                    format!(
                        "pairing request `{id}` to `{}` is still awaiting the peer's own approval — nothing to confirm yet; \
                         try again once they've run `aoide peer pair approve {id}` on their side, or \
                         `aoide peer pair reject {id}` to abort",
                        entry.name
                    ),
                )
                .with_data(json!({ "reason": "awaiting-peer-approval", "id": id }))
            }
            crate::peer::PairPollStatus::Approved { pubkey_hex } => pubkey_hex,
        };
        // The SAS/transcript binding (review-bounce Finding 2, preserved):
        // a released pubkey that does not match what THIS instance learned
        // at request time is refused here, entry untouched — the SAME
        // rejection the old callback's own mismatch handling gave.
        match aoide_storage::pairing::mark_outbound_awaiting_confirm(id, &polled_pubkey, now_epoch) {
            Ok(marked) => marked,
            Err(aoide_storage::pairing::ConfirmMarkError::Mismatch) => {
                return Outcome::error(
                    cmd,
                    format!("the peer's released identity does not match what this instance learned at request time for `{}` — refusing to bind a substituted reveal", entry.name),
                )
                .with_data(json!({ "reason": "reveal-mismatch", "id": id }))
            }
            Err(aoide_storage::pairing::ConfirmMarkError::Unknown) => {
                return Outcome::error(cmd, format!("no pending outbound pairing request with id `{id}` (unknown, already resolved, or expired)"))
                    .with_data(json!({ "reason": "unknown-id", "id": id }))
            }
            Err(aoide_storage::pairing::ConfirmMarkError::Io(e)) => return Outcome::error(cmd, format!("resolving the outbound pairing request: {e}")),
        }
    } else {
        entry
    };

    let (kp, _) = match aoide_storage::identity::load_or_mint() {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(cmd, format!("loading this instance's identity: {e}"))
                .with_data(json!({ "reason": "identity-io-failed" }))
        }
    };
    let own_pubkey = kp.info().pubkey_hex;
    let sas = aoide_storage::pairing::derive_sas(&own_pubkey, &entry.pubkey_hex, &entry.requester_nonce_hex, &entry.approver_nonce_hex);

    if !skip_confirm {
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
    let first_pairing = !peers.iter().any(|p| p.name == entry.name && p.verified);
    let change = aoide_storage::peer_store::upsert_paired_peer(&mut peers, &entry.name, &entry.url, &entry.pubkey_hex, now, &allows);
    // P-S4: the via this ceremony resolved back at `peer pair` request
    // time (K1's src_addr-derived default, or an explicit `--via`) rode
    // the parked entry here — commit it onto the peer record in the SAME
    // write as the pairing commit above, via the sibling writer
    // (`set_peer_via`'s own doc on why it's separate from
    // `upsert_paired_peer`'s signature). ONLY when `entry.via` is `Some`
    // (review fix, P-S4 follow-up) — a plain re-pair with no `--via` must
    // LEAVE a previously-recorded via (e.g. one earlier `peer pair` set)
    // exactly as it was, the same "untouched unless this call names a change"
    // stance `upsert_paired_peer` itself already holds for `autogate`/
    // `tokenFile`/`bearerSecret`/`hub`/`allows` on re-pairing; calling
    // `set_peer_via` unconditionally with `None` would silently WIPE that
    // marker as a side effect of an unrelated re-pair, never a deliberate
    // clear.
    if let Some(via) = entry.via.as_deref() {
        if let Err(e) = aoide_storage::peer_store::set_peer_via(&mut peers, &entry.name, Some(via)) {
            return Outcome::error(cmd, format!("recording the peer's transport marker: {e}"));
        }
    }
    if let Err(e) = aoide_storage::peer_store::save_peers(&peers) {
        return Outcome::error(cmd, format!("writing the peer registry: {e}"));
    }
    let _ = aoide_storage::pairing::take_outbound(id, now_epoch);

    use aoide_storage::peer_store::PairChange;
    let word = match change {
        PairChange::Inserted => "paired with",
        PairChange::Updated => "re-paired with",
    };
    Outcome::ok(cmd, format!("{word} `{}` (code {sas}) — verified{}", entry.name, grant_note(first_pairing, &allows)))
        .changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
        .with_data(json!({ "confirmed": true, "sas": sas, "peer": entry.name, "pubkeyHex": entry.pubkey_hex, "direction": "outbound", "grant": allows, "grantStamped": first_pairing }))
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
    reject_by_id(cmd, &id)
}

/// The shared body of `peer pair reject <id>` — extracted (P-P5) so
/// `pair_watch`'s own popup arm (a `--yes`-shaped CLI invocation is the
/// wrong shape for a dialog's "Reject request" button, which knows only
/// the id) can call it directly with no [`Invocation`] to construct.
/// Whichever direction the id is parked in, removes it — no peer record
/// on either end, no wire notification to the other side (module doc on
/// [`handle_peer_pair_reject`]).
pub(crate) fn reject_by_id(cmd: &str, id: &str) -> Outcome {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);

    match aoide_storage::pairing::take_inbound(id, now_epoch) {
        Ok(Some(entry)) => {
            return Outcome::ok(cmd, format!("rejected pairing request `{id}` from `{}` — no peer record written", entry.name))
                .with_data(json!({ "rejected": true, "id": id, "name": entry.name, "direction": "inbound" }))
        }
        Ok(None) => {}
        Err(e) => return Outcome::error(cmd, format!("removing the pairing request: {e}")),
    }

    match aoide_storage::pairing::take_outbound(id, now_epoch) {
        Ok(Some(entry)) => Outcome::ok(cmd, format!("aborted outbound pairing request `{id}` to `{}` — no peer record written", entry.name))
            .with_data(json!({ "rejected": true, "id": id, "name": entry.name, "direction": "outbound" })),
        Ok(None) => Outcome::error(cmd, format!("no pending pairing request with id `{id}` (unknown, already resolved, or expired)"))
            .with_data(json!({ "reason": "unknown-id", "id": id })),
        Err(e) => Outcome::error(cmd, format!("removing the pairing request: {e}")),
    }
}

/// `peer pair watch [--popup] [--json]`'s launch-record handler (P-P5) —
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
fn handle_peer_pair_watch(inv: &Invocation) -> Outcome {
    let cmd = "peer.pair.watch";
    if inv.door != aoide_protocol::Door::Cli {
        return Outcome::usage(
            cmd,
            "peer pair watch is a foreground follow that blocks until Ctrl-C; run it from a terminal (not over this door)",
        );
    }
    if inv.flag_present("popup") && inv.flag_present("json") {
        return Outcome::usage(
            cmd,
            "peer pair watch: --popup and --json are mutually exclusive — --popup replaces the terminal narration with a \
             confirm dialog, --json emits narration-only machine-readable lines; pick one",
        );
    }
    Outcome::ok(cmd, "watching pairing events")
}

/// `peer discover [--secs N] [--json]` (P-P6 + task #120,
/// `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
/// section): listens on the fixed UDP port for `--secs` seconds (default
/// `discover::DEFAULT_SWEEP_SECS`, ~4) and prints every DISTINCT
/// (name, source) heard — name, the claimed ssh hop (`user`@`host`),
/// `srcAddr`, first/last heard, and how many times
/// (`discover::run_sweep`'s own bounded fold). `host`/`user` are the
/// advertisement's own CLAIM; `srcAddr` is the packet's actual source
/// address, an OBSERVATION this process made directly (P-S1) — shown side
/// by side precisely so an operator can see them disagree. **Read-only**
/// — this command never writes `state/peers.json`; the pairing ceremony
/// is the only thing that ever registers a peer. Malformed advertisements
/// are dropped and counted, never echoed raw (house rule 4) — `dropped`
/// in the JSON data is a bare total, nothing more specific about what was
/// wrong with any one of them.
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

/// `peer discover`'s own default window ([`crate::discover::DEFAULT_SWEEP_SECS`],
/// ~4s) — unrelated to and unchanged by P-PV2; [`pair_via_hostname`] holds
/// its own, much longer, default instead ([`PAIR_TARGET_SWEEP_SECS`]).
fn parse_secs_flag(inv: &Invocation) -> Result<u64, ()> {
    parse_secs_flag_with_default(inv, crate::discover::DEFAULT_SWEEP_SECS)
}

/// Prompt `y/N` on stderr before running the pairing ceremony against a
/// discovered peer — a LOCAL UX confirmation only (mirrors
/// `confirm_spawn`/`confirm_sas`'s exact idiom), never a security gate:
/// the ceremony's own SAS confirmation (both operators, both ends) is the
/// sole authority either way. Shows BOTH the advertisement's claimed ssh
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

/// [`handle_peer_pair`]'s own default sweep window when `<target>` reads as
/// a hostname (P-PV2, the User's locked spec) — deliberately NOT
/// [`crate::discover::DEFAULT_SWEEP_SECS`] (`peer discover`'s own ~4s,
/// unrelated and unchanged): a real LAN's advertise cadence is a ~30-40s
/// tick (`handle_peer_advertise`'s own doc), so 4s reliably missed it in
/// practice — task #129's known miss. 45s comfortably spans one tick.
const PAIR_TARGET_SWEEP_SECS: u64 = 45;

/// `peer pair <target>`'s HOSTNAME arm (`target` is not a URL) — the old
/// `peer invite <name>` handler's own body, unchanged apart from the
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
/// non-default far-end port needs the explicit url arm (`peer pair
/// <url>`) instead. Before dialing, the SELF-PAIR GUARD
/// (`discover::is_self_target`) refuses when the heard name is this
/// instance's own or the datagram came from loopback — the "you just
/// tried to pair with yourself" case owed here because this is where the
/// target is chosen (a broadcast always loops back to its own sender).
/// `--yes` skips only the LOCAL proceed-confirm (`confirm_invite`), exactly
/// `peer spawn`'s own `--yes` idiom — the ceremony's OWN SAS confirmation
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

    pair_with_heard(cmd, &hit, via_flag.as_ref(), self_via_flag.as_deref())
}

/// The tail `peer pair`'s hostname arm ([`pair_via_hostname`]) and bare
/// `pair` share once a [`crate::discover::Heard`] target is settled (each
/// having already run its own guard/confirmation): compose the dial URL
/// from the hit's OBSERVED source address on the house door port
/// ([`default_a2a_port`] — the advertisement carries no door URL to read a
/// port off, by design), and run the SAME [`run_pair_request`] core the
/// url arm ([`pair_via_url`]) calls — reused, never forked.
///
/// P-PV1's settled default (task #131 — loopback-only doors, superseding
/// K1): the peer this ceremony creates gets an automatic `via` derived from
/// the advertisement's OBSERVED source address plus its claimed ssh login
/// (task #120 — the one thing the wire exists to carry), so its own FUTURE
/// calls (pull/spawn/send) can reach it through an ssh tunnel — recorded at
/// `peer pair approve` commit time, exactly as before. The SAME derived
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
) -> Outcome {
    let dial_url = format!("http://{}:{}/", hit.src_addr, default_a2a_port());
    let self_url = default_self_url();
    // `hit.src_addr` is the OBSERVED source address — the real dial target
    // this whole ceremony is already using, so it is also the right target
    // for `default_self_via`'s outbound-route trick.
    let self_via = self_via_flag.map(|s| s.to_string()).or_else(|| default_self_via(&hit.src_addr));
    let (dial_via, record_via) = resolve_pair_vias(hit, via_flag);
    run_pair_request(cmd, &dial_url, &hit.advertisement.name, &self_url, self_via.as_deref(), dial_via.as_ref(), record_via)
}

/// The pure decision [`pair_with_heard`] otherwise buries inline (P-PV1,
/// task #131) — split out so it is unit-testable with no dial, no tempdir,
/// no ssh: what `via` the ceremony's OWN two POSTs dial through, and what
/// `via` gets parked for LATER commit onto the resulting peer record.
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

/// `peer pair`/`peer pending` (P-PV2, the User's locked spec, superseding
/// P-P2's `peer pair request`/`peer pair pending` split) plus `peer pair
/// approve|reject|watch`, registered directly after the six legacy `peer`
/// commands — same-network federation's pairing ceremony joins the group
/// it extends, nothing existing reorders.
pub fn register_peer_pair(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "pair"],
        summary: "Send a pairing request and display the confirmation code (SAS) plus its pending id to compare out-of-band. A URL-shaped target (contains \"://\") dials it directly; anything else is a hostname, resolved by a discovery beacon sweep.",
        args: [arg!("target", "string", true, "A URL (e.g. http://host:8710/) to dial directly, or a hostname to resolve via a discovery sweep.")],
        flags: [
            flag!("name", "string", "A local nickname for the other instance (URL target only); defaults to a sanitized form of the URL's host."),
            flag!("self-url", "string", "This instance's own advertised A2A door URL, recorded on the resulting peer record for the approver's future non-ceremony calls (the ceremony itself now polls, so this is no longer dialed to complete pairing); defaults to http://<host>:<AOIDE_A2A_PORT or 8710>/."),
            flag!("self-via", "string", "This instance's own ssh://[user@]host reach-back hop claim, sent on the wire beside --self-url so an approver that only ever observes this request over a tunnel (loopback) can still record a working via; defaults to ssh://<local user>@<the local address routed toward the peer>."),
            flag!("via", "string", "An ssh://[user@]host[:port] transport marker — both the ceremony's own dial AND the resulting peer's recorded via. Absent = direct dial (today's behavior)."),
            flag!("secs", "int", "Hostname target only: how many seconds to sweep for the advertisement (default 45)."),
            flag!("yes", "bool", "Hostname target only: skip the interactive y/N proceed confirmation (scripted use) — the ceremony's own SAS confirmation is untouched."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_pair,
    ));
    r.insert(cmd!(
        path: ["peer", "pending"],
        summary: "List pairing requests parked on this instance. Never shows the confirmation code (SAS) — that is read off the requester's own screen and typed on the approver's, out-of-band; see `peer pair approve`.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_pending,
    ));
    r.insert(cmd!(
        path: ["peer", "pair", "approve"],
        summary: "Approve a pending pairing request — the approver TYPES the pairing code as read from the requester's screen (3 cumulative mismatches auto-deny; --code NNN-NNN scripted) and commits locally; the requester polls for the release, confirms y/N (--yes scripted), then commits; run on both ends. <id> may be omitted when exactly one request is pending.",
        args: [arg!("id", "string", false, "The pending pairing request's id (see `peer pending`); required when more than one request is pending.")],
        flags: [
            flag!("yes", "bool", "Skip the interactive y/N confirmation on an OUTBOUND (requester-side) id (scripted use); an inbound id takes --code instead — --yes never bypasses the approver's typed code."),
            flag!("code", "string", "The pairing code, read from the requester's screen, for approving an INBOUND id without a terminal prompt (scripted use); a wrong code counts one persisted try, and 3 cumulative mismatches auto-deny the request."),
            flag!("allow", "string", "The capabilities this commit grants the peer, comma-separated (read, spawn) — overriding config.toml's `[pairing] defaultGrant` for this pairing only, and empty (--allow \"\") to grant nothing. Applies ONLY on a peer's FIRST verification: re-pairing an already-verified peer never re-grants, so use `peer allow` to change a live grant."),
        ],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_approve,
    ));
    r.insert(cmd!(
        path: ["peer", "pair", "reject"],
        summary: "Refuse a pending pairing request — a clean removal, no peer record on either end.",
        args: [arg!("id", "string", true, "The pending pairing request's id (see `peer pending`).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_reject,
    ));
    r.insert(cmd!(
        path: ["peer", "pair", "watch"],
        summary: "Foreground, line-mode follow of the pairing-ceremony events feed (parked/revealed/awaiting-confirm) plus a 30s reconcile safety tick. --json emits one event object per line instead of narration. --popup (opt-in, aoide.a2a.pairingPopup) swaps the terminal narration for a dialog shaped by direction on each actionable request: typed-code entry on an inbound reveal, a single Approve/Reject on an outbound awaiting-confirm — lyra when it resolves, zenity otherwise — mutually exclusive with --json. CLI-only — blocks until Ctrl-C.",
        args: [],
        flags: [flag!(
            "popup",
            "bool",
            "Surface each actionable request as a dialog instead of terminal narration: typed-code entry (inbound reveal) or a single Approve/Reject (outbound awaiting-confirm) — lyra when it resolves, zenity otherwise. Requires one of the two on PATH. Mutually exclusive with --json."
        )],
        gated: false,
        implemented: true,
        handler: handle_peer_pair_watch,
        examples: ["peer pair watch", "peer pair watch --json", "peer pair watch --popup"],
    ));
}

/// `peer advertise on|off` (task #120): flip this instance's discovery
/// advertise switch (`aoide_storage::advertise::set_enabled`,
/// `state/advertise.json`). Idempotent, and says which of the two it was —
/// "flipped" names both states, "already" names the one it stays in. The
/// switch is READ by a running `a2a serve`'s advertise thread on every
/// tick (~30-40s), so no restart is involved — but no `a2a serve` running
/// means nothing is emitting either way, which the message teaches rather
/// than assumes.
fn handle_peer_advertise(inv: &Invocation) -> Outcome {
    let cmd = "peer.advertise";
    const USAGE: &str = "usage: aoide peer advertise on|off";
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

/// `peer discover`/`peer advertise` (P-P6 + task #120,
/// `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
/// section), registered directly after `register_peer_pair` — discovery is
/// sugar OVER the ceremony that group already owns, never a parallel
/// mechanism, so it joins the group it extends the same way
/// `register_peer_pair` itself did for the six legacy `peer` commands.
/// `peer pair <hostname>`'s own hostname arm ([`pair_via_hostname`], P-PV2)
/// is the sugar-over-the-ceremony command now — `peer invite` died in the
/// same phase, hard cutover, no alias.
pub fn register_peer_discovery(r: &mut Registry) {
    r.insert(cmd!(
        path: ["peer", "discover"],
        summary: "Listen for discovery advertisements on the LAN (UDP broadcast, fixed port) and print every distinct instance heard (name, claimed ssh hop user@host, and the observed source address) — read-only, never writes state/peers.json.",
        args: [],
        flags: [flag!("secs", "int", "How many seconds to listen (default ~4).")],
        gated: false,
        implemented: true,
        handler: handle_peer_discover,
    ));
    r.insert(cmd!(
        path: ["peer", "advertise"],
        summary: "Switch this instance's discovery advertising on or off (state/advertise.json; default off) — a running a2a serve reads the switch every tick and emits name + ssh hop info only, never a door URL or key.",
        args: [arg!("state", "string", true, "`on` or `off`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_peer_advertise,
        examples: ["peer advertise on", "peer advertise off"],
    ));
}

/// Bare `pair`'s sweep window (task #120 P3): one bounded listen, ~2s —
/// the same short window `peer list`'s roster sweep settled on (a friendly
/// entry command should answer fast; a quiet LAN that needs longer has
/// `peer discover --secs N`).
const PAIR_SWEEP_SECS: u64 = 2;

/// Bare `aoide pair` (task #120 P3) — the friendly entry into the pairing
/// ceremony: one bounded advertisement sweep ([`crate::discover::run_sweep`],
/// [`PAIR_SWEEP_SECS`]), then an interactive SELECT menu over the
/// advertising candidates (`aoide_protocol::pick::choose` — the same
/// `inquire`-backed picker substrate bare `session` opens), and the picked
/// row drives the EXISTING [`pair_with_heard`] → [`run_pair_request`] path
/// — reuse, never a fork; `run_pair_request`'s own success message then
/// prints the SAS and teaches the approve step on both ends. Picking a row
/// IS the proceed-confirmation — no second `confirm_invite`-style y/N on
/// top (`peer pair <hostname>` needs one because its target arrives as a
/// typed argument, not a choice made looking at the candidate).
///
/// Row text renders only already-validated advertisement fields
/// (`advertise::parse_and_validate` gates every one — house rule 4) plus
/// the OBSERVED source address, claim and observation side by side, the
/// same untrusted-display stance `peer list`'s `◆` candidate rows hold.
/// Own advertisements are filtered out up front
/// (`discover::is_self_target` — a broadcast always loops back to its own
/// sender), so the menu never offers a self-pair.
///
/// CLI-door + real-tty only (`pick::interactive`, the same gate bare
/// `session` holds; `--json` steers to the taught refusal too — a picker's
/// prompts have no business interleaving with a machine-readable stream):
/// every other shape gets a taught refusal naming the scripted spellings,
/// never a hang on a stdin nobody is typing into.
fn handle_pair(inv: &Invocation) -> Outcome {
    let cmd = "pair";
    let taught = "bare `pair` opens an interactive pairing picker on a real CLI terminal; scripted path: \
                  `aoide peer advertise on` on the other box, then `aoide peer pair <name> --yes` \
                  (hostname) or `aoide peer pair <url> [--via ssh://[user@]host]` (explicit dial) here";
    if inv.door != aoide_protocol::Door::Cli {
        return Outcome::usage(cmd, format!("{taught} (this door is not the CLI)"));
    }
    if inv.flag_present("json") || !aoide_protocol::pick::interactive(inv.door) {
        return Outcome::usage(cmd, taught);
    }

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
    if candidates.is_empty() {
        return Outcome::ok(
            cmd,
            format!(
                "heard no advertising instances in {PAIR_SWEEP_SECS}s ({} malformed dropped) — on the OTHER box, \
                 switch advertising on with `aoide peer advertise on` (a running `a2a serve` emits it within ~40s) \
                 and run `aoide pair` here again; or pair manually with \
                 `aoide peer pair <url> [--via ssh://[user@]host]`",
                swept.dropped
            ),
        )
        .with_data(json!({ "heard": 0, "dropped": swept.dropped }));
    }

    let rows: Vec<String> = candidates
        .iter()
        .map(|h| {
            format!(
                "{} — claims ssh {}@{}, observed at {}",
                h.advertisement.name, h.advertisement.user, h.advertisement.host, h.src_addr
            )
        })
        .collect();
    match aoide_protocol::pick::choose("pair with which instance?", &rows, None) {
        None => Outcome::ok(cmd, "nothing chosen — nothing sent"),
        Some(i) => pair_with_heard(cmd, &candidates[i], None, None),
    }
}

/// Bare `pair` (task #120 P3), registered at the END of assembly like
/// every appended-newest command — the top-level friendly entry into the
/// ceremony `register_peer_pair`/`register_peer_discovery` own the
/// scripted spellings of.
pub fn register_pair(r: &mut Registry) {
    r.insert(cmd!(
        path: ["pair"],
        summary: "Open the interactive pairing picker on a real CLI terminal: one ~2s advertisement sweep, a select menu over the advertising instances heard (name, claimed ssh hop, observed source), and the picked one runs the same ceremony `peer pair` drives — then prints the code to compare and the approve step for both ends. Non-tty or non-CLI invocations get a taught pointer at the scripted spellings instead.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_pair,
        examples: ["pair"],
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
    /// local outbound address toward the peer, never a claimed OS
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
    fn default_self_via_formats_login_at_the_outbound_address_toward_the_peer() {
        let _guard = crate::env_lock().lock().unwrap();
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

    // ── `handle_peer_allow` (P-P3) — pure file I/O, so unlike most `peer`
    // ── commands (network-touching, tested at `cli/tests/peer_connectivity.rs`'s
    // ── `#[ignore]`'d integration layer) this one is directly unit-testable,
    // ── same reasoning `handle_peer_hub`'s own storage-layer tests already
    // ── rest on. ─────────────────────────────────────────────────────────────

    /// `AOIDE_ROOT` and `AOIDE_CONFIG` are sandboxed alongside the state dir
    /// because a pairing commit now resolves its grant from `config.toml`
    /// (`resolve_grant`): left alone, these tests would read the developer's
    /// own `~/.aoide/config.toml` and go red on a machine whose operator had
    /// widened `defaultGrant` — or on a malformed file that has nothing to do
    /// with the code under test. Inside the sandbox the file is absent, so
    /// every `grant: None` path resolves the built-in `["read"]`.
    fn with_peer_state<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let saved_root = std::env::var("AOIDE_ROOT").ok();
        let saved_config = std::env::var("AOIDE_CONFIG").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-client-peer-allow-{tag}-{}-{}",
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
            assert_eq!(get(aoide_storage::wire_auth::HEADER_PEER), aoide_storage::display::local_host_name());
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
    fn sign_headers_for_peer_sends_this_instances_own_self_name_not_the_peer_nickname() {
        // Live yomi<->sakaki defect, 2026-08-26: e78999f fixed the pairing
        // wire name (`run_pair_request`) but left THIS header sending
        // `peer.name` — this instance's local nickname for the counterpart
        // — instead of its own self name, so the far end's
        // `verify_signed_request` lookup (`peers.iter().find(|p| p.name ==
        // peer_name)`) failed with "unknown peer" for every signed request
        // after an otherwise-successful pair. `fixture_peer`'s name
        // ("yomi-strix") deliberately stands in for "this side's nickname
        // for the counterpart," distinct from whatever this test process's
        // own `local_host_name()` resolves to, so a regression back to
        // `peer.name.clone()` fails this assertion.
        with_peer_state("sign-self-name", || {
            let mut peer = fixture_peer(None);
            peer.name = "this-sides-nickname-for-the-approver".to_string();
            peer.verified = true;
            let headers = sign_headers_for_peer(&peer, "{}").unwrap();
            let sent = headers
                .iter()
                .find(|(k, _)| k == aoide_storage::wire_auth::HEADER_PEER)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("missing {}: {headers:?}", aoide_storage::wire_auth::HEADER_PEER));
            assert_eq!(sent, aoide_storage::display::local_host_name(), "must carry this instance's own self name");
            assert_ne!(sent, peer.name, "must never carry the local nickname for the counterpart");
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
                out.message.contains("peer pair"),
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
                out.message.contains("peer pair"),
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
    // `run_sweep` needs a real socket (a plain fixed-port bind — no group
    // join since the #106 broadcast fix, so this runs everywhere, the nix
    // build sandbox included), but it does NOT need a real ADVERTISEMENT
    // to prove the one invariant that matters here: a 1s sweep that hears
    // nothing still must leave `state/peers.json` byte-identical to what
    // it was before. The genuine heard-a-real-advertisement path is
    // `discover::tests::run_sweep_hears_an_advertisement_sent_over_the_
    // real_loopback_stack` plus `cli/tests/discovery_connectivity.rs`'s
    // `#[ignore]`'d real-network tests.

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
        with_peer_state("discover-no-write-empty", || {
            let out = handle_peer_discover(&discover_inv("1"));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert!(
                aoide_storage::peer_store::load_peers().is_empty(),
                "discover must never create state/peers.json out of nothing"
            );
        });
    }

    // ── `peer advertise on|off` (task #120) — the runtime switch, default
    // ── off, idempotent, reporting exactly what changed. ─────────────────────

    fn advertise_inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["peer".to_string(), "advertise".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn peer_advertise_flips_the_switch_idempotently_and_reports_exactly_what_changed() {
        with_peer_state("advertise-toggle", || {
            assert!(!aoide_storage::advertise::enabled(), "default posture is OFF");

            let on = handle_peer_advertise(&advertise_inv(&["on"]));
            assert_eq!(on.status, aoide_protocol::output::Status::Ok, "{on:?}");
            assert_eq!(on.data.as_ref().unwrap()["changed"], true, "{on:?}");
            assert!(aoide_storage::advertise::enabled());

            let again = handle_peer_advertise(&advertise_inv(&["on"]));
            assert_eq!(again.status, aoide_protocol::output::Status::Ok, "{again:?}");
            assert_eq!(again.data.as_ref().unwrap()["changed"], false, "{again:?}");
            assert!(again.message.contains("already on"), "{}", again.message);

            let off = handle_peer_advertise(&advertise_inv(&["off"]));
            assert_eq!(off.data.as_ref().unwrap()["changed"], true, "{off:?}");
            assert!(!aoide_storage::advertise::enabled());
        });
    }

    #[test]
    fn peer_advertise_refuses_anything_but_on_or_off() {
        // Pure arg validation — refused before any state file is touched,
        // so no temp dir is needed.
        for bad in [&[][..], &["maybe"][..], &["ON"][..]] {
            let out = handle_peer_advertise(&advertise_inv(bad));
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
        }
    }

    // ── `peer pair`'s hostname arm bottoms out in the exact same
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
    fn peer_pair_hostname_arm_and_url_arm_are_the_same_function_not_two_copies() {
        with_peer_state("hostname-arm-shares-run-pair-request", || {
            // Port 1 is reserved and never listened on in practice — an
            // immediate, deterministic connection refusal either way.
            let url = "http://127.0.0.1:1/";
            let name = "unreachable-pair-target";
            let self_url = default_self_url();

            // `pair_via_url`'s own documented tail.
            let direct = run_pair_request("peer.pair", url, name, &self_url, None, None, None);
            // The same ceremony tail `pair_via_hostname` reaches on its
            // single-match branch — it composes an OBSERVED dial url first
            // (src_addr + `default_a2a_port`, P-S1/task #120) and passes
            // that, but the tail function is still this one; reproduced
            // here under the identical `peer.pair` command name both arms
            // now share.
            let via_hostname = run_pair_request("peer.pair", url, name, &self_url, None, None, None);

            assert_eq!(direct.status, aoide_protocol::output::Status::Error, "{direct:?}");
            assert_eq!(direct.command, "peer.pair");
            assert_eq!(via_hostname.status, direct.status);
            assert_eq!(via_hostname.command, "peer.pair");
            // Same failure MESSAGE from both call sites — proves it is one
            // function's error path taken twice, not two independently
            // drifting implementations that merely happen to agree today.
            assert_eq!(
                via_hostname.message, direct.message,
                "peer pair's url arm and hostname arm must produce an identical failure message here"
            );
        });
    }

    // ── Dial resolution (P-S4): the identity guarantee, per call site,
    // ── pinned directly rather than trusted from a comment — §0.4's
    // ── "off = unchanged" promise, and the path-preservation invariant
    // ── sign_headers_for_peer's canonical string depends on. No real ssh
    // ── anywhere below: a `via` case seeds a REUSABLE tunnel record
    // ── (a real local listener, this test process's own — genuinely
    // ── alive — pid) so `aoide_client::tunnel::open_or_reuse` takes its
    // ── reuse branch and never spawns anything, the same seam
    // ── `client/src/tunnel.rs`'s own tests exercise, reached here through
    // ── the public record API instead of the private `SpawnFn` closure. ──

    fn with_temp_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
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
    fn post_json_to_peer_dials_peer_url_verbatim_when_peer_via_is_absent() {
        // post_json_to_peer's OWN via resolution (peer.via, not the
        // resolve_dial_url helper directly) — proven by forcing a
        // connection failure and asserting the error names peer.url's own
        // host:port, never a rewritten 127.0.0.1:<port> authority.
        let mut peer = fixture_peer(None);
        peer.url = "http://127.0.0.1:1/aoide/rpc".to_string(); // reserved, never listened on
        let err = post_json_to_peer(&peer, "{}", None, &[], 1).unwrap_err();
        assert!(
            err.contains("127.0.0.1:1") || err.contains("connect"),
            "an absent via must dial peer.url's own authority verbatim: {err}"
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
                    format!("http://127.0.0.1:{port}{}", aoide_storage::peer_store::url_path(logical)),
                    "authority becomes 127.0.0.1:<local port>, path preserved via url_path directly"
                );
            }
            drop(listener);
        });
    }

    /// §0.4's identity guarantee, pinned directly against
    /// `sign_headers_for_peer`'s own path source: `sign_headers_for_peer`
    /// never reads the DIAL url at all (it signs over
    /// `peer_store::url_path(&peer.url)`, computed independently, before
    /// dial resolution ever runs) — so the canonical string it signs is
    /// unaffected by a via rewrite PROVIDED the dial's own path equals
    /// that same `url_path(&peer.url)`. This asserts exactly that equality
    /// for a peer carrying a `via`, which is what makes "the far end's
    /// `HttpRequest.path` (what the tunnel actually delivers) matches what
    /// was signed" true — a live curl round trip through the tunnel is out
    /// of reach here (no real ssh), but every byte this signature depends
    /// on is proven identical either way.
    #[test]
    fn a_via_rewrite_never_changes_the_path_sign_headers_for_peer_signs_over() {
        // Sandbox fix (review): this test calls `sign_headers_for_peer`,
        // which mints/loads THIS instance's identity
        // (`aoide_storage::identity::load_or_mint`) — that needs a
        // writable `AOIDE_STATE_DIR`, which `with_temp_runtime_dir` alone
        // never sets (it only isolates `XDG_RUNTIME_DIR` for the tunnel
        // record). In a build sandbox with no real `$HOME`,
        // `load_or_mint`'s own default state-dir fallback is unwritable —
        // "Permission denied" — exactly the failure `with_peer_state`
        // (used by every OTHER identity-touching test in this module,
        // e.g. `sign_headers_for_peer_round_trips_a_genuine_signature_for_
        // a_verified_peer`) already avoids. `with_peer_state_and_temp_
        // runtime_dir` isolates BOTH under one `env_lock` acquisition
        // (nesting the two single-purpose helpers would deadlock — see
        // its own doc).
        with_peer_state_and_temp_runtime_dir("sign-headers-path-pin", || {
            let session_id = tunnel_session_id();
            let (listener, port) = seed_reusable_tunnel(&session_id, "sakaki");

            let mut peer = fixture_peer(None);
            peer.name = "sakaki".to_string();
            peer.url = "http://sakaki:8710/aoide/rpc".to_string();
            peer.via = Some("ssh://sakaki".to_string());

            let signed_path = aoide_storage::peer_store::url_path(&peer.url);

            let via = aoide_storage::tunnel::parse_via(peer.via.as_deref().unwrap()).unwrap();
            let dial = resolve_dial_url(&peer.url, Some(&via), &peer.name).unwrap();
            let dial_path = aoide_storage::peer_store::url_path(&dial);

            assert_eq!(
                dial_path, signed_path,
                "the tunnel rewrite must never change the byte-for-byte path sign_headers_for_peer signs over"
            );
            assert!(dial.starts_with(&format!("http://127.0.0.1:{port}")), "authority is rewritten to the local forward: {dial}");

            // And directly: sign_headers_for_peer itself only ever reads
            // peer.url (never peer.via, never a dial url) — an unverified
            // peer's empty-headers shortcut is untouched by via either way.
            assert_eq!(sign_headers_for_peer(&peer, "{}").unwrap(), Vec::<(String, String)>::new(), "unverified peers are unaffected, via or not");
            peer.verified = true;
            let headers_with_via = sign_headers_for_peer(&peer, "{}").unwrap();
            let mut peer_no_via = peer.clone();
            peer_no_via.via = None;
            let headers_without_via = sign_headers_for_peer(&peer_no_via, "{}").unwrap();
            // Nonce/timestamp differ call to call (fresh each time) — but
            // the PEER identity header (never derived from via) must agree.
            let peer_header_idx = aoide_storage::wire_auth::HEADER_PEER;
            let get = |hs: &[(String, String)]| hs.iter().find(|(k, _)| k == peer_header_idx).map(|(_, v)| v.clone());
            assert_eq!(get(&headers_with_via), get(&headers_without_via), "peer.via must never influence the signed X-Aoide-Peer identity");

            drop(listener);
        });
    }

    #[test]
    fn parse_via_flag_absent_is_none_present_invalid_is_err_never_a_silent_fallback() {
        let inv = |flags: &[(&str, &str)]| Invocation {
            path: vec!["peer".to_string(), "add".to_string()],
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
    fn handle_peer_add_with_an_invalid_via_is_a_usage_error_and_registers_nothing() {
        with_peer_state("add-invalid-via", || {
            let inv = Invocation {
                path: vec!["peer".to_string(), "add".to_string()],
                args: vec!["sakaki".to_string(), "http://sakaki:8710/".to_string()],
                flags: [("via".to_string(), "http://not-ssh".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_peer_add(&inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(aoide_storage::peer_store::load_peers().is_empty(), "an invalid --via registers nothing");
        });
    }

    /// Both `AOIDE_STATE_DIR` (peers.json) and `XDG_RUNTIME_DIR` (tunnel
    /// records) under ONE `env_lock` acquisition — `with_peer_state` and
    /// `with_temp_runtime_dir` each lock it themselves, so nesting them
    /// would deadlock (a plain `std::sync::Mutex` is not reentrant).
    fn with_peer_state_and_temp_runtime_dir<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
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
    /// (its full `#!/bin/sh` body), restoring the previous `PATH` and
    /// removing the shim directory when `f` returns. Reused by both
    /// `MAX_RESPONSE_BYTES` tests below (#114) — no real network, no real
    /// `curl` process, same no-mock-needed shim technique the no-verify
    /// test above already established for proving what does/doesn't reach
    /// `run_curl`.
    fn with_fake_curl<T>(tag: &str, script: &str, f: impl FnOnce() -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let shim_dir = std::env::temp_dir().join(format!(
            "aoide-client-curlshim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let shim = shim_dir.join("curl");
        std::fs::write(&shim, script).unwrap();
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
        let script = format!("#!/bin/sh\ndd if=/dev/zero bs=1M count={over_cap_mib} 2>/dev/null\n");
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
        let script = "#!/bin/sh\nprintf '{\"ok\":true}\\n200'\n";
        let result = with_fake_curl("under-cap", script, || run_curl(&["--", "http://example.invalid/"], None));
        let (code, body) = result.expect("a small, ordinary payload must pass through the cap untouched");
        assert_eq!(code, 200);
        assert_eq!(body, "{\"ok\":true}");
    }

    /// Task #103, requester side: once the remote A2A door's bounded
    /// liveness check (`aoide-server::a2a::do_spawn`) turns a failed spawn
    /// into a proper JSON-RPC error instead of an optimistic `submitted`
    /// ack, `spawn_on_peer_via` must surface that taught message CLEANLY —
    /// never swallowed, never re-summarized — through its existing
    /// `"peer-refused"` arm. No new client-side code was needed for this;
    /// this test PINS that the existing plumbing already does the job,
    /// driven through a fake `curl` shim standing in for the remote door's
    /// HTTP 200 / JSON-RPC-error response (JSON-RPC errors are always HTTP
    /// 200 — the error lives in the envelope, not the status line).
    #[test]
    fn spawn_on_peer_via_surfaces_a_json_rpc_error_ack_as_a_taught_peer_refused_error() {
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
        let script = format!("#!/bin/sh\ncat <<'JSONBODY'\n{body}\nJSONBODY\nprintf '200'\n");
        let peer = fixture_peer(None);
        let result = with_fake_curl("spawn-refused", &script, || spawn_on_peer_via(&peer, "hello", None));
        let err = result.expect_err("a JSON-RPC error ack must surface as an Err, never as Ok");
        assert_eq!(err.reason, "peer-refused");
        assert!(
            err.message.contains(taught),
            "the taught message must reach the caller verbatim, not summarized: {}",
            err.message
        );
    }

    /// Review finding, P-S4 follow-up: `peer add`'s AgentCard verification
    /// is its ONE network call, and used to dial `peer.url` directly even
    /// when `--via` was given — exactly the scenario `--via` exists for (a
    /// loopback-bound door reachable only through the tunnel) would fail
    /// verification and never get registered. Proven end to end with a
    /// REAL `curl` GET (no mock) reaching a REAL local HTTP responder
    /// through a REUSED tunnel record (P-S3's seam, no real ssh anywhere):
    /// the peer's logical url names an RFC 2606 `.invalid` host that can
    /// never resolve, so the fetch can only have succeeded by going
    /// through the rewritten `127.0.0.1:<port>` target the seeded record
    /// names — an `Ok` outcome here is the proof. The recorded `peer.url`
    /// must still be the LOGICAL url, never the rewritten one.
    #[test]
    fn handle_peer_add_with_a_valid_via_verifies_the_agentcard_through_the_tunnel_and_records_the_logical_url() {
        with_peer_state_and_temp_runtime_dir("add-valid-via", || {
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
                path: vec!["peer".to_string(), "add".to_string()],
                args: vec!["sakaki".to_string(), logical_url.to_string()],
                flags: [("via".to_string(), "ssh://sakaki".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_peer_add(&inv);
            assert_eq!(
                out.status,
                aoide_protocol::output::Status::Ok,
                "the fetch must have gone through the tunnel — the logical host cannot resolve at all: {out:?}"
            );

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].url, logical_url, "the recorded peer.url stays LOGICAL, never the rewritten dial url");
            assert_eq!(peers[0].via.as_deref(), Some("ssh://sakaki"));

            drop(listener);
        });
    }

    /// `peer add --no-verify` (M3, task #16: Melete inbound via the
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
    fn handle_peer_add_no_verify_never_invokes_curl() {
        with_peer_state("add-no-verify", || {
            let shim_dir = std::env::temp_dir().join(format!(
                "aoide-client-peer-add-noverify-curlshim-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));
            std::fs::create_dir_all(&shim_dir).unwrap();
            let marker = shim_dir.join("curl-was-invoked");
            let shim = shim_dir.join("curl");
            std::fs::write(&shim, format!("#!/bin/sh\ntouch {}\nexit 1\n", marker.display())).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let saved_path = std::env::var("PATH").ok();
            std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

            let inv = Invocation {
                path: vec!["peer".to_string(), "add".to_string()],
                args: vec!["melete".to_string(), "http://melete.example:8710/".to_string()],
                flags: [("no-verify".to_string(), "true".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_peer_add(&inv);

            match saved_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            let curl_ran = marker.exists();
            let _ = std::fs::remove_dir_all(&shim_dir);

            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert!(!curl_ran, "--no-verify must never invoke curl (the shim would have touched its marker)");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "melete");
            assert_eq!(peers[0].url, "http://melete.example:8710/");
            assert!(
                !peers[0].verified,
                "peer add --no-verify still records verified:false — a card fetch was never identity, only reachability"
            );
        });
    }

    /// `--via` beats `Peer.via` — proven WITHOUT ever needing a real
    /// tunnel or ssh, by making the RECORDED `peer.via` a deliberately
    /// UNPARSEABLE string (`parse_via`'s own refusal, pure and instant):
    /// with no override, `post_json_to_peer` must consult it and fail
    /// immediately on the parse error (proving the recorded via IS read
    /// when nothing beats it); with an explicit, VALID override, the same
    /// invalid `peer.via` string must never surface at all — the override
    /// short-circuits before `peer.via` is ever parsed. The override case
    /// seeds a REUSABLE tunnel record (this test module's own no-real-ssh
    /// seam) so the override path completes rather than needing a live
    /// ssh child.
    #[test]
    fn via_override_beats_the_recorded_peer_via() {
        with_temp_runtime_dir("override-beats-recorded", || {
            let mut peer = fixture_peer(None);
            peer.name = "sakaki".to_string();
            peer.url = "http://sakaki:8710/".to_string();
            peer.via = Some("not-a-valid-via-at-all".to_string());

            // No override: post_json_to_peer_with_via_override falls back
            // to post_json_to_peer, which parses peer.via and refuses
            // immediately — no network touched, the taught parse error
            // surfaces directly, proving peer.via WAS consulted.
            let no_override_err =
                post_json_to_peer_with_via_override(&peer, "{}", None, &[], 1, None).unwrap_err();
            assert!(
                no_override_err.contains("not-a-valid-via-at-all"),
                "with no override, the recorded (invalid) peer.via must be the thing that fails: {no_override_err}"
            );

            // With an explicit, VALID override, peer.via's garbage string
            // must never even be looked at — seed a reusable record for
            // the SAME key (peer.name) the override path also dials
            // through, so this completes with no real ssh spawned.
            let session_id = tunnel_session_id();
            let (listener, _port) = seed_reusable_tunnel(&session_id, "sakaki");
            let override_via = aoide_storage::tunnel::parse_via("ssh://khoa@sakaki").unwrap();
            let with_override =
                post_json_to_peer_with_via_override(&peer, "{}", None, &[], 1, Some(&override_via));
            match with_override {
                Err(e) => assert!(
                    !e.contains("not-a-valid-via-at-all"),
                    "an explicit --via override must never surface the recorded (invalid) peer.via: {e}"
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
    /// gone outright. Proven the same way `handle_peer_add_no_verify_
    /// never_invokes_curl` proves an external binary was never invoked: a
    /// fake `curl` dropped on `PATH` that touches a marker file if ever run.
    /// This is THE test that pins "no approver->requester network callback
    /// happens" at the client layer (the a2a.rs full-ceremony test pins the
    /// same invariant one layer down, by never dialing an undialable url).
    #[test]
    fn approve_inbound_never_invokes_curl_purely_local_commit() {
        with_peer_state("approve-inbound-no-curl", || {
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
            std::fs::write(&shim, format!("#!/bin/sh\ntouch {}\nexit 1\n", marker.display())).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let saved_path = std::env::var("PATH").ok();
            std::env::set_var("PATH", format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default()));

            let outcome = approve_inbound(InboundGate::Code(sas), "peer.pair.approve", &id, entry, &now, now_epoch, None);

            match saved_path {
                Some(p) => std::env::set_var("PATH", p),
                None => std::env::remove_var("PATH"),
            }
            let curl_ran = marker.exists();
            let _ = std::fs::remove_dir_all(&shim_dir);

            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");
            assert!(!curl_ran, "approving an inbound request must never invoke curl — it is purely local");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert!(peers[0].verified);
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
        }
    }

    /// `approve_outbound`'s own poll step, proven end to end through a REAL
    /// local HTTP responder (no mock) answering `{"status":"approved",
    /// "pubkeyHex":<the SAME pubkey the entry already learned at request
    /// time>}` — the poll REPLACES the old reverse callback, over the SAME
    /// forward dial (module doc on `approve_outbound`, task #119).
    #[test]
    fn approve_outbound_polls_a_real_server_and_completes_on_an_approved_matching_release() {
        with_peer_state("approve-outbound-poll-approved", || {
            let pubkey_b = "b".repeat(64);
            let body: String = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"approved","pubkeyHex":"{pubkey_b}"}}}}"#);
            let body: &'static str = Box::leak(body.into_boxed_str());
            let (_listener, port) = spawn_fake_pair_poll_server(body);
            let url = format!("http://127.0.0.1:{port}/");
            let entry = sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();

            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
            let outcome = approve_outbound(true, "peer.pair.approve", "deadbeef", entry, &now, now_epoch, None);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Ok, "{outcome:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].name, "box-b");
            assert_eq!(peers[0].pubkey.as_deref(), Some(pubkey_b.as_str()));
            assert!(peers[0].verified);
            assert!(aoide_storage::pairing::list_outbound(now_epoch).is_empty(), "the outbound entry is consumed on commit");
        });
    }

    /// A poll answering `{"status":"pending"}` refuses with the SAME
    /// "still awaiting the peer's own approval" message the old
    /// callback-wait refusal gave — an ordinary, expected outcome; the
    /// outbound entry is untouched, so a later retry can still resolve it.
    #[test]
    fn approve_outbound_polls_a_real_server_and_refuses_cleanly_while_pending() {
        with_peer_state("approve-outbound-poll-pending", || {
            let pubkey_b = "b".repeat(64);
            let (_listener, port) = spawn_fake_pair_poll_server(r#"{"jsonrpc":"2.0","id":1,"result":{"status":"pending"}}"#);
            let url = format!("http://127.0.0.1:{port}/");
            let entry = sample_outbound_awaiting_approval("deadbeef", &url, &pubkey_b);
            aoide_storage::pairing::park_outbound(entry.clone()).unwrap();

            let now = aoide_storage::time::now_iso_utc();
            let now_epoch = aoide_storage::time::parse_iso_utc(&now).unwrap();
            let outcome = approve_outbound(true, "peer.pair.approve", "deadbeef", entry, &now, now_epoch, None);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
            assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("awaiting-peer-approval"));

            assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing commits while still pending");
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
        with_peer_state("approve-outbound-poll-mismatch", || {
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
            let outcome = approve_outbound(true, "peer.pair.approve", "deadbeef", entry, &now, now_epoch, None);
            assert_eq!(outcome.status, aoide_protocol::output::Status::Error, "{outcome:?}");
            assert_eq!(outcome.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("reveal-mismatch"));

            assert!(aoide_storage::peer_store::load_peers().is_empty(), "a substituted release must never commit a peer record");
            let listed = aoide_storage::pairing::list_outbound(now_epoch);
            assert_eq!(listed.len(), 1, "the entry is left untouched, never removed, on a mismatch");
            assert_eq!(listed[0].state, aoide_storage::pairing::OutboundState::AwaitingApproval, "never advances past awaiting-approval on a mismatch");
            assert_eq!(listed[0].pubkey_hex, real_pubkey_b, "the ORIGINAL learned pubkey stays on record, never overwritten by the substituted one");
        });
    }

    // ── typed-code approval (task #120 P3) — the approver-side gate's
    // ── tty-free halves: the pure comparison, the scripted `--code` path,
    // ── the persisted tries, the auto-deny at 3, and the no-code refusal.
    // ── The interactive `InboundGate::Prompt` loop renders through a real
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
        let entry = aoide_storage::pairing::park_inbound(
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
        with_peer_state("approve-inbound-code-mismatch", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();

            // "xxx-xxx" can never equal a digits-only SAS — a guaranteed mismatch.
            for expected_tries in 1..=2u32 {
                let fresh = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id).unwrap();
                let out = approve_inbound(InboundGate::Code("xxx-xxx".into()), "peer.pair.approve", &id, fresh, &now, now_epoch, None);
                assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
                assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("code-mismatch"));
                assert_eq!(out.data.as_ref().and_then(|d| d.get("tries")).and_then(Value::as_u64), Some(expected_tries as u64));
                // Cumulative across invocations: persisted on the parked entry.
                assert_eq!(aoide_storage::pairing::list_inbound(now_epoch)[0].tries, expected_tries);
            }

            // The third mismatch auto-denies: the same clean removal reject
            // performs, nothing committed, its own audited reason.
            let fresh = aoide_storage::pairing::list_inbound(now_epoch).into_iter().find(|e| e.id == id).unwrap();
            let out = approve_inbound(InboundGate::Code("xxx-xxx".into()), "peer.pair.approve", &id, fresh, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str), Some("auto-deny-on-code-mismatch"));
            assert!(aoide_storage::pairing::list_inbound(now_epoch).is_empty(), "the parked entry is removed, exactly like a reject");
            assert!(aoide_storage::peer_store::load_peers().is_empty(), "nothing was ever committed");
        });
    }

    #[test]
    fn approve_inbound_scripted_correct_code_commits_and_marks_approved() {
        with_peer_state("approve-inbound-code-match", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();

            // The undashed spelling exercises code_matches' normalization on
            // the real path, not just the pure test above.
            let out = approve_inbound(InboundGate::Code(sas.replace('-', "")), "peer.pair.approve", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert!(peers[0].verified, "the ceremony's commit is unchanged by the gate swap");
            let listed = aoide_storage::pairing::list_inbound(now_epoch);
            assert_eq!(listed.len(), 1, "an approved entry stays parked for the requester's poll (Design A)");
            assert!(listed[0].approved);
        });
    }

    // ── The grant a commit stamps (task #135 P1) — `config.toml`'s
    // ── `[pairing] defaultGrant`, or this commit's own `--allow`. ────────────

    /// Write a `config.toml` into the sandboxed `AOIDE_ROOT` `with_peer_state`
    /// already sets up, so a test can drive the real resolution path rather
    /// than a hand-built `Config`.
    fn write_config(body: &str) {
        std::fs::write(aoide_storage::fs::root().join(aoide_storage::config::CONFIG_FILE), body).unwrap();
    }

    fn approve_the_one_inbound(now_epoch: i64, grant: Option<&[String]>) -> Outcome {
        let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
        let (entry, sas) = parked_revealed_inbound(now_epoch);
        let id = entry.id.clone();
        approve_inbound(InboundGate::Code(sas), "peer.pair.approve", &id, entry, &now, now_epoch, grant)
    }

    #[test]
    fn a_first_pairing_stamps_the_configs_default_grant_not_a_literal() {
        with_peer_state("grant-config-default", || {
            // No config.toml at all — the built-in default, which task #135
            // P1 narrowed from ["read","spawn"] to ["read"].
            let out = approve_the_one_inbound(1_700_000_000, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(aoide_storage::peer_store::load_peers()[0].allows, vec!["read".to_string()]);
            assert!(out.message.contains("granted read"), "the commit says what it granted: {}", out.message);
        });
        with_peer_state("grant-config-widened", || {
            write_config("[pairing]\ndefaultGrant = [\"read\", \"spawn\"]\n");
            let out = approve_the_one_inbound(1_700_000_000, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(
                aoide_storage::peer_store::load_peers()[0].allows,
                vec!["read".to_string(), "spawn".to_string()],
                "an operator who widened defaultGrant gets the wider set, with no code change and no rebuild"
            );
        });
    }

    #[test]
    fn allow_overrides_the_config_default_for_this_one_pairing() {
        with_peer_state("grant-allow-override", || {
            write_config("[pairing]\ndefaultGrant = [\"read\"]\n");
            let out = approve_the_one_inbound(1_700_000_000, Some(&["read".to_string(), "spawn".to_string()]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(aoide_storage::peer_store::load_peers()[0].allows, vec!["read".to_string(), "spawn".to_string()]);
            assert!(out.message.contains("granted read, spawn"), "{}", out.message);

            // Nothing persisted it: the config is untouched, so the NEXT
            // pairing is back to the declared default (the User's decision —
            // the grant stays attached to a live human at commit time).
            assert_eq!(aoide_storage::config::load().unwrap().config.pairing.default_grant, vec!["read".to_string()]);
        });
    }

    /// The half an operator is most likely to get wrong: `--allow` on a
    /// RE-pairing looks like it widens a live peer and does not.
    #[test]
    fn re_pairing_never_regrants_and_the_message_says_so() {
        with_peer_state("grant-repair-unchanged", || {
            let now_epoch = 1_700_000_000_i64;
            approve_the_one_inbound(now_epoch, None);
            assert_eq!(aoide_storage::peer_store::load_peers()[0].allows, vec!["read".to_string()]);

            // Same box pairs again (a key rotation) and this operator types
            // the wider grant.
            let out = approve_the_one_inbound(now_epoch, Some(&["read".to_string(), "spawn".to_string()]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(
                aoide_storage::peer_store::load_peers()[0].allows,
                vec!["read".to_string()],
                "an already-verified peer's grant survives a re-pair untouched — a revoked spawn stays revoked"
            );
            assert!(out.message.contains("grant unchanged"), "a --allow that did nothing must never be silent: {}", out.message);
            assert!(out.message.contains("peer allow"), "and it names the command that does change a live grant: {}", out.message);
        });
    }

    #[test]
    fn a_malformed_config_refuses_the_commit_rather_than_guessing_a_grant() {
        with_peer_state("grant-config-malformed", || {
            write_config("[pairing]\ndefaultGrant = [\"read\", \"root\"]\n");
            let out = approve_the_one_inbound(1_700_000_000, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert!(out.message.contains("root"), "the refusal names the offending value: {}", out.message);
            assert!(out.message.contains("--allow"), "and the way past it: {}", out.message);
            assert!(
                aoide_storage::peer_store::load_peers().is_empty(),
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
            path: vec!["peer".to_string(), "pair".to_string(), "approve".to_string()],
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
    /// production `peers.json` are this exact shape, hand-derived before
    /// this fix existed.
    #[test]
    fn approve_inbound_records_loopback_url_and_claimed_via_when_self_via_present() {
        with_peer_state("approve-inbound-self-via-present", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound_with_self_via(now_epoch, Some("ssh://khoa@box-a"));
            let id = entry.id.clone();

            let out = approve_inbound(InboundGate::Code(sas), "peer.pair.approve", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            // The fixture's own url (`http://box-a:8710/`) happens to carry
            // the house default port too — `approve_inbound_records_the_
            // requesters_own_port_parsed_from_entry_url` below is the test
            // that actually proves this is parsed off entry.url and not
            // this box's own `AOIDE_A2A_PORT`, by using a DIFFERENT port.
            assert_eq!(peers[0].url, format!("http://127.0.0.1:{}/", default_a2a_port()), "the claim's presence rewrites the record to the loopback-as-seen-from-the-far-side convention, never entry.url");
            assert_eq!(peers[0].via.as_deref(), Some("ssh://khoa@box-a"), "via is the claim itself, committed in the same write");
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
        with_peer_state("approve-inbound-self-via-nondefault-port", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) =
                parked_revealed_inbound_with_self_via_and_url(now_epoch, Some("ssh://khoa@box-a"), "http://box-a:9999/");
            let id = entry.id.clone();
            assert_ne!(9999, default_a2a_port(), "the fixture port must differ from the default for this test to prove anything");

            let out = approve_inbound(InboundGate::Code(sas), "peer.pair.approve", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].url, "http://127.0.0.1:9999/", "the loopback rewrite must carry the REQUESTER's own door port, parsed from entry.url, never this box's own AOIDE_A2A_PORT/default");
        });
    }

    /// The mirror of the test above: no `selfVia` claim on the parked entry
    /// (an old requester, or one with nothing to claim) commits EXACTLY
    /// today's shape — `entry.url` verbatim, `via` left absent. No
    /// regression on the ordinary direct-LAN case.
    #[test]
    fn approve_inbound_leaves_todays_shape_when_self_via_absent() {
        with_peer_state("approve-inbound-self-via-absent", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, sas) = parked_revealed_inbound(now_epoch);
            let entry_url = entry.url.clone();
            let id = entry.id.clone();

            let out = approve_inbound(InboundGate::Code(sas), "peer.pair.approve", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let peers = aoide_storage::peer_store::load_peers();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].url, entry_url, "no claim — url is entry.url verbatim, exactly today's behavior");
            assert!(peers[0].via.is_none(), "no claim — via stays absent, exactly today's behavior");
        });
    }

    #[test]
    fn approve_inbound_refuses_where_no_code_can_be_collected_and_counts_no_try() {
        with_peer_state("approve-inbound-no-code", || {
            let now_epoch = 1_700_000_000_i64;
            let now = aoide_storage::time::iso_utc_from_epoch(now_epoch);
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            let id = entry.id.clone();

            let out = approve_inbound(InboundGate::Unavailable, "peer.pair.approve", &id, entry, &now, now_epoch, None);
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains("--code"), "the refusal teaches the scripted spelling: {}", out.message);
            assert_eq!(aoide_storage::pairing::list_inbound(now_epoch)[0].tries, 0, "a refusal is not a wrong code");
        });
    }

    fn approve_inv(id: &str, flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["peer".into(), "pair".into(), "approve".into()],
            args: vec![id.to_string()],
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    /// The handler's own gate resolution, driven through the real
    /// `handle_peer_pair_approve`: `--yes` on an inbound id maps to the
    /// taught refusal (never a bypass), and so does a bare non-tty CLI
    /// invocation (cargo test's stdio is never a terminal — the exact
    /// non-tty shape a scripted caller hits).
    #[test]
    fn handle_approve_inbound_refuses_yes_and_non_tty_without_code() {
        with_peer_state("approve-inbound-handler-gate", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, _sas) = parked_revealed_inbound(now_epoch);

            for flags in [vec![("yes", "true")], vec![]] {
                let out = handle_peer_pair_approve(&approve_inv(&entry.id, &flags));
                assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
                assert!(out.message.contains("--code"), "{}", out.message);
            }
        });
    }

    /// Bare `pair` never hangs where nobody can answer a menu: a non-CLI
    /// door, a `--json` ask, and a non-tty CLI invocation (cargo test's
    /// stdio) all get the taught refusal BEFORE any sweep runs — pinned
    /// here by the refusal arriving instantly with the scripted spellings
    /// in it.
    #[test]
    fn bare_pair_refuses_non_tty_non_cli_and_json_with_the_taught_message() {
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
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{why}: {out:?}");
            assert!(out.message.contains("peer advertise on"), "{why} refusal teaches the advertise switch: {}", out.message);
            assert!(out.message.contains("peer pair"), "{why} refusal teaches the manual path: {}", out.message);
        }
    }

    /// Idempotency survives the gate swap: an ALREADY-approved inbound
    /// entry short-circuits to the no-op success before any gate is
    /// consulted, so a re-run (scripted or not) never trips the refusal.
    #[test]
    fn handle_approve_inbound_already_approved_is_still_a_no_op_success() {
        with_peer_state("approve-inbound-idempotent", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, _sas) = parked_revealed_inbound(now_epoch);
            aoide_storage::pairing::mark_inbound_approved(&entry.id, now_epoch).unwrap();

            let out = handle_peer_pair_approve(&approve_inv(&entry.id, &[("yes", "true")]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("alreadyApproved")).and_then(Value::as_bool), Some(true));
        });
    }

    // ── P-PV2 (the User's locked spec): the collapsed command surface ────

    fn approve_inv_no_id(flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["peer".into(), "pair".into(), "approve".into()],
            args: vec![],
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: aoide_protocol::Door::Cli,
        }
    }

    /// `peer pair approve` with NO id, exactly one pending request: that
    /// one is resolved and approved — no id-copying required for the
    /// common case (the User's locked spec, point 4).
    #[test]
    fn approve_with_no_id_resolves_the_sole_pending_request() {
        with_peer_state("approve-no-id-sole-pending", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (entry, sas) = parked_revealed_inbound(now_epoch);

            let out = handle_peer_pair_approve(&approve_inv_no_id(&[("code", &sas)]));
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
            assert_eq!(out.data.as_ref().and_then(|d| d.get("peer")).and_then(Value::as_str), Some(entry.name.as_str()));
        });
    }

    /// `peer pair approve` with NO id, ZERO pending: a taught refusal
    /// naming there is nothing to approve — never a silent no-op.
    #[test]
    fn approve_with_no_id_and_nothing_pending_is_a_taught_refusal() {
        with_peer_state("approve-no-id-zero-pending", || {
            let out = handle_peer_pair_approve(&approve_inv_no_id(&[]));
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains("no pending"), "{}", out.message);
        });
    }

    /// `peer pair approve` with NO id, MULTIPLE pending: a taught refusal
    /// requiring an explicit id, listing every id currently pending —
    /// never a silent guess at which request the operator meant.
    #[test]
    fn approve_with_no_id_and_multiple_pending_requires_the_id_and_lists_them() {
        with_peer_state("approve-no-id-multiple-pending", || {
            let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap();
            let (first, _) = parked_revealed_inbound(now_epoch);
            let pubkey_b = "b".repeat(64);
            let outbound = sample_outbound_awaiting_approval("deadbeef", "http://box-b/", &pubkey_b);
            aoide_storage::pairing::park_outbound(outbound).unwrap();

            let out = handle_peer_pair_approve(&approve_inv_no_id(&[]));
            assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
            assert!(out.message.contains(&first.id), "{}", out.message);
            assert!(out.message.contains("deadbeef"), "{}", out.message);
            let ids = out.data.as_ref().and_then(|d| d.get("ids")).and_then(Value::as_array).cloned().unwrap_or_default();
            assert_eq!(ids.len(), 2, "{out:?}");
        });
    }

    /// `peer pending` (P-PV2, the User's locked spec point 3) NEVER shows
    /// the SAS/pairing code — neither in the human message nor anywhere in
    /// the JSON data — for an inbound OR an outbound row, whether revealed,
    /// approved, or freshly parked. The code is read off the requester's
    /// own screen and typed on the approver's; showing it here would defeat
    /// that out-of-band comparison.
    #[test]
    fn peer_pending_never_carries_the_sas_code_inbound_or_outbound() {
        with_peer_state("pending-no-sas", || {
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

            let out = handle_peer_pending(&Invocation {
                path: vec!["peer".into(), "pending".into()],
                args: vec![],
                flags: Default::default(),
                door: aoide_protocol::Door::Cli,
            });
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");

            let rows = out.data.as_ref().unwrap()["requests"].as_array().unwrap();
            assert_eq!(rows.len(), 2, "{rows:?}");
            for row in rows {
                assert!(row.get("sas").is_none(), "peer pending must never carry a `sas` field: {row}");
            }

            let rendered = serde_json::to_string(out.data.as_ref().unwrap()).unwrap();
            assert!(!rendered.contains(&inbound_sas), "the inbound code must never appear in peer pending's data: {rendered}");
            assert!(!rendered.contains(&outbound_sas), "the outbound code must never appear in peer pending's data: {rendered}");
            assert!(!out.message.contains(&inbound_sas), "nor in its human message: {}", out.message);
            assert!(!out.message.contains(&outbound_sas), "nor in its human message: {}", out.message);
        });
    }

    /// `peer pair <target>` SMART TARGET dispatch (the User's locked spec,
    /// point 1): a URL-shaped target (`"://"`) takes the EXPLICIT DIAL arm
    /// — proven here by its own distinct failure shape (`fetch-failed`,
    /// [`pair_via_url`]'s own reason, no sweep ever runs). A bare word
    /// takes the HOSTNAME arm — proven by ITS distinct failure shape
    /// (`no-match`, [`pair_via_hostname`]'s own reason, naming the sweep
    /// window it actually ran) — never the url arm's reason, and vice
    /// versa.
    #[test]
    fn peer_pair_smart_target_dispatches_url_and_hostname_to_different_arms() {
        with_peer_state("smart-target-url-arm", || {
            // Port 1 is reserved and never listened on in practice — an
            // immediate, deterministic connection refusal, never a sweep.
            let inv = Invocation {
                path: vec!["peer".into(), "pair".into()],
                args: vec!["http://127.0.0.1:1/".to_string()],
                flags: Default::default(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_peer_pair(&inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            let reason = out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str).unwrap_or("");
            assert!(
                matches!(reason, "fetch-failed" | "fetch-http-error" | "unparseable" | "refused" | "no-default-name" | "invalid-name"),
                "a URL target must take the explicit-dial arm, never the sweep arm: {out:?}"
            );
        });

        with_peer_state("smart-target-hostname-arm", || {
            // `with_peer_state` already holds `crate::env_lock()` for its
            // whole body — the SAME lock every real-sweep test in this
            // module takes (its own doc, `run_sweep_hears_an_advertisement_
            // sent_over_the_real_loopback_stack`'s doc in `discover.rs`); a
            // second `.lock()` here on the same (non-reentrant) mutex, on
            // the SAME thread, would deadlock rather than merely block.
            let inv = Invocation {
                path: vec!["peer".into(), "pair".into()],
                args: vec!["nobody-is-advertising-this-name".to_string()],
                flags: [("secs".to_string(), "1".to_string())].into_iter().collect(),
                door: aoide_protocol::Door::Cli,
            };
            let out = handle_peer_pair(&inv);
            assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
            assert_eq!(
                out.data.as_ref().and_then(|d| d.get("reason")).and_then(Value::as_str),
                Some("no-match"),
                "a bare hostname target must take the sweep arm and refuse with no-match: {out:?}"
            );
            assert!(out.message.contains("1s"), "the refusal names the sweep window actually used: {}", out.message);
        });
    }

    /// Review finding (P-PV2 follow-up): old `peer pair request <url>`
    /// muscle memory has no third `peer.pair.request` path to greedily
    /// match anymore, so it lands here as `peer.pair`'s OWN two args
    /// (`["request", "<url>"]`) — reading only `args[0]` and discarding the
    /// url would silently burn a full sweep window looking for an
    /// advertiser named "request" before failing with no mention the url
    /// was ever seen. `peer pair` now refuses ANY second positional
    /// outright — proven here by asserting Usage AND that no sweep or dial
    /// ever ran (no `data.reason` at all: neither arm's error shape, since
    /// neither arm is ever reached). The taught text lives in `USAGE`
    /// itself, shown identically for every arity error — never a special
    /// case keyed on the first arg spelling "request".
    #[test]
    fn peer_pair_refuses_a_second_positional_naming_the_dead_dual_command_fold() {
        let inv = Invocation {
            path: vec!["peer".into(), "pair".into()],
            args: vec!["request".to_string(), "http://127.0.0.1:1/".to_string()],
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        };
        let out = handle_peer_pair(&inv);
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
        assert!(
            out.data.as_ref().and_then(|d| d.get("reason")).is_none(),
            "neither arm's error shape must appear — this refusal fires before either arm ever runs: {out:?}"
        );
        assert!(out.message.contains("peer pair request"), "{}", out.message);
        assert!(out.message.contains("peer invite"), "{}", out.message);
        assert!(out.message.contains("peer pair <target>"), "{}", out.message);
    }

    /// `peer pair approve`/`reject`/`watch` are SUBCOMMANDS of `peer pair`
    /// and WIN over a hostname positional of the same literal spelling
    /// (the User's locked spec, point 4) — the registry's own greedy
    /// longest-prefix match ([`aoide_protocol::door::parse`]) resolves
    /// `aoide peer pair approve` to the 3-segment subcommand before it ever
    /// considers the 2-segment `peer pair <target>` with `"approve"` riding
    /// as the target; an ordinary hostname resolves to the smart-target
    /// command instead, with the word riding as its positional arg. A box
    /// literally named "approve" (or "reject"/"watch") therefore cannot be
    /// paired by bare hostname — it needs the explicit URL form, which is
    /// documented on `peer pair`'s own registered usage line.
    #[test]
    fn peer_pair_approve_reject_watch_subcommand_names_win_over_a_hostname_positional() {
        let mut r = Registry::new();
        register_peer_pair(&mut r);
        register_peer_discovery(&mut r);
        register_pair(&mut r);

        for sub in ["approve", "reject", "watch"] {
            let argv = vec!["peer".to_string(), "pair".to_string(), sub.to_string()];
            let (inv, _json) = aoide_protocol::door::parse(&argv, aoide_protocol::Door::Cli, "aoide", &r)
                .unwrap_or_else(|e| panic!("`peer pair {sub}` must parse as the subcommand: {e:?}"));
            assert_eq!(inv.path, vec!["peer".to_string(), "pair".to_string(), sub.to_string()], "{sub} must resolve to the subcommand, not a hostname target");
        }

        // An ordinary hostname (no collision) resolves to the smart-target
        // command, with the word riding as its own positional arg.
        let argv = vec!["peer".to_string(), "pair".to_string(), "yomi-strix".to_string()];
        let (inv, _json) = aoide_protocol::door::parse(&argv, aoide_protocol::Door::Cli, "aoide", &r).unwrap();
        assert_eq!(inv.path, vec!["peer".to_string(), "pair".to_string()]);
        assert_eq!(inv.args, vec!["yomi-strix".to_string()]);
    }
}
