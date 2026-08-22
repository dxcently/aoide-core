//! The `secrets exec` client — RELEASE TO CLIENT, the plan's one subtle
//! decision (this crate's README's "Release-to-client flow"). The broker
//! never execs the agent's command: it runs as the secrets uid (wrong cwd/
//! env, and the child would inherit secrets privileges). Instead THIS
//! process — running as the CALLING uid — resolves the secret over the
//! socket, then execs the wrapped command itself, `Stdio::inherit()`
//! throughout.
//!
//! The resolved value exists ONLY as a local `String` here, from
//! [`resolve`]'s return to the `.env(...)` call inside
//! [`spawn_with_secret`] — never argv, never an `Outcome`/JSON envelope,
//! never either audit log (both audit lines are written BROKER-side,
//! before the value is ever released — see `broker`'s module doc).
//! [`resolve`] extracts the value straight out of the reply's
//! `serde_json::Value` into that local `String`; there is no
//! `#[derive(Serialize)]` struct anywhere in this crate with a `value`
//! field for it to land on (this crate's `AGENTS.md` invariant) — a
//! `serde_json::Value` read at the use site, not a named reusable type, is
//! the shape that honors it.
//!
//! **`put` (P-V4c, `secrets put <name>`) is the write-side mirror, and
//! flows the OTHER direction**: [`run_put`] reads the value from THIS
//! process's own stdin (stdin-only intake — never argv, never a `--value`
//! flag) into a local `String`, hands it straight to [`put`], which builds
//! the wire request with `serde_json::json!` at the point of use (same
//! rule as `resolve`'s request — never a `#[derive(Serialize)]` struct)
//! and sends it. `put`'s reply carries no value at all (just `{"ok":true}`
//! or `{"ok":false,"error":...}`), so unlike `exec`, `secrets put` is a
//! PLAIN registered handler (`commands::handle_secrets_put`), not a
//! `cli`-crate `special`-hook case: nothing about its control flow needs
//! to bypass the generic `Outcome` envelope or return a spawned child's
//! own exit code (`commands.rs`'s own module doc justifies this choice
//! next to `serve`/`exec`/`enroll`'s).
//!
//! **P-V4e: `run_put` prompts and hides input when stdin is a terminal.**
//! A piped/redirected stdin (`printf %s hunter2 | aoide secrets put t`,
//! the historical shape, and every existing test/script) is BYTE-IDENTICAL
//! to before — [`stdin_is_tty`] is false in that case and `run_put` falls
//! straight through to the old `read_to_string` path, untouched. Only when
//! stdin IS a terminal ([`stdin_is_tty`] true — `libc::isatty` on fd 0,
//! already a dependency via `enroll::local_hostname`'s `gethostname`, no
//! new crate) does [`read_hidden_line`] take over: it prints a prompt to
//! STDERR (never stdout — stdout stays clean for scripting), clears
//! `ECHO` on stdin's `termios` for the read, and restores the ORIGINAL
//! termios afterward unconditionally — even on a read error — so a killed
//! read can never leave the caller's shell echo-less. [`strip_one_trailing_newline`]
//! is split out as its own pure function (module doc's "small seam"): the
//! termios dance itself is not exercised by `cargo test` (this process's
//! own stdin is never a tty in CI), but the trim logic it feeds is.
//!
//! **P-67: `run_put` warns and confirms before an overwrite.** The
//! existence check is BROKER-SIDE — the client never fetches a value to
//! find out (that would be a `resolve`-shaped leak on an op that isn't
//! `resolve`, and a client-side file peek is impossible anyway, since the
//! client never runs as the secrets uid). [`put`] now takes an `overwrite`
//! bool and reports whether the broker's reply carries the distinct
//! `{"exists":true}` refusal via [`PutError::Exists`] — never inferred by
//! matching the `error` string's prose. `run_put`'s flow:
//! - The value is read from stdin EXACTLY as before (tty-hidden or piped),
//!   held in a local `String`, and the first `put` attempt sends
//!   `overwrite: force` (the new `--force` flag, `commands::
//!   handle_secrets_put`) — `--force` therefore skips the confirmation on
//!   BOTH a tty and a pipe, storing on the first round trip either way.
//! - A [`PutError::Exists`] refusal (only reachable when `force` was
//!   false) branches on [`stdin_is_tty`] a SECOND time: on a tty, it
//!   prints a `y/N` confirmation prompt (unhidden — a yes/no answer isn't
//!   sensitive) to stderr and reads one line; `y`/`yes` (case-insensitive)
//!   re-sends the SAME in-memory value with `overwrite: true` (the caller
//!   is never asked to retype it), anything else — including EOF, `read_line`
//!   returning `Ok(0)` — aborts with an "unchanged" message. On a non-tty
//!   stdin, there is no one to ask, so it refuses outright and teaches the
//!   `--force` spelling ([`non_tty_exists_message`], a plain pure function
//!   so this refusal is testable without faking a tty — module doc's own
//!   "pure-testable" requirement).
//! - The value NEVER touches argv, a log line, or a cache at any point in
//!   this flow — it exists only as `run_put`'s own local `String`, exactly
//!   as before this feature, just potentially handed to [`put`] TWICE
//!   instead of once.

use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;

/// Map a `UnixStream::connect` failure against the broker socket into an
/// actionable message — pure (an injected [`io::Error`], no real socket),
/// so this is fully unit-tested without a live broker. This IS the exact
/// wall the User hit live (this task's own report): a bare "Permission
/// denied (os error 13)" with zero indication of what to do about it.
///
/// [`io::ErrorKind::PermissionDenied`]: the caller's own login session
/// isn't in the broker's `aoide-secrets-access` group yet — group
/// membership is login-scoped (`README.md`'s "Deployment" section), so a
/// `usermod -aG`/nix-module rebuild done from *this* shell never applies
/// until either a fresh login or an `sg` re-exec picks it up. Both fixes
/// are taught, since either genuinely works and which is more convenient
/// depends on the caller.
///
/// [`io::ErrorKind::NotFound`]/[`io::ErrorKind::ConnectionRefused`]: nothing
/// is listening at `socket_path` at all — the broker isn't running, or the
/// resolved path doesn't match the deployed one (`socket.rs`'s module doc:
/// `AOIDE_SECRETS_SOCKET`, or its `/run/aoide-secrets/secrets.sock`
/// default).
///
/// Every other `io::ErrorKind` (a transient `EMFILE`, an unreadable
/// destination directory, ...) rides through with just the socket path
/// prefixed — unchanged from before this function existed — rather than
/// guessing at a fix this function has no evidence for.
fn describe_connect_error(socket_path: &Path, err: &io::Error, reinvoke: &str) -> String {
    match err.kind() {
        io::ErrorKind::PermissionDenied => format!(
            "connecting to the secrets broker at {}: permission denied — this session isn't in the \
             `aoide-secrets-access` group yet (group membership is login-scoped: joining the group \
             doesn't apply to an already-open shell). Fix: run `sg aoide-secrets-access -c '{reinvoke}'` \
             in THIS session, or log out and back in so a fresh session picks up the group.",
            socket_path.display()
        ),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => format!(
            "connecting to the secrets broker at {}: {err} — the broker doesn't look like it's running \
             (or the socket path is wrong). Check `systemctl status aoide-secrets-serve`, or set \
             AOIDE_SECRETS_SOCKET if this host's broker socket lives somewhere else.",
            socket_path.display()
        ),
        _ => format!("connecting to the secrets broker at {}: {err}", socket_path.display()),
    }
}

/// Parsed `secrets exec` arguments — pure, no I/O, fully unit-testable
/// without a running broker.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecArgs {
    pub consumer: String,
    pub secret: String,
    pub var: String,
    pub totp: Option<String>,
    pub cmd: Vec<String>,
}

/// The env-var name a bare `--secret <name>` (no explicit `:VAR`) injects
/// under: the secret name, uppercased, `-` -> `_` (`db-prod` -> `DB_PROD`)
/// — the "documented default derivation" the phase brief calls for.
pub fn default_var_name(secret: &str) -> String {
    secret.to_uppercase().replace('-', "_")
}

/// Parse `aoide secrets exec --as <consumer> --secret <name>[:VAR] [--totp N]
/// -- <cmd>` out of an already-parsed [`Invocation`]. `inv.args` is exactly
/// the wrapped command + its args — `aoide_protocol::door::parse` already
/// treats a bare `--` as ending flag parsing, so everything after it
/// arrives here verbatim as positionals (that module's own doc).
/// `secrets exec`'s own usage line — printed alongside every specific
/// missing/malformed-argument message below, never a generic usage dump on
/// its own (task: name WHICH flag is wrong AND show this verb's usage).
pub const EXEC_USAGE: &str = "usage: secrets exec --as <consumer> --secret <name>[:VAR] [--totp NNNNNN] -- <cmd>";

pub fn parse_exec_args(inv: &Invocation) -> Result<ExecArgs, String> {
    let consumer = inv
        .flags
        .get("as")
        .cloned()
        .ok_or_else(|| format!("secrets exec: missing --as <consumer> — {EXEC_USAGE}"))?;
    let secret_flag = inv
        .flags
        .get("secret")
        .cloned()
        .ok_or_else(|| format!("secrets exec: missing --secret <name>[:VAR] — {EXEC_USAGE}"))?;
    let (secret, var) = match secret_flag.split_once(':') {
        Some((n, v)) if !v.is_empty() => (n.to_string(), v.to_string()),
        _ => {
            let n = secret_flag.trim_end_matches(':').to_string();
            let derived = default_var_name(&n);
            (n, derived)
        }
    };
    if !crate::policy::valid_secret_name(&secret) {
        return Err(format!(
            "invalid secret name `{secret}` (must be lowercase [a-z0-9-], no leading/trailing/doubled \
             hyphen) — {EXEC_USAGE}"
        ));
    }
    let totp = inv.flags.get("totp").cloned();
    let cmd = inv.args.clone();
    if cmd.is_empty() {
        return Err(format!("secrets exec: missing a command after `--` — {EXEC_USAGE}"));
    }
    Ok(ExecArgs { consumer, secret, var, totp, cmd })
}

/// Connect to `socket_path`, send ONE `resolve` request, read the wire's
/// FINAL reply line ([`read_final_reply`] — zero or more interim lines may
/// come first, P-N2c FIX 1), and return the value or a value-free error
/// message.
pub fn resolve(
    socket_path: &Path,
    secret: &str,
    consumer: &str,
    totp: Option<&str>,
    argv0: Option<&str>,
) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        describe_connect_error(
            socket_path,
            &e,
            &format!("aoide secrets exec --as {consumer} --secret {secret} -- ..."),
        )
    })?;

    let mut req = json!({ "op": "resolve", "secret": secret, "consumer": consumer });
    if let Some(t) = totp {
        req["totp"] = Value::String(t.to_string());
    }
    if let Some(a) = argv0 {
        req["argv0"] = Value::String(a.to_string());
    }
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let reply = read_final_reply(&mut reader)?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        reply
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "the secrets broker's reply had no `value`".to_string())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Read wire lines until the FINAL (non-interim) reply — the framing
/// contract P-N2c FIX 1 establishes (`CONTRACTS.md`'s Transport paragraph,
/// `broker.rs`'s module doc): "one request line -> zero or more interim
/// lines (`"interim":true`) -> exactly one final reply line." Every
/// interim line is surfaced via [`announce_interim`] (STDERR only, never
/// stdout — stdout stays clean for scripting) and then discarded; the
/// first line WITHOUT `"interim":true` is the final reply this function
/// returns. Only [`resolve`] can ever receive an interim line today (the
/// only op that parks) — kept as its own function rather than inlined so a
/// future op gaining interim lines reuses this loop instead of
/// re-deriving it.
fn read_final_reply(reader: &mut impl BufRead) -> Result<Value, String> {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
        if line.trim().is_empty() {
            return Err("the secrets broker closed the connection with no reply".to_string());
        }
        let value: Value = serde_json::from_str(line.trim())
            .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;
        if value.get("interim").and_then(Value::as_bool) == Some(true) {
            announce_interim(&value);
            continue;
        }
        return Ok(value);
    }
}

/// Surface ONE interim line to the human at the terminal — STDERR only,
/// never stdout (module doc's own discipline). Today the only interim
/// shape the broker ever sends is a park announcement
/// (`{"interim":true,"parked":true,"id":...,"timeoutSecs":...}`) — this
/// only prints for THAT shape; an interim line with a different shape (a
/// future mode) is still safely consumed by [`read_final_reply`]'s loop
/// even when this function has nothing to say about it yet.
fn announce_interim(value: &Value) {
    if value.get("parked").and_then(Value::as_bool) == Some(true) {
        let id = value.get("id").and_then(Value::as_str).unwrap_or("?");
        let timeout_secs = value.get("timeoutSecs").and_then(Value::as_u64).unwrap_or(0);
        eprintln!(
            "parked as ask {id} — complete with: aoide secrets approve {id} --totp <code>  (or dismiss {id}); \
             times out in {timeout_secs}s"
        );
    }
}

/// A [`put`] failure, distinguishing the P-67 "already has a stored value"
/// refusal from every other error — via the wire's `exists` FLAG, never by
/// matching text out of the `error` string (the task's own requirement:
/// "distinguishable WITHOUT string-matching prose").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    /// `overwrite` was false/absent and the secret already has a stored
    /// value (the broker's `{"ok":false,"exists":true,...}` reply).
    Exists,
    /// Every other denial/error — connect failures, "secret not found", a
    /// backend problem, ... — value-free, same as before this feature.
    Other(String),
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutError::Exists => write!(f, "secret already has a stored value"),
            PutError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// Connect to `socket_path`, send ONE `put` request carrying `value` and
/// `overwrite`, read ONE reply line, and return whether an existing value
/// was REPLACED (`true`) or this was a first-ever store (`false`) — or a
/// [`PutError`] otherwise. Mirrors [`resolve`]'s one-shot socket shape;
/// `overwrite` only rides the wire when `true` (absent means false — wire
/// compat, `broker.rs`'s module doc), same discipline `resolve`'s optional
/// `totp`/`argv0` fields already hold.
pub fn put(socket_path: &Path, secret: &str, value: &str, overwrite: bool) -> Result<bool, PutError> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        PutError::Other(describe_connect_error(socket_path, &e, &format!("aoide secrets put {secret}")))
    })?;

    let mut req = json!({ "op": "put", "secret": secret, "value": value });
    if overwrite {
        req["overwrite"] = Value::Bool(true);
    }
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| PutError::Other(format!("writing to the secrets broker: {e}")))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| PutError::Other(format!("reading from the secrets broker: {e}")))?;
    if reply_line.trim().is_empty() {
        return Err(PutError::Other("the secrets broker closed the connection with no reply".to_string()));
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| PutError::Other(format!("the secrets broker sent an unparseable reply: {e}")))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply.get("replaced").and_then(Value::as_bool).unwrap_or(false))
    } else if reply.get("exists").and_then(Value::as_bool) == Some(true) {
        Err(PutError::Exists)
    } else {
        Err(PutError::Other(
            reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("the secrets broker denied the request")
                .to_string(),
        ))
    }
}

/// One parked ask, as `secrets pending` lists it — id/secret/consumer/
/// requestedAt ONLY, never a value (mirrors the wire's own `pending` reply
/// shape, `broker.rs`'s module doc's wire table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    pub id: String,
    pub secret: String,
    pub consumer: String,
    pub requested_at: u64,
}

/// Connect to `socket_path`, send ONE `pending` request, read ONE reply
/// line, and return every parked ask — value-free by construction (the
/// wire's `pending` reply never carries one; this simply reads the fields
/// that ARE there).
pub fn pending(socket_path: &Path) -> Result<Vec<PendingAsk>, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| describe_connect_error(socket_path, &e, "aoide secrets pending"))?;

    let line = json!({ "op": "pending" }).to_string() + "\n";
    stream.write_all(line.as_bytes()).map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader.read_line(&mut reply_line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string());
    }
    let asks = reply
        .get("pending")
        .and_then(Value::as_array)
        .ok_or_else(|| "the secrets broker's reply had no `pending` array".to_string())?;
    asks.iter()
        .map(|a| {
            Ok(PendingAsk {
                id: a.get("id").and_then(Value::as_str).ok_or("a pending entry had no `id`")?.to_string(),
                secret: a
                    .get("secret")
                    .and_then(Value::as_str)
                    .ok_or("a pending entry had no `secret`")?
                    .to_string(),
                consumer: a
                    .get("consumer")
                    .and_then(Value::as_str)
                    .ok_or("a pending entry had no `consumer`")?
                    .to_string(),
                requested_at: a
                    .get("requestedAt")
                    .and_then(Value::as_u64)
                    .ok_or("a pending entry had no `requestedAt`")?,
            })
        })
        .collect::<Result<Vec<_>, &str>>()
        .map_err(str::to_string)
}

/// Connect to `socket_path`, send ONE `approve` request carrying `id` and
/// `totp`, read ONE reply line. Success is `{"ok":true}` only — never a
/// value (the value went down the ORIGINAL parked connection, broker-side;
/// this function's own reply can't carry it because the wire reply it reads
/// never has one, `handle_approve`'s own doc). An invalid/expired code, or
/// an unknown id, comes back as a value-free `Err`.
pub fn approve(socket_path: &Path, id: &str, totp: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| describe_connect_error(socket_path, &e, &format!("aoide secrets approve {id} --totp ...")))?;

    let line = json!({ "op": "approve", "id": id, "totp": totp }).to_string() + "\n";
    stream.write_all(line.as_bytes()).map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader.read_line(&mut reply_line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Connect to `socket_path`, send ONE `dismiss` request carrying `id`, read
/// ONE reply line. An unknown id is a taught error (`handle_dismiss`'s own
/// doc), value-free either way.
pub fn dismiss(socket_path: &Path, id: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| describe_connect_error(socket_path, &e, &format!("aoide secrets dismiss {id}")))?;

    let line = json!({ "op": "dismiss", "id": id }).to_string() + "\n";
    stream.write_all(line.as_bytes()).map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader.read_line(&mut reply_line).map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the secrets broker denied the request")
            .to_string())
    }
}

/// Is stdin a terminal? `libc::isatty` on fd 0 — the branch point between
/// the historical pipe path and P-V4e's hidden-input prompt (module doc).
/// `pub(crate)` since `watch.rs` (this crate's line-mode broker-event
/// surface) needs the SAME tty branch point to decide narration-only vs.
/// prompting — widened per `pkgs/aoide/crates/AGENTS.md`'s "no cross-crate
/// copying" rule, applied in-crate: reach into the existing seam, never
/// fork a second `isatty` call site.
pub(crate) fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) != 0 }
}

/// Strip exactly ONE trailing `\n`, never a blanket `.trim_end()` (same
/// "exactly one, not a blanket trim" discipline `backend::fetch_value`'s
/// module doc already holds for a backend's stdout) — a hidden-input read
/// carries the newline the user's Enter key produced; this removes that
/// one character and nothing else a pasted value might legitimately end
/// with. Pure and total, so it is the "small seam" the tty path's own
/// termios dance is tested through, per this module's own doc.
fn strip_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// Read one line from stdin with terminal echo disabled — the tty half of
/// [`run_put`]'s prompt (module doc). Restores the ORIGINAL termios
/// unconditionally before returning, on the success path AND the error
/// path alike, so a read that fails partway can never leave the caller's
/// terminal echo-less. Prints the prompt AND the post-read newline to
/// STDERR (never stdout, module doc) — the newline exists because the
/// user's own Enter never reached the terminal with echo off, so without
/// it the next line printed would glue onto the hidden input's line.
///
/// `pub(crate)`: `watch.rs`'s approve prompt reuses this VERBATIM for its
/// own hidden TOTP-code read (the design's own requirement — the code must
/// never touch argv, and this is the one place in the crate that already
/// gets the termios dance right).
pub(crate) fn read_hidden_line(prompt: &str) -> Result<String, String> {
    use std::io::{BufRead, Write};
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut term) } != 0 {
        return Err("reading terminal attributes: tcgetattr failed".to_string());
    }
    let original = term;
    term.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &term) } != 0 {
        return Err("disabling terminal echo: tcsetattr failed".to_string());
    }

    let mut line = String::new();
    let read_result = std::io::stdin().lock().read_line(&mut line);

    // Always restore, even on a read error — never leave the terminal
    // echo-less (module doc).
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &original) };
    eprintln!();

    read_result.map_err(|e| format!("reading value from stdin: {e}"))?;
    Ok(strip_one_trailing_newline(line))
}

/// The non-tty "exists" refusal message (P-67) — a plain pure function so
/// it's testable without faking a tty (module doc). Teaches the exact
/// `--force` spelling: there is no one to ask for a `y/N` confirmation
/// when stdin is a pipe, so this refuses outright rather than guessing.
fn non_tty_exists_message(secret: &str) -> String {
    format!(
        "secret `{secret}` already has a stored value — refusing to overwrite it from a non-interactive \
         stdin without confirmation. Re-run with --force to overwrite: printf %s <value> | aoide secrets put \
         {secret} --force"
    )
}

/// Prompt `y/N` on stderr and read ONE line from stdin, unhidden (a yes/no
/// answer isn't sensitive, unlike the value itself). `true` only for
/// `y`/`yes` (case-insensitive, surrounding whitespace trimmed); EOF
/// (`read_line` returning `Ok(0)`) and every other input default to `false`
/// — the task's own "default No" requirement.
fn confirm_overwrite(secret: &str) -> Result<bool, String> {
    eprint!("secret `{secret}` already has a stored value — overwrite? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line).map_err(|e| format!("reading confirmation from stdin: {e}"))?;
    Ok(read > 0 && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// The full `secrets put <name>` client flow: read the value from THIS
/// process's own stdin (stdin-only intake, module doc) — prompting with
/// echo hidden when stdin is a terminal (P-V4e), reading straight through
/// unchanged when it's piped/redirected (the historical shape) — then
/// [`put`] it over `socket_path`. The value exists only as this function's
/// own local `String`, from the stdin read to the `put()` call(s) — never
/// returned, never logged, never touching argv.
///
/// **P-67:** `force` (the CLI's `--force` flag) rides as `overwrite` on the
/// FIRST attempt — a forced put always succeeds in one round trip, tty or
/// not. Only when `force` is false and the broker refuses with
/// [`PutError::Exists`] does this branch on [`stdin_is_tty`] a second time:
/// a tty gets [`confirm_overwrite`]'s `y/N` prompt and, on yes, a SECOND
/// `put` with the SAME value and `overwrite: true` — the caller is never
/// asked to retype it; a non-tty stdin gets [`non_tty_exists_message`] and
/// aborts. Returns the human-facing success message ("stored" vs.
/// "replaced", so the CLI's own `Outcome` can say which happened) or a
/// value-free error string.
pub fn run_put(secret: &str, socket_path: &Path, force: bool) -> Result<String, String> {
    let value = if stdin_is_tty() {
        read_hidden_line(&format!("value for `{secret}` (input hidden): "))?
    } else {
        use std::io::Read;
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .map_err(|e| format!("reading value from stdin: {e}"))?;
        value
    };

    match put(socket_path, secret, &value, force) {
        Ok(true) => Ok(format!("replaced secret `{secret}`'s stored value")),
        Ok(false) => Ok(format!("stored secret `{secret}`")),
        Err(PutError::Other(e)) => Err(e),
        Err(PutError::Exists) => {
            if !stdin_is_tty() {
                return Err(non_tty_exists_message(secret));
            }
            if !confirm_overwrite(secret)? {
                return Err(format!("secret `{secret}` left unchanged"));
            }
            match put(socket_path, secret, &value, true) {
                Ok(true) => Ok(format!("replaced secret `{secret}`'s stored value")),
                Ok(false) => Ok(format!("stored secret `{secret}`")),
                Err(PutError::Other(e)) => Err(e),
                Err(PutError::Exists) => {
                    Err(format!("secret `{secret}`: the broker refused the confirmed overwrite unexpectedly"))
                }
            }
        }
    }
}

/// Spawn `cmd`, `var`=`value` injected, `Stdio::inherit()` throughout
/// (never captured — aoide never holds the child's bytes, so there is
/// nothing here that could redact wrong), and return the CHILD's own exit
/// code — never aoide's own exit-code vocabulary, a wrapped command's exit
/// code is its own signal.
fn spawn_with_secret(cmd: &[String], var: &str, value: &str) -> Result<i32, String> {
    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .env(var, value)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("spawning `{}`: {e}", cmd[0]))?;
    Ok(status.code().unwrap_or(1))
}

/// The full `secrets exec` client flow — parse, resolve over `socket_path`,
/// spawn with the value injected. Returns the process exit code to hand
/// back from `main`: `2` (usage) for a bad invocation, `1` (error) for a
/// denied resolve or a spawn failure, else the CHILD's own exit code.
pub fn run_exec(inv: &Invocation, socket_path: &Path) -> i32 {
    let args = match parse_exec_args(inv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aoide secrets exec: {e}");
            return 2;
        }
    };
    let value = match resolve(
        socket_path,
        &args.secret,
        &args.consumer,
        args.totp.as_deref(),
        args.cmd.first().map(String::as_str),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("aoide secrets exec: {e}");
            return 1;
        }
    };
    match spawn_with_secret(&args.cmd, &args.var, &value) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aoide secrets exec: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::Door;
    use std::collections::BTreeMap;

    fn inv(flags: &[(&str, &str)], args: &[&str]) -> Invocation {
        let mut flag_map = BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: vec!["secrets".to_string(), "exec".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flag_map,
            door: Door::Cli,
        }
    }

    #[test]
    fn default_var_name_uppercases_and_underscores_hyphens() {
        assert_eq!(default_var_name("db-prod"), "DB_PROD");
        assert_eq!(default_var_name("token"), "TOKEN");
        assert_eq!(default_var_name("a-b-c"), "A_B_C");
    }

    #[test]
    fn parses_a_full_invocation() {
        let i = inv(&[("as", "m"), ("secret", "db-prod")], &["psql", "-c", "select 1"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.consumer, "m");
        assert_eq!(args.secret, "db-prod");
        assert_eq!(args.var, "DB_PROD");
        assert_eq!(args.totp, None);
        assert_eq!(args.cmd, vec!["psql", "-c", "select 1"]);
    }

    #[test]
    fn explicit_var_name_wins_over_the_derived_default() {
        let i = inv(&[("as", "m"), ("secret", "db-prod:PGPASSWORD")], &["psql"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.secret, "db-prod");
        assert_eq!(args.var, "PGPASSWORD");
    }

    #[test]
    fn totp_flag_is_carried_through() {
        let i = inv(&[("as", "m"), ("secret", "t"), ("totp", "123456")], &["cmd"]);
        let args = parse_exec_args(&i).unwrap();
        assert_eq!(args.totp.as_deref(), Some("123456"));
    }

    #[test]
    fn missing_as_is_a_clear_error() {
        let i = inv(&[("secret", "t")], &["cmd"]);
        assert!(parse_exec_args(&i).unwrap_err().contains("--as"));
    }

    #[test]
    fn missing_secret_is_a_clear_error() {
        let i = inv(&[("as", "m")], &["cmd"]);
        assert!(parse_exec_args(&i).unwrap_err().contains("--secret"));
    }

    #[test]
    fn missing_command_is_a_clear_error() {
        let i = inv(&[("as", "m"), ("secret", "t")], &[]);
        assert!(parse_exec_args(&i).unwrap_err().contains("command after"));
    }

    #[test]
    fn invalid_secret_name_is_rejected() {
        let i = inv(&[("as", "m"), ("secret", "Bad Name")], &["cmd"]);
        assert!(parse_exec_args(&i).unwrap_err().contains("invalid secret name"));
    }

    // ── describe_connect_error (pure — injected io::Error, no real socket) ──

    #[test]
    fn permission_denied_teaches_both_the_sg_and_relogin_fixes() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let msg = describe_connect_error(socket, &err, "aoide secrets put db-prod");
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains("aoide-secrets-access"), "{msg}");
        assert!(msg.contains("sg aoide-secrets-access -c 'aoide secrets put db-prod'"), "{msg}");
        assert!(msg.to_lowercase().contains("log out"), "{msg}");
    }

    #[test]
    fn not_found_teaches_checking_the_broker_service() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::NotFound, "no such file or directory");
        let msg = describe_connect_error(socket, &err, "aoide secrets exec --as m --secret t -- true");
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains("systemctl status aoide-secrets-serve"), "{msg}");
        assert!(msg.contains("AOIDE_SECRETS_SOCKET"), "{msg}");
    }

    #[test]
    fn connection_refused_gets_the_same_not_running_hint_as_not_found() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let msg = describe_connect_error(socket, &err, "aoide secrets put t");
        assert!(msg.contains("systemctl status aoide-secrets-serve"), "{msg}");
    }

    #[test]
    fn an_unrelated_error_kind_rides_through_unenriched() {
        let socket = Path::new("/run/aoide-secrets/secrets.sock");
        let err = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        let msg = describe_connect_error(socket, &err, "aoide secrets put t");
        assert!(msg.contains(&socket.display().to_string()), "{msg}");
        assert!(msg.contains("timed out"), "{msg}");
        assert!(!msg.contains("aoide-secrets-access"), "{msg}");
        assert!(!msg.contains("systemctl"), "{msg}");
    }

    #[test]
    fn resolve_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-test.sock");
        let err = resolve(dead, "t", "m", None, None).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn put_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-put-test.sock");
        let err = put(dead, "t", "irrelevant", false).unwrap_err();
        assert!(matches!(err, PutError::Other(_)), "{err}");
        assert!(err.to_string().contains("connecting"), "{err}");
    }

    // ── P-V4e: `secrets put`'s tty prompt ───────────────────────────────
    //
    // The termios dance itself (`read_hidden_line`) is not exercised here —
    // `cargo test`'s own stdin is never a tty — so these cover exactly the
    // "small seam" the module doc calls out: the pure trim logic, and that
    // `stdin_is_tty` reads false (so `run_put` takes the untouched pipe
    // path) under this process's own non-tty stdin, same as every existing
    // `run_put`-adjacent test already implicitly relies on.

    #[test]
    fn strip_one_trailing_newline_removes_exactly_one() {
        assert_eq!(strip_one_trailing_newline("hunter2\n".to_string()), "hunter2");
        assert_eq!(strip_one_trailing_newline("hunter2\n\n".to_string()), "hunter2\n");
        assert_eq!(strip_one_trailing_newline("hunter2".to_string()), "hunter2");
        assert_eq!(strip_one_trailing_newline(String::new()), "");
        // Trailing spaces in a pasted value are NOT eaten — only the one
        // newline the Enter key produced, never a blanket `.trim_end()`.
        assert_eq!(strip_one_trailing_newline("hunter2  \n".to_string()), "hunter2  ");
    }

    // ── P-67: warn-before-overwrite ─────────────────────────────────────

    #[test]
    fn non_tty_exists_message_teaches_the_force_spelling() {
        let msg = non_tty_exists_message("db-prod");
        assert!(msg.contains("already has a stored value"), "{msg}");
        assert!(msg.contains("--force"), "{msg}");
        assert!(
            msg.contains("printf %s <value> | aoide secrets put db-prod --force"),
            "must spell out the exact fix: {msg}"
        );
    }

    /// End-to-end proof that [`put`] surfaces the wire's `exists` flag as
    /// [`PutError::Exists`] (never inferred by matching `error` prose) and
    /// that `overwrite: true` reports `replaced: true` back — a REAL
    /// broker + socket round trip, same shape as `commands.rs`'s own
    /// `require_totp_on_add_births_a_gated_policy_denied_without_a_code`.
    #[test]
    fn put_reports_exists_then_replaced_true_through_a_real_broker() {
        let home = std::env::temp_dir().join(format!(
            "aoide-secrets-client-put-overwrite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        crate::store::save_policies(&home, &[crate::policy::Policy::new("t", "file", "k")]).unwrap();

        // A short /tmp-direct socket path — sockaddr_un's ~108-byte
        // sun_path can overflow under a nested tempdir (same SUN_LEN
        // caution `tests/e2e.rs`/`commands.rs`'s own TOTP e2e test document).
        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-secrets-client-put-overwrite-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });

        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        // First put: no stored value yet -> `replaced: false`.
        assert_eq!(put(&socket_path, "t", "first-value", false), Ok(false));

        // Second put, no overwrite: the DISTINCT exists refusal.
        assert_eq!(put(&socket_path, "t", "attempted-overwrite", false), Err(PutError::Exists));

        // Third put, overwrite: true -> `replaced: true`.
        assert_eq!(put(&socket_path, "t", "second-value", true), Ok(true));

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }

    // ── P-N2: pending/approve/dismiss ───────────────────────────────────

    #[test]
    fn pending_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-pending-test.sock");
        let err = pending(dead).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn approve_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-approve-test.sock");
        let err = approve(dead, "1", "123456").unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn dismiss_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-dismiss-test.sock");
        let err = dismiss(dead, "1").unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    /// A real broker + socket round trip through the client wrappers
    /// themselves: `resolve` parks (no code given), `pending` sees the ask
    /// with no value anywhere in it, `approve` releases the value down the
    /// ORIGINAL `resolve` call — never into `approve`'s own `Ok(())` — and
    /// once approved the ask is gone from `pending` again. Same real-broker
    /// shape as `put_reports_exists_then_replaced_true_through_a_real_broker`
    /// (a single `serve` call for the whole test, dropped-not-joined, same
    /// pattern that test already establishes).
    #[test]
    fn pending_approve_round_trips_through_a_real_broker_and_releases_to_the_original_caller() {
        let home = std::env::temp_dir().join(format!(
            "aoide-secrets-client-park-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let mut p = crate::policy::Policy::new("t", "file", "k");
        p.require_totp = true;
        crate::store::save_policies(&home, &[p]).unwrap();
        let totp_secret = b"a-twenty-byte-totp-s".to_vec();
        crate::store::save_totp_secret(&home, &totp_secret).unwrap();

        let socket_path = std::path::PathBuf::from(format!(
            "/tmp/aoide-secrets-client-park-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        let home_for_thread = home.clone();
        let sock_for_thread = socket_path.clone();
        let broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });
        let mut connected = false;
        for _ in 0..50 {
            if UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        // `put` a value first (no TOTP gate on `put`, module doc), so the
        // parked `resolve` below has something real to release.
        assert_eq!(put(&socket_path, "t", "the-real-value", false), Ok(false));
        assert_eq!(pending(&socket_path).unwrap(), Vec::new());

        let sock_for_resolve = socket_path.clone();
        let resolve_thread = std::thread::spawn(move || resolve(&sock_for_resolve, "t", "m", None, None));

        let mut ask = None;
        for _ in 0..200 {
            let list = pending(&socket_path).unwrap();
            if let Some(a) = list.into_iter().next() {
                ask = Some(a);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ask = ask.expect("the resolve did not park in time");
        assert_eq!(ask.secret, "t");
        assert_eq!(ask.consumer, "m");

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let step = crate::totp::timestep(now);
        let code = crate::totp::format6(crate::totp::hotp(&totp_secret, step, crate::totp::DIGITS));
        approve(&socket_path, &ask.id, &code).unwrap();

        assert_eq!(resolve_thread.join().unwrap(), Ok("the-real-value".to_string()));
        assert_eq!(pending(&socket_path).unwrap(), Vec::new());

        drop(broker_thread);
        std::fs::remove_file(&socket_path).ok();
        std::fs::remove_dir_all(&home).ok();
    }

    // ── P-N2c FIX 1: interim-line framing (`read_final_reply`) ──────────

    #[test]
    fn read_final_reply_skips_interim_lines_and_returns_the_first_real_one() {
        let wire = "{\"interim\":true,\"parked\":true,\"id\":\"ab12-1\",\"timeoutSecs\":300}\n\
                    {\"ok\":true,\"value\":\"the-value\"}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let reply = read_final_reply(&mut reader).unwrap();
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["value"], "the-value");
    }

    #[test]
    fn read_final_reply_with_no_interim_line_behaves_exactly_as_before() {
        // Old-broker compat: a reply with zero interim lines (every op
        // besides a parking `resolve`) must round-trip byte-identically.
        let wire = "{\"ok\":false,\"error\":\"secret not found\"}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let reply = read_final_reply(&mut reader).unwrap();
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "secret not found");
    }

    #[test]
    fn read_final_reply_skips_multiple_interim_lines() {
        let wire = "{\"interim\":true,\"parked\":true,\"id\":\"1\",\"timeoutSecs\":1}\n\
                    {\"interim\":true,\"parked\":true,\"id\":\"1\",\"timeoutSecs\":1}\n\
                    {\"ok\":false,\"error\":\"timed out\"}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let reply = read_final_reply(&mut reader).unwrap();
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "timed out");
    }

    #[test]
    fn read_final_reply_on_a_connection_that_closes_after_only_interim_lines_is_a_clear_error() {
        let wire = "{\"interim\":true,\"parked\":true,\"id\":\"1\",\"timeoutSecs\":1}\n";
        let mut reader = std::io::Cursor::new(wire.as_bytes());
        let err = read_final_reply(&mut reader).unwrap_err();
        assert!(err.contains("closed the connection"), "{err}");
    }

    #[test]
    fn resolve_against_a_dead_socket_never_reaches_the_interim_loop_at_all() {
        // Sanity: a dead-socket connect error still short-circuits before
        // `read_final_reply` is ever called — same shape as the existing
        // `resolve_against_a_dead_socket_is_a_connect_error` test, kept
        // here as a reminder that FIX 1's new loop sits strictly AFTER the
        // connect step, never wrapping it.
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-interim-test.sock");
        let err = resolve(dead, "t", "m", None, None).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn stdin_is_tty_is_false_under_cargo_test() {
        // `cargo test` never runs with a tty on fd 0 — this is the same
        // guarantee `run_put`'s existing pipe-path callers already lean on
        // implicitly; asserted directly so a sandboxing change that somehow
        // attaches a tty would fail loudly here instead of silently
        // changing `run_put`'s behavior under every other test.
        assert!(!stdin_is_tty());
    }
}
