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

use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;

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
pub fn parse_exec_args(inv: &Invocation) -> Result<ExecArgs, String> {
    let consumer = inv
        .flags
        .get("as")
        .cloned()
        .ok_or_else(|| "secrets exec requires --as <consumer>".to_string())?;
    let secret_flag = inv
        .flags
        .get("secret")
        .cloned()
        .ok_or_else(|| "secrets exec requires --secret <name>[:VAR]".to_string())?;
    let (secret, var) = match secret_flag.split_once(':') {
        Some((n, v)) if !v.is_empty() => (n.to_string(), v.to_string()),
        _ => {
            let n = secret_flag.trim_end_matches(':').to_string();
            let derived = default_var_name(&n);
            (n, derived)
        }
    };
    if !crate::policy::valid_secret_name(&secret) {
        return Err(format!("invalid secret name `{secret}`"));
    }
    let totp = inv.flags.get("totp").cloned();
    let cmd = inv.args.clone();
    if cmd.is_empty() {
        return Err("secrets exec requires a command after `--`".to_string());
    }
    Ok(ExecArgs { consumer, secret, var, totp, cmd })
}

/// Connect to `socket_path`, send ONE `resolve` request, read ONE reply
/// line, and return the value or a value-free error message.
pub fn resolve(
    socket_path: &Path,
    secret: &str,
    consumer: &str,
    totp: Option<&str>,
    argv0: Option<&str>,
) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connecting to the secrets broker at {}: {e}", socket_path.display()))?;

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
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| format!("reading from the secrets broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the secrets broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the secrets broker sent an unparseable reply: {e}"))?;

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

/// Connect to `socket_path`, send ONE `put` request carrying `value`, read
/// ONE reply line, and return `Ok(())` on a stored value or a value-free
/// `Err` otherwise. Mirrors [`resolve`]'s one-shot socket shape; unlike
/// `resolve`'s reply, `put`'s never carries a value back — only ok/error —
/// so there is nothing here for a caller to extract.
pub fn put(socket_path: &Path, secret: &str, value: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connecting to the secrets broker at {}: {e}", socket_path.display()))?;

    let req = json!({ "op": "put", "secret": secret, "value": value });
    let mut line = req.to_string();
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("writing to the secrets broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| format!("reading from the secrets broker: {e}"))?;
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
fn stdin_is_tty() -> bool {
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
fn read_hidden_line(prompt: &str) -> Result<String, String> {
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

/// The full `secrets put <name>` client flow: read the value from THIS
/// process's own stdin (stdin-only intake, module doc) — prompting with
/// echo hidden when stdin is a terminal (P-V4e), reading straight through
/// unchanged when it's piped/redirected (the historical shape) — then
/// [`put`] it over `socket_path`. The value exists only as this function's
/// own local `String`, from the stdin read to the `put()` call — never
/// returned, never logged, never touching argv.
pub fn run_put(secret: &str, socket_path: &Path) -> Result<(), String> {
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
    put(socket_path, secret, &value)
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

    #[test]
    fn resolve_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-test.sock");
        let err = resolve(dead, "t", "m", None, None).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }

    #[test]
    fn put_against_a_dead_socket_is_a_connect_error() {
        let dead = Path::new("/tmp/aoide-secrets-nonexistent-put-test.sock");
        let err = put(dead, "t", "irrelevant").unwrap_err();
        assert!(err.contains("connecting"), "{err}");
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
