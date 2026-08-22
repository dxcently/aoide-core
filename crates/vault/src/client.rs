//! The `vault exec` client — RELEASE TO CLIENT, the plan's one subtle
//! decision (this crate's README's "Release-to-client flow"). The broker
//! never execs the agent's command: it runs as the vault uid (wrong cwd/
//! env, and the child would inherit vault privileges). Instead THIS
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

use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;

/// Parsed `vault exec` arguments — pure, no I/O, fully unit-testable
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

/// Parse `aoide vault exec --as <consumer> --secret <name>[:VAR] [--totp N]
/// -- <cmd>` out of an already-parsed [`Invocation`]. `inv.args` is exactly
/// the wrapped command + its args — `aoide_protocol::door::parse` already
/// treats a bare `--` as ending flag parsing, so everything after it
/// arrives here verbatim as positionals (that module's own doc).
pub fn parse_exec_args(inv: &Invocation) -> Result<ExecArgs, String> {
    let consumer = inv
        .flags
        .get("as")
        .cloned()
        .ok_or_else(|| "vault exec requires --as <consumer>".to_string())?;
    let secret_flag = inv
        .flags
        .get("secret")
        .cloned()
        .ok_or_else(|| "vault exec requires --secret <name>[:VAR]".to_string())?;
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
        return Err("vault exec requires a command after `--`".to_string());
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
        .map_err(|e| format!("connecting to the vault broker at {}: {e}", socket_path.display()))?;

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
        .map_err(|e| format!("writing to the vault broker: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut reply_line = String::new();
    reader
        .read_line(&mut reply_line)
        .map_err(|e| format!("reading from the vault broker: {e}"))?;
    if reply_line.trim().is_empty() {
        return Err("the vault broker closed the connection with no reply".to_string());
    }
    let reply: Value = serde_json::from_str(reply_line.trim())
        .map_err(|e| format!("the vault broker sent an unparseable reply: {e}"))?;

    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        reply
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "the vault broker's reply had no `value`".to_string())
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the vault broker denied the request")
            .to_string())
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

/// The full `vault exec` client flow — parse, resolve over `socket_path`,
/// spawn with the value injected. Returns the process exit code to hand
/// back from `main`: `2` (usage) for a bad invocation, `1` (error) for a
/// denied resolve or a spawn failure, else the CHILD's own exit code.
pub fn run_exec(inv: &Invocation, socket_path: &Path) -> i32 {
    let args = match parse_exec_args(inv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("aoide vault exec: {e}");
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
            eprintln!("aoide vault exec: {e}");
            return 1;
        }
    };
    match spawn_with_secret(&args.cmd, &args.var, &value) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aoide vault exec: {e}");
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
            path: vec!["vault".to_string(), "exec".to_string()],
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
        let dead = Path::new("/tmp/aoide-vault-nonexistent-test.sock");
        let err = resolve(dead, "t", "m", None, None).unwrap_err();
        assert!(err.contains("connecting"), "{err}");
    }
}
