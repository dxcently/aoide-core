//! The broker daemon (`aoide vault serve`): a unix-socket JSON-lines
//! server, ONE request per line, ONE reply per line — the shellbridge
//! precedent (`aoide_conduct::shellbridge`, read and matched deliberately
//! per the phase brief): a single-threaded accept loop, a `serve`/
//! `handle_conn` split, every failure contained (a malformed line, an
//! unknown op, or a dropped connection ends only that line/connection —
//! never the service).
//!
//! Wire (V2 — `resolve` is the only op):
//! ```text
//! -> {"op":"resolve","secret":"<name>","consumer":"<consumer>","totp":"<code>"?,"argv0":"<cmd>"?}
//! <- {"ok":true,"value":"<value>"}                    (granted)
//! <- {"ok":false,"error":"<value-free message>"}      (denied/error)
//! ```
//! `totp`/`argv0` are optional. `consumer` is SELF-ASSERTED (the plan's
//! V1 ruling, `crate::replay`'s module doc): the policy's `consumers[]`
//! list is the real gate, not caller identity.
//!
//! **STANDING GRANTS ONLY this phase.** A policy with `requireTotp: true`
//! is UNRESOLVABLE — rejected outright with a clear "no TOTP enrollment on
//! this host yet" error, regardless of whether a `totp` code rode the
//! request. `crate::totp::verify` + `crate::replay::ReplayLedger` stay
//! unwired until `vault enroll` lands (P-V3/P-V4) — there is no enrolled
//! secret to verify a code AGAINST yet, so wiring verification now would
//! be dead code with no honest way to exercise its granted branch.
//!
//! **Audit, broker-side only** (this crate's `AGENTS.md`): every resolve
//! attempt is logged HERE — never by the client, which only ever learns
//! granted/denied from the wire reply — to TWO places: vault's own
//! append-only log in vault home (`audit.log`, hand-built
//! `serde_json::Value` via the `json!` macro, never a named
//! `#[derive(Serialize)]` struct with a reusable field a value could land
//! on) and the mirrored aoide audit log via `aoide_protocol::audit` with
//! `EventClass::Secret`. Both carry secret name + consumer + argv0 (if the
//! client sent one) + granted/denied + a value-free reason — NEVER the
//! value, which exists only as this module's own local `String` between
//! the backend fetch and the `{"ok":true,"value":...}` line write.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Bind `socket_path` and serve `resolve` requests forever. Creates
/// `vault_home` if absent and locks it down to `0700` (bounce-fix item 3,
/// P-V2 review — `create_dir_all` alone honors the process umask, which
/// would leave `policy.json`/`backends.json` world-readable); removes a
/// stale socket file first (single-owner path per host, same precedent as
/// `shellbridge::run`). Only returns on a bind/permission failure — a
/// running broker never returns `Ok`.
pub fn serve(vault_home: &Path, socket_path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(vault_home)?;
    crate::home::secure_dir(vault_home)?;
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;

    let home = vault_home.to_path_buf();
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => handle_conn(&home, stream),
            Err(e) => eprintln!("[aoide/vault] accept error (continuing): {e}"),
        }
    }
    Ok(())
}

/// Handle ONE client connection: read newline-delimited JSON requests and
/// reply to each. A read error (dropped connection) ends only this
/// connection; nothing here can unwind into `serve`'s accept loop.
fn handle_conn(vault_home: &Path, stream: UnixStream) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[aoide/vault] could not clone connection: {e}");
            return;
        }
    };
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = handle_line(vault_home, &line);
        let mut out = reply.to_string();
        out.push('\n');
        if writer.write_all(out.as_bytes()).is_err() {
            break;
        }
    }
}

/// Parse and dispatch ONE wire line. Pure with respect to the wire framing
/// (all I/O — policy load, backend fetch, audit — happens inside
/// [`handle_resolve`]/[`resolve_gate`]); malformed JSON or an unknown `op`
/// always gets a reply line, never a silently dropped connection (unlike
/// shellbridge's fire-and-forget commands, a vault client is BLOCKED
/// waiting on this reply).
fn handle_line(vault_home: &Path, line: &str) -> Value {
    let req: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "malformed request: not valid JSON"}),
    };
    match req.get("op").and_then(Value::as_str) {
        Some("resolve") => handle_resolve(vault_home, &req),
        Some(other) => json!({"ok": false, "error": format!("unknown op `{other}`")}),
        None => json!({"ok": false, "error": "malformed request: missing `op`"}),
    }
}

fn handle_resolve(vault_home: &Path, req: &Value) -> Value {
    let secret = req.get("secret").and_then(Value::as_str).unwrap_or("").to_string();
    let consumer = req.get("consumer").and_then(Value::as_str).unwrap_or("").to_string();
    let argv0 = req.get("argv0").and_then(Value::as_str).map(str::to_string);
    // Accepted on the wire, parsed only so the shape doesn't shift before
    // P-V3/P-V4 wire it — see the module doc: never consulted this phase.
    let _totp = req.get("totp").and_then(Value::as_str);

    if secret.is_empty() || consumer.is_empty() {
        return json!({"ok": false, "error": "malformed request: `secret` and `consumer` are required"});
    }

    let (granted, result) = resolve_gate(vault_home, &secret, &consumer);
    audit_resolve(vault_home, &secret, &consumer, argv0.as_deref(), granted, result.as_ref().err());

    match result {
        Ok(value) => json!({"ok": true, "value": value}),
        Err(reason) => json!({"ok": false, "error": reason}),
    }
}

/// The policy gate + backend fetch, in one place. `granted` is carried
/// alongside the `Result` (rather than inferred from `is_ok()` at the call
/// site) so the caller's audit call reads as one obviously-correct pairing
/// rather than a second derivation of the same fact.
fn resolve_gate(vault_home: &Path, secret: &str, consumer: &str) -> (bool, Result<String, String>) {
    let policies = match crate::store::load_policies(vault_home) {
        Ok(p) => p,
        Err(e) => return (false, Err(format!("policy.json: {e}"))),
    };
    let Some(policy) = policies.iter().find(|p| p.name == secret) else {
        return (false, Err("secret not found".to_string()));
    };
    let authorized = policy.consumers.is_empty() || policy.consumers.iter().any(|c| c == consumer);
    if !authorized {
        return (false, Err("consumer not authorized for this secret".to_string()));
    }
    if policy.require_totp {
        return (
            false,
            Err("requireTotp is set but no TOTP enrollment exists on this host yet (P-V2: standing grants only)"
                .to_string()),
        );
    }
    match crate::backend::fetch_value(vault_home, &policy.backend, &policy.key) {
        Ok(value) => (true, Ok(value)),
        Err(e) => (false, Err(e)),
    }
}

fn own_audit_log_path(vault_home: &Path) -> PathBuf {
    vault_home.join("audit.log")
}

fn append_own_log(vault_home: &Path, record: &Value) -> std::io::Result<()> {
    let path = own_audit_log_path(vault_home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let mut line = record.to_string();
    line.push('\n');
    f.write_all(line.as_bytes())
}

/// Write BOTH audit lines for one resolve attempt (module doc). Name-only,
/// by construction: nothing passed here is ever the secret's value.
fn audit_resolve(
    vault_home: &Path,
    secret: &str,
    consumer: &str,
    argv0: Option<&str>,
    granted: bool,
    reason: Option<&String>,
) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "secret": secret,
        "consumer": consumer,
        "argv0": argv0,
        "granted": granted,
        "reason": reason,
    });
    if let Err(e) = append_own_log(vault_home, &record) {
        eprintln!("[aoide/vault] could not write the vault audit log: {e}");
    }

    let status = if granted { "granted" } else { "denied" };
    let message = match reason {
        Some(r) => format!("secret `{secret}` for consumer `{consumer}`: {status} ({r})"),
        None => format!("secret `{secret}` for consumer `{consumer}`: {status}"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "vault.resolve",
        status,
        &message,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn tmp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-vault-broker-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn seed(home: &Path, policies: &[Policy]) {
        crate::store::save_policies(home, policies).unwrap();
        let backends = serde_json::json!({ "scratch": { "get": "printf %s {name}" } });
        std::fs::write(crate::backend::backends_path(home), serde_json::to_vec(&backends).unwrap()).unwrap();
    }

    #[test]
    fn unknown_secret_is_denied_with_a_clear_reason() {
        let home = tmp_home("unknown");
        seed(&home, &[]);
        let (granted, result) = resolve_gate(&home, "nope", "m");
        assert!(!granted);
        assert_eq!(result.unwrap_err(), "secret not found");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn consumer_not_in_the_list_is_denied() {
        let home = tmp_home("wrongconsumer");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let (granted, result) = resolve_gate(&home, "t", "someone-else");
        assert!(!granted);
        assert!(result.unwrap_err().contains("not authorized"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn empty_consumers_list_means_any_consumer() {
        let home = tmp_home("anyconsumer");
        let p = Policy::new("t", "scratch", "stored-value");
        seed(&home, &[p]);
        let (granted, result) = resolve_gate(&home, "t", "whoever");
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn require_totp_is_unresolvable_this_phase_no_matter_what() {
        let home = tmp_home("totp");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        seed(&home, &[p]);
        let (granted, result) = resolve_gate(&home, "t", "m");
        assert!(!granted);
        assert!(result.unwrap_err().contains("no TOTP enrollment"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_granted_resolve_fetches_through_the_named_backend() {
        let home = tmp_home("granted");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let (granted, result) = resolve_gate(&home, "t", "m");
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── wire framing (handle_line) ──────────────────────────────────────

    #[test]
    fn malformed_json_gets_a_reply_not_a_dropped_connection() {
        let home = tmp_home("malformed");
        let reply = handle_line(&home, "not json at all");
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("not valid JSON"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn missing_op_is_a_clear_error() {
        let home = tmp_home("missingop");
        let reply = handle_line(&home, r#"{"secret":"t","consumer":"m"}"#);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("missing `op`"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn unknown_op_is_a_clear_error() {
        let home = tmp_home("unknownop");
        let reply = handle_line(&home, r#"{"op":"explode"}"#);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("unknown op"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn resolve_with_missing_fields_is_malformed() {
        let home = tmp_home("missingfields");
        let reply = handle_line(&home, r#"{"op":"resolve","secret":"t"}"#);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("required"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_full_resolve_line_round_trips_the_value() {
        // `handle_line` -> `handle_resolve` -> `audit_resolve` writes the
        // MIRRORED aoide audit log too, via `aoide_protocol::
        // default_audit_log()` — redirect it into this test's own tempdir
        // (`env_lock`, restored after) so the test never touches the real
        // `~/Aoide/log`. The vault's OWN `audit.log` lives under `home`
        // regardless, no redirection needed for that half.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("fullline");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        let p = Policy::new("t", "scratch", "stored-value");
        seed(&home, &[p]);
        let reply = handle_line(&home, r#"{"op":"resolve","secret":"t","consumer":"m"}"#);
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["value"], "stored-value");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    /// Bounce-fix item 1 (P-V2 review), full path: a backend that dumps a
    /// sentinel to stderr and fails must not leak that sentinel through
    /// EITHER audit line OR the wire reply — `backend::fetch_value` already
    /// proves the `Err` string is clean in isolation; this proves the
    /// guarantee survives all the way through `handle_line` ->
    /// `audit_resolve`'s `reason` field on both logs.
    #[test]
    fn a_backend_stderr_sentinel_never_reaches_the_wire_reply_or_either_audit_log() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("stderrleak");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        let p = Policy::new("t", "scratch", "stored-value");
        crate::store::save_policies(&home, &[p]).unwrap();
        let backends = serde_json::json!({
            "scratch": { "get": "printf 'SENTINEL-STDERR-XYZ' 1>&2; exit 1" }
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let reply = handle_line(&home, r#"{"op":"resolve","secret":"t","consumer":"m"}"#);
        assert_eq!(reply["ok"], false);
        let wire_error = reply["error"].as_str().unwrap();
        assert!(!wire_error.contains("SENTINEL"), "wire reply leaked stderr: {wire_error}");

        let own_log = std::fs::read_to_string(own_audit_log_path(&home)).unwrap();
        assert!(!own_log.contains("SENTINEL"), "vault's own audit.log leaked stderr: {own_log}");

        let mirrored_log = std::fs::read_to_string(home.join("mirrored-aoide-log")).unwrap();
        assert!(!mirrored_log.contains("SENTINEL"), "mirrored aoide audit log leaked stderr: {mirrored_log}");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }
}
