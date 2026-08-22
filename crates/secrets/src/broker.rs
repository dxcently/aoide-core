//! The broker daemon (`aoide secrets serve`): a unix-socket JSON-lines
//! server, ONE request per line, ONE reply per line — the shellbridge
//! precedent (`aoide_conduct::shellbridge`, read and matched deliberately
//! per the phase brief): a single-threaded accept loop, a `serve`/
//! `handle_conn` split, every failure contained (a malformed line, an
//! unknown op, or a dropped connection ends only that line/connection —
//! never the service).
//!
//! Wire (`resolve` and `put`, P-V4c):
//! ```text
//! -> {"op":"resolve","secret":"<name>","consumer":"<consumer>","totp":"<code>"?,"argv0":"<cmd>"?}
//! <- {"ok":true,"value":"<value>"}                    (granted)
//! <- {"ok":false,"error":"<value-free message>"}      (denied/error)
//!
//! -> {"op":"put","secret":"<name>","value":"<value>"}
//! <- {"ok":true}                                       (stored)
//! <- {"ok":false,"error":"<value-free message>"}      (denied/error)
//! ```
//! `totp`/`argv0` are optional on `resolve`. `consumer` is SELF-ASSERTED
//! (the plan's V1 ruling, `crate::replay`'s module doc): the policy's
//! `consumers[]` list is the real gate, not caller identity. This repo-wide
//! machine-consumer contract (both ops, every error string, the
//! group-membership trust model) is ALSO documented in `CONTRACTS.md`'s
//! "Secrets home" section — services (verba voluntia, Melete-side models)
//! are meant to speak this wire directly, no LLM in the loop; `secrets
//! exec`/`secrets put` are convenience wrappers over the same two ops, not
//! the only door onto them.
//!
//! **`put` carries NO `consumer` field and is never gated by
//! `requireTotp`** (P-V4c, deliberate): `secrets put` is CLI-only
//! (`commands::handle_secrets_put`'s `require_cli` gate) and, in
//! deployment, runs AS THE SECRETS UID's own operator (`sudo -u
//! aoide-secrets aoide secrets put …`, same admin-verb precedent as
//! `add`/`grant` — README's "Admin verbs" section) — there is no separate
//! "consumer" identity to authorize the way `resolve`'s agent-facing
//! callers need, and a code check would be gating the secrets uid against
//! itself. [`put_gate`] therefore checks ONLY that a policy exists for the
//! named secret (`put` never auto-creates one — `secrets add` owns policy
//! creation, same as before P-V4c) and that its backend has a `set`
//! template; it never touches `policy.require_totp` or `verify_totp_gate`
//! at all.
//!
//! **`requireTotp` is wired live (P-V3).** [`resolve_gate`] rejects it
//! outright ONLY when no `secrets enroll` has ever run on this host
//! (`crate::store::load_totp_secret` returns `None`) — a clear "no TOTP
//! enrollment" error, same wording as before P-V3. Once enrolled, a
//! `requireTotp` policy verifies the wire's `totp` code against the
//! enrolled secret (`crate::totp::verify`, `±1`-timestep window) and
//! consumes the matched timestep in a [`crate::replay::ReplayLedger`]
//! persisted via `crate::store::load_replay_ledger`/`save_replay_ledger`
//! (this crate's `AGENTS.md` ruling: keyed on timestep ALONE, never
//! consumer) — a missing/wrong/already-used code is a denial, exactly
//! like every other gate failure below: the backend never runs, both
//! audit lines fire with a value-free (and CODE-free — the typed code is
//! untrusted input, never echoed) reason. The ledger is reloaded fresh
//! from disk on every TOTP-gated attempt rather than cached across
//! connections (no in-memory broker state at all, matching how policies
//! are already handled) — which is also what makes "a broker restart must
//! not resurrect a spent code" true for free: the very next resolve after
//! a restart re-reads the same file.
//!
//! `resolve_gate`'s clock is a PARAMETER (`now_unix`), not a `SystemTime::
//! now()` call inside it — [`handle_resolve`] is the one place in this
//! module that reads the real clock (`aoide_protocol::audit::now_secs()`)
//! and hands it in, so `resolve_gate`/`verify_totp_gate` stay exactly as
//! deterministically testable as `crate::totp`/`crate::replay` themselves
//! (this crate's `AGENTS.md`, "clock-as-parameter, everywhere" — the
//! broker is where the real-clock wrapper is allowed to live, and this is
//! that one wrapper).
//!
//! **Audit, broker-side only** (this crate's `AGENTS.md`): every resolve
//! attempt is logged HERE — never by the client, which only ever learns
//! granted/denied from the wire reply — to TWO places: the broker's own
//! append-only log in secrets home (`audit.log`, hand-built
//! `serde_json::Value` via the `json!` macro, never a named
//! `#[derive(Serialize)]` struct with a reusable field a value could land
//! on) and the mirrored aoide audit log via `aoide_protocol::audit` with
//! `EventClass::Secret`. Both carry secret name + consumer + argv0 (if the
//! client sent one) + granted/denied + a value-free reason — NEVER the
//! value, which exists only as this module's own local `String` between
//! the backend fetch and the `{"ok":true,"value":...}` line write.
//!
//! **The socket is chmod'd to `0660` immediately after bind** (P-V4,
//! deployment). `UnixListener::bind` alone honors the process umask, so
//! the socket's mode is whatever the ambient umask happens to yield —
//! under the common `022` that's `0755`, which (since `connect(2)` on an
//! `AF_UNIX` socket requires WRITE permission) is actually unreachable for
//! the intended access GROUP, while under a loose umask (`002`/`000`, a
//! hand-run non-nix box) it drifts toward group- or world-connectable —
//! and the wire's `consumer` field is SELF-ASSERTED (this module's own
//! doc, above), so an over-open socket means any local user could resolve
//! any standing-grant secret. The explicit chmod replaces that
//! umask-dependent lottery with the one deliberate mode either way.
//! `0660` (owner + group rw, no other bits) is the
//! DESIGN, not a tightened-as-far-as-possible default: the socket is
//! deliberately GROUP-connectable, not owner-only, because the whole point
//! is that ordinary operator-uid agents (members of the access group) can
//! reach it. [`bind_socket`] sets only the MODE bits (`0o660` literal, the
//! group-connectable design point — contrast [`crate::home::secure_file`]'s
//! `0o600`, which is the wrong mode HERE on purpose). Group OWNERSHIP —
//! making the socket's gid the real `aoide-secrets-access` group — is
//! deployment's job, not this crate's: P-V4's nix module sets the
//! `aoide-secrets-serve` unit's `Group=aoide-secrets-access`, so every file the
//! broker process creates (including this socket) inherits that gid from
//! the process's own primary/effective group. This module only ever touches
//! the mode bits.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Bind `socket_path`: create its parent dir if absent, remove a stale
/// socket file first (single-owner path per host, same precedent as
/// `shellbridge::run`), bind, then chmod the socket file to `0660`
/// (module doc — group-connectable is the DESIGN, group OWNERSHIP is
/// deployment's job). Split out of [`serve`] so a test can exercise the
/// bind-and-secure step directly without entering the forever-loop accept
/// body.
fn bind_socket(socket_path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Bind `socket_path` and serve `resolve`/`put` requests forever. Creates
/// `secrets_home` if absent and locks it down to `0700` (bounce-fix item 3,
/// P-V2 review — `create_dir_all` alone honors the process umask, which
/// would leave `policy.json`/`backends.json` world-readable). **Seeds
/// `backends.json` with the built-in `file` backend when absent** (P-V4c,
/// `crate::backend::seed_default_backends`) — this is the ONE seeding site
/// (decision recorded here, not duplicated at `secrets add`/`secrets put`):
/// `serve` is the single long-running process that ever actually resolves
/// a backend name against a `get`/`set` template (both the CLI's `secrets
/// exec` and the new `secrets put` reach a backend only by round-tripping
/// through THIS process over the socket), so seeding here guarantees every
/// such attempt sees a `backends.json` on disk without a second seed call
/// anywhere else. A seeding failure is logged and NON-fatal — an existing
/// or hand-authored `backends.json` (or none at all, for a host that only
/// ever uses non-`file` backends) is still a perfectly servable broker.
/// Only returns on a bind/permission failure — a running broker never
/// returns `Ok`.
pub fn serve(secrets_home: &Path, socket_path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(secrets_home)?;
    crate::home::secure_dir(secrets_home)?;
    if let Err(e) = crate::backend::seed_default_backends(secrets_home) {
        eprintln!("[aoide/secrets] could not seed the default `file` backend into backends.json: {e}");
    }
    let listener = bind_socket(socket_path)?;

    let home = secrets_home.to_path_buf();
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => handle_conn(&home, stream),
            Err(e) => eprintln!("[aoide/secrets] accept error (continuing): {e}"),
        }
    }
    Ok(())
}

/// Handle ONE client connection: read newline-delimited JSON requests and
/// reply to each. A read error (dropped connection) ends only this
/// connection; nothing here can unwind into `serve`'s accept loop.
fn handle_conn(secrets_home: &Path, stream: UnixStream) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[aoide/secrets] could not clone connection: {e}");
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
        let reply = handle_line(secrets_home, &line);
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
/// shellbridge's fire-and-forget commands, a secrets client is BLOCKED
/// waiting on this reply).
fn handle_line(secrets_home: &Path, line: &str) -> Value {
    let req: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "malformed request: not valid JSON"}),
    };
    match req.get("op").and_then(Value::as_str) {
        Some("resolve") => handle_resolve(secrets_home, &req),
        Some("put") => handle_put(secrets_home, &req),
        Some(other) => json!({"ok": false, "error": format!("unknown op `{other}`")}),
        None => json!({"ok": false, "error": "malformed request: missing `op`"}),
    }
}

fn handle_resolve(secrets_home: &Path, req: &Value) -> Value {
    let secret = req.get("secret").and_then(Value::as_str).unwrap_or("").to_string();
    let consumer = req.get("consumer").and_then(Value::as_str).unwrap_or("").to_string();
    let argv0 = req.get("argv0").and_then(Value::as_str).map(str::to_string);
    let totp = req.get("totp").and_then(Value::as_str).map(str::to_string);

    if secret.is_empty() || consumer.is_empty() {
        return json!({"ok": false, "error": "malformed request: `secret` and `consumer` are required"});
    }

    // The one real-clock read in this module — see module doc.
    let now_unix = aoide_protocol::audit::now_secs();
    let (granted, result) = resolve_gate(secrets_home, &secret, &consumer, totp.as_deref(), now_unix);
    audit_resolve(secrets_home, &secret, &consumer, argv0.as_deref(), granted, result.as_ref().err());

    match result {
        Ok(value) => json!({"ok": true, "value": value}),
        Err(reason) => json!({"ok": false, "error": reason}),
    }
}

/// `put` (P-V4c): stores `value` through the named secret's backend `set`
/// template. No `consumer` field on this op, no TOTP gate — see module doc
/// for why (CLI-only, admin-side). The value exists here ONLY as this
/// function's own local read of `req`'s `value` field, handed straight to
/// [`put_gate`]/`crate::backend::store_value`; it never lands anywhere
/// else in this function (not the returned `Value`, not either audit line
/// — [`audit_put`] is name-only by construction, same as `audit_resolve`).
fn handle_put(secrets_home: &Path, req: &Value) -> Value {
    let secret = req.get("secret").and_then(Value::as_str).unwrap_or("").to_string();
    let value = req.get("value").and_then(Value::as_str).unwrap_or("").to_string();

    if secret.is_empty() {
        return json!({"ok": false, "error": "malformed request: `secret` is required"});
    }

    let (granted, result) = put_gate(secrets_home, &secret, &value);
    audit_put(secrets_home, &secret, granted, result.as_ref().err());

    match result {
        Ok(()) => json!({"ok": true}),
        Err(reason) => json!({"ok": false, "error": reason}),
    }
}

/// The `put` policy gate + backend store, in one place — mirrors
/// [`resolve_gate`]'s shape (`granted` carried alongside the `Result`, same
/// reasoning). `put` never auto-creates a policy (`secrets add` owns policy
/// creation, module doc) and never checks `requireTotp` (module doc): a
/// missing policy or a backend with no `set` template are both ordinary,
/// value-free denials — the backend is never invoked on either.
fn put_gate(secrets_home: &Path, secret: &str, value: &str) -> (bool, Result<(), String>) {
    let policies = match crate::store::load_policies(secrets_home) {
        Ok(p) => p,
        Err(e) => return (false, Err(format!("policy.json: {e}"))),
    };
    let Some(policy) = policies.iter().find(|p| p.name == secret) else {
        return (false, Err("secret not found".to_string()));
    };
    match crate::backend::store_value(secrets_home, &policy.backend, &policy.key, value) {
        Ok(()) => (true, Ok(())),
        Err(e) => (false, Err(e)),
    }
}

/// Timesteps kept in the replay ledger beyond the oldest one a `±1`-window
/// `totp::verify` could still match — a generous buffer (not a tight `±1`)
/// so a slightly-delayed save can never prune the very timestep
/// [`verify_totp_gate`] just recorded. Pure bound, no clock read.
const REPLAY_RETENTION_STEPS: u64 = 4; // ~2 minutes at the 30s step

/// The policy gate + backend fetch, in one place. `granted` is carried
/// alongside the `Result` (rather than inferred from `is_ok()` at the call
/// site) so the caller's audit call reads as one obviously-correct pairing
/// rather than a second derivation of the same fact. `now_unix` is the
/// caller's clock read (module doc's clock-as-parameter discipline) — this
/// function and everything it calls stay deterministic given the same
/// inputs.
fn resolve_gate(
    secrets_home: &Path,
    secret: &str,
    consumer: &str,
    totp: Option<&str>,
    now_unix: u64,
) -> (bool, Result<String, String>) {
    let policies = match crate::store::load_policies(secrets_home) {
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
        if let Err(e) = verify_totp_gate(secrets_home, totp, now_unix) {
            return (false, Err(e));
        }
    }
    match crate::backend::fetch_value(secrets_home, &policy.backend, &policy.key) {
        Ok(value) => (true, Ok(value)),
        Err(e) => (false, Err(e)),
    }
}

/// The `requireTotp` half of [`resolve_gate`]. No enrollment on this host
/// -> unresolvable (unchanged wording from before P-V3). Enrolled -> a
/// fresh `±1`-window code, single-use per TIMESTEP via the persisted
/// [`crate::replay::ReplayLedger`] (this crate's `AGENTS.md` ruling: keyed
/// on timestep alone, never consumer). Every error string here is
/// value-free AND code-free by construction: the caller-typed `totp`
/// string is untrusted input (module doc) and is never interpolated into
/// any returned message, only parsed/compared.
fn verify_totp_gate(secrets_home: &Path, totp: Option<&str>, now_unix: u64) -> Result<(), String> {
    let secret = match crate::store::load_totp_secret(secrets_home) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err("requireTotp is set but no TOTP enrollment exists on this host yet".to_string())
        }
        Err(e) => return Err(format!("totp.secret: {e}")),
    };
    let Some(code_str) = totp else {
        return Err("requireTotp is set but no totp code was provided".to_string());
    };
    let Ok(code) = code_str.trim().parse::<u32>() else {
        return Err("malformed totp code".to_string());
    };
    let Some(step) = crate::totp::verify(&secret, code, now_unix, crate::totp::DEFAULT_WINDOW) else {
        return Err("totp code invalid or expired".to_string());
    };

    let mut ledger = match crate::store::load_replay_ledger(secrets_home) {
        Ok(l) => l,
        Err(e) => return Err(format!("totp-replay.json: {e}")),
    };
    if !ledger.record(step) {
        return Err("totp code already used".to_string());
    }
    ledger.prune_before(crate::totp::timestep(now_unix).saturating_sub(REPLAY_RETENTION_STEPS));
    if let Err(e) = crate::store::save_replay_ledger(secrets_home, &ledger) {
        return Err(format!("writing totp-replay.json: {e}"));
    }
    Ok(())
}

fn own_audit_log_path(secrets_home: &Path) -> PathBuf {
    secrets_home.join("audit.log")
}

fn append_own_log(secrets_home: &Path, record: &Value) -> std::io::Result<()> {
    let path = own_audit_log_path(secrets_home);
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
    secrets_home: &Path,
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
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
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
        "secrets.resolve",
        status,
        &message,
    );
}

/// Write BOTH audit lines for one `put` attempt — the `put` mirror of
/// [`audit_resolve`], same two destinations (the broker's own `audit.log`
/// + the mirrored `EventClass::Secret` aoide-log line), same name-only
/// discipline. No `consumer`/`argv0` fields — `put`'s wire request carries
/// neither (module doc).
fn audit_put(secrets_home: &Path, secret: &str, granted: bool, reason: Option<&String>) {
    let record = json!({
        "ts": aoide_protocol::audit::now_secs(),
        "op": "put",
        "secret": secret,
        "granted": granted,
        "reason": reason,
    });
    if let Err(e) = append_own_log(secrets_home, &record) {
        eprintln!("[aoide/secrets] could not write the secrets audit log: {e}");
    }

    let status = if granted { "granted" } else { "denied" };
    let message = match reason {
        Some(r) => format!("put `{secret}`: {status} ({r})"),
        None => format!("put `{secret}`: {status}"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        aoide_protocol::Door::Daemon,
        aoide_protocol::EventClass::Secret,
        "secrets.put",
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
            "aoide-secrets-broker-test-{tag}-{}-{}",
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

    /// A fixed "now" for every test that doesn't specifically exercise TOTP
    /// timing — deterministic, never `SystemTime::now()`.
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn unknown_secret_is_denied_with_a_clear_reason() {
        let home = tmp_home("unknown");
        seed(&home, &[]);
        let (granted, result) = resolve_gate(&home, "nope", "m", None, NOW);
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
        let (granted, result) = resolve_gate(&home, "t", "someone-else", None, NOW);
        assert!(!granted);
        assert!(result.unwrap_err().contains("not authorized"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn empty_consumers_list_means_any_consumer() {
        let home = tmp_home("anyconsumer");
        let p = Policy::new("t", "scratch", "stored-value");
        seed(&home, &[p]);
        let (granted, result) = resolve_gate(&home, "t", "whoever", None, NOW);
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn require_totp_is_unresolvable_with_no_enrollment_on_this_host() {
        let home = tmp_home("totp-noenroll");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        seed(&home, &[p]);
        // No `totp.secret` written — nothing has enrolled this host yet.
        let (granted, result) = resolve_gate(&home, "t", "m", Some("123456"), NOW);
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
        let (granted, result) = resolve_gate(&home, "t", "m", None, NOW);
        assert!(granted);
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── requireTotp, enrolled (P-V3) ────────────────────────────────────

    /// Seeds an enrollment (`totp.secret`) alongside the usual policy/
    /// backend fixture. Returns the raw secret bytes so a test can derive
    /// a code from them via `crate::totp` directly.
    fn seed_enrolled(home: &Path, mut p: Policy) -> Vec<u8> {
        p.require_totp = true;
        seed(home, &[p]);
        let secret = b"a-twenty-byte-totp-s".to_vec();
        assert_eq!(secret.len(), 20);
        crate::store::save_totp_secret(home, &secret).unwrap();
        secret
    }

    /// Time-sensitivity discipline (phase brief): derive the TIMESTEP
    /// first, then the code for exactly that step — never `totp6(secret,
    /// now)` against a live clock, which could straddle a boundary between
    /// computing the code and the assertion running.
    fn code_for_now(secret: &[u8], now: u64) -> String {
        let step = crate::totp::timestep(now);
        crate::totp::format6(crate::totp::hotp(secret, step, crate::totp::DIGITS))
    }

    #[test]
    fn enrolled_and_correct_code_is_granted_and_runs_the_backend() {
        let home = tmp_home("totp-granted");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let code = code_for_now(&secret, NOW);

        let (granted, result) = resolve_gate(&home, "t", "m", Some(&code), NOW);
        assert!(granted, "{result:?}");
        assert_eq!(result.unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn enrolled_with_no_code_is_denied() {
        let home = tmp_home("totp-missingcode");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);

        let (granted, result) = resolve_gate(&home, "t", "m", None, NOW);
        assert!(!granted);
        assert!(result.unwrap_err().contains("no totp code"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn enrolled_with_the_wrong_code_is_denied() {
        let home = tmp_home("totp-wrongcode");
        let p = Policy::new("t", "scratch", "stored-value");
        let secret = seed_enrolled(&home, p);
        let correct = code_for_now(&secret, NOW);
        // Any 6-digit code that isn't the correct one.
        let wrong_num: u32 = (correct.parse::<u32>().unwrap() + 1) % 1_000_000;
        let wrong = crate::totp::format6(wrong_num);

        let (granted, result) = resolve_gate(&home, "t", "m", Some(&wrong), NOW);
        assert!(!granted);
        assert!(result.unwrap_err().contains("invalid or expired"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_malformed_totp_code_is_denied_without_panicking() {
        let home = tmp_home("totp-malformed");
        let p = Policy::new("t", "scratch", "stored-value");
        seed_enrolled(&home, p);

        let (granted, result) = resolve_gate(&home, "t", "m", Some("not-a-number"), NOW);
        assert!(!granted);
        assert!(result.unwrap_err().contains("malformed"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_same_code_used_twice_is_denied_the_second_time_replay() {
        let home = tmp_home("totp-replay");
        // Empty consumers list = any consumer — so BOTH calls clear the
        // authorization check, isolating the replay/ledger behavior this
        // test is actually about (a consumer mismatch would deny the
        // second call for the WRONG reason).
        let p = Policy::new("t", "scratch", "stored-value");
        let secret = seed_enrolled(&home, p);
        let code = code_for_now(&secret, NOW);

        let (first_granted, first_result) = resolve_gate(&home, "t", "m", Some(&code), NOW);
        assert!(first_granted, "{first_result:?}");

        // A second, DIFFERENT claimed consumer doesn't matter — the ledger
        // keys on timestep alone (this crate's AGENTS.md ruling: the
        // resolve wire's `consumer` field is self-asserted, so a
        // per-consumer ledger would let one typed code redeem once per
        // invented label).
        let (second_granted, second_result) = resolve_gate(&home, "t", "someone-else-entirely", Some(&code), NOW);
        assert!(!second_granted);
        assert!(second_result.unwrap_err().contains("already used"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// The ledger persistence requirement, exercised directly against
    /// `resolve_gate`: a SEPARATE call — standing in for "after a broker
    /// restart", since `resolve_gate` never caches the ledger in memory —
    /// still refuses the timestep an earlier call consumed, because the
    /// only state connecting the two calls is the file on disk.
    #[test]
    fn a_spent_code_stays_spent_across_a_simulated_broker_restart() {
        let home = tmp_home("totp-restart");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.consumers = vec!["m".to_string()];
        let secret = seed_enrolled(&home, p);
        let code = code_for_now(&secret, NOW);

        let (granted, _) = resolve_gate(&home, "t", "m", Some(&code), NOW);
        assert!(granted);

        // Nothing here reuses any in-process state from the call above —
        // this is exactly what a fresh broker process would do.
        let ledger_after_restart = crate::store::load_replay_ledger(&home).unwrap();
        let step = crate::totp::timestep(NOW);
        assert!(ledger_after_restart.is_used(step), "the ledger file must have the spent timestep");

        let (granted_again, result_again) = resolve_gate(&home, "t", "m", Some(&code), NOW);
        assert!(!granted_again);
        assert!(result_again.unwrap_err().contains("already used"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// Every TOTP denial path must short-circuit BEFORE the backend ever
    /// runs — same "positive control" discipline as `tests/e2e.rs`'s
    /// backend-invoked marker.
    #[test]
    fn totp_denial_paths_never_invoke_the_backend() {
        let home = tmp_home("totp-marker");
        let marker = home.join("backend-invoked-marker");
        let mut p = Policy::new("t", "scratch", "stored-value");
        p.require_totp = true;
        p.consumers = vec!["m".to_string()];
        seed(&home, &[p]);
        let secret = b"a-twenty-byte-totp-s".to_vec();
        crate::store::save_totp_secret(&home, &secret).unwrap();
        // Overwrite the fixture backend so it touches a marker before
        // producing output — same technique as `tests/e2e.rs`.
        let backends = serde_json::json!({
            "scratch": { "get": format!("touch {} && printf %s {{name}}", marker.display()) }
        });
        std::fs::write(crate::backend::backends_path(&home), serde_json::to_vec(&backends).unwrap()).unwrap();

        let code = code_for_now(&secret, NOW);
        let wrong_num: u32 = (code.parse::<u32>().unwrap() + 1) % 1_000_000;
        let wrong = crate::totp::format6(wrong_num);

        // No code, wrong code, replay (after one legitimate grant) — every
        // denial must leave the marker untouched.
        let (granted, _) = resolve_gate(&home, "t", "m", None, NOW);
        assert!(!granted);
        assert!(!marker.exists(), "backend ran on a missing-code denial");

        let (granted, _) = resolve_gate(&home, "t", "m", Some(&wrong), NOW);
        assert!(!granted);
        assert!(!marker.exists(), "backend ran on a wrong-code denial");

        let (granted, _) = resolve_gate(&home, "t", "m", Some(&code), NOW);
        assert!(granted, "the legitimate code should be granted (and now the marker DOES exist)");
        assert!(marker.exists(), "positive control: the backend must run on a granted resolve");
        std::fs::remove_file(&marker).unwrap();

        let (granted, _) = resolve_gate(&home, "t", "m", Some(&code), NOW);
        assert!(!granted, "the same code must be denied the second time (replay)");
        assert!(!marker.exists(), "backend ran on a replay denial");

        std::fs::remove_dir_all(&home).ok();
    }

    // ── socket permissions (P-V4) ───────────────────────────────────────

    #[test]
    fn bind_socket_chmods_the_socket_file_to_0660() {
        let home = tmp_home("sockmode");
        let socket_path = home.join("secrets.sock");
        let listener = bind_socket(&socket_path).unwrap();
        let mode = std::fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "secrets socket must be group-connectable (0660), got {mode:o}");
        drop(listener);
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
        // `~/Aoide/log`. The broker's OWN `audit.log` lives under `home`
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
        assert!(!own_log.contains("SENTINEL"), "the broker's own audit.log leaked stderr: {own_log}");

        let mirrored_log = std::fs::read_to_string(home.join("mirrored-aoide-log")).unwrap();
        assert!(!mirrored_log.contains("SENTINEL"), "mirrored aoide audit log leaked stderr: {mirrored_log}");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    // ── `put` (P-V4c) ────────────────────────────────────────────────────

    fn seed_with_set(home: &Path, policies: &[Policy], get: &str, set: &str) {
        crate::store::save_policies(home, policies).unwrap();
        let backends = serde_json::json!({ "scratch": { "get": get, "set": set } });
        std::fs::write(crate::backend::backends_path(home), serde_json::to_vec(&backends).unwrap()).unwrap();
    }

    #[test]
    fn put_on_an_unknown_secret_is_denied_and_never_invokes_a_backend() {
        let home = tmp_home("put-unknown");
        seed(&home, &[]);
        let (granted, result) = put_gate(&home, "nope", "irrelevant");
        assert!(!granted);
        assert_eq!(result.unwrap_err(), "secret not found");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn put_on_a_backend_with_no_set_template_is_a_clean_error() {
        let home = tmp_home("put-noset");
        let p = Policy::new("t", "scratch", "k");
        seed(&home, &[p]); // `seed`'s fixture backend has only `get`.
        let (granted, result) = put_gate(&home, "t", "irrelevant");
        assert!(!granted);
        assert!(result.unwrap_err().contains("no `set` template"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_granted_put_writes_through_the_named_backends_set_template() {
        let home = tmp_home("put-granted");
        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        let (granted, result) = put_gate(&home, "t", "the-stored-value");
        assert!(granted, "{result:?}");
        assert!(result.is_ok());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "the-stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// `put` never checks `requireTotp` — even a policy with it set is
    /// storable without any code at all (module doc: put is CLI-only/
    /// admin-side, not agent-facing).
    #[test]
    fn put_ignores_require_totp_entirely() {
        let home = tmp_home("put-ignorestotp");
        let out = home.join("out.txt");
        let mut p = Policy::new("t", "scratch", "k");
        p.require_totp = true;
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        let (granted, result) = put_gate(&home, "t", "value-with-no-totp-anywhere");
        assert!(granted, "{result:?}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "value-with-no-totp-anywhere");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_full_put_line_round_trips_through_handle_line_with_no_value_in_the_reply() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("put-fullline");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        let out = home.join("out.txt");
        let p = Policy::new("t", "scratch", "k");
        seed_with_set(&home, &[p], &format!("cat {}", out.display()), &format!("cat > {}", out.display()));

        let reply = handle_line(&home, r#"{"op":"put","secret":"t","value":"stored-value"}"#);
        assert_eq!(reply["ok"], true);
        assert!(reply.get("value").is_none(), "put's reply must never carry a value: {reply}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "stored-value");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn put_with_a_missing_secret_field_is_malformed() {
        let home = tmp_home("put-missingfields");
        let reply = handle_line(&home, r#"{"op":"put","value":"x"}"#);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("required"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// The sentinel test (P-V4c phase brief): a put of a sentinel value,
    /// forced through BOTH failure paths (missing policy, missing `set`
    /// template), must leave the sentinel out of the wire reply AND both
    /// audit logs on every single attempt.
    #[test]
    fn put_sentinel_value_never_leaks_on_missing_policy_or_missing_set_template() {
        const SENTINEL: &str = "SENTINEL-PUT-VALUE-XYZ";
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_AUDIT_LOG").ok();
        let home = tmp_home("put-sentinel");
        std::env::set_var("AOIDE_AUDIT_LOG", home.join("mirrored-aoide-log"));

        // ── failure 1: no policy at all for this secret ────────────────
        seed(&home, &[]);
        let reply = handle_line(&home, &format!(r#"{{"op":"put","secret":"nope","value":"{SENTINEL}"}}"#));
        assert_eq!(reply["ok"], false);
        assert!(!reply.to_string().contains(SENTINEL), "wire reply leaked the sentinel: {reply}");

        // ── failure 2: policy exists, but its backend has no `set` ─────
        let p = Policy::new("t", "scratch", "k");
        seed(&home, &[p]); // `seed`'s fixture backend is get-only.
        let reply = handle_line(&home, &format!(r#"{{"op":"put","secret":"t","value":"{SENTINEL}"}}"#));
        assert_eq!(reply["ok"], false);
        assert!(!reply.to_string().contains(SENTINEL), "wire reply leaked the sentinel: {reply}");

        let own_log = std::fs::read_to_string(own_audit_log_path(&home)).unwrap();
        assert!(!own_log.contains(SENTINEL), "the broker's own audit.log leaked the sentinel:\n{own_log}");
        assert!(own_log.contains("\"op\":\"put\""), "{own_log}");

        let mirrored_log = std::fs::read_to_string(home.join("mirrored-aoide-log")).unwrap();
        assert!(!mirrored_log.contains(SENTINEL), "mirrored aoide audit log leaked the sentinel:\n{mirrored_log}");

        match saved {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        std::fs::remove_dir_all(&home).ok();
    }

}
