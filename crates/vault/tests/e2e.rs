//! End-to-end broker + client round-trip (P-V2 gate, the phase brief's
//! item 6): a scratch vault home, a fake backend (`printf`, no real
//! `pass`/`gpg`), a policy granting one consumer, a broker bound to a
//! SHORT `/tmp`-direct socket path (the SUN_LEN hazard is real in this
//! sandbox — a nested tempdir can overflow `sockaddr_un`'s ~108-byte
//! `sun_path` before the socket filename is even appended), and a client
//! that resolves the secret into a spawned child's real env.
//!
//! Also proves: the three denied paths (unknown secret, wrong consumer,
//! `requireTotp` with no enrollment), that BOTH audit logs (vault's own
//! `audit.log` in vault home, and the mirrored aoide log via
//! `EventClass::Secret`) are value-free, and that the granted line's audit
//! carries `"granted":true` without the value ever appearing anywhere in
//! either file.
//!
//! **Why the child writes to a file instead of the test reading its
//! stdout**: `aoide_vault::client::run_exec` uses `Stdio::inherit()`
//! throughout, by design (this crate's `AGENTS.md` — aoide never holds a
//! wrapped command's bytes). That means the child's stdout goes to
//! WHATEVER this test process's own stdout is, which `cargo test` doesn't
//! hand back programmatically. Rather than add a test-only capturing
//! branch to `run_exec` (which would test something production code never
//! does), the wrapped command itself is `sh -c "printenv VAR > file"` — the
//! CHILD redirects its own fd 1 to a file via its own shell, which works
//! identically regardless of what `run_exec` set the inherited fd to. This
//! exercises the real, unmodified `run_exec`/`Stdio::inherit()` path.

use aoide_vault::{backend, broker, client, home, policy::Policy, store};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A short path directly under `/tmp` — NOT `std::env::temp_dir()`, which
/// under a sandboxed `$TMPDIR` can already be a long nested path (module
/// doc's SUN_LEN concern).
fn short_tmp(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    PathBuf::from(format!("/tmp/av-{tag}-{}-{nanos}", std::process::id()))
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    std::fs::File::open(path).unwrap().read_to_string(&mut s).unwrap();
    s
}

#[test]
fn end_to_end_resolve_denies_and_grants_env_round_trip() {
    let vault_home = short_tmp("home");
    std::fs::create_dir_all(&vault_home).unwrap();
    let socket_path = PathBuf::from(format!("{}.sock", short_tmp("sock").display()));
    // The mirrored aoide audit log — its own tempfile, so this test never
    // touches the real `~/Aoide/log`.
    let aoide_log = vault_home.join("mirrored-aoide-log");
    std::env::set_var("AOIDE_AUDIT_LOG", &aoide_log);

    // ── seed the vault home ─────────────────────────────────────────────
    std::fs::write(
        backend::backends_path(&vault_home),
        serde_json::to_vec(&serde_json::json!({ "scratch": { "get": "printf %s {name}" } })).unwrap(),
    )
    .unwrap();

    let mut granted_policy = Policy::new("t", "scratch", "stored-value");
    granted_policy.consumers = vec!["m".to_string()];
    let mut totp_policy = Policy::new("locked", "scratch", "irrelevant");
    totp_policy.require_totp = true;
    store::save_policies(&vault_home, &[granted_policy, totp_policy]).unwrap();

    // ── spin up the broker ──────────────────────────────────────────────
    let home_for_thread = vault_home.clone();
    let sock_for_thread = socket_path.clone();
    let broker_thread = std::thread::spawn(move || {
        let _ = broker::serve(&home_for_thread, &sock_for_thread);
    });

    // Poll-connect rather than a blind sleep: bind happens fast, but give
    // it a bounded number of short retries.
    let mut connected = false;
    for _ in 0..50 {
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(connected, "broker did not bind {} in time", socket_path.display());

    // ── denied: unknown secret ──────────────────────────────────────────
    let err = client::resolve(&socket_path, "nope", "m", None, None).unwrap_err();
    assert_eq!(err, "secret not found");

    // ── denied: consumer not in the policy's list ───────────────────────
    let err = client::resolve(&socket_path, "t", "someone-else", None, None).unwrap_err();
    assert!(err.contains("not authorized"), "{err}");

    // ── denied: requireTotp with no enrollment on this host ────────────
    let err = client::resolve(&socket_path, "locked", "m", Some("123456"), None).unwrap_err();
    assert!(err.contains("no TOTP enrollment"), "{err}");

    // ── granted: resolve() round-trips the value directly ──────────────
    let value = client::resolve(&socket_path, "t", "m", None, Some("printenv")).unwrap();
    assert_eq!(value, "stored-value");

    // ── granted: the value round-trips into a REAL child's env, through
    //    the unmodified `run_exec`/Stdio::inherit() production path ─────
    let out_file = vault_home.join("child-env-output");
    let inv = aoide_protocol::Invocation {
        path: vec!["vault".to_string(), "exec".to_string()],
        args: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printenv T > {}", out_file.display()),
        ],
        flags: {
            let mut f = std::collections::BTreeMap::new();
            f.insert("as".to_string(), "m".to_string());
            f.insert("secret".to_string(), "t:T".to_string());
            f
        },
        door: aoide_protocol::Door::Cli,
    };
    let code = client::run_exec(&inv, &socket_path);
    assert_eq!(code, 0, "run_exec should exit with the child's own (successful) status");
    assert_eq!(read_to_string(&out_file).trim_end(), "stored-value");

    // ── both audit logs are value-free, and the granted line says so ───
    let own_log = std::fs::read_to_string(vault_home.join("audit.log")).unwrap();
    assert!(!own_log.contains("stored-value"), "vault's own audit log leaked the value:\n{own_log}");
    assert!(own_log.contains("\"granted\":true"), "{own_log}");
    assert!(own_log.contains("\"granted\":false"), "{own_log}");
    assert!(own_log.contains("\"secret\":\"t\""), "{own_log}");
    assert!(own_log.contains("\"argv0\":\"printenv\""), "{own_log}");

    let mirrored_log = std::fs::read_to_string(&aoide_log).unwrap();
    assert!(
        !mirrored_log.contains("stored-value"),
        "the mirrored aoide audit log leaked the value:\n{mirrored_log}"
    );
    for line in mirrored_log.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        if v["class"] == "secret" {
            assert!(v.get("untrusted_data").is_none(), "Secret event carried untrusted_data: {line}");
        }
    }
    assert!(mirrored_log.contains("\"class\":\"secret\""), "{mirrored_log}");

    // ── cleanup ──────────────────────────────────────────────────────────
    drop(broker_thread); // the process exiting tears the thread down; serve() never returns cleanly
    std::env::remove_var("AOIDE_AUDIT_LOG");
    std::fs::remove_dir_all(&vault_home).ok();
    std::fs::remove_file(&socket_path).ok();
}

/// `home::vault_home`'s env-override half, proven ONE more time at the
/// integration-test level (unit tests already cover it inside the crate)
/// — cheap, and this file is the only integration-test binary that could
/// plausibly also want to exercise it against a real `vault add` flow
/// later. Does not touch the shared crate-internal `env_lock` (a separate
/// OS process from the lib's own unit tests, so no race is possible).
#[test]
fn vault_home_resolves_through_the_env_override() {
    let dir = short_tmp("home-override");
    std::env::set_var("AOIDE_VAULT_HOME", &dir);
    assert_eq!(home::vault_home(), dir);
    std::env::remove_var("AOIDE_VAULT_HOME");
}
