//! End-to-end broker + client round-trip (P-V2 gate, the phase brief's
//! item 6): a scratch secrets home, a fake backend (`printf`, no real
//! `pass`/`gpg`), a policy granting one consumer, a broker bound to a
//! SHORT `/tmp`-direct socket path (the SUN_LEN hazard is real in this
//! sandbox — a nested tempdir can overflow `sockaddr_un`'s ~108-byte
//! `sun_path` before the socket filename is even appended), and a client
//! that resolves the secret into a spawned child's real env.
//!
//! Also proves: the three denied paths (unknown secret, wrong consumer,
//! `requireTotp` with no enrollment), that BOTH audit logs (the broker's own
//! `audit.log` in secrets home, and the mirrored aoide log via
//! `EventClass::Secret`) are value-free, and that the granted line's audit
//! carries `"granted":true` without the value ever appearing anywhere in
//! either file.
//!
//! **Denial marker check** (bounce-fix item 5, P-V2 review): the earlier
//! revision of this test only checked the returned error STRING for each
//! denied path, never whether the backend was actually invoked — a broker
//! bug that ran the backend anyway and then discarded the value would have
//! passed silently. The scratch backend's template now `touch`es a marker
//! file before its `printf`; each denial asserts the marker is ABSENT
//! afterward, proving `resolve_gate` short-circuits BEFORE ever touching
//! the backend, and the granted path asserts the marker IS present as a
//! positive control on the mechanism itself.
//!
//! **Why the child writes to a file instead of the test reading its
//! stdout**: `aoide_secrets::client::run_exec` uses `Stdio::inherit()`
//! throughout, by design (this crate's `AGENTS.md` — aoide never holds a
//! wrapped command's bytes). That means the child's stdout goes to
//! WHATEVER this test process's own stdout is, which `cargo test` doesn't
//! hand back programmatically. Rather than add a test-only capturing
//! branch to `run_exec` (which would test something production code never
//! does), the wrapped command itself is `sh -c "printenv VAR > file"` — the
//! CHILD redirects its own fd 1 to a file via its own shell, which works
//! identically regardless of what `run_exec` set the inherited fd to. This
//! exercises the real, unmodified `run_exec`/`Stdio::inherit()` path.

use aoide_secrets::{backend, broker, client, home, policy::Policy, store};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `cargo test` runs every `#[test]` fn in this binary concurrently by
/// default, but `AOIDE_AUDIT_LOG` is process-global — a test setting it to
/// its own scratch path would otherwise race any OTHER test in this file
/// doing the same (P-V4c added two more real-broker tests alongside the
/// original P-V2 one, which is what surfaced this). Every test below that
/// touches `AOIDE_AUDIT_LOG` holds this lock for its whole body, same
/// discipline as the lib's own `env_lock()` (not usable here — it is
/// `pub(crate)` to the lib, and this file is a separate integration-test
/// crate).
fn audit_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

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
    let _guard = audit_env_lock().lock().unwrap();
    let secrets_home = short_tmp("home");
    std::fs::create_dir_all(&secrets_home).unwrap();
    let socket_path = PathBuf::from(format!("{}.sock", short_tmp("sock").display()));
    // The mirrored aoide audit log — its own tempfile, so this test never
    // touches the real `~/Aoide/log`.
    let aoide_log = secrets_home.join("mirrored-aoide-log");
    std::env::set_var("AOIDE_AUDIT_LOG", &aoide_log);

    // ── seed the secrets home ─────────────────────────────────────────────
    // `touch`es a marker before its `printf` — proves whether the backend
    // was actually run, not just what the resolve returned (module doc).
    let marker_path = secrets_home.join("backend-invoked-marker");
    std::fs::write(
        backend::backends_path(&secrets_home),
        serde_json::to_vec(&serde_json::json!({
            "scratch": { "get": format!("touch {} && printf %s {{name}}", marker_path.display()) }
        }))
        .unwrap(),
    )
    .unwrap();

    let mut granted_policy = Policy::new("t", "scratch", "stored-value");
    granted_policy.consumers = vec!["m".to_string()];
    let mut totp_policy = Policy::new("locked", "scratch", "irrelevant");
    totp_policy.require_totp = true;
    store::save_policies(&secrets_home, &[granted_policy, totp_policy]).unwrap();

    // ── spin up the broker ──────────────────────────────────────────────
    let home_for_thread = secrets_home.clone();
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
    assert!(!marker_path.exists(), "backend was invoked for a denied (unknown secret) resolve");

    // ── denied: consumer not in the policy's list ───────────────────────
    let err = client::resolve(&socket_path, "t", "someone-else", None, None).unwrap_err();
    assert!(err.contains("not authorized"), "{err}");
    assert!(!marker_path.exists(), "backend was invoked for a denied (wrong consumer) resolve");

    // ── denied: requireTotp with no enrollment on this host ────────────
    let err = client::resolve(&socket_path, "locked", "m", Some("123456"), None).unwrap_err();
    assert!(err.contains("no TOTP enrollment"), "{err}");
    assert!(!marker_path.exists(), "backend was invoked for a denied (requireTotp) resolve");

    // ── granted: resolve() round-trips the value directly ──────────────
    let value = client::resolve(&socket_path, "t", "m", None, Some("printenv")).unwrap();
    assert_eq!(value, "stored-value");
    assert!(marker_path.exists(), "positive control: the backend must run on a granted resolve");

    // ── granted: the value round-trips into a REAL child's env, through
    //    the unmodified `run_exec`/Stdio::inherit() production path ─────
    let out_file = secrets_home.join("child-env-output");
    let inv = aoide_protocol::Invocation {
        path: vec!["secrets".to_string(), "exec".to_string()],
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
    let own_log = std::fs::read_to_string(secrets_home.join("audit.log")).unwrap();
    assert!(!own_log.contains("stored-value"), "the broker's own audit log leaked the value:\n{own_log}");
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
    std::fs::remove_dir_all(&secrets_home).ok();
    std::fs::remove_file(&socket_path).ok();
}

/// `put`/`get` round trip through the REAL socket, against the SEEDED
/// built-in `file` backend (P-V4c) — nothing here hand-writes
/// `backends.json`; `broker::serve`'s own startup seeding
/// (`backend::seed_default_backends`) is what puts the `file` backend
/// there, proving the seeding site works end-to-end, not merely in
/// isolation.
#[test]
fn put_then_get_round_trips_through_the_real_socket_with_the_seeded_file_backend() {
    let _guard = audit_env_lock().lock().unwrap();
    let secrets_home = short_tmp("puthome");
    std::fs::create_dir_all(&secrets_home).unwrap();
    let socket_path = PathBuf::from(format!("{}.sock", short_tmp("putsock").display()));
    let aoide_log = secrets_home.join("mirrored-aoide-log");
    std::env::set_var("AOIDE_AUDIT_LOG", &aoide_log);

    // Deliberately NO `backends.json` written here — `broker::serve`
    // startup must seed the `file` backend itself.
    let mut policy = Policy::new("filed", "file", "filed-key");
    policy.consumers = vec!["m".to_string()];
    store::save_policies(&secrets_home, &[policy]).unwrap();

    let home_for_thread = secrets_home.clone();
    let sock_for_thread = socket_path.clone();
    let broker_thread = std::thread::spawn(move || {
        let _ = broker::serve(&home_for_thread, &sock_for_thread);
    });

    let mut connected = false;
    for _ in 0..50 {
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(connected, "broker did not bind {} in time", socket_path.display());

    // ── put ──────────────────────────────────────────────────────────
    client::put(&socket_path, "filed", "sentinel-put-value").unwrap();

    // The seeded `file` backend's contract: 0600 file under a 0700 store
    // dir, named after the POLICY's `key` (not the secret's own name).
    let store_dir = secrets_home.join("store");
    let stored_file = store_dir.join("filed-key");
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = std::fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "store dir must be 0700, got {dir_mode:o}");
        let file_mode = std::fs::metadata(&stored_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "stored secret file must be 0600, got {file_mode:o}");
    }
    assert_eq!(read_to_string(&stored_file), "sentinel-put-value");

    // ── get: the SAME value comes back through resolve() ───────────────
    let value = client::resolve(&socket_path, "filed", "m", None, None).unwrap();
    assert_eq!(value, "sentinel-put-value");

    // ── overwrite: a second put replaces the value wholesale ───────────
    client::put(&socket_path, "filed", "second-value").unwrap();
    assert_eq!(client::resolve(&socket_path, "filed", "m", None, None).unwrap(), "second-value");

    // ── neither audit log ever carries the value ────────────────────────
    let own_log = std::fs::read_to_string(secrets_home.join("audit.log")).unwrap();
    assert!(!own_log.contains("sentinel-put-value"), "the broker's own audit log leaked the put value:\n{own_log}");
    assert!(!own_log.contains("second-value"), "the broker's own audit log leaked the put value:\n{own_log}");
    assert!(own_log.contains("\"op\":\"put\""), "{own_log}");

    let mirrored_log = std::fs::read_to_string(&aoide_log).unwrap();
    assert!(
        !mirrored_log.contains("sentinel-put-value") && !mirrored_log.contains("second-value"),
        "the mirrored aoide audit log leaked the put value:\n{mirrored_log}"
    );

    drop(broker_thread);
    std::env::remove_var("AOIDE_AUDIT_LOG");
    std::fs::remove_dir_all(&secrets_home).ok();
    std::fs::remove_file(&socket_path).ok();
}

/// The rider (parked P-V3 review nit, folded into P-V4c): a GRANTED
/// `requireTotp` resolve through the REAL socket, not merely
/// `broker::resolve_gate` in isolation — enroll a secret into a scratch
/// home via `store` functions directly, compute the code with the `totp`
/// module at the CURRENT time (timestep computed first, then the code
/// derived for exactly that captured step — never re-reading the clock a
/// second time, which could straddle a 30s boundary between computing the
/// code and the request actually landing), assert the grant AND the
/// backend marker, then the SAME code again denied (replay) — also
/// through the real socket, not the pure `resolve_gate` function.
#[test]
fn end_to_end_requiretotp_resolve_grants_then_denies_replay_through_the_socket() {
    let _guard = audit_env_lock().lock().unwrap();
    let secrets_home = short_tmp("totphome");
    std::fs::create_dir_all(&secrets_home).unwrap();
    let socket_path = PathBuf::from(format!("{}.sock", short_tmp("totpsock").display()));
    let aoide_log = secrets_home.join("mirrored-aoide-log");
    std::env::set_var("AOIDE_AUDIT_LOG", &aoide_log);

    let marker_path = secrets_home.join("backend-invoked-marker");
    std::fs::write(
        backend::backends_path(&secrets_home),
        serde_json::to_vec(&serde_json::json!({
            "scratch": { "get": format!("touch {} && printf %s {{name}}", marker_path.display()) }
        }))
        .unwrap(),
    )
    .unwrap();

    let mut policy = Policy::new("locked", "scratch", "stored-value");
    policy.require_totp = true;
    store::save_policies(&secrets_home, &[policy]).unwrap();

    // Enroll this scratch host directly via `store` (no `secrets enroll`
    // CLI flow needed for this test).
    let totp_secret = b"a-twenty-byte-totp-s".to_vec();
    assert_eq!(totp_secret.len(), 20);
    store::save_totp_secret(&secrets_home, &totp_secret).unwrap();

    let home_for_thread = secrets_home.clone();
    let sock_for_thread = socket_path.clone();
    let broker_thread = std::thread::spawn(move || {
        let _ = broker::serve(&home_for_thread, &sock_for_thread);
    });

    let mut connected = false;
    for _ in 0..50 {
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(connected, "broker did not bind {} in time", socket_path.display());

    // Timestep computed FIRST, then the code derived for exactly that
    // step — dodges a boundary flake between computing the code and the
    // resolve actually reaching the broker's own clock read.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let step = aoide_secrets::totp::timestep(now);
    let code = aoide_secrets::totp::format6(aoide_secrets::totp::hotp(&totp_secret, step, aoide_secrets::totp::DIGITS));

    // ── granted ──────────────────────────────────────────────────────
    let value = client::resolve(&socket_path, "locked", "m", Some(&code), None).unwrap();
    assert_eq!(value, "stored-value");
    assert!(marker_path.exists(), "positive control: the backend must run on a granted requireTotp resolve");
    std::fs::remove_file(&marker_path).unwrap();

    // ── the SAME code again: denied (replay), backend not re-invoked ──
    let err = client::resolve(&socket_path, "locked", "m", Some(&code), None).unwrap_err();
    assert!(err.contains("already used"), "{err}");
    assert!(!marker_path.exists(), "backend was invoked again on a replayed code");

    let own_log = std::fs::read_to_string(secrets_home.join("audit.log")).unwrap();
    assert!(!own_log.contains("stored-value"), "the broker's own audit log leaked the value:\n{own_log}");
    assert!(!own_log.contains(&code), "the broker's own audit log leaked the totp code:\n{own_log}");

    drop(broker_thread);
    std::env::remove_var("AOIDE_AUDIT_LOG");
    std::fs::remove_dir_all(&secrets_home).ok();
    std::fs::remove_file(&socket_path).ok();
}

/// `home::secrets_home`'s env-override half, proven ONE more time at the
/// integration-test level (unit tests already cover it inside the crate)
/// — cheap, and this file is the only integration-test binary that could
/// plausibly also want to exercise it against a real `secrets add` flow
/// later. Does not touch the shared crate-internal `env_lock` (a separate
/// OS process from the lib's own unit tests, so no race is possible).
#[test]
fn secrets_home_resolves_through_the_env_override() {
    let dir = short_tmp("home-override");
    std::env::set_var("AOIDE_SECRETS_HOME", &dir);
    assert_eq!(home::secrets_home(), dir);
    std::env::remove_var("AOIDE_SECRETS_HOME");
}
