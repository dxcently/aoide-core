//! `secrets enroll`: the full TOTP-enrollment flow (P-V3), called from
//! `aoide-cli`'s `special` hook exactly the way `broker::serve`/
//! `client::run_exec` already are (`aoide-protocol`'s own `AGENTS.md`:
//! "`door::run`'s `special` hook is the only sanctioned one-shot escape"
//! from the generic `Outcome` envelope) — `commands::handle_secrets_enroll`
//! only gates the door and records the launch, [`run`] does everything
//! else, including printing the secret DIRECTLY to stdout. That split
//! exists for the same reason `serve`/`exec` are split the way they are:
//! a secret's value must never land on a `Serialize` type (this crate's
//! `AGENTS.md`), and `Outcome` is one.
//!
//! Widens this crate's I/O boundary (`AGENTS.md`'s "I/O is confined to
//! five named modules") to six: this module owns random-secret generation
//! (`/dev/urandom`), the local hostname (`libc::gethostname`, same
//! precedent as `aoide_storage::display::local_host_name` — see
//! `Cargo.toml`'s comment for why this crate repeats rather than depends
//! on it), and the `qrencode` shell-out. Secrets-home file persistence
//! itself stays `store`'s job ([`store::save_totp_secret`]/
//! [`store::save_replay_ledger`]) — this module never writes a secrets-home
//! file directly.
//!
//! **[`show`] (P-V4e) is `run`'s read-only sibling**: `secrets enroll
//! --show` reprints an EXISTING enrollment's URI/base32/QR through the
//! same [`print_enrollment`] tail `run` uses, but calls neither
//! `generate_secret` nor `store::save_totp_secret`/`save_replay_ledger` —
//! there is nothing in it that could rotate anything. `commands::
//! handle_secrets_enroll` rejects `--force`+`--show` together as a usage
//! error before either reaches `cli`'s `special` hook, which dispatches to
//! `run` or `show` from the SAME `["secrets", "enroll"]` arm (no second
//! arm — see that hook's own comment).

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// TOTP secret length in bytes: 20 (160 bits) — RFC 4226 §4's recommended
/// HOTP/TOTP key size for SHA-1, this crate's whole hand-rolled stack
/// (`totp.rs`'s module doc).
pub const SECRET_LEN: usize = 20;

/// A fresh random TOTP secret: `SECRET_LEN` bytes read from `/dev/urandom`
/// — zero new deps (the phase brief's own constraint: no `rand`/`getrandom`
/// crate). `/dev/urandom` never blocks on Linux once the kernel's CSPRNG is
/// seeded (true well before userspace runs) — the standard justification
/// for reading it directly rather than `/dev/random`.
pub fn generate_secret() -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; SECRET_LEN];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

/// This host's name for the enrollment's `otpauth://` label — the OS
/// hostname via `libc::gethostname`, mirroring `aoide_storage::display::
/// local_host_name`'s own call (module doc: this crate stays off
/// `aoide-storage` on purpose, so the short call is repeated here rather
/// than reached for, same as `policy::valid_secret_name`'s precedent).
/// Falls back to the literal `"host"` on any failure — never panics, never
/// blocks an enrollment on a hostname syscall going sideways.
pub fn local_hostname() -> String {
    let mut buf = vec![0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "host".to_string();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if s.is_empty() {
        "host".to_string()
    } else {
        s
    }
}

/// Render `uri` as an ANSI-UTF8 QR code by shelling out to `qrencode -t
/// ANSIUTF8`, feeding the URI over STDIN — never argv (argv is
/// world-readable via `/proc/<pid>/cmdline` on Linux, and the URI carries
/// the secret). `None` whenever `qrencode` isn't reachable on `PATH` or
/// fails to run — feature-detected by the spawn itself failing, never an
/// error: a QR code is a convenience, the URI + base32 secret printed
/// alongside it ([`run`]) are the actual point of the command.
pub fn render_qr(uri: &str) -> Option<String> {
    let mut child = Command::new("qrencode")
        .args(["-t", "ANSIUTF8"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(uri.as_bytes()).ok()?;
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// The `(otpauth:// URI, base32 secret)` pair `run`/`show` both print — a
/// pure formatting split-out (module doc's I/O-boundary widening note),
/// so a test can assert on the exact text either path would print without
/// capturing this process's real stdout (there is no precedent for that in
/// this crate's tests, and OS-level stdout capture is fragile across
/// `cargo test`'s parallel test threads).
fn enrollment_text(secret: &[u8]) -> (String, String) {
    let hostname = local_hostname();
    let uri = crate::uri::totp_uri(&hostname, "aoide-secrets", secret);
    let secret_b32 = crate::base32::encode(secret);
    (uri, secret_b32)
}

/// Print an enrollment's URI + base32 + QR (or the qrencode-absent hint) —
/// the shared tail of `run` and [`show`]: identical output shape, whether
/// the secret behind it is freshly generated or an existing one being
/// reprinted.
fn print_enrollment(secret: &[u8]) {
    let (uri, secret_b32) = enrollment_text(secret);
    println!("{uri}");
    println!("secret (base32): {secret_b32}");
    match render_qr(&uri) {
        Some(qr) => println!("{qr}"),
        None => println!(
            "(qrencode not found on PATH — scan the URI above by hand, or install qrencode for a QR code)"
        ),
    }
}

/// The full `secrets enroll` flow. ONE enrollment per host: an existing
/// `totp.secret` is left untouched unless `force` is set, in which case
/// the OLD secret AND its replay ledger are both replaced — a stale
/// "already used" timestep from before a re-enrollment must never shadow
/// a legitimate fresh code from the NEW secret (timesteps are wall-clock-
/// derived, independent of which secret produced the code that consumed
/// one; see `store.rs`'s module doc).
///
/// Prints the `otpauth://` URI and the base32 secret DIRECTLY to stdout —
/// never through an `Outcome`/JSON envelope (module doc) — and a QR code
/// too when `qrencode` is reachable ([`render_qr`]'s feature-detect; its
/// absence is a one-line hint, never an error).
///
/// Carries the SAME admin-identity guard as `commands::require_admin_identity`
/// (`home::admin_identity_check`'s module doc — the yomi-strix incident,
/// 2026-08-22): checked FIRST, before even the existing-enrollment read,
/// because `run`'s actual work happens from `cli`'s `special` hook rather
/// than through `commands::handle_secrets_enroll`'s own dispatch, so this
/// is the one place in the write path that can enforce it. [`show`] does
/// NOT carry this guard — it rotates nothing, so a wrong-uid caller has
/// nothing to corrupt, only an ordinary permission error to hit on the
/// read.
pub fn run(secrets_home: &Path, force: bool) -> Result<(), String> {
    if let Some(msg) = crate::home::admin_identity_check(secrets_home, "enroll") {
        return Err(msg);
    }
    match crate::store::load_totp_secret(secrets_home) {
        Ok(Some(_)) if !force => {
            return Err(
                "TOTP is already enrolled on this host — pass --force to regenerate \
                 (old codes stop working immediately)"
                    .to_string(),
            );
        }
        Ok(_) => {}
        Err(e) => {
            return Err(crate::home::describe_home_file_error(
                secrets_home,
                &crate::store::totp_secret_path(secrets_home),
                &e,
            ))
        }
    }

    let secret = generate_secret().map_err(|e| format!("generating a secret: {e}"))?;
    crate::store::save_totp_secret(secrets_home, &secret).map_err(|e| {
        crate::home::describe_home_file_error(secrets_home, &crate::store::totp_secret_path(secrets_home), &e)
    })?;
    // Re-enrollment resets the ledger too — see module/function doc.
    crate::store::save_replay_ledger(secrets_home, &crate::replay::ReplayLedger::new()).map_err(|e| {
        crate::home::describe_home_file_error(secrets_home, &crate::store::replay_ledger_path(secrets_home), &e)
    })?;

    print_enrollment(&secret);
    if force {
        println!("re-enrolled: the previous secret and every consumed code are now invalid.");
    }
    Ok(())
}

/// `secrets enroll --show` (P-V4e): reprint the EXISTING enrollment's URI +
/// base32 + QR through the exact same [`print_enrollment`] path `run`
/// uses, WITHOUT generating, persisting, or touching anything — no
/// `store::save_totp_secret`/`save_replay_ledger` call anywhere in this
/// function, by construction (there is nothing here for it to call). Errors
/// cleanly when no enrollment exists yet rather than silently enrolling one
/// — that would be exactly the surprise rotation `--show` exists to let a
/// caller avoid.
pub fn show(secrets_home: &Path) -> Result<(), String> {
    let secret = match crate::store::load_totp_secret(secrets_home) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Err("no TOTP enrollment on this host yet — run `secrets enroll` first".to_string())
        }
        Err(e) => {
            return Err(crate::home::describe_home_file_error(
                secrets_home,
                &crate::store::totp_secret_path(secrets_home),
                &e,
            ))
        }
    };
    print_enrollment(&secret);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_returns_the_expected_length() {
        let secret = generate_secret().unwrap();
        assert_eq!(secret.len(), SECRET_LEN);
    }

    #[test]
    fn generate_secret_is_not_the_same_bytes_twice() {
        // Not a rigorous randomness test — just a sanity check that this
        // isn't reading a fixed/zeroed buffer.
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn local_hostname_is_never_empty() {
        // Best-effort chain (env-free here, unlike `aoide_storage::display`
        // — this fn has no env override, only the syscall-or-"host"
        // fallback), so the only universal assertion is non-emptiness.
        assert!(!local_hostname().is_empty());
    }

    #[test]
    fn render_qr_returns_none_when_qrencode_is_absent_from_path() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved_path = std::env::var("PATH").ok();
        std::env::set_var("PATH", "/nonexistent-dir-for-aoide-secrets-test");
        assert_eq!(render_qr("otpauth://totp/x"), None);
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
    }

    /// Positive control, via a fake `qrencode` shim script on `PATH` (no
    /// real `qrencode` binary required — phase brief: "the presence branch
    /// may be tested with a fake shim script on PATH in a tempdir if
    /// cheap"). Proves the URI is fed over STDIN (the shim reads it and
    /// discards it) and the shim's stdout is what `render_qr` returns.
    #[test]
    fn render_qr_returns_the_shim_output_when_qrencode_is_present() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-enroll-test-qrshim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("qrencode");
        std::fs::write(&shim, "#!/bin/sh\ncat > /dev/null\necho FAKE-QR-OUTPUT\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let saved_path = std::env::var("PATH").ok();
        let new_path = format!("{}:{}", dir.display(), saved_path.clone().unwrap_or_default());
        std::env::set_var("PATH", &new_path);

        let out = render_qr("otpauth://totp/x");

        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(out.as_deref(), Some("FAKE-QR-OUTPUT\n"));
    }

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-enroll-run-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn run_writes_a_fresh_secret_and_a_reset_ledger() {
        let home = tmp_home("fresh");
        run(&home, false).unwrap();
        let secret = crate::store::load_totp_secret(&home).unwrap();
        assert_eq!(secret.map(|s| s.len()), Some(SECRET_LEN));
        assert!(crate::store::load_replay_ledger(&home).unwrap().is_empty());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn run_without_force_refuses_a_second_enrollment() {
        let home = tmp_home("double");
        run(&home, false).unwrap();
        let first = crate::store::load_totp_secret(&home).unwrap();
        let err = run(&home, false).unwrap_err();
        assert!(err.contains("already enrolled"), "{err}");
        assert_eq!(crate::store::load_totp_secret(&home).unwrap(), first, "a refused re-enroll must not change the secret");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn run_with_force_regenerates_the_secret_and_resets_a_nonempty_ledger() {
        let home = tmp_home("force");
        run(&home, false).unwrap();
        let first = crate::store::load_totp_secret(&home).unwrap();

        // Seed a spent timestep as if a resolve had consumed one under the
        // OLD secret.
        let mut ledger = crate::replay::ReplayLedger::new();
        ledger.record(4242);
        crate::store::save_replay_ledger(&home, &ledger).unwrap();

        run(&home, true).unwrap();
        let second = crate::store::load_totp_secret(&home).unwrap();
        assert_ne!(first, second, "--force must regenerate the secret");
        assert!(
            crate::store::load_replay_ledger(&home).unwrap().is_empty(),
            "--force must reset the replay ledger too — a stale spent timestep must not survive re-enrollment"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    // ── show (P-V4e) ─────────────────────────────────────────────────────

    #[test]
    fn show_reprints_the_seeded_secrets_uri_and_rotates_nothing() {
        let home = tmp_home("show");
        run(&home, false).unwrap();
        let secret_path = crate::store::totp_secret_path(&home);
        let bytes_before = std::fs::read(&secret_path).unwrap();
        let seeded = crate::store::load_totp_secret(&home).unwrap().unwrap();

        show(&home).unwrap();

        // Byte-identical, not merely value-equal — `show` must not even
        // rewrite the file (mtime/formatting included).
        let bytes_after = std::fs::read(&secret_path).unwrap();
        assert_eq!(bytes_before, bytes_after, "show must not touch totp.secret at all");
        let after = crate::store::load_totp_secret(&home).unwrap().unwrap();
        assert_eq!(seeded, after, "show must never rotate the secret");

        // Same secret in, same URI/base32 text out.
        assert_eq!(enrollment_text(&seeded), enrollment_text(&after));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn show_without_an_existing_enrollment_errors_cleanly() {
        let home = tmp_home("show-none");
        let err = show(&home).unwrap_err();
        assert!(err.contains("no TOTP enrollment"), "{err}");
        std::fs::remove_dir_all(&home).ok();
    }
}
