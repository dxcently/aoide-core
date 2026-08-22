//! The secrets home: the directory holding `policy.json`, `backends.json`,
//! the broker's own append-only `audit.log`, and (later phases) the TOTP
//! secret + replay ledger. **One function** — every other module in this
//! crate reaches the secrets home through [`secrets_home`], never re-derives
//! it (the phase brief's own wording).
//!
//! Nix-independent: no nix shell-out, no NixOS assumption anywhere in this
//! module (root `AGENTS.md`'s HARD CONSTRAINT — core, and the secrets broker
//! with it, must build with cargo and run on any Linux).
//!
//! **The default is a placeholder, not yet the deployed reality.** P-V4
//! (deployment) is what actually provisions `/var/lib/aoide-secrets`,
//! chowned to a real `aoide-secrets` system user, via a nix module +
//! tmpfiles rule — until then, this default exists so the code has a
//! concrete answer, and the OWNER is whatever ordinary uid runs `secrets
//! serve`/`secrets add` first. Set `AOIDE_SECRETS_SOCKET`/`AOIDE_SECRETS_HOME`
//! to a writable directory (a tempdir in every test here, or a dev
//! directory by hand) on any host that hasn't run P-V4's module yet —
//! `secrets serve` will fail to bind against the placeholder default with
//! an ordinary permission error, not a panic, which is the expected shape
//! of "not deployed yet".
//!
//! **This module DOES create and lock down the secrets home** (corrected,
//! P-V2 review bounce-fix item 3 — an earlier revision of this doc
//! claimed otherwise, which was false: `broker::serve` and
//! `store::save_policies` both call `std::fs::create_dir_all` on it).
//! [`secure_dir`] is the PERMISSIONS half of that: `create_dir_all` alone
//! honors the process umask (0755 by default), which would leave
//! `policy.json`/`backends.json` world-readable inside a world-searchable
//! directory — every `create_dir_all(secrets_home)` call site in this crate
//! is immediately followed by `secure_dir(secrets_home)`, propagating the
//! error rather than serving/writing into an insecure directory.
//! [`secure_file`] is the matching per-file half, used by `store::
//! save_policies` on `policy.json`.
//!
//! **This module also owns the admin-verb identity guard** (the
//! yomi-strix incident, 2026-08-22): [`admin_identity_error`] is the pure
//! decision (injected `euid`/`home_owner`, unit-testable without a real
//! stat or a real process uid), [`admin_identity_check`] wires it to a
//! real [`effective_uid`] and a real `std::fs::metadata(home)` — a
//! not-yet-existing home returns `None` (no refusal) rather than inventing
//! an owner nobody has decided yet; see that function's own doc. Every
//! admin verb that reads/writes `policy.json`/`totp.secret` calls this
//! BEFORE any such read-modify-write — `commands.rs`'s `require_admin_identity`
//! for the policy-CRUD quintet, `enroll::run` directly for the one other
//! broker-home write outside `commands.rs`'s own dispatch.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Resolve the secrets home: `$AOIDE_SECRETS_HOME` when set to a non-blank
/// value, else the placeholder default (see module doc).
pub fn secrets_home() -> PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_SECRETS_HOME") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from("/var/lib/aoide-secrets")
}

/// Lock a secrets-home-owned DIRECTORY down to `0700` (owner rwx only).
/// Called immediately after every `create_dir_all(secrets_home)` in this
/// crate — see module doc.
pub fn secure_dir(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Lock a secrets-home-owned FILE down to `0600` (owner rw only). Called
/// after writing a sensitive secrets-home file (`store::save_policies`'s
/// `policy.json`).
pub fn secure_file(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// This process's real effective uid. `std` has no `geteuid(2)` wrapper, but
/// `libc` is already a workspace dependency this crate links for
/// `enroll::local_hostname`'s `gethostname(2)` call (`Cargo.toml`'s
/// comment), so this costs nothing new in the lockfile — zero new
/// dependencies, per this crate's own house rule.
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid(2)` takes no arguments, can't fail, and touches no
    // memory this process doesn't already own.
    unsafe { libc::geteuid() }
}

/// The admin-verb identity guard's decision, PURE so it's testable with
/// injected uids (`euid`/`home_owner`) rather than a real stat + a real
/// process uid — see [`admin_identity_check`] for the live wiring.
///
/// `None` when `euid` already owns `home` (the expected shape: an admin
/// verb run as the broker user, or a test/dev host where one ordinary uid
/// created the home itself). `Some(message)` otherwise, naming the actual
/// home path, the actual owning uid, and the corrective `sudo -u
/// aoide-secrets` spelling — root gets an EXTRA clause spelling out why
/// plain `sudo` is wrong: root can always write regardless of ownership,
/// which is exactly what silently reowns `policy.json` to `root:root` and
/// bricks the broker (the yomi-strix incident, 2026-08-22, this guard
/// exists to make impossible).
pub fn admin_identity_error(euid: u32, home_owner: u32, home: &Path, verb: &str) -> Option<String> {
    if euid == home_owner {
        return None;
    }
    let running_as = if euid == 0 {
        "root (uid 0) — plain `sudo` runs as root, and root CAN write here regardless of file ownership, \
         which is exactly what silently corrupts it"
            .to_string()
    } else {
        format!("uid {euid}")
    };
    Some(format!(
        "secrets {verb} must run as the broker user (uid {home_owner}, the owner of {}) — this process is running as {running_as}. \
         Run: sudo -u aoide-secrets aoide secrets {verb} ...",
        home.display()
    ))
}

/// Live wiring for [`admin_identity_error`]: stats `home` for its owning
/// uid and compares it against this process's real [`effective_uid`].
///
/// **Returns `None` (no refusal) when `home` does not exist yet, or its
/// owner can't be read at all** — deliberate, not an oversight: on a
/// brand-new deployment nothing has decided who the broker user is until
/// the FIRST admin verb creates the home directory, so there is nothing
/// yet to compare the caller's uid against. Per the deployment doc's own
/// admin-verb section, that first invocation is expected to already be
/// `sudo -u aoide-secrets ...`; a caller who skips that on a fresh host
/// still only ends up owning a freshly created home (a narrower failure
/// than the incident this guard exists for — an EXISTING, correctly-owned
/// home getting silently reowned by root). This function never invents an
/// owner Linux didn't actually report.
pub fn admin_identity_check(home: &Path, verb: &str) -> Option<String> {
    let owner = std::fs::metadata(home).ok()?.uid();
    admin_identity_error(effective_uid(), owner, home, verb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins_when_set_and_non_blank() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::set_var("AOIDE_SECRETS_HOME", "/tmp/aoide-secrets-test-home");
        assert_eq!(secrets_home(), PathBuf::from("/tmp/aoide-secrets-test-home"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    #[test]
    fn default_is_the_documented_placeholder_path() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::remove_var("AOIDE_SECRETS_HOME");
        assert_eq!(secrets_home(), PathBuf::from("/var/lib/aoide-secrets"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    #[test]
    fn blank_env_value_falls_back_to_default() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::set_var("AOIDE_SECRETS_HOME", "   ");
        assert_eq!(secrets_home(), PathBuf::from("/var/lib/aoide-secrets"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-home-perms-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn secure_dir_sets_owner_only_permissions() {
        let dir = tmp_dir("dir");
        secure_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "secrets home must be owner-rwx-only, got {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secure_file_sets_owner_read_write_only() {
        let dir = tmp_dir("file");
        let file = dir.join("policy.json");
        std::fs::write(&file, b"[]").unwrap();
        secure_file(&file).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a secrets-home file must be owner-rw-only, got {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── admin_identity_error (pure — injected uids, no real stat/geteuid) ──

    #[test]
    fn admin_identity_error_is_none_when_euid_owns_the_home() {
        assert_eq!(admin_identity_error(1000, 1000, Path::new("/var/lib/aoide-secrets"), "add"), None);
        // Root owning its own home (an unusual but not impossible
        // deployment) is also a match, not a special case.
        assert_eq!(admin_identity_error(0, 0, Path::new("/var/lib/aoide-secrets"), "add"), None);
    }

    #[test]
    fn admin_identity_error_flags_root_explicitly_as_the_wrong_uid() {
        let msg = admin_identity_error(0, 1000, Path::new("/var/lib/aoide-secrets"), "add").unwrap();
        assert!(msg.contains("secrets add"), "{msg}");
        assert!(msg.contains("/var/lib/aoide-secrets"), "{msg}");
        assert!(msg.contains("uid 1000"), "{msg}");
        assert!(msg.to_lowercase().contains("root"), "{msg}");
        assert!(msg.contains("sudo -u aoide-secrets aoide secrets add"), "{msg}");
    }

    #[test]
    fn admin_identity_error_flags_an_arbitrary_mismatched_uid() {
        let msg = admin_identity_error(1001, 1000, Path::new("/var/lib/aoide-secrets"), "grant").unwrap();
        assert!(msg.contains("uid 1001"), "{msg}");
        assert!(msg.contains("uid 1000"), "{msg}");
        assert!(msg.contains("sudo -u aoide-secrets aoide secrets grant"), "{msg}");
        // Not root, so no plain-sudo digression.
        assert!(!msg.to_lowercase().contains("plain `sudo`"), "{msg}");
    }

    // ── admin_identity_check (real stat + real effective_uid) ──────────────

    #[test]
    fn admin_identity_check_is_none_when_the_home_does_not_exist_yet() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-home-identity-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        assert!(!dir.exists());
        assert_eq!(admin_identity_check(&dir, "add"), None);
    }

    #[test]
    fn admin_identity_check_is_none_when_this_process_owns_the_home() {
        // A tmpdir this test process just created is owned by this
        // process's own euid — the ordinary single-user dev/CI shape.
        let dir = tmp_dir("identity-owned");
        assert_eq!(admin_identity_check(&dir, "add"), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn effective_uid_matches_a_freshly_created_files_owner() {
        // No root/setuid assumption needed: whatever this process's euid
        // is, a file it just created is owned by exactly that uid.
        let dir = tmp_dir("euid-sanity");
        let owner = std::fs::metadata(&dir).unwrap().uid();
        assert_eq!(effective_uid(), owner);
        std::fs::remove_dir_all(&dir).ok();
    }
}
