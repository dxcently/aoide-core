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

use std::io;
use std::os::unix::fs::PermissionsExt;
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
}
