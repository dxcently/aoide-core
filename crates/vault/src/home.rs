//! The vault home: the directory holding `policy.json`, `backends.json`,
//! the broker's own append-only `audit.log`, and (later phases) the TOTP
//! secret + replay ledger. **One function** — every other module in this
//! crate reaches the vault home through [`vault_home`], never re-derives
//! it (the phase brief's own wording).
//!
//! Nix-independent: no nix shell-out, no NixOS assumption anywhere in this
//! module (root `AGENTS.md`'s HARD CONSTRAINT — core, and the vault broker
//! with it, must build with cargo and run on any Linux).
//!
//! **The default is a placeholder, not yet the deployed reality.** P-V4
//! (deployment) is what actually provisions `/var/lib/aoide-vault` as
//! 0700, owned by a real `aoide-vault` system user, via a nix module +
//! tmpfiles rule — until then, this default exists so the code has a
//! concrete answer, but nothing in this phase creates or chowns that
//! directory. Set `AOIDE_VAULT_SOCKET`/`AOIDE_VAULT_HOME` to a writable
//! directory (a tempdir in every test here, or a dev directory by hand) on
//! any host that hasn't run P-V4's module yet — `vault serve` will fail to
//! bind against the placeholder default with an ordinary permission error,
//! not a panic, which is the expected shape of "not deployed yet".

use std::path::PathBuf;

/// Resolve the vault home: `$AOIDE_VAULT_HOME` when set to a non-blank
/// value, else the placeholder default (see module doc).
pub fn vault_home() -> PathBuf {
    if let Ok(dir) = std::env::var("AOIDE_VAULT_HOME") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from("/var/lib/aoide-vault")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins_when_set_and_non_blank() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_VAULT_HOME").ok();
        std::env::set_var("AOIDE_VAULT_HOME", "/tmp/aoide-vault-test-home");
        assert_eq!(vault_home(), PathBuf::from("/tmp/aoide-vault-test-home"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_VAULT_HOME", v),
            None => std::env::remove_var("AOIDE_VAULT_HOME"),
        }
    }

    #[test]
    fn default_is_the_documented_placeholder_path() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_VAULT_HOME").ok();
        std::env::remove_var("AOIDE_VAULT_HOME");
        assert_eq!(vault_home(), PathBuf::from("/var/lib/aoide-vault"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_VAULT_HOME", v),
            None => std::env::remove_var("AOIDE_VAULT_HOME"),
        }
    }

    #[test]
    fn blank_env_value_falls_back_to_default() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_VAULT_HOME").ok();
        std::env::set_var("AOIDE_VAULT_HOME", "   ");
        assert_eq!(vault_home(), PathBuf::from("/var/lib/aoide-vault"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_VAULT_HOME", v),
            None => std::env::remove_var("AOIDE_VAULT_HOME"),
        }
    }
}
