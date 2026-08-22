//! The vault broker's socket path: `$AOIDE_VAULT_SOCKET` env override,
//! else a default UNDER the vault home (`vault.sock`) — deliberately NOT
//! `/run/aoide-vault/vault.sock` yet. That path requires a provisioned,
//! typically root-owned `/run/aoide-vault/` directory this phase never
//! creates (P-V4's tmpfiles rule does). Defaulting under
//! [`crate::home::vault_home`] means `vault serve`/`vault exec` work out
//! of the box against any writable `AOIDE_VAULT_HOME` — a tempdir in
//! tests, a dev directory by hand — with no privileged path to provision
//! first. P-V4's nix module sets `AOIDE_VAULT_SOCKET=/run/aoide-vault/
//! vault.sock` explicitly on the systemd units, which is what actually
//! moves the deployed socket there; this module's own default never
//! changes.
//!
//! **SUN_LEN hazard** (every caller, this crate's own tests included): a
//! unix socket path is capped at ~108 bytes on Linux
//! (`sockaddr_un.sun_path`). A vault home nested under a long sandboxed
//! tempdir can overflow that before the `vault.sock` suffix is even
//! added. A caller that needs a GUARANTEED-short path (this crate's own
//! end-to-end test, `tests/e2e.rs`) passes `AOIDE_VAULT_SOCKET` — or, for
//! a direct `broker::serve`/`client::resolve` call, an explicit
//! `/tmp`-direct path — rather than relying on this derived default.

use std::path::PathBuf;

/// Resolve the broker's socket path: `$AOIDE_VAULT_SOCKET` when set to a
/// non-blank value, else `vault_home().join("vault.sock")` (see module
/// doc for why that's the default rather than `/run/...`).
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_VAULT_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    crate::home::vault_home().join("vault.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins_when_set_and_non_blank() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_VAULT_SOCKET").ok();
        std::env::set_var("AOIDE_VAULT_SOCKET", "/tmp/av-test.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/av-test.sock"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_VAULT_SOCKET", v),
            None => std::env::remove_var("AOIDE_VAULT_SOCKET"),
        }
    }

    #[test]
    fn default_lives_under_the_vault_home() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sock = std::env::var("AOIDE_VAULT_SOCKET").ok();
        let saved_home = std::env::var("AOIDE_VAULT_HOME").ok();
        std::env::remove_var("AOIDE_VAULT_SOCKET");
        std::env::set_var("AOIDE_VAULT_HOME", "/tmp/av-test-home");
        assert_eq!(socket_path(), PathBuf::from("/tmp/av-test-home/vault.sock"));
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_VAULT_SOCKET", v),
            None => std::env::remove_var("AOIDE_VAULT_SOCKET"),
        }
        match saved_home {
            Some(v) => std::env::set_var("AOIDE_VAULT_HOME", v),
            None => std::env::remove_var("AOIDE_VAULT_HOME"),
        }
    }

    #[test]
    fn blank_env_value_falls_back_to_the_derived_default() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sock = std::env::var("AOIDE_VAULT_SOCKET").ok();
        let saved_home = std::env::var("AOIDE_VAULT_HOME").ok();
        std::env::set_var("AOIDE_VAULT_SOCKET", "  ");
        std::env::set_var("AOIDE_VAULT_HOME", "/tmp/av-test-home2");
        assert_eq!(socket_path(), PathBuf::from("/tmp/av-test-home2/vault.sock"));
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_VAULT_SOCKET", v),
            None => std::env::remove_var("AOIDE_VAULT_SOCKET"),
        }
        match saved_home {
            Some(v) => std::env::set_var("AOIDE_VAULT_HOME", v),
            None => std::env::remove_var("AOIDE_VAULT_HOME"),
        }
    }
}
