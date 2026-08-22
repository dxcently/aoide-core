//! The secrets broker's socket path: `$AOIDE_SECRETS_SOCKET` env override,
//! else a default UNDER the secrets home (`secrets.sock`) — deliberately NOT
//! `/run/aoide-secrets/secrets.sock` yet. That path requires a provisioned,
//! typically root-owned `/run/aoide-secrets/` directory this phase never
//! creates (P-V4's tmpfiles rule does). Defaulting under
//! [`crate::home::secrets_home`] means `secrets serve`/`secrets exec` work out
//! of the box against any writable `AOIDE_SECRETS_HOME` — a tempdir in
//! tests, a dev directory by hand — with no privileged path to provision
//! first. P-V4's nix module sets `AOIDE_SECRETS_SOCKET=/run/aoide-secrets/
//! secrets.sock` explicitly on the systemd units, which is what actually
//! moves the deployed socket there; this module's own default never
//! changes.
//!
//! **SUN_LEN hazard** (every caller, this crate's own tests included): a
//! unix socket path is capped at ~108 bytes on Linux
//! (`sockaddr_un.sun_path`). A secrets home nested under a long sandboxed
//! tempdir can overflow that before the `secrets.sock` suffix is even
//! added. A caller that needs a GUARANTEED-short path (this crate's own
//! end-to-end test, `tests/e2e.rs`) passes `AOIDE_SECRETS_SOCKET` — or, for
//! a direct `broker::serve`/`client::resolve` call, an explicit
//! `/tmp`-direct path — rather than relying on this derived default.

use std::path::PathBuf;

/// Resolve the broker's socket path: `$AOIDE_SECRETS_SOCKET` when set to a
/// non-blank value, else `secrets_home().join("secrets.sock")` (see module
/// doc for why that's the default rather than `/run/...`).
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_SECRETS_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    crate::home::secrets_home().join("secrets.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins_when_set_and_non_blank() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        std::env::set_var("AOIDE_SECRETS_SOCKET", "/tmp/av-test.sock");
        assert_eq!(socket_path(), PathBuf::from("/tmp/av-test.sock"));
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
    }

    #[test]
    fn default_lives_under_the_secrets_home() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sock = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        let saved_home = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::remove_var("AOIDE_SECRETS_SOCKET");
        std::env::set_var("AOIDE_SECRETS_HOME", "/tmp/av-test-home");
        assert_eq!(socket_path(), PathBuf::from("/tmp/av-test-home/secrets.sock"));
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved_home {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    #[test]
    fn blank_env_value_falls_back_to_the_derived_default() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sock = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        let saved_home = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::set_var("AOIDE_SECRETS_SOCKET", "  ");
        std::env::set_var("AOIDE_SECRETS_HOME", "/tmp/av-test-home2");
        assert_eq!(socket_path(), PathBuf::from("/tmp/av-test-home2/secrets.sock"));
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved_home {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }
}
