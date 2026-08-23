//! The secrets broker's socket path: `$AOIDE_SECRETS_SOCKET` env override,
//! else the canonical deployed path `/run/aoide-secrets/secrets.sock`
//! (P-V4d, corrected from an earlier secrets-home-relative default after
//! the first live deployment, yomi-strix, found the mismatch: a plain
//! client shell with no env set — `aoide secrets put/exec` run by hand —
//! resolved the OLD default to `<secrets_home>/secrets.sock`
//! (`/var/lib/aoide-secrets/secrets.sock`) while the deployed socket sits at
//! `/run/aoide-secrets/secrets.sock`, so every such client got `Permission
//! denied`/`No such file or directory` on the wrong path unless the operator
//! exported `AOIDE_SECRETS_SOCKET` by hand every session). Hardcoding `/run`
//! as the default — rather than deriving it from [`crate::home::secrets_home`]
//! — is deliberate: the client and the service must agree on the socket
//! location WITHOUT per-shell env, and `/run` is what P-V4's nix module (and
//! the non-nix install doc) has always provisioned as the real deployed
//! socket. A host that hasn't run that provisioning yet (a tempdir in tests,
//! a dev box by hand) sets `AOIDE_SECRETS_SOCKET` explicitly — same as it
//! always had to for `AOIDE_SECRETS_HOME` before `/var/lib/aoide-secrets`
//! existed.
//!
//! **SUN_LEN hazard** (every caller, this crate's own tests included): a
//! unix socket path is capped at ~108 bytes on Linux
//! (`sockaddr_un.sun_path`). A caller that needs a GUARANTEED-short path
//! (this crate's own end-to-end test, `tests/e2e.rs`) passes
//! `AOIDE_SECRETS_SOCKET` — or, for a direct `broker::serve`/
//! `client::resolve` call, an explicit `/tmp`-direct path — rather than
//! relying on this default, which is now a fixed absolute path independent
//! of any tempdir nesting.

use std::path::{Path, PathBuf};

/// Resolve the broker's socket path: `$AOIDE_SECRETS_SOCKET` when set to a
/// non-blank value, else the canonical deployed path
/// `/run/aoide-secrets/secrets.sock` (see module doc — P-V4d).
pub fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_SECRETS_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("/run/aoide-secrets/secrets.sock")
}

/// Resolve the broker's events feed path (P-G4, task #77 — the
/// ProtectHome fix): `$AOIDE_SECRETS_EVENTS` when set to a non-blank
/// value, else a sibling of `socket_path` named `events.jsonl` — the SAME
/// directory the socket itself lives in, so the deployed default is
/// `/run/aoide-secrets/events.jsonl` next to `secrets.sock` with zero new
/// nix provisioning (`RuntimeDirectory=aoide-secrets` already creates that
/// directory), and a scratch/test home's short `/tmp`-direct socket lands
/// its events file in the exact same tempdir.
///
/// Takes the ALREADY-RESOLVED socket path as a parameter rather than
/// re-deriving it — this crate's own "`home::secrets_home`/
/// `socket::socket_path` are THE resolution" discipline (`AGENTS.md`)
/// extends to this derived path too: every caller (`broker::serve`, and
/// `cli`'s dispatch resolving it once for `watch::run`, the SAME site that
/// already resolves `socket_path` once for that call) already has a
/// resolved socket path on hand, so this stays a pure function of that
/// parameter, never a second read of `AOIDE_SECRETS_SOCKET`.
///
/// **Why the broker OWNS this path instead of the operator's `~/Aoide/log`
/// mirror `emit_notify` already writes to**: that mirror lives under the
/// OPERATOR's home, and the deployed broker unit runs with
/// `ProtectHome=true` — its best-effort write into `~/Aoide/log` silently
/// fails there in the field (found live on yomi-strix, 2026-08-23), so
/// `secrets watch` received zero event lines and fell back to its 30s
/// pending-reconcile tick for every popup. A path beside the broker's own
/// socket is inside the directory the broker's own unit already owns and
/// writes to (`RuntimeDirectory=`/`/run`), so it exists under
/// `ProtectHome=true` exactly the way the socket itself already does. The
/// `~/Aoide/log` mirror in `emit_notify` is UNCHANGED by this — it still
/// serves the audit trail; only `secrets watch`'s own tail moves to this
/// feed (`watch.rs`'s module doc).
pub fn events_path(socket_path: &Path) -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_SECRETS_EVENTS") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    match socket_path.parent() {
        Some(parent) => parent.join("events.jsonl"),
        None => PathBuf::from("events.jsonl"),
    }
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
    fn default_is_the_canonical_run_path_regardless_of_secrets_home() {
        // P-V4d: the default no longer derives from AOIDE_SECRETS_HOME — a
        // client shell with only AOIDE_SECRETS_HOME set (never
        // AOIDE_SECRETS_SOCKET) must still resolve the real deployed socket.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sock = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        let saved_home = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::remove_var("AOIDE_SECRETS_SOCKET");
        std::env::set_var("AOIDE_SECRETS_HOME", "/tmp/av-test-home");
        assert_eq!(socket_path(), PathBuf::from("/run/aoide-secrets/secrets.sock"));
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
    fn blank_env_value_falls_back_to_the_canonical_default() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sock = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        let saved_home = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::set_var("AOIDE_SECRETS_SOCKET", "  ");
        std::env::set_var("AOIDE_SECRETS_HOME", "/tmp/av-test-home2");
        assert_eq!(socket_path(), PathBuf::from("/run/aoide-secrets/secrets.sock"));
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved_home {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    // ── events_path (P-G4, task #77) ────────────────────────────────────

    #[test]
    fn events_default_is_a_sibling_of_the_socket_path() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_EVENTS").ok();
        std::env::remove_var("AOIDE_SECRETS_EVENTS");
        assert_eq!(
            events_path(&PathBuf::from("/run/aoide-secrets/secrets.sock")),
            PathBuf::from("/run/aoide-secrets/events.jsonl")
        );
        // A scratch/test socket under a tempdir lands its events file in
        // the SAME tempdir the socket does — no separate provisioning
        // needed for a short `/tmp`-direct test socket.
        assert_eq!(
            events_path(&PathBuf::from("/tmp/av-test-sock/secrets.sock")),
            PathBuf::from("/tmp/av-test-sock/events.jsonl")
        );
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_EVENTS", v),
            None => std::env::remove_var("AOIDE_SECRETS_EVENTS"),
        }
    }

    #[test]
    fn events_env_override_wins_over_the_derived_sibling() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_EVENTS").ok();
        std::env::set_var("AOIDE_SECRETS_EVENTS", "/tmp/av-test-events.jsonl");
        assert_eq!(
            events_path(&PathBuf::from("/run/aoide-secrets/secrets.sock")),
            PathBuf::from("/tmp/av-test-events.jsonl")
        );
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_EVENTS", v),
            None => std::env::remove_var("AOIDE_SECRETS_EVENTS"),
        }
    }

    #[test]
    fn events_blank_env_value_falls_back_to_the_derived_sibling() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_EVENTS").ok();
        std::env::set_var("AOIDE_SECRETS_EVENTS", "   ");
        assert_eq!(
            events_path(&PathBuf::from("/run/aoide-secrets/secrets.sock")),
            PathBuf::from("/run/aoide-secrets/events.jsonl")
        );
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_EVENTS", v),
            None => std::env::remove_var("AOIDE_SECRETS_EVENTS"),
        }
    }
}
