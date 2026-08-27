//! The ssh tunnel registry (ssh-transport lane, phase P-S2,
//! `docs/architecture/PAIRING.md`'s forthcoming Transport section): the
//! shape of a tunnel record and every PURE helper around it. No process is
//! ever spawned here — `aoide-client::tunnel` (P-S3) owns the one place
//! `ssh` itself is invoked; this module only knows how to name, parse, and
//! persist what that child left behind.
//!
//! **Why this crate, not `aoide-client`.** Both the client (opens a tunnel)
//! and the reaper (`aoide-conduct`, collects an orphaned one) must read the
//! same record, and `conduct -> client -> storage` is the crate DAG
//! (`client/AGENTS.md`, "the `conduct -> client` edge is load-bearing") —
//! a shape both ends need sits at the lowest crate that reaches both,
//! exactly the split `peer_store` (storage) / `commands` (client) already
//! holds for peer transport.
//!
//! **The runtime-dir convention is RE-DERIVED here, never imported
//! upward.** `aoide_conduct::graph::conduct_socket_path` resolves
//! `$XDG_RUNTIME_DIR/aoide/session-<id>.sock` (fallback `/run/user/1000`),
//! and `aoide_client::daemon::socket_path` already re-derives the identical
//! rule for the daemon socket rather than depending on `aoide-conduct` (a
//! crate `aoide-storage` sits BELOW in the DAG) — [`runtime_dir`] repeats
//! that same three-line resolution a third time rather than inventing a new
//! shared helper for it, matching both existing sites' own "a sibling
//! convention re-derived, not imported" doc note.
//!
//! **Path preservation is load-bearing (§0.4 of the ssh-transport plan).**
//! `sign_headers_for_peer` (`aoide-client`) signs a canonical string built
//! from the URL's PATH ONLY (`peer_store::url_path`), never its host or
//! port — so rewriting a dial url's authority to `127.0.0.1:<local port>`
//! changes no byte of what gets signed, PROVIDED the path is copied
//! verbatim from the logical url rather than reinvented. [`dial_url`]
//! below calls [`crate::peer_store::url_path`] directly for exactly this
//! reason; a dropped or hardcoded path here would make every signed call
//! through the tunnel fail on the far end with an opaque `-32007`.
//!
//! **The record is RUNTIME state, never versioned, never a credential.**
//! It carries a pid and two local ports — enough to prove a tunnel is
//! still alive and to reuse it, nothing a caller could authenticate with.
//! It still writes at `0600` ([`fs::atomic_write_private`]) as a matter of
//! this crate's private-file discipline (`identity.rs`'s precedent), not
//! because the content is sensitive.

use crate::fs::atomic_write_private;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// `tunnel-<sessionId>-<key>.json` schema version (v0).
pub const TUNNEL_VERSION: &str = "0";

/// One open (or recently open) ssh tunnel, as persisted at
/// [`record_path`]`(session_id, key)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelRecord {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub key: String,
    /// The `--via`/`Peer.via` target this tunnel was opened for, rendered
    /// back through [`Via`]'s `Display` — kept for display/debugging, never
    /// re-parsed to resolve the tunnel (the pid + local port are what prove
    /// liveness).
    #[serde(rename = "sshTarget")]
    pub ssh_target: String,
    #[serde(rename = "localPort")]
    pub local_port: u16,
    #[serde(rename = "remoteHost")]
    pub remote_host: String,
    #[serde(rename = "remotePort")]
    pub remote_port: u16,
    pub pid: u32,
    #[serde(rename = "openedAt")]
    pub opened_at: String,
}

/// A parsed `ssh://[user@]host[:port]` transport marker — the `--via` flag's
/// value, or a `Peer.via` recorded at pair time (P-S4). Pure data, no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ssh://")?;
        if let Some(user) = &self.user {
            write!(f, "{user}@")?;
        }
        write!(f, "{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

/// Parse a `--via`/`Peer.via` transport marker. Only the `ssh` scheme is
/// ever accepted — this doubles as the "refuse `http://`" guard, since any
/// other scheme (including one that merely LOOKS like a url) fails the same
/// check. The user segment is optional (`open_or_reuse`, P-S3, falls back
/// to `$USER`/`$LOGNAME` when absent); the port segment is optional
/// (defaults to ssh's own `22` at dial time, P-S3) but when PRESENT must be
/// a valid TCP port, `1..=65535` — `0` and anything unparsable is refused
/// here rather than reaching `ssh -p` as a silently-wrong argument.
pub fn parse_via(spec: &str) -> Result<Via, String> {
    let spec = spec.trim();
    let Some((scheme, rest)) = spec.split_once("://") else {
        return Err(format!(
            "`{spec}` is not a valid --via target: expected ssh://[user@]host[:port]"
        ));
    };
    if scheme != "ssh" {
        return Err(format!(
            "`{spec}` is not a valid --via target: scheme must be `ssh`, got `{scheme}`"
        ));
    }
    let (user, host_port) = match rest.split_once('@') {
        Some((u, hp)) => {
            if u.is_empty() {
                return Err(format!(
                    "`{spec}` is not a valid --via target: empty user before `@`"
                ));
            }
            (Some(u.to_string()), hp)
        }
        None => (None, rest),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().ok().filter(|n| *n >= 1).ok_or_else(|| {
                format!("`{spec}` is not a valid --via target: port must be 1..=65535, got `{p}`")
            })?;
            (h, Some(port))
        }
        None => (host_port, None),
    };
    if host.is_empty() {
        return Err(format!("`{spec}` is not a valid --via target: empty host"));
    }
    Ok(Via { user, host: host.to_string(), port })
}

/// Build a `Via` directly from an observed IP and login, skipping the
/// string round trip [`parse_via`] exists for — the beacon-derived default
/// (`Heard::src_addr`, P-S1) when no explicit `--via` was given. `user`
/// empty is treated as absent, the same "no user segment" shape a bare
/// `ssh://host` parses to.
pub fn default_via(ip: &str, user: &str) -> Via {
    Via {
        user: Some(user.to_string()).filter(|s| !s.is_empty()),
        host: ip.to_string(),
        port: None,
    }
}

/// Rewrite a logical peer url's authority to `127.0.0.1:<local_port>`,
/// preserving its scheme and its PATH VERBATIM — see this module's own doc
/// for why the path half is load-bearing (§0.4). Delegates the path
/// extraction to [`crate::peer_store::url_path`] rather than re-deriving
/// it, so a dial url's path and a signature's canonical-string path can
/// never drift apart from two independent implementations of the same cut.
pub fn dial_url(logical_url: &str, local_port: u16) -> String {
    let scheme = logical_url.trim().split_once("://").map(|(s, _)| s).unwrap_or("http");
    let path = crate::peer_store::url_path(logical_url);
    format!("{scheme}://127.0.0.1:{local_port}{path}")
}

/// Is `id` safe to join onto a filesystem path with no further checking? A
/// looser guard than [`crate::peer_store::valid_peer_name`] (session ids
/// are not operator-typed nicknames — the default shape is
/// `conduct-<pid>-<unix ts>`, and `aoide conduct --id <id>` lets an operator
/// override it) — but empty, any path separator, a `..` traversal segment,
/// a NUL byte, or a leading `.` are refused outright, the same defense
/// `handle_peer_remove` (`aoide-client`) applies before a delete.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains('/')
        && !id.contains('\\')
        && !id.contains('\0')
        && !id.split('/').any(|seg| seg == "..")
        && id != ".."
        && !id.starts_with('.')
}

/// `$XDG_RUNTIME_DIR/aoide/` — the same directory
/// `aoide_conduct::graph::conduct_socket_path` resolves its socket into
/// (module doc's "runtime-dir convention" note): `$XDG_RUNTIME_DIR` when set
/// to a non-empty value, else `/run/user/1000`.
fn runtime_dir() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime).join("aoide")
}

/// The path a tunnel record for `(session_id, key)` lives at:
/// `$XDG_RUNTIME_DIR/aoide/tunnel-<sessionId>-<key>.json`. Refuses either
/// component before any path join is attempted — `key` through
/// [`crate::peer_store::valid_peer_name`] (it names a peer or a `--via`
/// target, the same nickname shape everywhere else on the wire), and
/// `session_id` through [`is_safe_id`] (a looser but still traversal-proof
/// guard — see that function's own doc for why it can't reuse
/// `valid_peer_name` verbatim).
pub fn record_path(session_id: &str, key: &str) -> Result<PathBuf, String> {
    if !is_safe_id(session_id) {
        return Err(format!("`{session_id}` is not a valid session id for a tunnel record"));
    }
    if !crate::peer_store::valid_peer_name(key) {
        return Err(format!("`{key}` is not a valid tunnel key"));
    }
    Ok(runtime_dir().join(format!("tunnel-{session_id}-{key}.json")))
}

/// Atomic-write `record` to its own [`record_path`], at `0600`
/// ([`atomic_write_private`] — module doc's "never a credential" note on
/// why this stays the discipline anyway).
pub fn save(record: &TunnelRecord) -> Result<(), String> {
    let path = record_path(&record.session_id, &record.key)?;
    let body = serde_json::to_string_pretty(record)
        .map_err(|e| format!("serialize tunnel record: {e}"))?;
    atomic_write_private(&path, body.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// Load the tunnel record for `(session_id, key)`, tolerating a
/// missing/corrupt file or an invalid id/key pair as `None` — the same
/// tolerate-missing-as-empty discipline `peer_store::load_peers`/
/// `undying::load_undying` hold, so a caller never has to distinguish "no
/// tunnel yet" from "the file is unreadable."
pub fn load(session_id: &str, key: &str) -> Option<TunnelRecord> {
    let path = record_path(session_id, key).ok()?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Remove the tunnel record for `(session_id, key)`. Idempotent on a file
/// that is already gone (mirrors `close`'s own idempotence, P-S3) — only a
/// genuinely invalid id/key pair, or a removal that fails for a reason
/// other than "already absent," is an `Err`.
pub fn remove(session_id: &str, key: &str) -> Result<(), String> {
    let path = record_path(session_id, key)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Every tunnel record currently on disk, tolerating an unreadable
/// directory as empty. Only names matching `tunnel-*.json` are ever
/// candidates — the same `sweep_orphan_sockets` discipline
/// (`aoide-conduct::reap`) of scoping a directory sweep to one exact
/// filename shape, so a stray file (or another convention's file sharing
/// this same runtime directory, e.g. `session-*.sock`, `aoided.sock`) is
/// silently skipped rather than mis-parsed. A file that matches the name
/// shape but fails to parse is likewise skipped, never a hard error — a
/// half-written or corrupt record is exactly what a later reap (P-S5)
/// exists to clean up, not a reason for a caller like `list` to fail
/// outright.
pub fn list_records() -> Vec<TunnelRecord> {
    let Ok(entries) = std::fs::read_dir(runtime_dir()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("tunnel-") || !name.ends_with(".json") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(entry.path()) else { continue };
        if let Ok(rec) = serde_json::from_str::<TunnelRecord>(&raw) {
            out.push(rec);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_runtime_dir<T>(name: &str, f: impl FnOnce() -> T) -> T {
        let _g = crate::env_lock().lock().unwrap();
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-tunnel-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);

        let out = f();

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        out
    }

    fn fixture(session_id: &str, key: &str) -> TunnelRecord {
        TunnelRecord {
            schema_version: TUNNEL_VERSION.to_string(),
            session_id: session_id.to_string(),
            key: key.to_string(),
            ssh_target: "ssh://sakaki".to_string(),
            local_port: 41234,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8710,
            pid: 12345,
            opened_at: "2026-08-27T00:00:00Z".to_string(),
        }
    }

    // ── parse_via ────────────────────────────────────────────────────────

    #[test]
    fn parse_via_accepts_the_documented_shapes() {
        assert_eq!(
            parse_via("ssh://sakaki").unwrap(),
            Via { user: None, host: "sakaki".to_string(), port: None }
        );
        assert_eq!(
            parse_via("ssh://khoa@sakaki").unwrap(),
            Via { user: Some("khoa".to_string()), host: "sakaki".to_string(), port: None }
        );
        assert_eq!(
            parse_via("ssh://sakaki:2222").unwrap(),
            Via { user: None, host: "sakaki".to_string(), port: Some(2222) }
        );
        assert_eq!(
            parse_via("ssh://khoa@sakaki:2222").unwrap(),
            Via { user: Some("khoa".to_string()), host: "sakaki".to_string(), port: Some(2222) }
        );
        assert_eq!(
            parse_via("ssh://khoa@192.168.1.202").unwrap(),
            Via { user: Some("khoa".to_string()), host: "192.168.1.202".to_string(), port: None }
        );
    }

    #[test]
    fn parse_via_refuses_a_non_ssh_scheme() {
        assert!(parse_via("http://sakaki").is_err());
        assert!(parse_via("https://khoa@sakaki:22").is_err());
        assert!(parse_via("not-a-url-at-all").is_err());
    }

    #[test]
    fn parse_via_refuses_an_empty_host() {
        assert!(parse_via("ssh://").is_err());
        assert!(parse_via("ssh://khoa@").is_err());
        assert!(parse_via("ssh://khoa@:22").is_err());
    }

    #[test]
    fn parse_via_refuses_a_port_outside_1_65535() {
        assert!(parse_via("ssh://sakaki:0").is_err());
        assert!(parse_via("ssh://sakaki:65536").is_err());
        assert!(parse_via("ssh://sakaki:999999").is_err());
        assert!(parse_via("ssh://sakaki:not-a-port").is_err());
        // The boundary itself is valid.
        assert_eq!(parse_via("ssh://sakaki:1").unwrap().port, Some(1));
        assert_eq!(parse_via("ssh://sakaki:65535").unwrap().port, Some(65535));
    }

    #[test]
    fn via_display_renders_back_the_canonical_form() {
        assert_eq!(parse_via("ssh://sakaki").unwrap().to_string(), "ssh://sakaki");
        assert_eq!(
            parse_via("ssh://khoa@sakaki:2222").unwrap().to_string(),
            "ssh://khoa@sakaki:2222"
        );
    }

    #[test]
    fn default_via_builds_directly_without_a_string_round_trip() {
        assert_eq!(
            default_via("192.168.1.202", "khoa"),
            Via { user: Some("khoa".to_string()), host: "192.168.1.202".to_string(), port: None }
        );
        // An empty user is treated as absent, same as a bare `ssh://host`.
        assert_eq!(
            default_via("192.168.1.202", ""),
            Via { user: None, host: "192.168.1.202".to_string(), port: None }
        );
    }

    // ── dial_url (§0.4 — path preservation is load-bearing) ────────────────

    #[test]
    fn dial_url_preserves_the_path_verbatim() {
        assert_eq!(dial_url("http://h:8710/rpc", 41234), "http://127.0.0.1:41234/rpc");
        assert_eq!(dial_url("http://h:8710/", 41234), "http://127.0.0.1:41234/");
        assert_eq!(dial_url("https://h:8710/a/b?x=1", 9), "https://127.0.0.1:9/a/b");
    }

    #[test]
    fn dial_url_never_invents_a_path_it_asserts_against_url_path_directly() {
        // The whole point of §0.4: the path half of a dial url must come from
        // exactly the same function a signature's canonical string uses, not
        // a second, independently-written cut of the same url.
        for logical in ["http://h:8710/rpc", "http://h:8710/", "http://h:8710", "http://h:8710/a/b/c"]
        {
            let expected_path = crate::peer_store::url_path(logical);
            let dial = dial_url(logical, 5555);
            assert!(
                dial.ends_with(&expected_path) && dial == format!("http://127.0.0.1:5555{expected_path}"),
                "dial_url({logical}) = {dial}, expected path {expected_path}"
            );
        }
    }

    #[test]
    fn dial_url_handles_the_bare_authority_case() {
        // No path at all in the logical url → url_path's own "/" default,
        // never a dial_url-local hardcode of the same string.
        assert_eq!(dial_url("http://h:8710", 1), "http://127.0.0.1:1/");
    }

    // ── record_path (traversal refusal) ─────────────────────────────────

    #[test]
    fn record_path_builds_the_expected_shape() {
        with_temp_runtime_dir("path-shape", || {
            let p = record_path("conduct-1-2", "sakaki").unwrap();
            assert_eq!(p.file_name().unwrap().to_str().unwrap(), "tunnel-conduct-1-2-sakaki.json");
            assert_eq!(p.parent().unwrap().file_name().unwrap(), "aoide");
        });
    }

    #[test]
    fn record_path_refuses_traversal_shaped_session_ids() {
        assert!(record_path("../etc", "sakaki").is_err());
        assert!(record_path("a/../b", "sakaki").is_err());
        assert!(record_path("a/b", "sakaki").is_err());
        assert!(record_path("..", "sakaki").is_err());
        assert!(record_path("", "sakaki").is_err());
        assert!(record_path(".hidden", "sakaki").is_err());
    }

    #[test]
    fn record_path_refuses_traversal_shaped_keys() {
        assert!(record_path("conduct-1-2", "../etc").is_err());
        assert!(record_path("conduct-1-2", "a/b").is_err());
        assert!(record_path("conduct-1-2", "").is_err());
        assert!(record_path("conduct-1-2", "Upper").is_err());
        assert!(record_path("conduct-1-2", "-leading-hyphen").is_err());
    }

    // ── save/load/remove round trip ─────────────────────────────────────

    #[test]
    fn record_round_trips_through_a_temp_runtime_dir() {
        with_temp_runtime_dir("roundtrip", || {
            assert!(load("conduct-1-2", "sakaki").is_none());

            let rec = fixture("conduct-1-2", "sakaki");
            save(&rec).unwrap();
            assert_eq!(load("conduct-1-2", "sakaki"), Some(rec.clone()));

            // On-disk shape carries the v0 schemaVersion and 0600 mode.
            let path = record_path("conduct-1-2", "sakaki").unwrap();
            let raw = std::fs::read_to_string(&path).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(v["schemaVersion"], "0");
            assert_eq!(v["sessionId"], "conduct-1-2");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "tunnel record must be written 0600, got {mode:o}");
            }

            remove("conduct-1-2", "sakaki").unwrap();
            assert!(load("conduct-1-2", "sakaki").is_none());
            // Idempotent on an already-missing record.
            remove("conduct-1-2", "sakaki").unwrap();
        });
    }

    #[test]
    fn load_tolerates_a_corrupt_record_as_none() {
        with_temp_runtime_dir("corrupt", || {
            let path = record_path("conduct-1-2", "sakaki").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "{ not json at all").unwrap();
            assert!(load("conduct-1-2", "sakaki").is_none());
        });
    }

    #[test]
    fn remove_refuses_an_invalid_id_or_key_rather_than_silently_no_opping() {
        assert!(remove("../etc", "sakaki").is_err());
        assert!(remove("conduct-1-2", "../etc").is_err());
    }

    // ── list_records ────────────────────────────────────────────────────

    #[test]
    fn list_records_ignores_files_that_are_not_tunnel_json() {
        with_temp_runtime_dir("list-strangers", || {
            save(&fixture("conduct-1-2", "sakaki")).unwrap();
            save(&fixture("conduct-3-4", "yomi")).unwrap();

            let dir = runtime_dir();
            std::fs::write(dir.join("session-conduct-9-9.sock"), b"").unwrap();
            std::fs::write(dir.join("aoided.sock"), b"").unwrap();
            std::fs::write(dir.join("tunnel-not-json.txt"), b"stray").unwrap();
            std::fs::write(dir.join("not-a-tunnel-at-all.json"), b"{}").unwrap();

            let mut sessions: Vec<String> =
                list_records().into_iter().map(|r| r.session_id).collect();
            sessions.sort();
            assert_eq!(sessions, vec!["conduct-1-2".to_string(), "conduct-3-4".to_string()]);
        });
    }

    #[test]
    fn list_records_tolerates_an_unreadable_directory_as_empty() {
        with_temp_runtime_dir("list-missing-dir", || {
            // The helper only creates `$XDG_RUNTIME_DIR` itself, never the
            // `aoide/` subdirectory `runtime_dir()` resolves to — so no
            // `save` having run yet is already the "directory absent" case
            // `read_dir` must tolerate as empty, not panic on.
            assert!(!runtime_dir().exists());
            assert!(list_records().is_empty());
        });
    }

    #[test]
    fn list_records_skips_a_matching_name_that_fails_to_parse() {
        with_temp_runtime_dir("list-corrupt-entry", || {
            save(&fixture("conduct-1-2", "sakaki")).unwrap();
            let dir = runtime_dir();
            std::fs::write(dir.join("tunnel-broken-thing.json"), b"{ not json").unwrap();

            let sessions: Vec<String> = list_records().into_iter().map(|r| r.session_id).collect();
            assert_eq!(sessions, vec!["conduct-1-2".to_string()]);
        });
    }
}
