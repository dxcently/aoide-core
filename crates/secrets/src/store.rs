//! `policy.json` persistence — the only file I/O [`crate::policy::Policy`]
//! gained at P-V2 (that module's own doc: "Type surface only at P-V1 — no
//! daemon reads/writes `state/policy.json` yet"). A tiny hand-rolled
//! atomic write (temp file + rename), not a dependency on
//! `aoide-storage::fs::atomic_write` — this crate stays off `aoide-storage`
//! on purpose (`policy.rs`'s own module doc: this crate doesn't reach into
//! storage even for a smaller win, reusing `valid_peer_name`; the same
//! standoffishness applies here — atomic rename is ~5 lines to hand-roll
//! and saves a cross-crate dependency for a one-file concern).
//!
//! **P-V3 adds two more secrets-home files, same write-temp-then-rename +
//! `home::secure_dir`/`secure_file` discipline:**
//! - `totp.secret` ([`totp_secret_path`]/[`load_totp_secret`]/
//!   [`save_totp_secret`]): the enrolled TOTP secret, RAW BYTES (not
//!   base32-text) — `secrets enroll` prints the human-facing base32/URI form
//!   itself ([`crate::enroll::run`]), so there is no reason to also encode
//!   the file this crate reads back; storing raw bytes means no decode
//!   step on load. A missing file reads as `Ok(None)` (`load_policies`'s
//!   own "absence is not an error" shape) — this IS `broker::resolve_gate`'s
//!   "no TOTP enrollment on this host" signal, not a separate flag.
//! - `totp-replay.json` ([`replay_ledger_path`]/[`load_replay_ledger`]/
//!   [`save_replay_ledger`]): [`crate::replay::ReplayLedger`]'s
//!   persistence, so a broker restart inside a code's `±1`-window validity
//!   can never resurrect an already-spent timestep. Missing file = a fresh
//!   empty ledger (same shape as `load_policies`); `broker::resolve_gate`
//!   loads it fresh, records+prunes, and saves it back on every TOTP-gated
//!   resolve attempt (no in-memory ledger cached across connections — the
//!   same "no caching, `secrets_home` is the resolution" discipline
//!   `load_policies`/`save_policies` already hold, and the simplest way to
//!   honor "persist across a restart": the next resolve after a restart
//!   just re-reads the same file, no special-cased reload path needed).

use crate::policy::Policy;
use crate::replay::ReplayLedger;
use std::io;
use std::path::{Path, PathBuf};

/// `<secrets_home>/policy.json` — every policy read/write in this crate goes
/// through here, never a hand-built path elsewhere.
pub fn policy_path(secrets_home: &Path) -> PathBuf {
    secrets_home.join("policy.json")
}

/// Load every registered secret's policy. A MISSING file reads as an empty
/// list — the first `secrets add` on a fresh secrets home creates the file;
/// there is nothing wrong with a secrets store that has never had a secret
/// registered. A present-but-corrupt file IS an error (never silently
/// treated as empty — that would make a bad write look like "no policies",
/// hiding real damage).
pub fn load_policies(secrets_home: &Path) -> io::Result<Vec<Policy>> {
    let path = policy_path(secrets_home);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Write-temp-then-rename: a reader (the broker, mid-resolve) never sees a
/// torn `policy.json`. This phase does not lock against a concurrent admin
/// write racing a resolve read — the atomic rename is what keeps a TORN
/// read off the table regardless of that ordering; it does not by itself
/// make the two operations mutually exclusive.
///
/// Locks down permissions at BOTH levels (bounce-fix item 3, P-V2 review):
/// `create_dir_all` alone honors the process umask (0755/0644 by default),
/// which would leave the secrets home world-searchable and `policy.json`
/// world-readable. `home::secure_dir`/`home::secure_file` fix that
/// immediately after each creation/write — errors propagate rather than
/// silently persisting policy data into an insecure directory.
pub fn save_policies(secrets_home: &Path, policies: &[Policy]) -> io::Result<()> {
    std::fs::create_dir_all(secrets_home)?;
    crate::home::secure_dir(secrets_home)?;
    let path = policy_path(secrets_home);
    let tmp = path.with_extension("json.tmp");
    let bytes =
        serde_json::to_vec_pretty(policies).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

/// `<secrets_home>/totp.secret` — see module doc for why raw bytes, not
/// base32 text.
pub fn totp_secret_path(secrets_home: &Path) -> PathBuf {
    secrets_home.join("totp.secret")
}

/// `None` when no enrollment exists yet — `broker::resolve_gate`'s "no TOTP
/// enrollment on this host" signal (module doc). A present-but-EMPTY file
/// is an error, never silently read as "no enrollment": that would turn a
/// truncated/corrupt write into an ordinary rejection message instead of
/// surfacing the damage (same discipline as `load_policies`'s corrupt-file
/// case).
pub fn load_totp_secret(secrets_home: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::read(totp_secret_path(secrets_home)) {
        Ok(bytes) if bytes.is_empty() => {
            Err(io::Error::new(io::ErrorKind::InvalidData, "totp.secret exists but is empty"))
        }
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write-temp-then-rename + lock to `0600`, same discipline as
/// [`save_policies`]. Overwrites any previous enrollment wholesale — the
/// caller ([`crate::enroll::run`]) is what enforces "one enrollment per
/// host unless `--force`"; this function itself has no opinion on whether
/// overwriting is allowed.
pub fn save_totp_secret(secrets_home: &Path, secret: &[u8]) -> io::Result<()> {
    std::fs::create_dir_all(secrets_home)?;
    crate::home::secure_dir(secrets_home)?;
    let path = totp_secret_path(secrets_home);
    let tmp = path.with_extension("secret.tmp");
    std::fs::write(&tmp, secret)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

/// `<secrets_home>/totp-replay.json`.
pub fn replay_ledger_path(secrets_home: &Path) -> PathBuf {
    secrets_home.join("totp-replay.json")
}

/// Missing file = a fresh, empty ledger (module doc); corrupt = an error
/// (never silently emptied — a torn/corrupt ledger read as empty would
/// resurrect every timestep it had recorded as spent).
pub fn load_replay_ledger(secrets_home: &Path) -> io::Result<ReplayLedger> {
    match std::fs::read(replay_ledger_path(secrets_home)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("totp-replay.json: {e}"))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ReplayLedger::new()),
        Err(e) => Err(e),
    }
}

/// Write-temp-then-rename + lock to `0600`, same discipline as
/// [`save_policies`] — a reader mid-resolve never sees a torn ledger file.
pub fn save_replay_ledger(secrets_home: &Path, ledger: &ReplayLedger) -> io::Result<()> {
    std::fs::create_dir_all(secrets_home)?;
    crate::home::secure_dir(secrets_home)?;
    let path = replay_ledger_path(secrets_home);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(ledger).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-store-test-{tag}-{}-{}",
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
    fn missing_policy_file_reads_as_empty() {
        let home = tmp_home("missing");
        assert_eq!(load_policies(&home).unwrap(), Vec::<Policy>::new());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn round_trips_through_save_and_load() {
        let home = tmp_home("roundtrip");
        let mut p = Policy::new("db-prod", "pass", "prod/db");
        p.consumers.push("m".into());
        save_policies(&home, std::slice::from_ref(&p)).unwrap();
        let back = load_policies(&home).unwrap();
        assert_eq!(back, vec![p]);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_a_silent_empty_list() {
        let home = tmp_home("corrupt");
        std::fs::write(policy_path(&home), b"not json").unwrap();
        assert!(load_policies(&home).is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn save_overwrites_a_previous_policy_list_wholesale() {
        let home = tmp_home("overwrite");
        let first = Policy::new("a", "pass", "x");
        save_policies(&home, &[first]).unwrap();
        let second = Policy::new("b", "pass", "y");
        save_policies(&home, &[second.clone()]).unwrap();
        assert_eq!(load_policies(&home).unwrap(), vec![second]);
        std::fs::remove_dir_all(&home).ok();
    }

    /// Bounce-fix item 3 (P-V2 review): `save_policies` must leave BOTH the
    /// secrets home directory and `policy.json` locked down, not at whatever
    /// the process umask happens to be.
    #[test]
    fn save_policies_locks_down_the_home_dir_and_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("perms");
        save_policies(&home, &[Policy::new("t", "pass", "x")]).unwrap();

        let dir_mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "secrets home must be 0700, got {dir_mode:o}");

        let file_mode = std::fs::metadata(policy_path(&home)).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "policy.json must be 0600, got {file_mode:o}");

        std::fs::remove_dir_all(&home).ok();
    }

    // ── totp.secret ──────────────────────────────────────────────────────

    #[test]
    fn missing_totp_secret_reads_as_none() {
        let home = tmp_home("totp-missing");
        assert_eq!(load_totp_secret(&home).unwrap(), None);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn totp_secret_round_trips_through_save_and_load() {
        let home = tmp_home("totp-roundtrip");
        let secret = b"twenty-byte-secret!!".to_vec();
        assert_eq!(secret.len(), 20);
        save_totp_secret(&home, &secret).unwrap();
        assert_eq!(load_totp_secret(&home).unwrap(), Some(secret));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn totp_secret_is_locked_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("totp-perms");
        save_totp_secret(&home, b"x").unwrap();
        let mode = std::fs::metadata(totp_secret_path(&home)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "totp.secret must be 0600, got {mode:o}");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn an_empty_totp_secret_file_is_an_error_not_no_enrollment() {
        let home = tmp_home("totp-empty");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(totp_secret_path(&home), b"").unwrap();
        assert!(load_totp_secret(&home).is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn save_totp_secret_overwrites_a_previous_enrollment_wholesale() {
        let home = tmp_home("totp-overwrite");
        save_totp_secret(&home, b"first-secret").unwrap();
        save_totp_secret(&home, b"second-secret").unwrap();
        assert_eq!(load_totp_secret(&home).unwrap(), Some(b"second-secret".to_vec()));
        std::fs::remove_dir_all(&home).ok();
    }

    // ── totp-replay.json ─────────────────────────────────────────────────

    #[test]
    fn missing_replay_ledger_reads_as_empty() {
        let home = tmp_home("ledger-missing");
        assert!(load_replay_ledger(&home).unwrap().is_empty());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn replay_ledger_round_trips_through_save_and_load() {
        let home = tmp_home("ledger-roundtrip");
        let mut ledger = ReplayLedger::new();
        ledger.record(4242);
        save_replay_ledger(&home, &ledger).unwrap();
        assert_eq!(load_replay_ledger(&home).unwrap(), ledger);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn replay_ledger_is_locked_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("ledger-perms");
        save_replay_ledger(&home, &ReplayLedger::new()).unwrap();
        let mode = std::fs::metadata(replay_ledger_path(&home)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "totp-replay.json must be 0600, got {mode:o}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The persistence half of "a broker restart must not resurrect a spent
    /// code" (P-V3 phase brief): a SEPARATE `load_replay_ledger` call — a
    /// fresh read off disk, standing in for "a new broker process starting
    /// up" — still reports the timestep consumed, because nothing about
    /// this crate's ledger persistence lives in memory across the two
    /// load/save calls.
    #[test]
    fn a_freshly_loaded_ledger_still_refuses_a_timestep_recorded_by_a_previous_process() {
        let home = tmp_home("ledger-restart");
        let mut first_process_ledger = load_replay_ledger(&home).unwrap();
        assert!(first_process_ledger.record(999));
        save_replay_ledger(&home, &first_process_ledger).unwrap();

        // Simulated restart: a brand new `ReplayLedger` value, loaded fresh.
        let second_process_ledger = load_replay_ledger(&home).unwrap();
        assert!(second_process_ledger.is_used(999), "the restart resurrected a spent timestep");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_corrupt_replay_ledger_file_is_an_error_not_a_silent_empty_ledger() {
        let home = tmp_home("ledger-corrupt");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(replay_ledger_path(&home), b"not json").unwrap();
        assert!(load_replay_ledger(&home).is_err());
        std::fs::remove_dir_all(&home).ok();
    }
}
