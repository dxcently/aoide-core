//! `policy.json` persistence — the only file I/O [`crate::policy::Policy`]
//! gains at P-V2 (that module's own doc: "Type surface only at P-V1 — no
//! daemon reads/writes `state/policy.json` yet"). A tiny hand-rolled
//! atomic write (temp file + rename), not a dependency on
//! `aoide-storage::fs::atomic_write` — this crate stays off `aoide-storage`
//! on purpose (`policy.rs`'s own module doc: vault doesn't reach into
//! storage even for a smaller win, reusing `valid_peer_name`; the same
//! standoffishness applies here — atomic rename is ~5 lines to hand-roll
//! and saves a cross-crate dependency for a one-file concern).

use crate::policy::Policy;
use std::io;
use std::path::{Path, PathBuf};

/// `<vault_home>/policy.json` — every policy read/write in this crate goes
/// through here, never a hand-built path elsewhere.
pub fn policy_path(vault_home: &Path) -> PathBuf {
    vault_home.join("policy.json")
}

/// Load every registered secret's policy. A MISSING file reads as an empty
/// list — the first `vault add` on a fresh vault home creates the file;
/// there is nothing wrong with a vault that has never had a secret
/// registered. A present-but-corrupt file IS an error (never silently
/// treated as empty — that would make a bad write look like "no policies",
/// hiding real damage).
pub fn load_policies(vault_home: &Path) -> io::Result<Vec<Policy>> {
    let path = policy_path(vault_home);
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
/// which would leave the vault home world-searchable and `policy.json`
/// world-readable. `home::secure_dir`/`home::secure_file` fix that
/// immediately after each creation/write — errors propagate rather than
/// silently persisting policy data into an insecure directory.
pub fn save_policies(vault_home: &Path, policies: &[Policy]) -> io::Result<()> {
    std::fs::create_dir_all(vault_home)?;
    crate::home::secure_dir(vault_home)?;
    let path = policy_path(vault_home);
    let tmp = path.with_extension("json.tmp");
    let bytes =
        serde_json::to_vec_pretty(policies).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-vault-store-test-{tag}-{}-{}",
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
    /// vault home directory and `policy.json` locked down, not at whatever
    /// the process umask happens to be.
    #[test]
    fn save_policies_locks_down_the_home_dir_and_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("perms");
        save_policies(&home, &[Policy::new("t", "pass", "x")]).unwrap();

        let dir_mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "vault home must be 0700, got {dir_mode:o}");

        let file_mode = std::fs::metadata(policy_path(&home)).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "policy.json must be 0600, got {file_mode:o}");

        std::fs::remove_dir_all(&home).ok();
    }
}
