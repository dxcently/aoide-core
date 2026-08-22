//! Backend adapter: named fetch-command templates in vault home's
//! `backends.json`, run AS THE BROKER'S OWN UID (`crates/vault`'s README —
//! this is what solves the backing-store ownership trap structurally: the
//! `pass` GPG key / `bw` session / `sops` key stays owned by the vault
//! uid, never the caller's). One backend = one command template
//! (`get = "pass show {name}"`); `{name}` is substituted with the secret
//! POLICY's own `key` field — not the backend's name — so `pass show
//! {name}` + a policy `key: "prod/db"` runs `pass show prod/db`. See
//! [`fetch_value`].
//!
//! Shell-invoked (`sh -c "<substituted template>"`), stdout captured, and
//! EXACTLY ONE trailing `\n` trimmed if present: a well-behaved backend
//! emitting `value\n` round-trips to `value`, while a backend emitting
//! `value` with no trailing newline is untouched. Never a blanket
//! `.trim_end()` — that would also eat trailing whitespace that could be
//! part of the actual secret.
//!
//! pass/gopass/bw/sops are DOC PRESETS (P-V3), not code — this module has
//! no knowledge of any specific backend, only the template mechanism
//! itself.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// One named backend: a single fetch-command template.
#[derive(Debug, Clone, Deserialize)]
pub struct Backend {
    pub get: String,
}

/// `backends.json`'s whole shape: a map of backend name -> [`Backend`].
/// `#[serde(transparent)]` so the JSON is the bare object, not `{"0": {…}}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct Backends(pub BTreeMap<String, Backend>);

/// `<vault_home>/backends.json`.
pub fn backends_path(vault_home: &Path) -> std::path::PathBuf {
    vault_home.join("backends.json")
}

fn load_backends(vault_home: &Path) -> Result<Backends, String> {
    let path = backends_path(vault_home);
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// Resolve `backend_name`'s template against `key`, run it, and return
/// stdout with exactly one trailing newline trimmed. Errors are precise
/// but VALUE-FREE by construction: nothing here ever touches the secret's
/// value except the `Ok` return itself, so an `Err` path can never leak
/// one (a backend's stderr — its OWN tool's error text, e.g. `pass show:
/// not in the password store` — is not the secret's value, and is safe to
/// surface the same way `conduct::shellbridge`'s `classify_*` helpers
/// already do for other subprocess failures).
pub fn fetch_value(vault_home: &Path, backend_name: &str, key: &str) -> Result<String, String> {
    let backends = load_backends(vault_home)?;
    let backend = backends
        .0
        .get(backend_name)
        .ok_or_else(|| format!("unknown backend `{backend_name}`"))?;
    let command = backend.get.replace("{name}", key);

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .map_err(|e| format!("spawning backend `{backend_name}`: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "backend `{backend_name}` exited {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let mut stdout = output.stdout;
    if stdout.last() == Some(&b'\n') {
        stdout.pop();
    }
    String::from_utf8(stdout).map_err(|_| format!("backend `{backend_name}` produced non-UTF-8 output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-vault-backend-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_backends(home: &Path, get: &str) {
        let doc = serde_json::json!({ "scratch": { "get": get } });
        std::fs::write(backends_path(home), serde_json::to_vec(&doc).unwrap()).unwrap();
    }

    #[test]
    fn trims_exactly_one_trailing_newline() {
        let home = tmp_home("trim");
        write_backends(&home, "printf '%s\\n' {name}");
        assert_eq!(fetch_value(&home, "scratch", "stored-value").unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn no_trailing_newline_is_untouched() {
        let home = tmp_home("notrim");
        write_backends(&home, "printf %s {name}");
        assert_eq!(fetch_value(&home, "scratch", "stored-value").unwrap(), "stored-value");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Only ONE trailing newline is trimmed — a double newline proves the
    /// module doc's "exactly one", not a blanket `trim_end`.
    #[test]
    fn a_double_trailing_newline_leaves_one_behind() {
        let home = tmp_home("doubletrim");
        write_backends(&home, "printf '%s\\n\\n' {name}");
        assert_eq!(fetch_value(&home, "scratch", "stored-value").unwrap(), "stored-value\n");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn key_substitutes_into_name_not_the_backend_name() {
        let home = tmp_home("key");
        write_backends(&home, "printf %s {name}");
        // The backend is looked up by "scratch"; the COMMAND runs with the
        // policy's key ("literal-key-value"), never the backend name.
        assert_eq!(fetch_value(&home, "scratch", "literal-key-value").unwrap(), "literal-key-value");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn unknown_backend_is_an_error() {
        let home = tmp_home("unknown");
        write_backends(&home, "printf %s {name}");
        assert!(fetch_value(&home, "nope", "x").is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_failing_backend_command_is_an_error() {
        let home = tmp_home("fail");
        write_backends(&home, "false");
        assert!(fetch_value(&home, "scratch", "x").is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn missing_backends_file_is_an_error() {
        let home = tmp_home("missingfile");
        assert!(fetch_value(&home, "scratch", "x").is_err());
        std::fs::remove_dir_all(&home).ok();
    }
}
