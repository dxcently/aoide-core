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
//! **The substituted `key` is single-quote shell-escaped, never a raw
//! string replace** (bounce-fix item 4, P-V2 review): a legitimate key
//! containing whitespace or an apostrophe (`"Work Email/gmail"`, `"it's a
//! secret"`) would otherwise break the command or, worse, let a key value
//! reopen the shell's argument boundary. [`shell_single_quote`] wraps the
//! value in `'...'`, escaping any embedded `'` as `'\''` (close-quote,
//! escaped literal quote, reopen-quote — the standard POSIX-shell
//! technique). A template's own `{name}` placeholder must NOT be
//! pre-quoted (`pass show {name}`, never `pass show "{name}"`) — the
//! substituted text already carries its own quoting.
//!
//! Shell-invoked (`sh -c "<substituted template>"`), stdout captured, and
//! EXACTLY ONE trailing `\n` trimmed if present: a well-behaved backend
//! emitting `value\n` round-trips to `value`, while a backend emitting
//! `value` with no trailing newline is untouched. Never a blanket
//! `.trim_end()` — that would also eat trailing whitespace that could be
//! part of the actual secret.
//!
//! **A failed backend's stderr is BROKER-EPRINTLN-ONLY, never returned**
//! (bounce-fix item 1, P-V2 review — the headline defect): a backend's own
//! stderr can be verbose or interactive-prompt-shaped (`pass`/`gpg`
//! failure prompts have been known to quote entry content back), and the
//! `Err` this function returns rides three places that must stay
//! value-free — the wire's `{ok:false,error}` reply, `client::run_exec`'s
//! `eprintln!` into the CALLING AGENT's own stderr, and the `reason` field
//! of BOTH audit lines (vault's own `audit.log` and the mirrored
//! `EventClass::Secret` aoide-log line). [`fetch_value`]'s `Err` on a
//! failed command therefore carries ONLY the exit status; the full stderr
//! is `eprintln!`'d here, into the BROKER's own stderr, and nowhere else.
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

/// Single-quote shell-escape `s`: wrap in `'...'`, escaping any embedded
/// `'` as `'\''` (close the quote, emit an escaped literal quote, reopen
/// the quote — the standard POSIX technique). The result is always safe
/// to splice into an `sh -c` command line as ONE argument, regardless of
/// what `s` contains (whitespace, quotes, `$`, backticks, `;` — none of
/// it is interpreted once single-quoted).
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Resolve `backend_name`'s template against `key`, run it, and return
/// stdout with exactly one trailing newline trimmed. Errors are precise
/// but VALUE-FREE by construction: nothing here ever touches the secret's
/// value except the `Ok` return itself, so an `Err` path can never leak
/// one. A failed command's stderr is `eprintln!`'d to the BROKER's own
/// stderr (module doc) and never appears in the returned `Err` — only the
/// exit status does.
pub fn fetch_value(vault_home: &Path, backend_name: &str, key: &str) -> Result<String, String> {
    let backends = load_backends(vault_home)?;
    let backend = backends
        .0
        .get(backend_name)
        .ok_or_else(|| format!("unknown backend `{backend_name}`"))?;
    let command = backend.get.replace("{name}", &shell_single_quote(key));

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .map_err(|e| format!("spawning backend `{backend_name}`: {e}"))?;
    if !output.status.success() {
        // Full stderr goes ONLY here, to the broker's own stderr — never
        // into the returned `Err` (module doc: it rides the wire reply,
        // the calling agent's own stderr via `client::run_exec`, and both
        // audit lines' `reason` field otherwise).
        eprintln!(
            "[aoide/vault] backend `{backend_name}` exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Err(format!("backend `{backend_name}` exited {}", output.status));
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

    // ── bounce-fix item 1: backend stderr never rides the returned Err ──

    #[test]
    fn a_failing_backends_stderr_never_appears_in_the_returned_error() {
        let home = tmp_home("stderrleak");
        write_backends(&home, "printf 'SENTINEL-STDERR-XYZ' 1>&2; exit 1");
        let err = fetch_value(&home, "scratch", "x").unwrap_err();
        assert!(!err.contains("SENTINEL"), "stderr leaked into the returned error: {err}");
        assert!(err.contains("exited"), "error should still name the exit status: {err}");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── bounce-fix item 4: the key is shell-escaped, not raw-substituted ─

    #[test]
    fn key_with_a_space_round_trips_through_shell_quoting() {
        let home = tmp_home("space");
        write_backends(&home, "printf %s {name}");
        assert_eq!(fetch_value(&home, "scratch", "Work Email/gmail").unwrap(), "Work Email/gmail");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn key_with_an_embedded_single_quote_round_trips_through_shell_quoting() {
        let home = tmp_home("quote");
        write_backends(&home, "printf %s {name}");
        assert_eq!(fetch_value(&home, "scratch", "it's a secret").unwrap(), "it's a secret");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn shell_single_quote_escapes_every_embedded_quote() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_single_quote("''"), "''\\'''\\'''");
    }
}
