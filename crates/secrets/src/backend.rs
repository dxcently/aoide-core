//! Backend adapter: named fetch/store-command templates in secrets home's
//! `backends.json`, run AS THE BROKER'S OWN UID (`crates/secrets`'s README —
//! this is what solves the backing-store ownership trap structurally: the
//! `pass` GPG key / `bw` session / `sops` key stays owned by the secrets
//! uid, never the caller's). One backend = one `get` template
//! (`get = "pass show {name}"`) plus an OPTIONAL `set` template (P-V4c —
//! see "The `{home}` placeholder + `set`" below); `{name}` is substituted
//! with the secret POLICY's own `key` field — not the backend's name — so
//! `pass show {name}` + a policy `key: "prod/db"` runs `pass show
//! prod/db`. See [`fetch_value`]/[`store_value`].
//!
//! **The substituted `key` (and, at P-V4c, `{home}`) is single-quote
//! shell-escaped, never a raw string replace** (bounce-fix item 4, P-V2
//! review): a legitimate key containing whitespace or an apostrophe
//! (`"Work Email/gmail"`, `"it's a secret"`) would otherwise break the
//! command or, worse, let a key value reopen the shell's argument
//! boundary. [`shell_single_quote`] wraps the value in `'...'`, escaping
//! any embedded `'` as `'\''` (close-quote, escaped literal quote,
//! reopen-quote — the standard POSIX-shell technique). A template's own
//! `{name}`/`{home}` placeholders must NOT be pre-quoted (`pass show
//! {name}`, never `pass show "{name}"`) — the substituted text already
//! carries its own quoting.
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
//! of BOTH audit lines (the broker's own `audit.log` and the mirrored
//! `EventClass::Secret` aoide-log line). [`fetch_value`]'s `Err` on a
//! failed command therefore carries ONLY the exit status; the full stderr
//! is `eprintln!`'d here, into the BROKER's own stderr, and nowhere else.
//! [`store_value`] (P-V4c) holds the exact same discipline for a failing
//! `set` template.
//!
//! pass/gopass/bw/sops are DOC PRESETS (P-V3), not code — this module has
//! no knowledge of any specific backend, only the template mechanism
//! itself. The built-in `file` backend (P-V4c, below) is the one
//! exception that ships as data, not as special-cased Rust.
//!
//! ## The `{home}` placeholder + `set` (P-V4c)
//!
//! A template may also use `{home}`, substituted with `secrets_home`
//! itself (shell-single-quote-escaped exactly like `{name}` — same rule,
//! same [`shell_single_quote`] call). This is what lets a backend live
//! ENTIRELY inside the secrets home with no other privileged path to
//! provision (the built-in `file` backend below is the reason this
//! placeholder exists at all).
//!
//! [`expand_template`] substitutes both placeholders in a SINGLE
//! left-to-right scan over the ORIGINAL template text, never a sequential
//! two-pass `.replace()` — a naive `template.replace("{name}",
//! q).replace("{home}", h)` would re-scan the JUST-INSERTED, already-quoted
//! `key` text for a literal `{home}` token if the key happened to contain
//! that substring, mangling an unrelated key value. Scanning the original
//! template once and emitting already-quoted literal spans as they're
//! found is immune to that by construction: substituted text is never
//! re-examined for either token.
//!
//! An OPTIONAL `set` template ([`Backend::set`]) is what makes a backend
//! WRITABLE (`secrets put`, P-V4c) — a backend with only `get` is
//! read-only, same as every backend before P-V4c. [`store_value`] pipes
//! the value to the template's OWN stdin (never argv, matching the wire's
//! own stdin-only intake discipline — see `broker`'s module doc), runs it
//! via `sh -c` exactly like `fetch_value`, and returns nothing on success
//! (the `set` template's stdout, if any, is discarded — a `set` template
//! has nothing useful to report back over the wire, unlike `get`'s stdout
//! which IS the value).
//!
//! [`has_value`] (P-67, "warn before overwrite") is the broker-side
//! existence probe `broker::put_gate` uses to decide whether an
//! `overwrite:false` `put` should be refused: it just runs the `get`
//! template and reports success/failure, since that IS every backend's
//! existence contract already (`README.md`'s "Backend presets" table) —
//! no new per-backend primitive, no special-casing of the built-in `file`
//! backend.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// One named backend: a `get` fetch-command template, and an OPTIONAL `set`
/// store-command template (P-V4c) — a backend with no `set` is read-only.
#[derive(Debug, Clone, Deserialize)]
pub struct Backend {
    pub get: String,
    #[serde(default)]
    pub set: Option<String>,
}

/// `backends.json`'s whole shape: a map of backend name -> [`Backend`].
/// `#[serde(transparent)]` so the JSON is the bare object, not `{"0": {…}}`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct Backends(pub BTreeMap<String, Backend>);

/// `<secrets_home>/backends.json`.
pub fn backends_path(secrets_home: &Path) -> std::path::PathBuf {
    secrets_home.join("backends.json")
}

fn load_backends(secrets_home: &Path) -> Result<Backends, String> {
    let path = backends_path(secrets_home);
    let bytes = std::fs::read(&path)
        .map_err(|e| crate::home::describe_home_file_error(secrets_home, &path, &e))?;
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

/// Substitute `{name}` (with `key`) and `{home}` (with `secrets_home`) into
/// `template` in ONE left-to-right scan over the ORIGINAL text — see the
/// module doc for why this is not a sequential two-pass `.replace()`. Both
/// substitutions are shell-single-quote-escaped ([`shell_single_quote`]);
/// neither placeholder may be pre-quoted by the template author.
fn expand_template(template: &str, secrets_home: &Path, key: &str) -> String {
    let home_q = shell_single_quote(&secrets_home.to_string_lossy());
    let key_q = shell_single_quote(key);
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        let next_name = rest.find("{name}");
        let next_home = rest.find("{home}");
        let name_is_next = match (next_name, next_home) {
            (None, None) => {
                out.push_str(rest);
                break;
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (Some(n), Some(h)) => n < h,
        };
        if name_is_next {
            let n = next_name.unwrap();
            out.push_str(&rest[..n]);
            out.push_str(&key_q);
            rest = &rest[n + "{name}".len()..];
        } else {
            let h = next_home.unwrap();
            out.push_str(&rest[..h]);
            out.push_str(&home_q);
            rest = &rest[h + "{home}".len()..];
        }
    }
    out
}

/// Resolve `backend_name`'s `get` template against `key`/`secrets_home`, run
/// it, and return stdout with exactly one trailing newline trimmed. Errors
/// are precise but VALUE-FREE by construction: nothing here ever touches
/// the secret's value except the `Ok` return itself, so an `Err` path can
/// never leak one. A failed command's stderr is `eprintln!`'d to the
/// BROKER's own stderr (module doc) and never appears in the returned
/// `Err` — only the exit status does.
pub fn fetch_value(secrets_home: &Path, backend_name: &str, key: &str) -> Result<String, String> {
    let backends = load_backends(secrets_home)?;
    let backend = backends
        .0
        .get(backend_name)
        .ok_or_else(|| format!("unknown backend `{backend_name}`"))?;
    let command = expand_template(&backend.get, secrets_home, key);

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
            "[aoide/secrets] backend `{backend_name}` exited {}: {}",
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

/// Cheap-as-possible existence probe for a secret's STORED value (P-67,
/// "warn before overwrite" — `secrets put` warns+confirms before clobbering
/// an existing value, and the broker-side check backing that lives here):
/// runs the SAME `get` template [`fetch_value`] would and treats success as
/// "has a value", any failure (a missing file, an unknown backend, a spawn
/// error, a non-zero exit, ...) as "no stored value yet". This is exactly
/// the contract every `get` template in this crate's "Backend presets"
/// table already commits to — `cat`, `pass show`, `gopass show -o`, `bw get
/// password`, `sops -d --extract` all exit non-zero on a missing entry and
/// zero with the value on stdout otherwise — so there is no separate
/// "does it exist" primitive to add per backend, and no special-casing of
/// the built-in `file` backend either (house rule 7: no special-cased Rust
/// reads this backend's bytes — [`Backend`]'s shape carries only `get`/
/// `set` templates, nothing else this function could probe more cheaply
/// against). A backend that is merely misconfigured (unknown name, a
/// spawn failure) also reads as "no stored value" here — harmless, since
/// [`store_value`] re-checks the same policy/backend on the write that
/// follows and surfaces the real error there if the caller proceeds.
pub fn has_value(secrets_home: &Path, backend_name: &str, key: &str) -> bool {
    fetch_value(secrets_home, backend_name, key).is_ok()
}

/// Resolve `backend_name`'s `set` template against `key`/`secrets_home`, run
/// it with `value` piped to the template's OWN stdin (never argv), and
/// discard its stdout (a `set` template has nothing useful to report back —
/// unlike `get`'s stdout, which IS the value). Errors are precise but
/// VALUE-FREE by construction, same discipline as [`fetch_value`]: a
/// missing backend, a backend with no `set` template, or a failing `set`
/// command all return an `Err` that carries no part of `value` — the
/// backend's own stderr is `eprintln!`'d to the BROKER's own stderr and
/// never returned.
pub fn store_value(secrets_home: &Path, backend_name: &str, key: &str, value: &str) -> Result<(), String> {
    let backends = load_backends(secrets_home)?;
    let backend = backends
        .0
        .get(backend_name)
        .ok_or_else(|| format!("unknown backend `{backend_name}`"))?;
    let Some(set_template) = &backend.set else {
        return Err(format!("backend `{backend_name}` has no `set` template"));
    };
    let command = expand_template(set_template, secrets_home, key);

    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning backend `{backend_name}`: {e}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("backend `{backend_name}`: could not open its stdin"))?;
        stdin
            .write_all(value.as_bytes())
            .map_err(|e| format!("writing to backend `{backend_name}`'s stdin: {e}"))?;
        // `stdin` drops here, closing the write end (EOF) before we wait —
        // a `set` template blocked reading its own stdin would otherwise
        // hang forever.
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("waiting on backend `{backend_name}`: {e}"))?;
    if !output.status.success() {
        // Same value-free discipline as `fetch_value` — full stderr goes
        // ONLY to the broker's own stderr, never into the returned `Err`.
        eprintln!(
            "[aoide/secrets] backend `{backend_name}` (set) exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Err(format!("backend `{backend_name}` exited {}", output.status));
    }
    Ok(())
}

/// The built-in `file` backend's `get`/`set` templates — plain 0600 files
/// under `<secrets_home>/store/`, expressed ENTIRELY through the template
/// mechanism above (house rule 7, "everything is a plugin": no
/// special-cased Rust reads or writes a secret's bytes for this backend —
/// `sh -c` does, exactly like `pass`/`gopass`/`bw`/`sops`). `install -m
/// 0600 /dev/stdin` sets the file's mode explicitly (bypassing umask,
/// unlike a bare shell redirect); `mkdir -p -m 0700` sets the store dir's
/// mode on first creation the same way. Both resulting modes are a
/// CONTRACT (asserted directly in this module's own tests), even though
/// the template text itself is just documentation-as-data and could be
/// re-worded without changing the resulting file layout.
const FILE_BACKEND_GET: &str = "cat {home}/store/{name}";
const FILE_BACKEND_SET: &str = "mkdir -p -m 0700 {home}/store && install -m 0600 /dev/stdin {home}/store/{name}";

/// Seed `backends.json` with the built-in `file` backend WHEN ABSENT —
/// never when a `backends.json` already exists (module doc: this is
/// exactly the "seeded once, at broker startup" contract). Called from
/// [`crate::broker::serve`] (the seeding site, module doc) immediately
/// after `secrets_home` is created/secured and before the accept loop
/// starts, so every resolve/put reaching a backend — the `file` backend
/// included — always finds a `backends.json` on disk, without this crate
/// ever special-casing `file` in the resolve/put code paths themselves.
/// Locked to `0600` like every other secrets-home file this crate writes
/// ([`crate::home::secure_file`]), even though `backends.json` holds no
/// secret value itself — consistency with `policy.json`'s own permissions
/// beats a one-off exception here.
pub fn seed_default_backends(secrets_home: &Path) -> std::io::Result<()> {
    let path = backends_path(secrets_home);
    if path.exists() {
        return Ok(());
    }
    let doc = serde_json::json!({
        "file": { "get": FILE_BACKEND_GET, "set": FILE_BACKEND_SET }
    });
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-backend-test-{tag}-{}-{}",
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

    // ── {home} placeholder (P-V4c) ──────────────────────────────────────

    #[test]
    fn home_placeholder_substitutes_the_secrets_home_path() {
        let home = tmp_home("homeplaceholder");
        write_backends(&home, "printf %s {home}");
        assert_eq!(fetch_value(&home, "scratch", "unused").unwrap(), home.to_string_lossy());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn home_placeholder_with_a_spaced_path_round_trips_through_shell_quoting() {
        let base = tmp_home("homespaced-base");
        let home = base.join("a home with spaces");
        std::fs::create_dir_all(&home).unwrap();
        write_backends(&home, "printf %s {home}");
        assert_eq!(fetch_value(&home, "scratch", "unused").unwrap(), home.to_string_lossy());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn name_and_home_placeholders_both_substitute_correctly_together() {
        let home = tmp_home("bothplaceholders");
        write_backends(&home, "printf '%s:%s' {home} {name}");
        assert_eq!(
            fetch_value(&home, "scratch", "my-key").unwrap(),
            format!("{}:my-key", home.to_string_lossy())
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A key that happens to literally CONTAIN the text `{home}` must not
    /// make [`expand_template`] re-scan its own (already-quoted, already
    /// substituted) output for a second `{home}` token — module doc's
    /// "single left-to-right scan over the ORIGINAL template" guarantee.
    #[test]
    fn a_key_containing_the_literal_home_token_is_not_re_scanned() {
        let home = tmp_home("literaltoken");
        write_backends(&home, "printf %s {name}");
        assert_eq!(fetch_value(&home, "scratch", "weird{home}key").unwrap(), "weird{home}key");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── has_value (P-67, "warn before overwrite") ───────────────────────

    #[test]
    fn has_value_is_true_when_the_get_template_succeeds() {
        let home = tmp_home("hasvalue-true");
        write_backends(&home, "printf %s {name}");
        assert!(has_value(&home, "scratch", "stored-value"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn has_value_is_false_when_the_get_template_fails() {
        let home = tmp_home("hasvalue-false");
        write_backends(&home, "false");
        assert!(!has_value(&home, "scratch", "x"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn has_value_is_false_on_an_unknown_backend() {
        let home = tmp_home("hasvalue-unknown");
        write_backends(&home, "printf %s {name}");
        assert!(!has_value(&home, "nope", "x"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_seeded_file_backend_reports_no_value_until_one_is_stored() {
        let home = tmp_home("hasvalue-file");
        seed_default_backends(&home).unwrap();
        assert!(!has_value(&home, "file", "my-secret-key"), "a fresh file backend must report no stored value");
        store_value(&home, "file", "my-secret-key", "the-stored-value").unwrap();
        assert!(has_value(&home, "file", "my-secret-key"), "after a store, has_value must report true");
        std::fs::remove_dir_all(&home).ok();
    }

    // ── store_value / `set` templates (P-V4c) ───────────────────────────

    fn write_backend_with_set(home: &Path, get: &str, set: &str) {
        let doc = serde_json::json!({ "scratch": { "get": get, "set": set } });
        std::fs::write(backends_path(home), serde_json::to_vec(&doc).unwrap()).unwrap();
    }

    #[test]
    fn store_value_writes_through_the_set_template_and_fetch_value_reads_it_back() {
        let home = tmp_home("storeroundtrip");
        let out = home.join("out.txt");
        write_backend_with_set(&home, &format!("cat {}", out.display()), &format!("cat > {}", out.display()));
        store_value(&home, "scratch", "unused", "written-value").unwrap();
        assert_eq!(fetch_value(&home, "scratch", "unused").unwrap(), "written-value");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn store_value_errors_cleanly_when_the_backend_has_no_set_template() {
        let home = tmp_home("nosettemplate");
        write_backends(&home, "printf %s {name}"); // get-only, no `set`
        let err = store_value(&home, "scratch", "k", "v").unwrap_err();
        assert!(err.contains("no `set` template"), "{err}");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn store_value_errors_on_an_unknown_backend() {
        let home = tmp_home("storeunknown");
        write_backends(&home, "printf %s {name}");
        assert!(store_value(&home, "nope", "k", "v").is_err());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn store_value_never_leaks_the_value_into_a_failing_set_templates_error() {
        let home = tmp_home("storestderrleak");
        write_backend_with_set(&home, "printf %s {name}", "printf 'SENTINEL-STDERR-XYZ' 1>&2; exit 1");
        let err = store_value(&home, "scratch", "k", "the-value").unwrap_err();
        assert!(!err.contains("the-value"), "value leaked into the returned error: {err}");
        assert!(!err.contains("SENTINEL"), "stderr leaked into the returned error: {err}");
        assert!(err.contains("exited"), "{err}");
        std::fs::remove_dir_all(&home).ok();
    }


    // ── seed_default_backends / the built-in `file` backend (P-V4c) ────

    #[test]
    fn seed_default_backends_writes_the_file_backend_when_absent() {
        let home = tmp_home("seedabsent");
        assert!(!backends_path(&home).exists());
        seed_default_backends(&home).unwrap();
        let backends = load_backends(&home).unwrap();
        let file_backend = backends.0.get("file").expect("seeded `file` backend");
        assert_eq!(file_backend.get, FILE_BACKEND_GET);
        assert_eq!(file_backend.set.as_deref(), Some(FILE_BACKEND_SET));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn seed_default_backends_never_touches_an_existing_backends_json() {
        let home = tmp_home("seedpresent");
        std::fs::create_dir_all(&home).unwrap();
        let existing = br#"{"custom":{"get":"echo hi"}}"#;
        std::fs::write(backends_path(&home), existing).unwrap();
        seed_default_backends(&home).unwrap();
        let after = std::fs::read(backends_path(&home)).unwrap();
        assert_eq!(after, existing, "seeding must never touch an existing backends.json");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The file-modes contract (P-V4c phase brief): the seeded `file`
    /// backend's `set` template must leave a `0700` store dir and a `0600`
    /// secret file behind — asserted directly against a real filesystem,
    /// not merely implied by the template text.
    #[test]
    fn the_seeded_file_backend_writes_0600_files_under_a_0700_store_dir() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("filemodes");
        seed_default_backends(&home).unwrap();
        store_value(&home, "file", "my-secret-key", "the-stored-value").unwrap();

        let store_dir = home.join("store");
        let dir_mode = std::fs::metadata(&store_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "store dir must be 0700, got {dir_mode:o}");

        let file_path = store_dir.join("my-secret-key");
        let file_mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "stored secret file must be 0600, got {file_mode:o}");

        assert_eq!(std::fs::read_to_string(&file_path).unwrap(), "the-stored-value");
        assert_eq!(fetch_value(&home, "file", "my-secret-key").unwrap(), "the-stored-value");
        std::fs::remove_dir_all(&home).ok();
    }
}
