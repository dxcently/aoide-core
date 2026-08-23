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
//! `overwrite:false` `put` should be refused: when a backend carries no
//! `has` template it just runs the `get` template and reports
//! success/failure, since that IS every backend's existence contract
//! already (`README.md`'s "Backend presets" table). An OPTIONAL `has`
//! template (P-G1, task #70) lets a backend answer existence more cheaply
//! or more honestly than re-running `get` and discarding the value — when
//! present, [`has_value`] runs IT instead, treating exit 0 as "has a
//! value" — no new per-backend primitive REQUIRED, `has` is purely
//! additive.
//!
//! ## The built-in `age` backend (P-G1)
//!
//! A SECOND seeded (not merely documented) built-in, beside `file`:
//! age-encrypted `0600` files under `<secrets_home>/values/`, decrypted
//! with an identity file this crate lazily mints on first use
//! ([`mint_age_identity_if_needed`]). The actual ciphertext read/write
//! stays entirely template-driven (`AGE_BACKEND_GET`/`AGE_BACKEND_SET`,
//! shelled via `sh -c` exactly like every other backend, house rule 7) —
//! only the ONE-TIME identity bootstrap (`age.key`/`age.recipient`) is
//! real Rust I/O, the same precedent `enroll::generate_secret`/`store::
//! save_totp_secret` already set for the TOTP secret: key MATERIAL is
//! bootstrap state, not "this backend's bytes" the template mechanism
//! owns. Minting happens ONLY from the broker-side `put`/SET path
//! (`broker::put_gate`, "the same code path that runs SET templates") —
//! NEVER from a `get`/GET path: a missing `age.key` on GET is
//! [`missing_age_identity_hint`], a taught error, never an auto-mint (a
//! GET can only ever decrypt; minting an identity there would hand back
//! nothing useful and silently create key material nobody asked for on a
//! plain resolve/read attempt). A missing `age`/`age-keygen` binary on
//! PATH — either from a `get`/`set` template's own `sh -c` exiting 127
//! (universally "command not found"), or from [`mint_age_identity_if_needed`]'s
//! own `age-keygen` spawn failing — is [`missing_age_binary_hint`], the
//! same "name the package to install" idiom `home::describe_home_file_error`/
//! `client::describe_connect_error` already hold in this crate.
//!
//! `aoide`'s own two built-in stores (`file`, `age`) are the only backend
//! IMPLEMENTATIONS this crate supports today — `pass`/`gopass`/`bw`/`sops`
//! remain DOCUMENTATION-ONLY presets (below): copy the shape into
//! `backends.json` by hand, but integrating with any of those tools is
//! unsupported, untested territory this crate makes no promise about.
//!
//! **`age`-NAMED is not the same as `age`-CONFIGURED (P-G1 review fix,
//! task #70).** An existing deployment's `backends.json` can predate this
//! phase entirely — `file` only, no `age` entry — and `secrets add`'s
//! DEFAULT FLIP (below) records `backend: "age"` on a brand-new policy
//! regardless of what `backends.json` actually contains, since seeding
//! never touches an already-present file ([`seed_default_backends`]).
//! Both entry points check "is `age` actually a configured backend" BEFORE
//! doing anything `age`-specific: [`fetch_value`] runs the ordinary
//! `unknown backend` lookup before its identity check, so an unconfigured
//! `age` policy's GET reports the true cause rather than
//! [`missing_age_identity_hint`]'s "run `secrets put` to mint" (which
//! would be actively wrong there — `put` hits the identical unknown-backend
//! wall); `broker::put_gate` calls [`backend_is_known`] before
//! [`mint_age_identity_if_needed`], so a doomed `put` against an
//! unconfigured `age` policy never mints a REAL identity first.
//!
//! ## Closing the deployment gap: additive backfill (P-G2, task #72)
//!
//! The P-G1 review fix above only ever REPORTED the "unconfigured `age`"
//! gap honestly; it never closed it. [`backfill_missing_backends`] closes
//! it: it runs every broker startup, right after [`seed_default_backends`]
//! (`broker::serve`'s doc). Where seeding only acts on an ABSENT
//! `backends.json`, backfill acts on an EXISTING one, adding whichever
//! built-in entry (`file`/`age`) is missing BY NAME and never touching an
//! entry — built-in or custom — that's already there.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// One named backend: a `get` fetch-command template, an OPTIONAL `set`
/// store-command template (P-V4c) — a backend with no `set` is read-only —
/// and an OPTIONAL `has` existence-probe template (P-G1, task #70).
/// `#[serde(default)]` on both optional fields means a `backends.json`
/// written before either field existed loads unchanged: `set` absent stays
/// read-only, `has` absent falls back to [`has_value`]'s pre-existing
/// `fetch_value(...).is_ok()` probe exactly as before this field existed.
#[derive(Debug, Clone, Deserialize)]
pub struct Backend {
    pub get: String,
    #[serde(default)]
    pub set: Option<String>,
    #[serde(default)]
    pub has: Option<String>,
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

    // The built-in `age` backend's GET half: a missing identity is a
    // taught error, NEVER an auto-mint (module doc) — checked before the
    // template even runs, so this is deterministic and needs no real
    // `age` binary to exercise. Checked AFTER the backend lookup above
    // (P-G1 review fix): an `age` policy against a `backends.json` that
    // predates this phase (no `age` entry — an existing deployment,
    // `secrets add`'s new default flip) must report the TRUE cause,
    // `unknown backend \`age\``, never this hint — "run `secrets put` to
    // mint" is actively wrong advice there, since `store_value` hits the
    // identical unknown-backend wall.
    if backend_name == "age" && !secrets_home.join("age.key").exists() {
        return Err(missing_age_identity_hint());
    }
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
        // `sh -c`'s own exit 127 universally means "command not found" —
        // for the built-in `age` backend (whose templates shell out to
        // nothing else) that is unambiguous, so it earns the taught error
        // naming the package to install rather than a bare "exited 127".
        if backend_name == "age" && output.status.code() == Some(127) {
            return Err(missing_age_binary_hint());
        }
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
/// an existing value, and the broker-side check backing that lives here).
/// **P-G1 (task #70) adds an OPTIONAL per-backend `has` template**: when
/// [`Backend::has`] is present, this runs THAT template instead and treats
/// exit 0 as "has a value" — a backend can answer more cheaply (`test -f`,
/// no need to read and discard a whole value) or more honestly than
/// re-running `get`. **When `has` is ABSENT, behavior is preserved EXACTLY
/// as before this field existed**: runs the SAME `get` template
/// [`fetch_value`] would and treats success as "has a value", any failure
/// (a missing file, an unknown backend, a spawn error, a non-zero exit,
/// ...) as "no stored value yet". This is exactly the contract every `get`
/// template in this crate's "Backend presets" table already commits to —
/// `cat`, `pass show`, `gopass show -o`, `bw get password`, `sops -d
/// --extract` all exit non-zero on a missing entry and zero with the value
/// on stdout otherwise — so the fallback needs no new per-backend
/// primitive either. A backend that is merely misconfigured (unknown name,
/// a spawn failure) also reads as "no stored value" here — harmless, since
/// [`store_value`] re-checks the same policy/backend on the write that
/// follows and surfaces the real error there if the caller proceeds.
pub fn has_value(secrets_home: &Path, backend_name: &str, key: &str) -> bool {
    let Ok(backends) = load_backends(secrets_home) else {
        return false;
    };
    let Some(backend) = backends.0.get(backend_name) else {
        return false;
    };
    match &backend.has {
        Some(has_template) => run_has_template(secrets_home, backend_name, key, has_template),
        None => fetch_value(secrets_home, backend_name, key).is_ok(),
    }
}

/// Run a backend's OWN `has` template (P-G1) and report its exit status —
/// the ONE place this crate treats a template's success/failure as the
/// answer itself rather than reading its stdout. Any spawn failure reads as
/// "no stored value", the same tolerant shape [`has_value`]'s `get`-probe
/// fallback already holds.
fn run_has_template(secrets_home: &Path, backend_name: &str, key: &str, template: &str) -> bool {
    let command = expand_template(template, secrets_home, key);
    match std::process::Command::new("sh").arg("-c").arg(&command).output() {
        Ok(output) => output.status.success(),
        Err(e) => {
            eprintln!("[aoide/secrets] spawning backend `{backend_name}`'s has template: {e}");
            false
        }
    }
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
        // Same taught-error treatment as `fetch_value`'s own exit-127 case
        // — see that function's comment.
        if backend_name == "age" && output.status.code() == Some(127) {
            return Err(missing_age_binary_hint());
        }
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
/// P-G1 (task #70): a cheap `test -f`, never a `cat` whose stdout would
/// just be discarded — see [`has_value`]'s own doc for why this is now
/// possible at all.
const FILE_BACKEND_HAS: &str = "test -f {home}/store/{name}";

/// The built-in `age` backend's `get`/`set`/`has` templates (P-G1, task
/// #70) — the module doc's "The built-in `age` backend" section has the
/// full design. `age -d -i {home}/age.key` decrypts; the `set` template
/// (re)creates `<home>/values/` (`0700`, same `mkdir -p -m` idiom as
/// `file`'s own `store/`) and pipes stdin through `age -e -R
/// {home}/age.recipient -o ...` — `age -o` writes the ciphertext itself
/// (unlike `file`'s `install -m 0600 /dev/stdin`, `age` has no "write with
/// this mode" flag), so the trailing `chmod 0600` is what actually locks
/// the file down; without it the file's mode would drift with the ambient
/// umask, the same problem `home::secure_file`/`secure_dir` exist to close
/// elsewhere in this crate.
const AGE_BACKEND_GET: &str = "age -d -i {home}/age.key {home}/values/{name}.age";
const AGE_BACKEND_SET: &str =
    "mkdir -p -m 0700 {home}/values && age -e -R {home}/age.recipient -o {home}/values/{name}.age && chmod 0600 {home}/values/{name}.age";
const AGE_BACKEND_HAS: &str = "test -f {home}/values/{name}.age";

/// Seed `backends.json` with the two built-in backends WHEN ABSENT — never
/// when a `backends.json` already exists (module doc: this is exactly the
/// "seeded once, at broker startup" contract). `file` shipped SEEDED since
/// P-V4c; `age` joins it at P-G1 (task #70), same seeding site, same
/// exception status ("Backend presets", `README.md`) — `pass`/`gopass`/
/// `bw`/`sops` stay documentation-only presets, never seeded. Called from
/// [`crate::broker::serve`] (the seeding site, module doc) immediately
/// after `secrets_home` is created/secured and before the accept loop
/// starts, so every resolve/put reaching a backend — `file`/`age` included
/// — always finds a `backends.json` on disk, without this crate ever
/// special-casing either backend in the resolve/put code paths themselves.
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
        "file": { "get": FILE_BACKEND_GET, "set": FILE_BACKEND_SET, "has": FILE_BACKEND_HAS },
        "age": { "get": AGE_BACKEND_GET, "set": AGE_BACKEND_SET, "has": AGE_BACKEND_HAS },
    });
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &bytes)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

/// The taught error for a missing `age.key` on a GET (module doc: never an
/// auto-mint — minting is SET-only, from `broker::put_gate`'s own critical
/// section). Deterministic and value-free, and — unlike a bare `age`
/// stderr string — needs no real `age` binary on `PATH` to reach or to
/// unit-test.
fn missing_age_identity_hint() -> String {
    "no age identity found for this secrets home yet — run `secrets put <name>` once to lazily mint \
     `age.key`/`age.recipient` (SET mints; GET never does), or provision `age.key`/`age.recipient` \
     out of band"
        .to_string()
}

/// The taught error for a missing `age`/`age-keygen` binary — the SAME
/// "name the package to install" idiom `home::describe_home_file_error`/
/// `client::describe_connect_error` already hold in this crate (grep
/// `describe_` for the precedent), applied to a runtime shell-out rather
/// than a file/socket error.
fn missing_age_binary_hint() -> String {
    "the `age` backend needs the `age`/`age-keygen` CLI on PATH (age-encryption.org) — install it \
     (e.g. `nix profile install nixpkgs#age`, or your distro's `age` package) and retry"
        .to_string()
}

/// Map an `age-keygen` SPAWN failure (as opposed to a nonzero exit — this
/// is `Command::spawn`/`Command::output` itself returning `Err`, meaning
/// the binary was never found at all) into the same taught error a missing
/// `age` binary gets from the template path. Any OTHER spawn-error kind
/// (permissions, resource exhaustion, ...) rides through unenriched, same
/// restraint `home::describe_home_file_error`'s own match holds.
fn describe_missing_age_keygen(err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        missing_age_binary_hint()
    } else {
        format!("spawning age-keygen: {err}")
    }
}

/// **Additive backfill for an EXISTING `backends.json` (P-G2, task #72) —
/// the deployment-gap fix `README.md`'s "A second, related deployment gap"
/// note left open.** [`seed_default_backends`] only ever writes when the
/// file is entirely ABSENT (deliberate, unchanged); this is its sibling for
/// the far more common live case — a `backends.json` that already exists
/// but predates one or both built-ins (a pre-P-G1 deployment with `file`
/// only, or a hand-edited file missing `has`). Adds whatever built-in entry
/// is MISSING BY NAME, and nothing else: an entry already present under a
/// built-in's name — `file` or `age` — is NEVER touched, even if an
/// operator has customized it (a custom `get`/`set` shape under the name
/// `age`, say) — presence of the KEY is the only test, never a content
/// comparison. Every OTHER entry in the file (a `pass`/`gopass`/`bw`/`sops`
/// row, or any operator-named custom backend) rides through byte-for-byte:
/// this function loads the whole document as an ordered `serde_json::Map`
/// (never a typed `Backends`/`Backend` round trip, which would reorder or
/// reformat fields the built-ins loader doesn't itself care about) and only
/// ever `insert`s a new top-level key, never touching an existing `Value`.
/// **No write at all when nothing was missing** — checked before ever
/// opening a temp file — so re-running this on an already-complete
/// `backends.json` (the common case: called every broker startup, right
/// after [`seed_default_backends`]) never churns its mtime. Same
/// write-temp-then-rename + [`crate::home::secure_file`] discipline as
/// [`seed_default_backends`]. A missing `backends.json` is NOT this
/// function's job — it returns `Ok(())` without writing, leaving the
/// absent-file case entirely to [`seed_default_backends`] (called first, at
/// the same startup site) so the two functions never race to create the
/// same file two different ways.
pub fn backfill_missing_backends(secrets_home: &Path) -> std::io::Result<()> {
    let path = backends_path(secrets_home);
    if !path.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(&path)?;
    let mut doc: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?;

    let builtins: [(&str, serde_json::Value); 2] = [
        (
            "file",
            serde_json::json!({ "get": FILE_BACKEND_GET, "set": FILE_BACKEND_SET, "has": FILE_BACKEND_HAS }),
        ),
        (
            "age",
            serde_json::json!({ "get": AGE_BACKEND_GET, "set": AGE_BACKEND_SET, "has": AGE_BACKEND_HAS }),
        ),
    ];

    let mut added = false;
    for (name, value) in builtins {
        if !doc.contains_key(name) {
            doc.insert(name.to_string(), value);
            added = true;
        }
    }
    if !added {
        return Ok(());
    }

    let tmp = path.with_extension("json.tmp");
    let out = serde_json::to_vec_pretty(&doc)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, &out)?;
    crate::home::secure_file(&tmp)?;
    std::fs::rename(&tmp, &path)
}

/// Is `name` an actually-configured backend in this home's
/// `backends.json`? (P-G1 review fix, task #70.) `broker::put_gate` calls
/// this BEFORE [`mint_age_identity_if_needed`] so a `policy.backend ==
/// "age"` never mints a REAL identity — real `age-keygen` shell-outs, real
/// `age.key`/`age.recipient` files — for a `put` that is doomed anyway
/// (an existing deployment's `backends.json` predates P-G1 and has no
/// `age` entry, module doc's "The built-in `age` backend" section /
/// `README.md`'s deployment-gap note); that `put` still correctly fails
/// with `unknown backend \`age\`` from [`has_value`]/[`store_value`]
/// either way, just without the wasted side effect first. Any
/// `load_backends` error (missing/corrupt `backends.json`) reads as
/// "not known" here — harmless, since the same call fails again, with the
/// real I/O error, the moment [`has_value`]/[`store_value`] runs.
pub fn backend_is_known(secrets_home: &Path, name: &str) -> bool {
    load_backends(secrets_home).map(|b| b.0.contains_key(name)).unwrap_or(false)
}

/// Lazily mint this host's age identity (`{home}/age.key`, `0600`) and its
/// derived recipient (`{home}/age.recipient`, `0600`) via `age-keygen` —
/// real Rust I/O, not a template, the SAME one-time-bootstrap shape
/// `enroll::generate_secret`/`store::save_totp_secret` already establish
/// for the TOTP secret (module doc): the identity's own key MATERIAL is
/// bootstrap state, not "this backend's bytes" the template mechanism
/// owns — the secret's own ciphertext stays entirely template-driven via
/// `AGE_BACKEND_GET`/`AGE_BACKEND_SET`. Called ONLY from the broker-side
/// `put`/SET path (`broker::put_gate`, "the same code path that runs SET
/// templates") — NEVER from a GET path (module doc: a missing identity on
/// GET is [`missing_age_identity_hint`], not this function).
///
/// `Ok(true)` when THIS call minted a fresh identity — the caller uses
/// that to decide whether to audit "age identity minted"; `Ok(false)` when
/// `age.key` already existed (a pure no-op: never re-mints, never touches
/// an existing key or recipient file, since `age-keygen -o` itself refuses
/// to overwrite an existing output file — this early return is what keeps
/// this function itself idempotent even without relying on that). A
/// missing `age-keygen` binary is [`describe_missing_age_keygen`], the
/// same taught error the backend's own `get`/`set` templates give for a
/// missing `age`.
pub fn mint_age_identity_if_needed(secrets_home: &Path) -> Result<bool, String> {
    let key_path = secrets_home.join("age.key");
    if key_path.exists() {
        return Ok(false);
    }
    std::fs::create_dir_all(secrets_home).map_err(|e| format!("creating {}: {e}", secrets_home.display()))?;

    let keygen = std::process::Command::new("age-keygen")
        .arg("-o")
        .arg(&key_path)
        .output()
        .map_err(|e| describe_missing_age_keygen(&e))?;
    if !keygen.status.success() {
        eprintln!(
            "[aoide/secrets] age-keygen exited {}: {}",
            keygen.status,
            String::from_utf8_lossy(&keygen.stderr).trim()
        );
        return Err(format!("age-keygen exited {}", keygen.status));
    }
    crate::home::secure_file(&key_path).map_err(|e| format!("securing {}: {e}", key_path.display()))?;

    let recipient_path = secrets_home.join("age.recipient");
    let show = std::process::Command::new("age-keygen")
        .arg("-y")
        .arg("-o")
        .arg(&recipient_path)
        .arg(&key_path)
        .output()
        .map_err(|e| describe_missing_age_keygen(&e))?;
    if !show.status.success() {
        eprintln!(
            "[aoide/secrets] age-keygen -y exited {}: {}",
            show.status,
            String::from_utf8_lossy(&show.stderr).trim()
        );
        return Err(format!("age-keygen -y exited {}", show.status));
    }
    crate::home::secure_file(&recipient_path).map_err(|e| format!("securing {}: {e}", recipient_path.display()))?;

    Ok(true)
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
        assert_eq!(file_backend.has.as_deref(), Some(FILE_BACKEND_HAS));
        std::fs::remove_dir_all(&home).ok();
    }

    /// P-G1 (task #70): `age` is seeded ALONGSIDE `file`, not merely
    /// documented.
    #[test]
    fn seed_default_backends_also_writes_the_age_backend_when_absent() {
        let home = tmp_home("seedabsent-age");
        seed_default_backends(&home).unwrap();
        let backends = load_backends(&home).unwrap();
        let age_backend = backends.0.get("age").expect("seeded `age` backend");
        assert_eq!(age_backend.get, AGE_BACKEND_GET);
        assert_eq!(age_backend.set.as_deref(), Some(AGE_BACKEND_SET));
        assert_eq!(age_backend.has.as_deref(), Some(AGE_BACKEND_HAS));
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

    // ── the `has` template (P-G1, task #70) ─────────────────────────────

    fn write_backend_with_has(home: &Path, get: &str, has: &str) {
        let doc = serde_json::json!({ "scratch": { "get": get, "has": has } });
        std::fs::write(backends_path(home), serde_json::to_vec(&doc).unwrap()).unwrap();
    }

    #[test]
    fn has_value_uses_the_has_template_when_present() {
        let home = tmp_home("has-template-present");
        // `get` would SUCCEED, but `has` says no — proving the `has`
        // template wins over the fallback whenever both are present.
        write_backend_with_has(&home, "printf %s {name}", "false");
        assert!(!has_value(&home, "scratch", "x"), "a `has` template must win over a would-succeed `get`");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn has_value_reports_true_via_a_has_template_even_when_get_would_fail() {
        let home = tmp_home("has-template-true-get-false");
        write_backend_with_has(&home, "false", "true");
        assert!(has_value(&home, "scratch", "x"), "a `has` template must be consulted, not the failing `get`");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The exact live shape: a `backends.json` predating `has` carries no
    /// such key at all — behavior must be BYTE-IDENTICAL to before this
    /// field existed (`fetch_value(...).is_ok()`).
    #[test]
    fn has_value_falls_back_to_the_get_probe_when_has_is_absent() {
        let home = tmp_home("has-template-absent");
        write_backends(&home, "printf %s {name}"); // no `has` field at all
        assert!(has_value(&home, "scratch", "x"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_backends_json_predating_the_has_field_loads_cleanly() {
        let home = tmp_home("old-shape-no-has");
        let doc = br#"{"file":{"get":"cat {home}/store/{name}","set":"install -m 0600 /dev/stdin {home}/store/{name}"}}"#;
        std::fs::write(backends_path(&home), doc).unwrap();
        let backends = load_backends(&home).unwrap();
        let file_backend = backends.0.get("file").unwrap();
        assert!(file_backend.has.is_none());
        assert!(file_backend.set.is_some());
        std::fs::remove_dir_all(&home).ok();
    }

    // ── the built-in `age` backend (P-G1, task #70) ─────────────────────

    /// Feature-detects a real `age`/`age-keygen` on `PATH` the SAME way the
    /// production code itself does (a spawn attempt, not a `which`/`PATH`
    /// scan) — tests that need the real binaries skip with a printed reason
    /// rather than failing when this dev machine/CI box doesn't have `age`
    /// installed.
    fn age_tools_available() -> bool {
        let age_keygen = std::process::Command::new("age-keygen").arg("--version").output();
        let age = std::process::Command::new("age").arg("--version").output();
        matches!(age_keygen, Ok(o) if o.status.code().is_some()) && matches!(age, Ok(o) if o.status.code().is_some())
    }

    #[test]
    fn age_identity_is_lazily_minted_on_first_call_and_locked_to_0600() {
        if !age_tools_available() {
            eprintln!("skipping age_identity_is_lazily_minted_on_first_call_and_locked_to_0600: age/age-keygen not found on PATH");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("age-mint");
        let key_path = home.join("age.key");
        let recipient_path = home.join("age.recipient");
        assert!(!key_path.exists());
        assert!(!recipient_path.exists());

        let minted = mint_age_identity_if_needed(&home).unwrap();
        assert!(minted, "the first call must mint a fresh identity");

        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "age.key must be 0600, got {key_mode:o}");
        let recipient_mode = std::fs::metadata(&recipient_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(recipient_mode, 0o600, "age.recipient must be 0600, got {recipient_mode:o}");

        let recipient = std::fs::read_to_string(&recipient_path).unwrap();
        assert!(recipient.trim().starts_with("age1"), "recipient should be an age1... public key: {recipient}");

        let minted_again = mint_age_identity_if_needed(&home).unwrap();
        assert!(!minted_again, "a second call must be a no-op — never re-mint");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_seeded_age_backend_round_trips_a_value_through_a_real_age_binary() {
        if !age_tools_available() {
            eprintln!("skipping the_seeded_age_backend_round_trips_a_value_through_a_real_age_binary: age/age-keygen not found on PATH");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let home = tmp_home("age-roundtrip");
        seed_default_backends(&home).unwrap();
        assert!(mint_age_identity_if_needed(&home).unwrap());

        assert!(!has_value(&home, "age", "my-secret-key"), "a fresh age backend must report no stored value");
        store_value(&home, "age", "my-secret-key", "the-stored-value").unwrap();
        assert!(has_value(&home, "age", "my-secret-key"));
        assert_eq!(fetch_value(&home, "age", "my-secret-key").unwrap(), "the-stored-value");

        let values_dir = home.join("values");
        let dir_mode = std::fs::metadata(&values_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "values dir must be 0700, got {dir_mode:o}");
        let file_mode =
            std::fs::metadata(values_dir.join("my-secret-key.age")).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "the .age file must be 0600, got {file_mode:o}");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn get_on_a_missing_age_identity_is_a_taught_error_and_never_mints() {
        let home = tmp_home("age-missing-identity");
        seed_default_backends(&home).unwrap();
        assert!(!home.join("age.key").exists());

        let err = fetch_value(&home, "age", "my-secret-key").unwrap_err();
        assert_eq!(err, missing_age_identity_hint());
        assert!(!home.join("age.key").exists(), "GET must never mint an identity");
        assert!(!home.join("age.recipient").exists());
        std::fs::remove_dir_all(&home).ok();
    }

    /// Deterministic, no real `age` binary required: `sh -c`'s own exit 127
    /// universally means "command not found", so a fake, definitely-absent
    /// binary name reliably exercises this path.
    #[test]
    fn a_missing_age_binary_produces_a_taught_error_naming_the_package() {
        let home = tmp_home("age-missing-binary");
        // Bypass the missing-IDENTITY check above so the template actually
        // runs and hits the missing-BINARY path instead.
        std::fs::write(home.join("age.key"), b"dummy-identity-for-this-test").unwrap();
        let doc = serde_json::json!({
            "age": { "get": "definitely-not-a-real-age-binary-xyz {name}" }
        });
        std::fs::write(backends_path(&home), serde_json::to_vec(&doc).unwrap()).unwrap();

        let err = fetch_value(&home, "age", "k").unwrap_err();
        assert_eq!(err, missing_age_binary_hint());
        std::fs::remove_dir_all(&home).ok();
    }

    /// P-G1 review fix (task #70): an EXISTING deployment's `backends.json`
    /// predates this phase — it has no `age` entry at all (only `file`,
    /// seeded before P-G1 ever wrote a second built-in). `secrets add`'s
    /// new default records `backend: "age"` on such a home regardless
    /// (`commands::DEFAULT_BACKEND`, decoupled from what `backends.json`
    /// actually contains). A GET against that policy must report the
    /// TRUE cause — `unknown backend \`age\`` — never the age-specific
    /// "run `secrets put` to mint" hint, which would be actively
    /// misleading here: `secrets put` cannot fix this, since `store_value`
    /// hits the exact same "unknown backend" wall (no `set` template to
    /// even find). The `backend_name == "age"` shortcut must never fire
    /// AHEAD of confirming `age` is actually a configured backend.
    #[test]
    fn get_on_an_age_policy_against_a_backends_json_missing_the_age_entry_names_the_true_cause() {
        let home = tmp_home("age-not-configured-get");
        std::fs::create_dir_all(&home).unwrap();
        // Pre-P-G1 shape: `file` only, no `age`, no `has` — exactly what a
        // live deployment's `backends.json` looks like today.
        let pre_existing = br#"{"file":{"get":"cat {home}/store/{name}","set":"install -m 0600 /dev/stdin {home}/store/{name}"}}"#;
        std::fs::write(backends_path(&home), pre_existing).unwrap();

        let err = fetch_value(&home, "age", "foo").unwrap_err();
        assert_eq!(
            err, "unknown backend `age`",
            "an unconfigured `age` backend must report the true cause, not the age-specific mint hint: {err}"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    // ── backfill_missing_backends (P-G2, task #72) ──────────────────────

    /// The exact live shape: a pre-P-G1 deployment's `backends.json` has
    /// `file` only. Backfill must add `age` and leave `file`'s own bytes
    /// byte-identical — proven here by reserializing the ORIGINAL `file`
    /// entry through the same `to_vec_pretty` mechanism the whole document
    /// goes through and comparing the full file, not just structural
    /// equality of the parsed fields.
    #[test]
    fn backfill_adds_age_to_an_existing_file_only_backends_json_and_keeps_file_byte_identical() {
        let home = tmp_home("backfill-file-only");
        std::fs::create_dir_all(&home).unwrap();
        let file_entry = serde_json::json!({ "get": FILE_BACKEND_GET, "set": FILE_BACKEND_SET, "has": FILE_BACKEND_HAS });
        let before = serde_json::json!({ "file": file_entry.clone() });
        std::fs::write(backends_path(&home), serde_json::to_vec_pretty(&before).unwrap()).unwrap();

        backfill_missing_backends(&home).unwrap();

        let after_bytes = std::fs::read(backends_path(&home)).unwrap();
        let expected = serde_json::json!({
            "file": file_entry,
            "age": { "get": AGE_BACKEND_GET, "set": AGE_BACKEND_SET, "has": AGE_BACKEND_HAS },
        });
        assert_eq!(after_bytes, serde_json::to_vec_pretty(&expected).unwrap());

        let backends = load_backends(&home).unwrap();
        assert!(backends.0.contains_key("age"), "age must be backfilled");
        assert_eq!(backends.0.get("file").unwrap().get, FILE_BACKEND_GET, "file entry must be untouched");
        std::fs::remove_dir_all(&home).ok();
    }

    /// A hand-customized `age` entry (an operator's own template, not the
    /// built-in shape) must survive untouched — presence of the NAME is the
    /// only test backfill runs, never a content comparison.
    #[test]
    fn backfill_never_touches_a_customized_entry_under_a_built_ins_name() {
        let home = tmp_home("backfill-custom-age");
        std::fs::create_dir_all(&home).unwrap();
        let custom_age = serde_json::json!({ "get": "my-custom-age-wrapper {name}" });
        let before = serde_json::json!({ "age": custom_age.clone() });
        std::fs::write(backends_path(&home), serde_json::to_vec_pretty(&before).unwrap()).unwrap();

        backfill_missing_backends(&home).unwrap();

        let backends = load_backends(&home).unwrap();
        assert_eq!(backends.0.get("age").unwrap().get, "my-custom-age-wrapper {name}", "customized age must survive untouched");
        assert!(backends.0.contains_key("file"), "the missing built-in (file) must still be backfilled");
        std::fs::remove_dir_all(&home).ok();
    }

    /// A brand-new home (no `backends.json` at all) is NOT backfill's job —
    /// `seed_default_backends` (called first, at the same startup site)
    /// seeds both built-ins; backfill running right after must see nothing
    /// missing and write nothing new (the "fresh home still seeds both"
    /// case, driven through the same two-call startup sequence
    /// `broker::serve` uses).
    #[test]
    fn a_fresh_home_still_seeds_both_builtins_through_the_seed_then_backfill_sequence() {
        let home = tmp_home("backfill-fresh-home");
        assert!(!backends_path(&home).exists());
        seed_default_backends(&home).unwrap();
        backfill_missing_backends(&home).unwrap();

        let backends = load_backends(&home).unwrap();
        assert!(backends.0.contains_key("file"));
        assert!(backends.0.contains_key("age"));
        std::fs::remove_dir_all(&home).ok();
    }

    /// No gratuitous mtime churn: a `backends.json` that already carries
    /// both built-ins must not be rewritten at all — checked by comparing
    /// the file's mtime before and after, not merely its content.
    #[test]
    fn backfill_skips_the_write_when_both_builtins_are_already_present() {
        let home = tmp_home("backfill-noop");
        seed_default_backends(&home).unwrap();
        let before_mtime = std::fs::metadata(backends_path(&home)).unwrap().modified().unwrap();
        let before_bytes = std::fs::read(backends_path(&home)).unwrap();

        // A short sleep so a real rewrite (mtime bumped) would be
        // observable even on a coarse filesystem timestamp clock.
        std::thread::sleep(std::time::Duration::from_millis(20));
        backfill_missing_backends(&home).unwrap();

        let after_mtime = std::fs::metadata(backends_path(&home)).unwrap().modified().unwrap();
        let after_bytes = std::fs::read(backends_path(&home)).unwrap();
        assert_eq!(before_mtime, after_mtime, "backfill must not rewrite a backends.json with nothing missing");
        assert_eq!(before_bytes, after_bytes);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn backfill_is_a_no_op_on_a_missing_backends_json() {
        let home = tmp_home("backfill-missing-file");
        assert!(!backends_path(&home).exists());
        backfill_missing_backends(&home).unwrap();
        assert!(!backends_path(&home).exists(), "backfill must never create the file itself");
        std::fs::remove_dir_all(&home).ok();
    }

}
