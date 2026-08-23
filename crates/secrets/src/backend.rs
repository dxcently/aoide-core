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
//! ## Closing the deployment gap: backfill + migrate (P-G2, task #72)
//!
//! The P-G1 review fix above only ever REPORTED the "unconfigured `age`"
//! gap honestly; it never closed it. Two additive pieces close it here.
//! [`backfill_missing_backends`] runs every broker startup, right after
//! [`seed_default_backends`] (`broker::serve`'s doc): where seeding only
//! acts on an ABSENT `backends.json`, backfill acts on an EXISTING one,
//! adding whichever built-in entry (`file`/`age`) is missing BY NAME and
//! never touching an entry — built-in or custom — that's already there.
//! `secrets migrate <name> [--backend <target>]` (`commands::
//! handle_secrets_migrate`) is the per-secret companion: an admin verb that
//! moves one secret's stored VALUE from its policy's current backend to a
//! target one (default `age`) and flips the policy row, so an operator can
//! actually act on a secret that's been sitting on a newly-backfilled
//! backend instead of just being told about it.
//!
//! ## Bounded shell-outs (task #74)
//!
//! Every `get`/`set`/`has` template execution above now runs through ONE
//! shared, bounded spawn path, [`run_backend_command`] — before this phase,
//! [`fetch_value`], [`store_value`], and `has_value`'s own
//! `run_has_template` each spawned `sh -c` independently, with NO timeout at
//! all (this crate's `AGENTS.md`, KNOWN GAP note, now closed): a wedged
//! template blocked its calling thread forever, and on the `put` path that
//! thread was holding `broker::put_lock` the entire time, serializing every
//! OTHER `put` on this broker behind the one hang. [`backend_timeout`]
//! ([`BACKEND_TIMEOUT_ENV`], default [`DEFAULT_BACKEND_TIMEOUT_SECS`]
//! seconds, tolerant-fallback-parsed like `park::park_timeout`) bounds the
//! wait; a template still running past the deadline has its WHOLE PROCESS
//! GROUP `SIGKILL`ed and reaped ([`kill_process_group`] — never just the
//! immediate `sh`, so a pipeline the template forked can't outlive it, and
//! never a zombie left behind), and the caller gets
//! [`backend_timeout_error`]: the backend name, the op (`get`/`set`/`has`),
//! and the env knob — **never the template text**, which can't carry a
//! secret value in the first place ([`store_value`]'s `value` only ever
//! reaches its child over stdin, never interpolated into the command string
//! [`expand_template`] builds — that function substitutes only `{name}`/
//! `{home}`, neither of which is a secret value). Wall-clock via polling
//! `Child::try_wait`, never a per-child watchdog thread and never
//! `SIGALRM` — see [`run_backend_command`]'s own doc for why stdout/stderr
//! are drained NON-BLOCKINGLY while polling rather than read only after the
//! child exits (a large-output template would otherwise deadlock against
//! its own full pipe with nobody draining it).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

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

/// Env override for how long ANY backend template execution (`get`/`set`/
/// `has`) is allowed to run before [`run_backend_command`] kills it (task
/// #74). Read once per shell-out, never cached — a long-running broker
/// picks up a changed value on its very next call, the same "no
/// re-derivation, no daemon restart needed" shape `park::park_timeout`/
/// `park::park_cap` already hold for their own env overrides.
pub const BACKEND_TIMEOUT_ENV: &str = "AOIDE_SECRETS_BACKEND_TIMEOUT";

/// The default backend timeout: 10 seconds (task requirement) — generous
/// for any well-behaved `get`/`set`/`has` template (a local file read, an
/// `age`/`pass`/`gopass` invocation), tight enough that a wedged one no
/// longer serializes every other `put` behind `broker::put_lock`
/// indefinitely.
pub const DEFAULT_BACKEND_TIMEOUT_SECS: u64 = 10;

/// Resolve [`BACKEND_TIMEOUT_ENV`]: a valid non-negative integer wins,
/// anything else (absent, blank, or unparsable — e.g. an operator typo)
/// falls back to [`DEFAULT_BACKEND_TIMEOUT_SECS`] rather than panicking or
/// silently treating the backend as unbounded again. Same tolerant shape
/// `park::park_timeout`/`park::park_cap` already hold for their own env
/// overrides — documented here as the fallback, not merely implied.
pub fn backend_timeout() -> Duration {
    if let Ok(v) = std::env::var(BACKEND_TIMEOUT_ENV) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            if let Ok(secs) = trimmed.parse::<u64>() {
                return Duration::from_secs(secs);
            }
        }
    }
    Duration::from_secs(DEFAULT_BACKEND_TIMEOUT_SECS)
}

/// Poll interval for [`run_backend_command`]'s wait loop — coarse enough
/// not to busy-spin the broker, fine enough that a fast template (every
/// template in practice) never visibly waits on it.
const BACKEND_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Put `fd` into non-blocking mode — used on a backend child's piped
/// stdout/stderr so [`run_backend_command`]'s wait loop can drain both
/// pipes WHILE polling `try_wait`, never only after: a template that
/// writes more than one pipe buffer's worth of output (the OS default is a
/// modest fixed size) would otherwise block on the CHILD side waiting for
/// a reader that only shows up once the process has already exited — a
/// self-inflicted deadlock this crate's own timeout must not introduce.
fn set_nonblocking(fd: std::os::fd::RawFd) {
    // SAFETY: `fd` is a pipe fd this process just created via `Stdio::
    // piped()` and still owns; `fcntl(F_GETFL)`/`fcntl(F_SETFL)` are
    // ordinary, always-defined operations on any fd this process holds.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// Drain whatever is CURRENTLY available on a non-blocking pipe into `buf`,
/// without blocking — `WouldBlock` (nothing ready right now) and a clean
/// EOF both just stop the loop; any other read error is swallowed the same
/// tolerant way. This is best-effort output CAPTURE for the eventual
/// success/error message, not the mechanism that decides success or
/// failure — the child's own exit status is.
fn drain_nonblocking<R: Read>(reader: &mut R, buf: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

/// `SIGKILL` the child's WHOLE PROCESS GROUP, then reap it — never just the
/// immediate `sh`. [`run_backend_command`] spawns every child as its own
/// process-group leader (`CommandExt::process_group(0)`) specifically so
/// this can address `-pid` (the process-group form of `kill(2)`) and take
/// out anything the template itself forked (a pipeline, a backgrounded
/// helper), not only `sh -c` itself — killing only the shell would leave
/// such children running, wedged the same way, merely orphaned instead of
/// dead. `child.wait()` afterward reaps it — the exit status is discarded
/// (a killed child's own status tells us nothing new; the taught timeout
/// error is already decided by the time this runs), but the reap itself is
/// NOT optional: skipping it leaves a zombie behind.
fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    // SAFETY: `pid` is this process's own child, spawned moments ago as its
    // own process-group leader, so `-pid` addresses exactly that group and
    // nothing else running on this host.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

/// Why [`wait_bounded`] returned without a `(status, stdout, stderr)`
/// triple: either the deadline passed (the child's whole process group has
/// already been `SIGKILL`ed and reaped, [`kill_process_group`]) or
/// `Child::try_wait` itself returned an `Err` (rare — carries the raw
/// `io::Error` so each caller can word its own message; [`kill_process_group`]
/// was NOT called in this arm, since the child may still be perfectly
/// healthy and `try_wait` merely failed to ask).
enum WaitOutcome {
    TimedOut,
    WaitFailed(std::io::Error),
}

/// Poll `child` until it exits or [`backend_timeout`] elapses, draining
/// `stdout_pipe`/`stderr_pipe` non-blockingly on every tick — the ONE wait/
/// kill/reap loop [`run_backend_command`] (a `sh -c` template) and
/// [`run_age_keygen`] (the plain argv `age-keygen` bootstrap, task #74
/// review fix — P-G3) both build on, so a future change to the wait
/// mechanism (still wall-clock `try_wait` polling, never a watchdog thread
/// or `SIGALRM`) has exactly one place to change. `stdout_pipe`/
/// `stderr_pipe` are taken by value (moved out of the `Child` by the
/// caller first) since `Child::try_wait` needs `child` mutably borrowed on
/// every tick while the pipes are read independently. On success, returns
/// the exit status plus whatever was captured on both pipes, including one
/// FINAL drain after the child is confirmed exited (output written between
/// the last poll and the process actually exiting would otherwise be
/// lost). On timeout, kills and reaps the whole process group and returns
/// [`WaitOutcome::TimedOut`] — the caller decides how to word that as a
/// value-free error; this function never sees a backend name, an op, or a
/// template/command string, so there is nothing here that COULD leak one.
fn wait_bounded(
    child: &mut std::process::Child,
    mut stdout_pipe: Option<std::process::ChildStdout>,
    mut stderr_pipe: Option<std::process::ChildStderr>,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), WaitOutcome> {
    if let Some(ref out) = stdout_pipe {
        set_nonblocking(out.as_raw_fd());
    }
    if let Some(ref err) = stderr_pipe {
        set_nonblocking(err.as_raw_fd());
    }

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let deadline = Instant::now() + backend_timeout();

    let status = loop {
        if let Some(ref mut out) = stdout_pipe {
            drain_nonblocking(out, &mut stdout_buf);
        }
        if let Some(ref mut err) = stderr_pipe {
            drain_nonblocking(err, &mut stderr_buf);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(child);
                    return Err(WaitOutcome::TimedOut);
                }
                std::thread::sleep(BACKEND_POLL_INTERVAL);
            }
            Err(e) => return Err(WaitOutcome::WaitFailed(e)),
        }
    };
    // One final drain — output written between the last poll and the
    // process actually exiting would otherwise be lost.
    if let Some(ref mut out) = stdout_pipe {
        drain_nonblocking(out, &mut stdout_buf);
    }
    if let Some(ref mut err) = stderr_pipe {
        drain_nonblocking(err, &mut stderr_buf);
    }
    Ok((status, stdout_buf, stderr_buf))
}

/// The taught error for a backend shell-out that outran
/// [`BACKEND_TIMEOUT_ENV`] — names the backend, the op (`get`/`set`/
/// `has`), and the env knob to raise it. **Never the template text**: a
/// `set` template's VALUE only ever reaches its child over the child's OWN
/// stdin ([`store_value`]'s `run_backend_command(..., Some(value))` call
/// below), never interpolated into the command string itself —
/// [`expand_template`] substitutes only `{name}` (the policy's `key`) and
/// `{home}` (`secrets_home`), neither of which is a secret value — so there
/// is nothing value-bearing in a template's expanded command to leak here
/// even in principle. This function doesn't take the command as a
/// parameter at all, so there is no argument to accidentally echo later.
fn backend_timeout_error(backend_name: &str, op: &str) -> String {
    format!(
        "backend `{backend_name}` ({op}) timed out after {}s (`{BACKEND_TIMEOUT_ENV}`) — raise the knob, or fix the hung template",
        backend_timeout().as_secs()
    )
}

/// **THE shared choke point every `get`/`set`/`has` template execution in
/// this crate routes through (task #74).** Before this function existed,
/// [`fetch_value`], [`store_value`], and `has_value`'s own
/// `run_has_template` each spawned their own `sh -c` independently — three
/// copies, so a per-site timeout would have needed three separate fixes to
/// actually cover every backend shell-out this crate makes. The `age`
/// backend and `secrets migrate` (P-G1/P-G2) already multiplied the CALL
/// SITES onto `fetch_value`/`store_value`/`has_value` without multiplying
/// this spawn logic, so unifying here is what makes bounding it a
/// one-function fix rather than an N-site one.
///
/// Runs `sh -c command` as its own process group
/// (`CommandExt::process_group(0)` — see [`kill_process_group`]'s doc for
/// why), stdin fed from `stdin_data` when `Some` (a plain `Stdio::null()`
/// when `None`, so a `get`/`has` template that unexpectedly reads stdin
/// sees immediate EOF rather than blocking on it), stdout/stderr drained
/// NON-BLOCKINGLY while polling `Child::try_wait` — never via `Command::
/// output`'s own blocking wait, which has no bound at all. On success,
/// returns raw stdout bytes (trimming/UTF-8 interpretation stays the
/// caller's job, unchanged from before this function existed). On a
/// non-zero exit, the SAME value-free-error / stderr-eprintln-only /
/// age-exit-127 discipline [`fetch_value`]/[`store_value`] always held,
/// now written once. On a timeout (wall-clock, [`backend_timeout`]), kills
/// and reaps the WHOLE child process group and returns
/// [`backend_timeout_error`] — never a zombie left behind, never the
/// template text in the error.
fn run_backend_command(backend_name: &str, op: &str, command: &str, stdin_data: Option<&str>) -> Result<Vec<u8>, String> {
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd.stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // New process group, pgid == this child's own pid — see
    // `kill_process_group`'s doc for why a timeout kill needs this.
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawning backend `{backend_name}` ({op}): {e}"))?;

    if let Some(data) = stdin_data {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("backend `{backend_name}` ({op}): could not open its stdin"))?;
        // A pipe write this size (a secret value, a policy key) fits well
        // inside one pipe buffer in practice, so this blocking write does
        // not itself need the timeout treatment — the documented edge this
        // leaves open is a pathologically large value against a template
        // that never reads its stdin at all (this crate's "ONE VALUE PER
        // SECRET" invariant keeps values small in the first place).
        stdin
            .write_all(data.as_bytes())
            .map_err(|e| format!("writing to backend `{backend_name}` ({op})'s stdin: {e}"))?;
        // `stdin` drops here, closing the write end (EOF) before the wait
        // loop starts — same "close stdin before waiting" discipline
        // `store_value` held before this function existed.
    }

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (status, stdout_buf, stderr_buf) = match wait_bounded(&mut child, stdout_pipe, stderr_pipe) {
        Ok(v) => v,
        Err(WaitOutcome::TimedOut) => return Err(backend_timeout_error(backend_name, op)),
        Err(WaitOutcome::WaitFailed(e)) => return Err(format!("waiting on backend `{backend_name}` ({op}): {e}")),
    };

    if !status.success() {
        // Full stderr goes ONLY here, to the broker's own stderr — never
        // into the returned `Err` (module doc: it rides the wire reply,
        // the calling agent's own stderr via `client::run_exec`, and both
        // audit lines' `reason` field otherwise).
        eprintln!(
            "[aoide/secrets] backend `{backend_name}` ({op}) exited {status}: {}",
            String::from_utf8_lossy(&stderr_buf).trim()
        );
        // `sh -c`'s own exit 127 universally means "command not found" —
        // for the built-in `age` backend (whose templates shell out to
        // nothing else) that is unambiguous, so it earns the taught error
        // naming the package to install rather than a bare "exited 127".
        if backend_name == "age" && status.code() == Some(127) {
            return Err(missing_age_binary_hint());
        }
        return Err(format!("backend `{backend_name}` exited {status}"));
    }
    Ok(stdout_buf)
}

/// Resolve `backend_name`'s `get` template against `key`/`secrets_home`, run
/// it (bounded, [`run_backend_command`] — task #74), and return stdout with
/// exactly one trailing newline trimmed. Errors are precise but VALUE-FREE
/// by construction: nothing here ever touches the secret's value except the
/// `Ok` return itself, so an `Err` path can never leak one.
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

    let mut stdout = run_backend_command(backend_name, "get", &command, None)?;
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

/// Run a backend's OWN `has` template (P-G1, bounded by [`run_backend_command`]
/// since task #74) and report its exit status — the ONE place this crate
/// treats a template's success/failure as the answer itself rather than
/// reading its stdout. Any failure (spawn, non-zero exit, or a timeout)
/// reads as "no stored value", the same tolerant shape [`has_value`]'s
/// `get`-probe fallback already holds — a `has` template that itself hangs
/// degrades to "no value" here, and [`store_value`]'s own SET attempt that
/// follows hits the SAME hang and correctly fails with a real timeout error
/// there, so nothing gets silently overwritten on a mere probe timeout.
fn run_has_template(secrets_home: &Path, backend_name: &str, key: &str, template: &str) -> bool {
    let command = expand_template(template, secrets_home, key);
    run_backend_command(backend_name, "has", &command, None).is_ok()
}

/// Resolve `backend_name`'s `set` template against `key`/`secrets_home`, run
/// it (bounded, [`run_backend_command`] — task #74) with `value` piped to
/// the template's OWN stdin (never argv), and discard its stdout (a `set`
/// template has nothing useful to report back — unlike `get`'s stdout,
/// which IS the value). Errors are precise but VALUE-FREE by construction,
/// same discipline as [`fetch_value`]: a missing backend, a backend with no
/// `set` template, a failing `set` command, or a timeout all return an
/// `Err` that carries no part of `value`.
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

    run_backend_command(backend_name, "set", &command, Some(value))?;
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

/// Derive and remove the on-disk value file for a BUILT-IN backend only
/// (P-G2, task #72, `secrets migrate`'s old-value cleanup) — `file`/`age`
/// are the two backends whose value path this crate can name without
/// asking their own templates, since it minted the path itself
/// ([`FILE_BACKEND_SET`]/[`AGE_BACKEND_SET`] above). `None` for any other
/// backend name (a doc-preset like `pass`/`gopass`/`bw`/`sops`, or an
/// operator-custom entry) — this crate has no way to know where such a
/// backend keeps its own bytes, so it is never touched; the caller reports
/// that case honestly instead of guessing a path. `key` is the policy's own
/// `key` field — the SAME value `{name}` substitutes into a template
/// ([`expand_template`]'s module doc) — never the secret's display `name`,
/// which can differ. A missing file is NOT an error (`Ok(())`): the
/// migration this backs already succeeded on the TARGET backend by the time
/// this runs, so there is nothing left to clean up either way.
pub fn remove_builtin_value(secrets_home: &Path, backend_name: &str, key: &str) -> Option<std::io::Result<()>> {
    let path = match backend_name {
        "file" => secrets_home.join("store").join(key),
        "age" => secrets_home.join("values").join(format!("{key}.age")),
        _ => return None,
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Some(Ok(())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Ok(())),
        Err(e) => Some(Err(e)),
    }
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

    let key_path_str = key_path.to_string_lossy();
    let keygen = run_age_keygen(&["-o", &key_path_str])?;
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
    let recipient_path_str = recipient_path.to_string_lossy();
    let show = run_age_keygen(&["-y", "-o", &recipient_path_str, &key_path_str])?;
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

/// Run one `age-keygen` invocation, bounded by [`backend_timeout`] via the
/// SAME [`wait_bounded`] loop [`run_backend_command`] uses (task #74 review
/// fix, P-G3 — the flagged gap this closes: before this function existed,
/// [`mint_age_identity_if_needed`]'s two `age-keygen` calls ran through a
/// plain blocking `Command::output()`, exempt from every other backend
/// shell-out's new bound). `age-keygen` is a plain argv exec, never a
/// `sh -c` TEMPLATE — no `{name}`/`{home}` substitution applies to it, so
/// it doesn't go through [`run_backend_command`] itself — but
/// [`mint_age_identity_if_needed`] runs inside the SAME `broker::put_lock`
/// critical section a hung `set` template used to wedge indefinitely
/// before task #74's own fix (`broker.rs`'s module doc): leaving this one
/// call unbounded would have reopened that exact gap for the `age`
/// backend's own identity bootstrap specifically, the one case task #74's
/// commit message claimed to have closed in full. Spawn failure (most
/// commonly a missing binary) is [`describe_missing_age_keygen`], same as
/// before this function existed; a timeout gets the same "raise the knob"
/// wording [`backend_timeout_error`] uses, naming `age-keygen` in place of
/// a `Backend` (there is no backend name to attach here).
fn run_age_keygen(args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = std::process::Command::new("age-keygen");
    cmd.args(args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Same process-group-leader + kill-the-whole-group discipline
    // `run_backend_command` holds — see `kill_process_group`'s doc.
    cmd.process_group(0);

    let mut child = cmd.spawn().map_err(|e| describe_missing_age_keygen(&e))?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    match wait_bounded(&mut child, stdout_pipe, stderr_pipe) {
        Ok((status, stdout, stderr)) => Ok(std::process::Output { status, stdout, stderr }),
        Err(WaitOutcome::TimedOut) => Err(format!(
            "age-keygen timed out after {}s (`{BACKEND_TIMEOUT_ENV}`) — raise the knob, or fix the hung age-keygen",
            backend_timeout().as_secs()
        )),
        Err(WaitOutcome::WaitFailed(e)) => Err(format!("waiting on age-keygen: {e}")),
    }
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

    // ── remove_builtin_value (P-G2, task #72, `secrets migrate`) ────────

    #[test]
    fn remove_builtin_value_removes_the_file_backends_value() {
        let home = tmp_home("remove-file-value");
        seed_default_backends(&home).unwrap();
        store_value(&home, "file", "k", "v").unwrap();
        assert!(home.join("store").join("k").exists());

        let result = remove_builtin_value(&home, "file", "k");
        assert!(matches!(result, Some(Ok(()))));
        assert!(!home.join("store").join("k").exists());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn remove_builtin_value_removes_the_age_backends_value() {
        if !age_tools_available() {
            eprintln!("skipping remove_builtin_value_removes_the_age_backends_value: age/age-keygen not found on PATH");
            return;
        }
        let home = tmp_home("remove-age-value");
        seed_default_backends(&home).unwrap();
        mint_age_identity_if_needed(&home).unwrap();
        store_value(&home, "age", "k", "v").unwrap();
        assert!(home.join("values").join("k.age").exists());

        let result = remove_builtin_value(&home, "age", "k");
        assert!(matches!(result, Some(Ok(()))));
        assert!(!home.join("values").join("k.age").exists());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn remove_builtin_value_is_none_for_a_non_builtin_backend() {
        let home = tmp_home("remove-nonbuiltin");
        assert!(remove_builtin_value(&home, "pass", "k").is_none());
        assert!(remove_builtin_value(&home, "custom-thing", "k").is_none());
    }

    #[test]
    fn remove_builtin_value_on_an_already_missing_file_is_a_clean_ok() {
        let home = tmp_home("remove-missing");
        std::fs::create_dir_all(&home).unwrap();
        let result = remove_builtin_value(&home, "file", "never-stored");
        assert!(matches!(result, Some(Ok(()))));
        std::fs::remove_dir_all(&home).ok();
    }

    // ── bounded backend shell-outs (task #74) ───────────────────────────

    /// Restores whatever `AOIDE_SECRETS_BACKEND_TIMEOUT` held before the
    /// test ran — every test below that sets it does so through this guard
    /// rather than a bare `set_var`, so a panic mid-test still leaves the
    /// env sane for whatever runs next (this crate's whole suite runs
    /// `--test-threads=1`, so no cross-test lock is needed beyond that).
    struct EnvGuard {
        saved: Option<String>,
    }
    impl EnvGuard {
        fn set(value: &str) -> Self {
            let saved = std::env::var(BACKEND_TIMEOUT_ENV).ok();
            std::env::set_var(BACKEND_TIMEOUT_ENV, value);
            Self { saved }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.saved {
                Some(v) => std::env::set_var(BACKEND_TIMEOUT_ENV, v),
                None => std::env::remove_var(BACKEND_TIMEOUT_ENV),
            }
        }
    }

    #[test]
    fn backend_timeout_defaults_to_10_seconds() {
        let saved = std::env::var(BACKEND_TIMEOUT_ENV).ok();
        std::env::remove_var(BACKEND_TIMEOUT_ENV);
        assert_eq!(backend_timeout(), Duration::from_secs(10));
        match saved {
            Some(v) => std::env::set_var(BACKEND_TIMEOUT_ENV, v),
            None => std::env::remove_var(BACKEND_TIMEOUT_ENV),
        }
    }

    #[test]
    fn backend_timeout_env_override_wins() {
        let _guard = EnvGuard::set("3");
        assert_eq!(backend_timeout(), Duration::from_secs(3));
    }

    /// The documented fallback: a garbage value (an operator typo) must
    /// fall back to the default, never panic and never silently disable
    /// the bound by treating it as "no timeout".
    #[test]
    fn backend_timeout_env_garbage_falls_back_to_the_default() {
        let _guard = EnvGuard::set("not-a-number");
        assert_eq!(backend_timeout(), Duration::from_secs(DEFAULT_BACKEND_TIMEOUT_SECS));
    }

    #[test]
    fn backend_timeout_env_blank_falls_back_to_the_default() {
        let _guard = EnvGuard::set("   ");
        assert_eq!(backend_timeout(), Duration::from_secs(DEFAULT_BACKEND_TIMEOUT_SECS));
    }

    /// The choke point itself: a `get` template that sleeps well past the
    /// timeout must be killed, reaped (no zombie), and reported within
    /// bounds — the exact scenario `AGENTS.md`'s KNOWN GAP note described
    /// as unbounded before this phase. The template writes its OWN pid to
    /// a marker file first (via `$$`, the shell's own pid — never a
    /// subshell) so the test can confirm, from OUTSIDE this module's own
    /// bookkeeping, that the killed process is actually gone from `/proc`
    /// afterward rather than lingering as a zombie.
    #[test]
    fn a_hung_get_template_times_out_kills_and_reaps_the_child() {
        let home = tmp_home("hung-get-timeout");
        let marker = home.join("child.pid");
        write_backends(&home, &format!("echo $$ > {} && sleep 60", marker.display()));

        let _guard = EnvGuard::set("1");
        let start = Instant::now();
        let err = fetch_value(&home, "scratch", "x").unwrap_err();
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}, expected timeout at ~1s");
        assert!(err.contains("scratch"), "error should name the backend: {err}");
        assert!(err.contains("get"), "error should name the op: {err}");
        assert!(err.contains(BACKEND_TIMEOUT_ENV), "error should name the env knob: {err}");
        assert!(!err.contains("sleep 60"), "template text leaked into the error: {err}");

        // The marker is written near-instantly, well before the 1s
        // deadline — a short settle is just insurance against a slow disk.
        std::thread::sleep(Duration::from_millis(200));
        let pid_text = std::fs::read_to_string(&marker).expect("the template should have written its pid before hanging");
        let pid: i32 = pid_text.trim().parse().expect("marker should carry a bare pid");
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "the killed child (pid {pid}) must be fully reaped, not left as a zombie"
        );

        std::fs::remove_dir_all(&home).ok();
    }

    /// Task requirement: "a put against a sleeping set-template returns
    /// within bounds rather than hanging" — proven directly at the choke
    /// point `store_value` (and, transitively, `broker::put_gate`) routes
    /// through, with the env knob set tiny.
    #[test]
    fn store_value_against_a_hung_set_template_returns_within_bounds() {
        let home = tmp_home("hung-set-timeout");
        write_backend_with_set(&home, "printf %s {name}", "sleep 60");

        let _guard = EnvGuard::set("1");
        let start = Instant::now();
        let err = store_value(&home, "scratch", "k", "the-stored-value").unwrap_err();
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}, expected timeout at ~1s");
        assert!(err.contains("set"), "error should name the op: {err}");
        assert!(!err.contains("the-stored-value"), "value leaked into the timeout error: {err}");
        std::fs::remove_dir_all(&home).ok();
    }

    /// `has` templates get the same bound — a hung `has` degrades to
    /// "false" (module doc), never hangs `has_value` itself.
    #[test]
    fn a_hung_has_template_times_out_and_reads_as_no_stored_value() {
        let home = tmp_home("hung-has-timeout");
        write_backend_with_has(&home, "printf %s {name}", "sleep 60");

        let _guard = EnvGuard::set("1");
        let start = Instant::now();
        let result = has_value(&home, "scratch", "x");
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}, expected timeout at ~1s");
        assert!(!result, "a hung `has` template must read as no stored value, never hang has_value itself");
        std::fs::remove_dir_all(&home).ok();
    }

    /// Behavior unchanged for a well-behaved template under the DEFAULT
    /// (untouched) timeout — the bound must never slow down the common
    /// case.
    #[test]
    fn a_fast_template_is_unaffected_by_the_default_timeout() {
        let home = tmp_home("fast-template-unaffected");
        write_backends(&home, "printf %s {name}");
        assert_eq!(fetch_value(&home, "scratch", "quick").unwrap(), "quick");
        std::fs::remove_dir_all(&home).ok();
    }

    /// A template producing several MB of output faster than the 20ms poll
    /// interval drains it must still round-trip the FULL value under a
    /// generous timeout, never a truncated one — a truncated GET released
    /// to a consumer would be corruption, strictly worse than a timeout
    /// (P-G3 review). Proves `wait_bounded`'s per-tick, non-blocking drain
    /// never lets a fast writer stall on a full pipe.
    #[test]
    fn a_large_output_survives_the_drain_loop_intact() {
        let home = tmp_home("large-output-drain");
        write_backends(&home, "head -c 8000000 /dev/urandom | base64 | tr -d '\\n'");
        let _guard = EnvGuard::set("30");
        let value = fetch_value(&home, "scratch", "unused").expect("large-output template must succeed");
        // base64 of 8,000,000 bytes is ceil(n/3)*4 chars; just assert it's
        // in the right ballpark and not silently truncated to a pipe-buffer
        // multiple like 64KiB/65536.
        assert!(value.len() > 10_000_000, "expected ~10.6M base64 chars, got {} -- looks truncated", value.len());
        std::fs::remove_dir_all(&home).ok();
    }

    // ── the age-keygen bootstrap is ALSO bounded (P-G3 review fix) ──────

    /// The flagged gap: before this fix, [`mint_age_identity_if_needed`]'s
    /// two `age-keygen` calls ran through a plain blocking `Command::
    /// output()`, exempt from the bound task #74 gave every OTHER backend
    /// shell-out — a hung `age-keygen` would have wedged `broker::put_lock`
    /// exactly the way a hung `set` template used to before task #74's own
    /// fix. A PATH-shimmed fake `age-keygen` that just sleeps (same
    /// PATH-shim technique `enroll.rs`'s `render_qr` tests already use — no
    /// real `age` binary needed) proves `mint_age_identity_if_needed` now
    /// returns a timeout error within bounds, and reaps the shim rather
    /// than leaving it running.
    #[test]
    fn mint_age_identity_against_a_hung_age_keygen_returns_within_bounds() {
        let home = tmp_home("mint-hung-age-keygen");
        let shim_dir = std::env::temp_dir().join(format!(
            "aoide-secrets-age-keygen-shim-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&shim_dir).unwrap();
        let shim = shim_dir.join("age-keygen");
        std::fs::write(&shim, "#!/bin/sh\nsleep 60\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let saved_path = std::env::var("PATH").ok();
        let new_path = format!("{}:{}", shim_dir.display(), saved_path.clone().unwrap_or_default());
        std::env::set_var("PATH", &new_path);
        let _guard = EnvGuard::set("1");

        let start = Instant::now();
        let err = mint_age_identity_if_needed(&home).unwrap_err();
        let elapsed = start.elapsed();

        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}, expected timeout at ~1s");
        assert!(err.contains("age-keygen"), "error should name age-keygen: {err}");
        assert!(err.contains(BACKEND_TIMEOUT_ENV), "error should name the env knob: {err}");
        assert!(!home.join("age.key").exists(), "a hung age-keygen must never leave a half-written key file");
        std::fs::remove_dir_all(&home).ok();
        std::fs::remove_dir_all(&shim_dir).ok();
    }
}
