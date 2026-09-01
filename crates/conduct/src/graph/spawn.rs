//! `spawn` — the DETACHED command that starts a headless conducted agent
//! (P2 of the conducted-agents plan; P1 landed `conduct --headless`,
//! a044bae). Unlike `conduct`, which blocks the calling process
//! until the wrapped agent exits, `spawn` re-execs THIS SAME binary as
//! `conduct --headless … -- <command …>` (the same `std::env::current_exe()`
//! self-re-exec idiom `server/src/a2a.rs`'s `do_spawn` and `shellbridge.rs`
//! use), detaches it into its own session (`setsid`, stdio nulled) so it
//! OUTLIVES this call, waits briefly for it to register its control socket,
//! and returns immediately either way. An optional `--prompt` is then
//! injected through the ONE gated injection door (`send`, re-driven the
//! same way `graph/pending.rs::pending_approve` re-drives an approved entry)
//! — never a direct socket write.
//!
//! `--parent`, when given, passes straight through as `conduct`'s own
//! `--parent` flag (`session_conduct` already reads `inv.flags.get("parent")`
//! and threads it into `do_session_start` — no re-implementation needed
//! here).
//!
//! `--windowed` (P-D7) is the sibling launch mode: instead of detaching a
//! headless `conduct --headless` child, it execs a real terminal (its
//! invocation named by `$AOIDE_TERMINAL`, env only) that runs the exact SAME
//! `aoide conduct -- <agent cmd>` — built by [`build_conduct_args`], the one
//! command-construction path both branches share, `--headless` aside — so
//! registration, the control socket, and the parent-autogate lane come for
//! free either way. Parsing the terminal template into an argv
//! ([`build_terminal_argv`]) is pure string manipulation, no shell involved;
//! see that function's own doc for the placeholder-substitution rules. No
//! nix anywhere in this path — a terminal emulator is a shell concern, never
//! `lyra`'s.

use super::conduct::{captures_like_a_shell, conduct_socket_path, unix_ts};
use super::model::{load_stage, sessions_path, SessionsFile};
use super::send::session_send;
use super::undying::nothing_to_restore_warning;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use aoide_storage::undying::{load_undying, save_undying, set_undying};
use serde_json::json;
use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long `spawn` waits for the just-launched headless child to bind its
/// control socket before giving up and returning `registered: false` anyway.
/// The spawn itself has already succeeded (the process is running, detached,
/// and will keep running) — this is only a best-effort "did it get far
/// enough to be steerable yet" check, never a blocking guarantee.
const REGISTRATION_BUDGET: Duration = Duration::from_millis(3000);
const REGISTRATION_POLL: Duration = Duration::from_millis(25);

/// The command's basename — the agent-name default. Mirrors
/// `conduct.rs::command_basename`'s own copy: each `graph` command that
/// spawns a labelled agent keeps its own small copy of this one-liner rather
/// than sharing it across modules.
fn command_basename(program: &str) -> String {
    std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

/// Resolve the binary to re-exec as the headless conducted child.
///
/// In production this is always the running `aoide` binary itself — `spawn`
/// only ever executes AS that binary's own dispatch, so
/// `current_exe()` is correct live, exactly like `server/src/a2a.rs`'s
/// `do_spawn`. Under `cargo test -p aoide-conduct`, though, `current_exe()`
/// resolves to the unit-test harness binary, which has NO CLI dispatcher at
/// all (confirmed: it exits 101 "Unrecognized option: 'headless'" on this
/// module's own argv) — so the module's own end-to-end test points this at
/// the real, already-built sibling `aoide` binary via
/// `AOIDE_CONDUCT_SPAWN_EXE`, a test-only escape hatch that is
/// `cfg(test)`-gated so it can never exist as a live override in the shipped
/// binary.
fn spawn_exe() -> std::io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(over) = std::env::var_os("AOIDE_CONDUCT_SPAWN_EXE") {
        return Ok(PathBuf::from(over));
    }
    std::env::current_exe()
}

/// Build the `conduct` subcommand's own argv — the ONE command-construction
/// path shared by the headless (`spawn`) and windowed (`spawn
/// --windowed`) branches, the `--headless` flag aside: `["conduct",
/// ("--headless",)? "--agent", agent, "--id", id, ("--parent", parent)?,
/// "--", <command…>]`. Registration, the control socket, and the
/// parent-autogate lane (`send.rs`'s `sender_is_parent`) all key off this
/// same shape either way — do NOT fork a second builder for the windowed
/// path.
fn build_conduct_args(
    headless: bool,
    agent: &str,
    id: &str,
    parent: Option<&str>,
    command: &[String],
) -> Vec<String> {
    let mut args: Vec<String> = vec!["conduct".to_string()];
    // Unconditional, and deliberately not gated on `headless`: BOTH launch
    // modes are a spawn, and `reap`'s abandoned-shell sweep judges the
    // windowed one by the same rule as the headless one.
    args.push("--spawned".to_string());
    if headless {
        args.push("--headless".to_string());
    }
    args.push("--agent".to_string());
    args.push(agent.to_string());
    args.push("--id".to_string());
    args.push(id.to_string());
    if let Some(parent) = parent {
        args.push("--parent".to_string());
        args.push(parent.to_string());
    }
    args.push("--".to_string());
    args.extend(command.iter().cloned());
    args
}

/// Spawn `argv0` with `args`, detached into its own session (`setsid`) with
/// stdio nulled, so it outlives this call — the exact posture both the
/// headless re-exec and the windowed terminal exec need; only WHAT gets
/// exec'd differs between the two callers. `cwd`, when given, becomes the
/// spawned process's own working directory (P-D8): for the windowed branch
/// that is the TERMINAL EMULATOR's cwd, which every terminal this codebase
/// targets starts its own shell/child in by default — the mechanism
/// `resurrect` relies on to reopen a revived agent in its original project
/// directory without a `--cwd` flag on `conduct`/`session_conduct` itself
/// (that process derives its OWN `cwd` from `std::env::current_dir()` at
/// registration, so setting the terminal's cwd here is sufficient). `None`
/// (every pre-P-D8 caller) leaves the child on this process's own cwd,
/// unchanged from before.
fn spawn_detached(
    argv0: impl AsRef<std::ffi::OsStr>,
    args: &[String],
    cwd: Option<&str>,
) -> std::io::Result<std::process::Child> {
    let mut command = std::process::Command::new(argv0);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(dir) = cwd.filter(|d| !d.is_empty()) {
        command.current_dir(dir);
    }
    // SAFETY: `setsid()` is async-signal-safe and the only call made in this
    // pre_exec hook (same discipline as the two call sites this helper
    // replaces) — it detaches the child into its own session so it survives
    // THIS call's own process lifetime.
    unsafe {
        command.pre_exec(|| {
            let _ = libc::setsid();
            Ok(())
        });
    }
    command.spawn()
}

// ── `--windowed`: terminal template parsing (pure) ──────────────────────────
//
// `$AOIDE_TERMINAL` names a terminal emulator invocation as a plain string,
// e.g. `kitty -e {cmd}` or `foot sh -c '{cmd}'`. Parsing it is whitespace
// splitting ONLY — no shell-quote awareness — so a `{cmd}` placeholder is
// recognised two ways:
//
// - a BARE token, exactly `{cmd}` — the terminal execs its own argv
//   directly with no intervening shell (`kitty -e {cmd}`), so the conducted
//   command's OWN argv elements splice in as that many separate argv slots.
// - `{cmd}` wrapped in one layer of matching `'`/`"` (`foot sh -c '{cmd}'`)
//   — the terminal's own next argument is handed to a REAL shell as ONE
//   string (`sh -c <script>`), so the conducted argv is POSIX-single-quoted
//   and JOINED into that one slot. The wrapping quote characters are
//   template notation, not literal argv content: a config author writing
//   `foot sh -c '{cmd}'` is composing the line the way they would type it at
//   a shell prompt, and this parser honours that reading even though it
//   never invokes an actual shell to strip the quotes itself — they are
//   dropped along with the token they wrapped, never carried into the
//   spliced-in command.
//
// A template with no placeholder token at all gets the conducted command
// appended (bare-spliced) at the end — `kitty -e` alone, or a template that
// simply forgot the placeholder, still works.

/// Strip one layer of matching leading/trailing `'` or `"` from `tok`, if
/// present (`'{cmd}'` → `Some("{cmd}")`). A bare `{cmd}` (no quotes) returns
/// `None` here — it is matched separately, never conflated with a quoted
/// token of the same inner text.
fn strip_matching_quotes(tok: &str) -> Option<&str> {
    let bytes = tok.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'\'' || first == b'"') && first == last {
            return Some(&tok[1..tok.len() - 1]);
        }
    }
    None
}

/// Single-quote `s` the POSIX way if it needs it (anything outside a
/// conservative bare-safe set), so a `sh -c` re-split of the joined line
/// yields back the exact same word.
fn shell_quote(s: &str) -> String {
    let bare_safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@".contains(&b));
    if bare_safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Join `argv` into ONE POSIX shell command-line string — the "one slot"
/// substitution a quoted `{cmd}` placeholder needs.
fn shell_join(argv: &[String]) -> String {
    argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

/// Parse `$AOIDE_TERMINAL`'s raw string into a real argv, splicing `cmd` in
/// for a `{cmd}` placeholder token per the module doc above. Pure: no env
/// access, no process spawn — directly unit-testable, and the seam
/// `spawn --windowed`'s own tests stop at (never a real terminal in a
/// test).
pub(crate) fn build_terminal_argv(template: &str, cmd: &[String]) -> Vec<String> {
    let tokens: Vec<&str> = template.split_whitespace().collect();
    let mut placeholder: Option<(usize, bool)> = None; // (token index, was-quoted)
    for (i, tok) in tokens.iter().enumerate() {
        if *tok == "{cmd}" {
            placeholder = Some((i, false));
            break;
        }
        if strip_matching_quotes(tok) == Some("{cmd}") {
            placeholder = Some((i, true));
            break;
        }
    }
    match placeholder {
        Some((i, quoted)) => {
            let mut out: Vec<String> = tokens[..i].iter().map(|s| s.to_string()).collect();
            if quoted {
                out.push(shell_join(cmd));
            } else {
                out.extend(cmd.iter().cloned());
            }
            out.extend(tokens[i + 1..].iter().map(|s| s.to_string()));
            out
        }
        None => {
            let mut out: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
            out.extend(cmd.iter().cloned());
            out
        }
    }
}

/// Resolve `$AOIDE_TERMINAL`, or a taught error naming the env var plus one
/// worked example.
fn terminal_template() -> Result<String, Outcome> {
    match std::env::var("AOIDE_TERMINAL") {
        Ok(t) if !t.trim().is_empty() => Ok(t),
        _ => Err(Outcome::error(
            "spawn",
            "no terminal configured — set $AOIDE_TERMINAL, e.g. AOIDE_TERMINAL=\"kitty -e {cmd}\" (argv splice) or AOIDE_TERMINAL=\"foot sh -c '{cmd}'\" (quoted: joined into one shell word)",
        )
        .with_data(json!({ "reason": "no-terminal-template" }))),
    }
}

/// A live display present (`$WAYLAND_DISPLAY` or `$DISPLAY`, non-empty), or
/// a taught error steering back to the headless path.
fn require_display() -> Result<(), Outcome> {
    let has_display = std::env::var_os("WAYLAND_DISPLAY")
        .filter(|v| !v.is_empty())
        .is_some()
        || std::env::var_os("DISPLAY").filter(|v| !v.is_empty()).is_some();
    if has_display {
        Ok(())
    } else {
        Err(
            Outcome::error("spawn", "headless host — use `spawn` without `--windowed`")
                .with_data(json!({ "reason": "headless-host" })),
        )
    }
}

/// Pre-flight `--windowed` (template + display), then build the terminal's
/// own exec argv: the conduct command's argv (the resolved `aoide` binary
/// followed by `conduct_args`) spliced into the template per
/// [`build_terminal_argv`]. Everything up to and including this function is
/// argv construction only — no spawn — so a test can exercise it end to end
/// without ever opening a real terminal.
fn resolve_windowed_argv(
    exe: &std::path::Path,
    conduct_args: &[String],
) -> Result<Vec<String>, Outcome> {
    let template = terminal_template()?;
    require_display()?;
    let mut full_cmd: Vec<String> = vec![exe.to_string_lossy().into_owned()];
    full_cmd.extend(conduct_args.iter().cloned());
    Ok(build_terminal_argv(&template, &full_cmd))
}

/// Poll for a LIVE control socket at `path`, every [`REGISTRATION_POLL`],
/// until `budget` elapses. Returns whether one answered.
///
/// A successful `UnixStream::connect` — not bare existence — is the signal,
/// for the same reason `reap::sweep_orphan_sockets` and the a2a door's
/// `spawn_inject_prompt` both insist on it: a SIGKILLed conduct leaves its
/// socket FILE behind until the reaper sweeps it (~12s), so an existence
/// check against a reused `--id` can see the corpse of the PREVIOUS session
/// and report the new one registered before it has even forked.
fn wait_for(path: &std::path::Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(REGISTRATION_POLL);
    }
}

/// `aoide spawn [--agent <name>] [--parent <sessionId>] [--id <id>]
/// [--prompt <text>] [--windowed] [--undying] -- <command …>` — spawn
/// `<command>` as a conducted session that OUTLIVES this call (headless by
/// default, or in a real terminal with `--windowed`), wait briefly for it to
/// register, and return `{ sessionId, agent, socket, logPath, registered,
/// prompt, windowed, undying }`.
///
/// Ordering mirrors `conduct`/`wrap`: the re-exec'd `conduct` child (headless
/// or, under `--windowed`, running inside the just-opened terminal) spawns
/// its own command FIRST and only registers on success, so a bad `<command>`
/// never leaves a ghost session — the control socket simply never appears
/// here and `registered` comes back `false`.
///
/// `--windowed` pre-flights against two taught errors before ever touching a
/// process: no `$AOIDE_TERMINAL` set, and no live display
/// (`$WAYLAND_DISPLAY`/`$DISPLAY` both absent — a headless host, told to use
/// plain `spawn` instead).
pub fn session_spawn(inv: &Invocation) -> Outcome {
    let cmd = "spawn";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide spawn [--agent <name>] [--parent <sessionId>] [--id <id>] [--prompt <text>] [--windowed] -- <command …>",
        );
    }
    let program = inv.args[0].clone();
    let agent = inv
        .flags
        .get("agent")
        .cloned()
        .unwrap_or_else(|| command_basename(&program));
    let id = inv
        .flags
        .get("id")
        .cloned()
        .unwrap_or_else(|| format!("spawn-{}-{}", std::process::id(), unix_ts()));

    let windowed = inv.flag_present("windowed");
    let cwd = inv.flags.get("cwd").map(String::as_str);

    let exe = match spawn_exe() {
        Ok(e) => e,
        Err(e) => {
            return Outcome::error(cmd, format!("resolving the aoide binary to re-exec: {e}"))
                .with_data(json!({ "reason": "exe-unresolvable", "sessionId": id }));
        }
    };

    // The child is `aoide conduct -- <agent cmd>` — built the ONE way,
    // shared by both the headless and windowed branches (headless flag
    // aside), so registration, the control socket, and the parent-autogate
    // lane come for free either way (P-D7 — never a second
    // command-construction path).
    let conduct_args = build_conduct_args(
        !windowed,
        &agent,
        &id,
        inv.flags.get("parent").map(String::as_str),
        &inv.args,
    );

    let mut child = if windowed {
        // Instead of detaching a headless `conduct --headless` child, exec a
        // real terminal (from `$AOIDE_TERMINAL`) that runs the SAME
        // conducted command — a terminal emulator is a shell concern, no
        // nix, no `lyra`.
        let argv = match resolve_windowed_argv(&exe, &conduct_args) {
            Ok(a) => a,
            Err(outcome) => return outcome,
        };
        match spawn_detached(&argv[0], &argv[1..], cwd) {
            Ok(c) => c,
            Err(e) => {
                return Outcome::error(
                    cmd,
                    format!("failed to open a windowed terminal (`{}`): {e}", argv[0]),
                )
                .with_data(json!({ "reason": "spawn-failed", "sessionId": id }));
            }
        }
    } else {
        match spawn_detached(&exe, &conduct_args, cwd) {
            Ok(c) => c,
            Err(e) => {
                return Outcome::error(cmd, format!("failed to spawn headless `{program}`: {e}"))
                    .with_data(json!({ "reason": "spawn-failed", "sessionId": id }));
            }
        }
    };

    // `setsid()` above detaches the child into its own session so it outlives
    // THIS call, but a new session does NOT reparent it — this process is
    // still its parent and still owes it a `wait()`, or the kernel keeps its
    // exit status around as a zombie for as long as THIS process lives. A
    // short-lived CLI invocation of `spawn` exits right after returning
    // below, at which point the (still-running) child reparents to
    // init/a subreaper and gets collected there regardless of whether this
    // thread ever ran — but a caller that stays up far longer (an
    // orchestrator driving `spawn` the same way `server/src/a2a.rs`'s
    // `do_spawn` drives `conduct`) would otherwise leak one zombie per spawn
    // for as long as it kept running. Parking the wait on its own thread is
    // correct — and cheap — either way, so it is unconditional here rather
    // than only for the long-lived caller.
    std::thread::spawn(move || {
        let _ = child.wait();
    });

    // Registration wait: poll for the control socket the headless child binds
    // once `session_conduct` reaches that point.
    let socket_path = conduct_socket_path(&id);
    let registered = wait_for(&socket_path, REGISTRATION_BUDGET);

    let (socket, log_path) = if registered {
        // The child binds its control socket before its second record write
        // stamps logPath (at log open) — a one-shot read here can land in
        // that gap on a slow builder and report a registered session with a
        // null logPath. Poll for the stamped record on the same budget;
        // whatever the record holds at deadline is the honest answer.
        let deadline = Instant::now() + REGISTRATION_BUDGET;
        let mut found = (None, None);
        loop {
            if let Some(r) = load_stage::<SessionsFile>(&sessions_path())
                .ok()
                .and_then(|f| f.sessions.into_iter().find(|s| s.session_id == id))
            {
                let stamped = r.log_path.is_some();
                found = (r.socket, r.log_path);
                if stamped {
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(REGISTRATION_POLL);
        }
        found
    } else {
        (None, None)
    };

    // `--undying`: mark the spawned session durable, once registration has
    // actually succeeded (P-C3, durable-sessions plan) — an unregistered id
    // has no live session behind it, so there is nothing durable to mark
    // yet. Best-effort: an `undying.json` write failure must not fail an
    // otherwise-successful spawn, the same posture the prompt injection
    // below takes toward its own delivery failures.
    let undying_flag = inv.flag_present("undying");
    let undying = if undying_flag && registered {
        let mut list = load_undying();
        set_undying(&mut list, &id, true);
        let _ = save_undying(&list);
        true
    } else {
        false
    };
    // Same nothing-to-restore warning `session grant undying on` carries
    // (`undying.rs::nothing_to_restore_warning`, task #100): `program` (this
    // function's own, not a roster read-back) is the WRAPPED command
    // `captures_like_a_shell` decides on directly, no race against the
    // conducted child's own first refresh tick.
    let undying_warning = undying
        .then(|| nothing_to_restore_warning(&agent, captures_like_a_shell(&program)))
        .flatten();

    // `--prompt`: only after registration succeeded, through the one gated
    // injection door (`session_send`, `--yes --submit`, in-process) — the
    // exact re-drive shape `graph/pending.rs::pending_approve` uses to replay
    // an approved held entry. Never a direct write to the socket.
    let prompt_flag = inv.flags.get("prompt").cloned();
    let prompt_result = match &prompt_flag {
        None => "none".to_string(),
        Some(_) if !registered => "skipped-unregistered".to_string(),
        Some(text) => {
            let mut flags = BTreeMap::new();
            flags.insert("id".to_string(), id.clone());
            flags.insert("yes".to_string(), "true".to_string());
            flags.insert("submit".to_string(), "true".to_string());
            let inner = session_send(&Invocation {
                path: vec!["send".to_string()],
                args: vec![text.clone()],
                flags,
                door: inv.door,
            });
            if inner.status == Status::Ok {
                "delivered".to_string()
            } else {
                format!("failed: {}", inner.message)
            }
        }
    };

    let mode = if windowed { "windowed" } else { "headless" };
    let mut changed = vec![format!(
        "session {id}: spawned {mode}{}",
        if registered { ", registered" } else { " (not yet registered)" }
    )];
    if prompt_result == "delivered" {
        changed.push(format!("session {id}: prompt injected"));
    }
    if undying {
        changed.push(format!("session {id}: undying"));
    }

    let data = json!({
        "sessionId": id,
        "agent": agent,
        "socket": socket,
        "logPath": log_path,
        "registered": registered,
        "prompt": prompt_result,
        "windowed": windowed,
        "undying": undying,
    });

    let mut message = format!(
        "`{agent}` spawned {mode} (session `{id}`){}",
        if registered { "" } else { " — not yet registered" }
    );
    if let Some(warning) = &undying_warning {
        message = format!("{message} — {warning}");
    }

    Outcome::ok(cmd, message)
        .changed(changed)
        .with_data(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::model::SessionsFile;
    use crate::graph::testutil::*;

    // `built_aoide_bin` moved to `testutil.rs` (P-D8) — `resurrect.rs`'s own
    // end-to-end tests need the identical fixture; glob-imported above via
    // `use crate::graph::testutil::*;`.

    #[test]
    fn spawn_registers_a_detached_headless_child_and_mirrors_its_log() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-e2e");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        // The re-exec'd `conduct --headless` child (below) inherits this
        // process's full env, `AOIDE_AUDIT_LOG` included — without scoping it
        // here, both this test process AND the detached child it spawns
        // audit into the real `~/Aoide/log` (task #89: proven live via
        // "/no/such/binary-aoide-spawn-test" lines landing in the real log
        // from the sibling test below).
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-ok";
        let out = session_spawn(&spawn_invocation(
            &["sh", "-c", "echo spawn-mark; sleep 1"],
            &[("id", id)],
        ));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["sessionId"], id);
        assert_eq!(data["registered"], true, "data: {data}");
        let socket = data["socket"].as_str().expect("socket present once registered");
        assert!(socket.ends_with(&format!("session-{id}.sock")));
        let log_path = data["logPath"].as_str().expect("logPath present once registered");
        assert!(log_path.ends_with(&format!("{id}.log")));

        // The record itself is registered too, independent of the outcome's
        // own echo of it.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|r| r.session_id == id).expect("session registered");
        assert_eq!(rec.conductable, Some(true));

        // Wait out the child's own `sleep 1` (it outlives this call — the
        // whole point of `spawn` — so its `done` transition is not
        // synchronous with the outcome above) and confirm the log mirrors
        // its output.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(4000);
        let mut logged = String::new();
        while std::time::Instant::now() < deadline {
            logged = std::fs::read_to_string(log_path).unwrap_or_default();
            if logged.contains("spawn-mark") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(logged.contains("spawn-mark"), "log contents: {logged:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn spawn_of_a_nonexistent_binary_registers_no_ghost_session() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-badexec");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-badexec";
        // The wrapped command itself doesn't exist — the re-exec'd `conduct
        // --headless` fails its OWN spawn and registers nothing (parity with
        // `conduct`/`wrap`'s "spawn first" rule), so the socket never
        // appears and `spawn` honestly times out unregistered.
        let out = session_spawn(&spawn_invocation(
            &["/no/such/binary-aoide-spawn-test"],
            &[("id", id)],
        ));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["registered"], false, "data: {data}");
        assert!(data["socket"].is_null());
        assert!(data["logPath"].is_null());

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            !s.sessions.iter().any(|r| r.session_id == id),
            "a failed exec must not leave a ghost session record"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--undying` (P-C3, durable-sessions plan): once the headless child
    /// actually registers, the spawned id lands in `state/undying.json` —
    /// the headless arm exercises this with no terminal needed, asserting on
    /// the undying store directly, never on a process.
    #[test]
    fn undying_flag_marks_the_spawned_id_once_registered() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-undying-on");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-undying-on";
        let out = session_spawn(&spawn_invocation(
            &["sh", "-c", "sleep 1"],
            &[("id", id), ("undying", "true")],
        ));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["registered"], true, "data: {data}");
        assert_eq!(data["undying"], true, "data: {data}");
        assert!(
            out.changed.iter().any(|c| c.contains("undying")),
            "changed: {:?}",
            out.changed
        );
        assert!(
            aoide_storage::undying::is_undying(&aoide_storage::undying::load_undying(), id),
            "undying.json must mark the spawned id"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The opposite proof: without `--undying`, a spawn — even a successfully
    /// registered one — must mark nothing.
    #[test]
    fn without_undying_flag_a_spawn_marks_nothing() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-undying-off");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-undying-off";
        let out = session_spawn(&spawn_invocation(&["sh", "-c", "sleep 1"], &[("id", id)]));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["undying"], false);
        assert!(
            aoide_storage::undying::load_undying().is_empty(),
            "no --undying flag must mark nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn spawn_without_a_command_is_a_usage_error() {
        let out = session_spawn(&spawn_invocation(&[], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn prompt_is_skipped_honestly_when_registration_never_happens() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_SPAWN_EXE",
        ]);

        let root = unique_stage("spawn-prompt-skip");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-prompt-skip";
        let out = session_spawn(&spawn_invocation(
            &["/no/such/binary-aoide-spawn-test"],
            &[("id", id), ("prompt", "hello")],
        ));
        assert_eq!(out.data.as_ref().unwrap()["prompt"], "skipped-unregistered");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `--windowed`: terminal template parsing (pure, no spawn) ───────────

    #[test]
    fn terminal_argv_splices_a_bare_placeholder_token_as_separate_args() {
        // `kitty -e {cmd}` execs its own argv directly — the conducted
        // command's elements splice in as that many separate argv slots.
        let cmd = vec![
            "aoide".to_string(),
            "conduct".to_string(),
            "--".to_string(),
            "claude".to_string(),
        ];
        let argv = build_terminal_argv("kitty -e {cmd}", &cmd);
        assert_eq!(argv, vec!["kitty", "-e", "aoide", "conduct", "--", "claude"]);
    }

    #[test]
    fn terminal_argv_joins_a_single_quoted_placeholder_into_one_shell_string() {
        // `foot sh -c '{cmd}'` hands its next argument to a REAL shell as ONE
        // string — the conducted argv is single-quoted and joined into that
        // one slot, and the template's own wrapping quotes (notation, not
        // literal argv content) are dropped along with the token they wrapped.
        let cmd = vec![
            "aoide".to_string(),
            "conduct".to_string(),
            "--".to_string(),
            "claude".to_string(),
        ];
        let argv = build_terminal_argv("foot sh -c '{cmd}'", &cmd);
        assert_eq!(argv, vec!["foot", "sh", "-c", "aoide conduct -- claude"]);
    }

    #[test]
    fn terminal_argv_joins_a_double_quoted_placeholder_too() {
        let cmd = vec!["aoide".to_string(), "conduct".to_string()];
        let argv = build_terminal_argv(r#"alacritty -e sh -c "{cmd}""#, &cmd);
        assert_eq!(argv, vec!["alacritty", "-e", "sh", "-c", "aoide conduct"]);
    }

    #[test]
    fn terminal_argv_appends_the_command_when_the_template_has_no_placeholder() {
        let cmd = vec![
            "aoide".to_string(),
            "conduct".to_string(),
            "--".to_string(),
            "claude".to_string(),
        ];
        let argv = build_terminal_argv("kitty -e", &cmd);
        assert_eq!(argv, vec!["kitty", "-e", "aoide", "conduct", "--", "claude"]);
    }

    #[test]
    fn terminal_argv_multi_token_template_keeps_the_words_around_the_placeholder() {
        let cmd = vec!["aoide".to_string(), "conduct".to_string()];
        let argv = build_terminal_argv("wezterm start --always-new-process -- {cmd}", &cmd);
        assert_eq!(
            argv,
            vec!["wezterm", "start", "--always-new-process", "--", "aoide", "conduct"]
        );
    }

    #[test]
    fn terminal_argv_quoted_join_escapes_spaces_and_embedded_quotes() {
        // A conducted argv element containing whitespace or a literal single
        // quote (an agent flag value, a task prompt) must survive a REAL
        // `sh -c` re-split as ONE word — this is the whole reason the quoted
        // placeholder joins with POSIX single-quoting rather than a bare
        // space-join.
        let cmd = vec![
            "aoide".to_string(),
            "conduct".to_string(),
            "--".to_string(),
            "claude".to_string(),
            "--append-system-prompt".to_string(),
            "two words".to_string(),
            "it's fine".to_string(),
        ];
        let argv = build_terminal_argv("foot sh -c '{cmd}'", &cmd);
        assert_eq!(argv.len(), 4);
        assert_eq!(
            argv[3],
            r#"aoide conduct -- claude --append-system-prompt 'two words' 'it'\''s fine'"#
        );
    }

    #[test]
    fn terminal_argv_bare_placeholder_ignores_an_empty_command() {
        let argv = build_terminal_argv("kitty -e {cmd}", &[]);
        assert_eq!(argv, vec!["kitty", "-e"]);
    }

    #[test]
    fn resolve_windowed_argv_end_to_end_without_spawning_anything() {
        // Everything up to and including argv construction is exercised
        // here with no process ever spawned — the LIVE gate (a real
        // terminal opening under the compositor) is the orchestrator's and
        // the User's, never this crate's tests.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY"]);
        std::env::set_var("AOIDE_TERMINAL", "foot sh -c '{cmd}'");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        std::env::remove_var("DISPLAY");

        let exe = std::path::Path::new("/usr/bin/aoide");
        let conduct_args = build_conduct_args(false, "claude", "win-1", None, &["claude".to_string()]);
        let argv = resolve_windowed_argv(exe, &conduct_args).expect("template + display resolve");
        assert_eq!(
            argv,
            vec![
                "foot".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                "/usr/bin/aoide conduct --spawned --agent claude --id win-1 -- claude".to_string(),
            ]
        );
    }

    #[test]
    fn windowed_spawn_without_a_template_is_a_taught_error_naming_the_env_var() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY"]);
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0"); // a display IS present —
        // isolates this test to the template check alone.

        let out = session_spawn(&spawn_invocation(&["claude"], &[("windowed", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "no-terminal-template");
        assert!(out.message.contains("AOIDE_TERMINAL"), "message: {}", out.message);
    }

    #[test]
    fn windowed_spawn_without_a_template_never_touches_the_stage() {
        // The taught error is a pure pre-flight — it must return before ANY
        // process spawn or session-registration attempt (unlike a bad
        // `<command>`, which still registers-then-fails inside `conduct`).
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
        ]);
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        let root = unique_stage("spawn-windowed-no-template");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let id = "spawn-windowed-no-template";
        let out = session_spawn(&spawn_invocation(
            &["claude"],
            &[("id", id), ("windowed", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap_or_default();
        assert!(
            !s.sessions.iter().any(|r| r.session_id == id),
            "a pre-flight taught error must never register a session"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn windowed_spawn_without_a_display_is_a_taught_error_naming_the_fallback() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY"]);
        std::env::set_var("AOIDE_TERMINAL", "kitty -e {cmd}");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        let out = session_spawn(&spawn_invocation(&["claude"], &[("windowed", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "headless-host");
        assert!(out.message.contains("--windowed"), "message: {}", out.message);
    }

    #[test]
    fn windowed_spawn_accepts_either_display_variable() {
        // Only $DISPLAY (no Wayland) must still pass the display check — the
        // taught error is "both absent", not "Wayland absent".
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY"]);
        std::env::set_var("AOIDE_TERMINAL", "kitty -e {cmd}");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::set_var("DISPLAY", ":0");
        assert!(require_display().is_ok());
    }

    #[test]
    fn plain_spawn_without_windowed_never_checks_the_display_or_template() {
        // The default (headless) path must stay completely unaffected by
        // `--windowed`'s pre-flight — a headless host with neither
        // $AOIDE_TERMINAL nor a display must still spawn headless exactly as
        // before P-D7.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_SPAWN_EXE",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        let root = unique_stage("spawn-plain-unaffected");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_CONDUCT_SPAWN_EXE", built_aoide_bin());

        let id = "spawn-plain-unaffected";
        let out = session_spawn(&spawn_invocation(&["sh", "-c", "true"], &[("id", id)]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["windowed"], false);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shell_quote_is_identity_for_bare_safe_words_and_quotes_the_rest() {
        assert_eq!(shell_quote("claude"), "claude");
        assert_eq!(shell_quote("--resume"), "--resume");
        assert_eq!(shell_quote("a/b:c=d@e.f"), "a/b:c=d@e.f");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("two words"), "'two words'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
