//! shellbridge's socket loop — the session/hook state bridge
//! (concepts/shellbridge).
//!
//! Registers agent sessions + window addresses and records Claude Code hook
//! phases, publishing them to `state/stage/` for Quickshell to read. Writes
//! are atomic (write-temp-then-rename) so a hot-reload never sees a torn file
//! (CONTRACTS.md §4 discipline).
//!
//! The process seeds the stage files (atomic writer), then binds its unix
//! socket and serves newline-delimited JSON commands: a widget click sends
//! `{ "cmd": "focuswindow", "address": "0x…" }` and shellbridge dispatches the
//! Hyprland focus (the Terminal-Commander session-jump flow). The accept loop
//! is robust: a malformed line, an unknown command, or a dropped connection is
//! logged and skipped — nothing ever kills the service.
//!
//! Moved here from root `src/shellbridge.rs` (Phase 3b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) — ONLY the socket-loop half
//! (`socket_path`, `BridgeCommand`, `parse_command`, `run`); the stage-file FS
//! substrate (`stage_dir`, `atomic_write`, `with_stage_lock`, …) already
//! moved to `aoide-storage` in Phase 3a and stays there. Root re-exports both
//! halves at their old `crate::shellbridge::*` path so no caller changes.

use aoide_protocol as daemon;
use aoide_storage::fs::{conducting_stage_dir, seed_if_absent};
use aoide_storage::mode::{load_mode_marker, RiceMode};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

/// The shellbridge socket path — **contract**: never computed independently.
/// `$XDG_RUNTIME_DIR/aoide/shellbridge.sock`.
pub fn socket_path() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());
    PathBuf::from(runtime)
        .join("aoide")
        .join("shellbridge.sock")
}

/// One parsed inbound command from the socket wire (newline-delimited JSON).
/// The wire shape is defined by ShellBridge.qml; the only command today is the
/// session-jump `focuswindow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeCommand {
    /// `{ "cmd": "focuswindow", "address": "0x…" }` — jump to a window.
    Focus { address: String },
    /// `{ "cmd": "focussession", "sessionId": "…" }` — jump to a SESSION by id.
    /// The daemon resolves id → `windowAddress` (focus the exact window), or
    /// falls back to id → `workspace` (switch to it) when the address isn't
    /// resolved yet. This is the source-of-truth jump: QML sends only the
    /// sessionId a roster row already holds, never a stale/empty address.
    FocusSession { session_id: String },
    /// `{ "cmd": "power", "action": "lock|logout|suspend|hibernate|reboot|shutdown" }`
    /// — a system action from the Exodos powermenu (AoideExodos.qml). QML never
    /// shells out; this command is the gate through which the six endings reach
    /// hyprlock / hyprctl / systemctl.
    Power { action: PowerAction },
    /// `{ "cmd": "ricemode" }` — a click on the bar's rice-mode cell
    /// (bar.qml's `modeText`). No payload: the daemon reads
    /// `stage/mode.json` itself and decides the target — a two-way toggle
    /// (`staging ⇄ declarative`), never a picker QML would need to supply
    /// state for. See [`dispatch_rice_mode_toggle`].
    ToggleRiceMode,
    /// `{ "cmd": "refreshusage" }` — a click on the CLAUDE ledger gadget's ❋
    /// spark (UsageGadget.qml). No payload: the daemon re-runs `aoide usage`
    /// itself, which atomic-writes `state/usage.json`, and the gadget's own
    /// FileView watch picks the new file up and re-renders — the manual
    /// analogue of the poller timer's periodic write. See
    /// [`dispatch_usage_refresh`].
    RefreshUsage,
    /// `{ "cmd": "rechecksessions" }` — a click on the Terminals/Conductor
    /// header recheck control. No payload: the daemon re-execs `aoide graph
    /// reap` itself — the liveness/rehook sweep (reap dead sessions, decay
    /// `stopped` → `idle`, prune orphaned hook records) the ~12s
    /// `aoide-graph-reap.timer` runs periodically — so a resumed/exited session
    /// is re-evaluated NOW instead of waiting up to a full timer period. The
    /// gadgets refresh off the resulting `sessions.json`/`hooks.json`/
    /// `graph.json` writes through their own FileView watches. See
    /// [`dispatch_recheck_sessions`].
    RecheckSessions,
    /// Acknowledged session-menu action, routed through the core CLI.
    SessionAction { session_id: String, action: String, fields: Value },
    /// `{ "cmd": "heraldpush", "notification": { … } }` — file one notification
    /// into `stage/herald.json`. Sent by `aoide herald push` (dunst's `script`
    /// hook) and by `graph permit` for a summons; NOT by QML, which only reads
    /// the ledger. The daemon is the single writer, which is the whole point:
    /// dunst runs its scripts asynchronously, so two notifications arriving
    /// together would otherwise race and one would be lost. See
    /// [`dispatch_herald_push`].
    HeraldPush { notification: Box<Value> },
    /// `{ "cmd": "heraldverdict", "id": "…", "verdict": "approve|deny" }` — the
    /// human clicked a summons' approve or deny button in the QML herald. The
    /// daemon types the verdict into the waiting session through
    /// `graph send`, the one gated injection door. This is the button that
    /// dunst physically could not draw: it had no per-region hit testing, so a
    /// drawn deny chip fired the window-wide left-click binding and APPROVED.
    HeraldVerdict { id: String, verdict: String },
    /// `{ "cmd": "heralddismiss", "id": "…" }` — drop one card from the ledger.
    /// The QML herald owns the dismiss clock (a notification dunst never
    /// displays is never expired by dunst either), so this is how a timeout or
    /// a click closes a card. `"*"` clears the desk.
    HeraldDismiss { id: String },
}

/// The six system actions the powermenu can request. A closed set — an unknown
/// action string parses to `None` at the wire, never to a dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    Lock,
    Logout,
    Suspend,
    Hibernate,
    Reboot,
    Shutdown,
}

impl PowerAction {
    /// Parse the wire's `action` string. Case-sensitive lowercase by contract
    /// (ShellBridge.qml sends exactly these), anything else is `None`.
    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "lock" => Some(Self::Lock),
            "logout" => Some(Self::Logout),
            "suspend" => Some(Self::Suspend),
            "hibernate" => Some(Self::Hibernate),
            "reboot" => Some(Self::Reboot),
            "shutdown" => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// The program + args this action spawns. `lock` matches the existing
    /// `lock` shell alias (hyprlock); `logout` exits the compositor; the rest
    /// are systemd commands.
    fn command(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Lock => ("hyprlock", &[]),
            Self::Logout => ("hyprctl", &["dispatch", "exit"]),
            Self::Suspend => ("systemctl", &["suspend"]),
            Self::Hibernate => ("systemctl", &["hibernate"]),
            Self::Reboot => ("systemctl", &["reboot"]),
            Self::Shutdown => ("systemctl", &["poweroff"]),
        }
    }

    /// The wire name back, for audit lines.
    fn as_str(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Logout => "logout",
            Self::Suspend => "suspend",
            Self::Hibernate => "hibernate",
            Self::Reboot => "reboot",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Parse ONE wire line into a [`BridgeCommand`]. Pure and total: malformed
/// JSON, a missing/unknown `cmd`, or a `focuswindow` with an empty/absent
/// `address` all yield `None` (the loop logs and ignores them) — never a panic.
pub fn parse_command(line: &str) -> Option<BridgeCommand> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    match v.get("cmd").and_then(Value::as_str)? {
        "sessionaction" => {
            let session_id = v.get("sessionId")?.as_str()?.trim().to_string();
            let action = v.get("action")?.as_str()?.to_string();
            let fields = v.get("fields").cloned().unwrap_or_else(|| json!({}));
            session_action_args(&session_id, &action, &fields)?;
            Some(BridgeCommand::SessionAction { session_id, action, fields })
        }
        "focuswindow" => {
            let address = v
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if address.is_empty() {
                return None;
            }
            Some(BridgeCommand::Focus { address })
        }
        "focussession" => {
            let session_id = v
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if session_id.is_empty() {
                return None;
            }
            Some(BridgeCommand::FocusSession { session_id })
        }
        "power" => {
            let action = v
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            PowerAction::from_wire(&action).map(|action| BridgeCommand::Power { action })
        }
        "ricemode" => Some(BridgeCommand::ToggleRiceMode),
        "refreshusage" => Some(BridgeCommand::RefreshUsage),
        "rechecksessions" => Some(BridgeCommand::RecheckSessions),
        "heraldpush" => {
            let notification = v.get("notification")?.clone();
            // A record with no id is unfilable — it could neither replace its
            // predecessor nor be dismissed later.
            let id = notification.get("id").and_then(Value::as_str)?;
            if id.trim().is_empty() {
                return None;
            }
            Some(BridgeCommand::HeraldPush {
                notification: Box::new(notification),
            })
        }
        "heraldverdict" => {
            let id = v.get("id").and_then(Value::as_str)?.trim().to_string();
            let verdict = v.get("verdict").and_then(Value::as_str)?.trim().to_string();
            // A closed set: only the two real answers reach the injection door.
            // Anything else — a typo, a truncated wire line — is dropped here
            // rather than resolved to a default, because both defaults are
            // wrong on a permission gate.
            if id.is_empty() || !matches!(verdict.as_str(), "approve" | "deny") {
                return None;
            }
            Some(BridgeCommand::HeraldVerdict { id, verdict })
        }
        "heralddismiss" => {
            let id = v.get("id").and_then(Value::as_str)?.trim().to_string();
            if id.is_empty() {
                return None;
            }
            Some(BridgeCommand::HeraldDismiss { id })
        }
        _ => None,
    }
}

/// Dispatch ONE power action: spawn the mapped command and return. NEVER waits
/// for exit — several of these actions kill or freeze the very process that
/// would be waiting (logout tears the session down, suspend stops the clock) —
/// a detached reaper thread collects the child's status so it never lingers as
/// a zombie. A spawn failure is an `Err` for the caller to log; nothing here
/// can take down the accept loop.
fn dispatch_power(action: PowerAction) -> std::io::Result<()> {
    let (prog, args) = action.command();
    let mut child = std::process::Command::new(prog).args(args).spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Pure decision: which `rice mode <word>` this toggle targets, given the
/// CURRENT mode. A two-way toggle, not a three-way cycle — `Staging` locks
/// to `declarative`; `Declarative` OR `Draft` both unlock back to `stage`
/// (exiting a draft session to plain staging this way is deliberate:
/// `rice mode stage` already tears down the draft's routing symlink on its
/// own, `commands/mode.rs`'s `handle_mode_stage`). There is no generic "next
/// draft" a bare click could cycle into without a name, so draft is only
/// ever reachable via `rice mode draft <name>`, never this toggle.
///
/// This decides ONLY the target word, not which song it acts on — see
/// [`dispatch_rice_mode_toggle`] for the asymmetric song-arg resolution
/// (`declarative` explicitly re-pins to `AOIDE_DEFAULT_SONG`; `stage` stays
/// bare).
fn rice_mode_toggle_target(current: RiceMode) -> &'static str {
    match current {
        RiceMode::Staging => "declarative",
        RiceMode::Declarative | RiceMode::Draft => "stage",
    }
}

/// Dispatch ONE rice-mode toggle. Unlike [`dispatch_power`], this WAITS for
/// the child (`.output()`, not spawn-and-detach): a mode switch never kills
/// or freezes this process the way logout/suspend do, so it's safe — and
/// necessary — to know synchronously whether the switch actually succeeded
/// before deciding whether to fire a notification.
///
/// Execs the SIBLING `lyra` binary (`daemon::bin::rice_bin()`, protocol's
/// sibling resolver — never a bare `"aoide"`, and never `current_exe()`:
/// `rice mode` lives in lyra, not this running binary, since P-A5 moved it
/// out of core) as `rice mode <target> --json`. This call is NOT inside
/// `with_stage_lock` — see `protocol::bin`'s module doc for why that would
/// matter if it ever were.
///
/// The two toggle directions are deliberately asymmetric about which song
/// they act on. `stage` (declarative/draft → staging) passes no song arg —
/// `handle_mode_stage` resolves via its own `current_staged_song()`, and
/// staying on whatever's currently being edited is the reasonable default
/// there. `declarative` (staging → declarative) is different: that
/// direction is supposed to mean "matches nix," not "frozen wherever I
/// happened to be," so it explicitly appends the nix-declared baseline song
/// (`AOIDE_DEFAULT_SONG`, baked into shellbridge.service by
/// modules/nucleus/shellbridge.nix — the same env-var precedent as
/// AOIDE_WALLPAPER) as the CLI arg, overriding `handle_mode_declarative`'s
/// bare-call fallback to whatever song is currently staged
/// (`commands/mode.rs`). If the env var is absent or empty (outside the
/// systemd service, or before a rebuild lands it) this falls back to the
/// existing bare no-arg call rather than erroring — a missing env var must
/// never turn a working toggle into a broken one. This asymmetry is scoped
/// to THIS dispatch path only: a bare `aoide rice mode declarative` typed
/// directly in a terminal is untouched and keeps resolving via
/// `current_staged_song()`.
///
/// On success (exit 0), returns the CLI's own `message` string verbatim —
/// reusing that exact copy rather than inventing new wording — and fires a detached
/// `notify-send "Aoide" <message>` (same reaper-thread idiom as
/// `dispatch_power`'s spawned child, so a slow/hung `notify-send` can never
/// block the accept loop; a `notify-send` spawn failure is a soft, eprintln
/// -only failure — the mode DID switch, so it must not be reported as a
/// toggle failure). On failure (non-zero exit, a spawn error, or unparsable
/// JSON on an exit-0 that shouldn't happen) returns `Err` for the caller to
/// audit-log — no notification fires for a failed toggle.
/// Pure decision: does the declarative-direction toggle have an explicit
/// baseline song to pass, given the toggle's target word and the CURRENT
/// `AOIDE_DEFAULT_SONG` env value (read by the caller, passed in untouched —
/// kept pure and out of `std::env` here so this is unit-testable without
/// mutating process-wide env state, which races under parallel tests). The
/// `stage` direction never gets one (see [`dispatch_rice_mode_toggle`]'s doc
/// comment for why); an absent or blank/whitespace-only value also yields
/// `None` — never pass an empty arg, and never let a missing env var
/// (outside the systemd service, or before a rebuild lands it) turn the
/// toggle into anything but the existing bare call.
fn rice_mode_toggle_default_song(target: &str, env_value: Option<&str>) -> Option<String> {
    if target != "declarative" {
        return None;
    }
    let trimmed = env_value?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn dispatch_rice_mode_toggle() -> Result<String, String> {
    let current = load_mode_marker().mode;
    let target = rice_mode_toggle_target(current);
    let default_song =
        rice_mode_toggle_default_song(target, std::env::var("AOIDE_DEFAULT_SONG").ok().as_deref());

    let mut command = std::process::Command::new(daemon::bin::rice_bin());
    command.args(["rice", "mode", target]);
    if let Some(song) = &default_song {
        command.arg(song);
    }
    command.arg("--json");
    let output = command
        .output()
        .map_err(|e| format!("spawning `lyra rice mode {target}`: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "`lyra rice mode {target}` exited {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let message = serde_json::from_slice::<Value>(&output.stdout)
        .ok()
        .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| format!("rice mode: {target}"));

    match std::process::Command::new("notify-send")
        .arg("Aoide")
        .arg(&message)
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            // The mode switch itself already succeeded above — a dead/missing
            // notify-send must not turn a successful toggle into a reported
            // failure, so this is logged, not returned as `Err`.
            eprintln!("[aoide/shellbridge] notify-send failed (mode switch itself succeeded): {e}");
        }
    }

    Ok(message)
}

/// Pure decision: did one finished `aoide usage --json` actually refresh the
/// state file? Judged on the CLI's own JSON envelope `status`, NOT the exit
/// code alone — the same "success is the real output, not the exit status"
/// rule `song/src/ipc.rs`'s `classify_call` is built on. `aoide usage` prints
/// `{"status":"ok",…,"message":"…"}` and exits 0 on a real `state/usage.json`
/// write, and an error envelope (or a non-zero exit) when the atomic write
/// itself fails.
///
/// A DEGRADED live block is NOT a failure: a `live:{ok:false}` payload (no
/// credentials, the Claude-Code-only OAuth rejection, a transport error) still
/// yields status `ok` and a written file — exactly the graceful-degrade the
/// gadget is built to render — so the refresh SUCCEEDED. Only a failed write,
/// a non-zero exit, or unparseable output is an `Err`. Returns the CLI's own
/// `message` on success so the audit line reuses that exact wording rather than
/// inventing new copy (same discipline as [`dispatch_rice_mode_toggle`]).
fn classify_usage_refresh(exited_ok: bool, stdout: &str, stderr: &str) -> Result<String, String> {
    if !exited_ok {
        // `--json` still prints the structured envelope on failure; prefer a
        // spoken stderr, fall back to stdout, never a blank reason.
        let said = {
            let e = stderr.trim();
            if e.is_empty() {
                stdout.trim()
            } else {
                e
            }
        };
        return Err(if said.is_empty() {
            "`aoide usage` exited nonzero with no message".to_string()
        } else {
            said.to_string()
        });
    }
    let v: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| "`aoide usage --json` printed no parseable envelope".to_string())?;
    let message = v
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("usage refreshed")
        .to_string();
    match v.get("status").and_then(Value::as_str) {
        Some("ok") => Ok(message),
        Some(other) => Err(format!("`aoide usage` reported status {other}: {message}")),
        None => Err("`aoide usage --json` output had no status field".to_string()),
    }
}

/// Dispatch ONE usage refresh: exec the core `aoide` binary
/// (`daemon::bin::core_bin()`, protocol's sibling resolver — never a bare
/// `"aoide"` relying on PATH alone) as `aoide usage --json` and audit the
/// outcome, judged on its real output via [`classify_usage_refresh`]. This
/// call is NOT inside `with_stage_lock` — see `protocol::bin`'s module doc
/// for why that would matter if it ever were.
///
/// Runs on a DETACHED thread. Unlike the rice-mode toggle (a fast local switch,
/// safe to `.output()` inline), `aoide usage`'s live fetch is `curl --max-time
/// 15`, so waiting for it inline would tie up this connection's own thread for
/// up to 15 s for no reason (§3b's thread-per-connection accept loop keeps
/// that from starving anyone else, but there is still no reason to hold it).
/// So this SPAWNS and returns immediately — the same no-block posture
/// [`dispatch_power`] takes — and the thread collects the child and audits the
/// result so it neither lingers nor blocks. The gadget updates itself off the
/// resulting `state/usage.json` write through its own FileView watch regardless
/// of what this logs; the audit line exists for the operator, not to push data.
/// Best-effort throughout: a spawn failure or a classify error is audited,
/// never panicked or propagated.
fn dispatch_usage_refresh() {
    std::thread::spawn(|| {
        let result = match std::process::Command::new(daemon::bin::core_bin())
            .args(["usage", "--json"])
            .output()
        {
            Ok(out) => classify_usage_refresh(
                out.status.success(),
                &String::from_utf8_lossy(&out.stdout),
                &String::from_utf8_lossy(&out.stderr),
            ),
            Err(e) => Err(format!("spawning `aoide usage`: {e}")),
        };
        let (event, detail) = match result {
            Ok(msg) => ("usage-refresh", msg),
            Err(e) => ("usage-refresh-failed", e),
        };
        let _ = daemon::audit(
            &daemon::default_audit_log(),
            daemon::Door::Daemon,
            daemon::EventClass::Audit,
            "shellbridge",
            event,
            &detail,
        );
    });
}

/// Pure decision: did one finished `aoide session reap --json` actually run the
/// sweep? Judged on the CLI's own JSON envelope `status`, NOT the exit code
/// alone — the same "success is the real output, not the exit status" rule
/// [`classify_usage_refresh`] follows. `aoide session reap` prints
/// `{"status":"ok",…,"message":"…"}` and exits 0 on every real pass, INCLUDING
/// a no-op "nothing to reap (all sessions live)" one — a quiet sweep is a
/// successful sweep, not a failure — and an error envelope (or a non-zero exit)
/// only when a stage read/write actually failed. Returns the CLI's own
/// `message` on success so the audit line reuses that exact wording rather than
/// inventing new copy.
fn classify_recheck(exited_ok: bool, stdout: &str, stderr: &str) -> Result<String, String> {
    if !exited_ok {
        let said = {
            let e = stderr.trim();
            if e.is_empty() {
                stdout.trim()
            } else {
                e
            }
        };
        return Err(if said.is_empty() {
            "`aoide session reap` exited nonzero with no message".to_string()
        } else {
            said.to_string()
        });
    }
    let v: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| "`aoide session reap --json` printed no parseable envelope".to_string())?;
    let message = v
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("sessions rechecked")
        .to_string();
    match v.get("status").and_then(Value::as_str) {
        Some("ok") => Ok(message),
        Some(other) => Err(format!("`aoide session reap` reported status {other}: {message}")),
        None => Err("`aoide session reap --json` output had no status field".to_string()),
    }
}

/// Dispatch ONE session recheck: exec the core `aoide` binary
/// (`daemon::bin::core_bin()`, protocol's sibling resolver — never a bare
/// `"aoide"` relying on PATH alone) as `aoide session reap --announce --json`
/// — the liveness/rehook sweep (reap dead sessions, decay `stopped` →
/// `idle`, prune orphaned hook records, refresh every live agent's
/// transcript fields) the ~12s `aoide-graph-reap.timer` runs periodically —
/// so the Terminals/Conductor `[ reap ]` control triggers it NOW instead of
/// waiting up to a full timer period. This call is NOT inside
/// `with_stage_lock` — see `protocol::bin`'s module doc for why that would
/// matter if it ever were.
///
/// `--announce` is what makes the click ANSWER: the toast is unconditional here,
/// where a human pressed something, while the timer's own sweeps stay silent
/// unless they actually changed the roster (see `reap::reap_and_announce`). The
/// notification is raised by the child, not here — this thread only audits.
///
/// `--now` is the other half of "a human pressed something": the click takes
/// every idle worker shell `aoide spawn` left behind, rather than waiting out
/// the two-day silence the unattended sweep requires
/// (`reap::REAP_SPAWNED_SHELL_STALE_SECS`). It is passed EXPLICITLY here and
/// not inferred — this runs on a detached thread with no tty, so
/// `reap::with_human_gesture`'s own probe would read it as the timer.
///
/// Runs on a DETACHED thread. `session reap` shells out to `hyprctl clients -j`
/// for window liveness; that is normally instant, but a hung compositor query
/// must never tie up this connection's own thread waiting on it (§3b's
/// thread-per-connection accept loop keeps a stuck query from starving anyone
/// else, but there is still no reason to hold it). So this SPAWNS and returns
/// immediately — the same no-block posture [`dispatch_usage_refresh`] takes —
/// and the thread collects the child and audits the outcome via
/// [`classify_recheck`]. The Terminals/Conductor gadgets update themselves off
/// the resulting `sessions.json`/`hooks.json`/`graph.json` writes through their
/// own FileView watches regardless of what this logs; the audit line is for the
/// operator, not to push data. Best-effort throughout: a spawn failure or a
/// classify error is audited, never panicked or propagated.
fn dispatch_recheck_sessions() {
    std::thread::spawn(|| {
        let result = match std::process::Command::new(daemon::bin::core_bin())
            .args(["session", "reap", "--announce", "--now", "--json"])
            .output()
        {
            Ok(out) => classify_recheck(
                out.status.success(),
                &String::from_utf8_lossy(&out.stdout),
                &String::from_utf8_lossy(&out.stderr),
            ),
            Err(e) => Err(format!("spawning `aoide session reap`: {e}")),
        };
        let (event, detail) = match result {
            Ok(msg) => ("recheck", msg),
            Err(e) => ("recheck-failed", e),
        };
        let _ = daemon::audit(
            &daemon::default_audit_log(),
            daemon::Door::Daemon,
            daemon::EventClass::Audit,
            "shellbridge",
            event,
            &detail,
        );
    });
}

// ── session actions (the acknowledged session-menu bridge) ─────────────────

/// A wire value that becomes a bare argv token: a SESSION ID. Stricter than
/// [`safe_action_value`] below — a session id is a bookkeeping key with no
/// legitimate use for whitespace, so any is refused outright.
fn safe_session_id(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

/// A wire value that becomes a bare argv token: a PROJECT NAME (`project`'s
/// `project` field, `createproject`/`editproject`'s `name`). Ordinary spaces
/// ARE legal here — "My Project" is a real name, and an argv element is
/// passed to `Command::arg` whole, never through a shell — so only
/// emptiness, a leading `-` (flag-shaped), and control characters are
/// refused. Session ids keep the stricter [`safe_session_id`] above.
fn safe_action_value(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && !s.chars().any(char::is_control)
}

/// A wire value that becomes a filesystem path argument. Whitespace IS legal
/// here — `/home/khoa/My Documents` is a real directory, and an argv element
/// is passed to `Command::arg` whole, never through a shell — so this is a
/// separate rule, not a reuse of the one above. Absolute by requirement,
/// which also settles the leading-dash question: a string starting with `/`
/// can never be read as a flag, so no `-` check is needed here.
fn safe_action_path(s: &str) -> bool {
    s.starts_with('/') && !s.chars().any(char::is_control)
}

/// The closed, five-action session-menu whitelist — a PLAN, not one argv.
/// One action is one or two invocations, run in order, stopping at the first
/// failure; `Option<Vec<Vec<String>>>` is deliberate over a single-argv
/// function plus a second for the two-step case: `parse_command`'s own
/// `"sessionaction"` arm gates on `session_action_args(…)?`, which only ever
/// needs *an* `Option`, so this shape keeps that call site compiling
/// unedited AND keeps ONE authority for the whitelist and one call site for
/// the gate (CRAFT: one authority per fact).
///
/// A strict whitelist, not a translator: exactly five actions, anything else
/// is `None`. No generic exec, no arbitrary argv, ever — every element of
/// every returned vector is either a literal from this function or a value
/// that passed [`safe_action_value`]/[`safe_action_path`] below.
///
/// The field shapes are the song-side session menu's own, exactly — they are
/// not the shapes an API designer would pick in isolation, and the bridge
/// matching the UI is the whole point of this slice. Do not "normalize"
/// them.
fn session_action_args(session_id: &str, action: &str, fields: &Value) -> Option<Vec<Vec<String>>> {
    if !safe_session_id(session_id) {
        return None;
    }
    let id = session_id.to_string();
    match action {
        "undying" => {
            let state = fields.get("state").and_then(Value::as_str)?;
            if !matches!(state, "on" | "off") {
                return None;
            }
            Some(vec![vec![
                "session".to_string(),
                "grant".to_string(),
                "undying".to_string(),
                state.to_string(),
                "--id".to_string(),
                id,
            ]])
        }
        "project" => {
            // No `clear` field: an empty STRING is the clear request, which
            // is what the menu's "Automatic from directory" row sends. But
            // `project` must actually BE a JSON string — a missing key or a
            // non-string value (`null`, a number, …) is refused outright,
            // never read as an implicit clear: a malformed wire line must
            // never mutate anything.
            let name = fields.get("project").and_then(Value::as_str)?.trim();
            if name.is_empty() {
                Some(vec![vec![
                    "session".to_string(),
                    "project".to_string(),
                    "--id".to_string(),
                    id,
                    "--clear".to_string(),
                ]])
            } else if safe_action_value(name) {
                Some(vec![vec![
                    "session".to_string(),
                    "project".to_string(),
                    "--id".to_string(),
                    id,
                    "--project".to_string(),
                    name.to_string(),
                ]])
            } else {
                None
            }
        }
        // `fields` is not consulted at all: extra keys are accepted and
        // ignored rather than refused, since rejecting unknown keys would
        // break the menu the first time it grew a field.
        "kill" => Some(vec![vec![
            "session".to_string(),
            "kill".to_string(),
            "--id".to_string(),
            id,
        ]]),
        "createproject" | "editproject" => {
            let name = fields.get("name").and_then(Value::as_str)?.trim();
            if !safe_action_value(name) {
                return None;
            }
            let raw_paths = fields.get("paths").and_then(Value::as_array)?;
            // An empty list is `None`, not an instruction to erase: an
            // "exact replacement" with nothing to replace with is a mistake.
            // No length cap: the list is bounded by the wire's own line
            // length, not by a count guessed in advance.
            if raw_paths.is_empty() {
                return None;
            }
            let mut paths = Vec::with_capacity(raw_paths.len());
            for p in raw_paths {
                // One bad element rejects the whole action; never filter and
                // proceed. A non-string element fails the same way here.
                let p = p.as_str()?;
                if !safe_action_path(p) {
                    return None;
                }
                paths.push(p.to_string());
            }
            if action == "createproject" {
                // Two invocations, order load-bearing: `--new` is slice A's
                // refuse-when-the-name-exists flag — the bridge never
                // pre-checks whether a name is taken, the CLI is the one
                // authority for that.
                let mut add = vec!["project".to_string(), "add".to_string(), name.to_string()];
                add.extend(paths);
                add.push("--new".to_string());
                let assign = vec![
                    "session".to_string(),
                    "project".to_string(),
                    "--id".to_string(),
                    id,
                    "--project".to_string(),
                    name.to_string(),
                ];
                Some(vec![add, assign])
            } else {
                // The roots are replaced exactly; the name is immutable (the
                // lookup key, never a rename) — an unknown name is refused
                // by the CLI, not by the bridge.
                let mut edit = vec!["project".to_string(), "edit".to_string(), name.to_string()];
                edit.extend(paths);
                Some(vec![edit])
            }
        }
        _ => None,
    }
}

/// The `status`-is-ok flag, `message`, and optional `data` payload of one
/// `--json` envelope, from whichever stream carried it. `data` is `None`
/// when the key is absent — carried through verbatim by
/// [`session_action_reply`] when a step's CLI outcome has one (a `kill`
/// reply's resolved target/pid, say).
fn outcome_envelope(stream: &str) -> Option<(bool, String, Option<Value>)> {
    let v: Value = serde_json::from_str(stream.trim()).ok()?;
    let ok = v.get("status").and_then(Value::as_str)? == "ok";
    let message = v.get("message").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let data = v.get("data").cloned();
    Some((ok, message, data))
}

/// Shape the ONE JSON reply line for an acknowledged session action — pure
/// and total, mirroring [`classify_recheck`]'s own rule: success is the real
/// output, not the exit status. `--json` puts its envelope on a DIFFERENT
/// stream depending on where the command failed: a dispatched command
/// prints it on stdout, but a usage error the parser refused BEFORE dispatch
/// prints it on stderr with an empty stdout (`protocol/src/door.rs:800-814`)
/// — exactly the path `createproject`/`editproject` take until slice A
/// lands, so reading stdout alone would hand QML a raw JSON blob as its
/// "message".
fn session_action_reply(
    session_id: &str,
    action: &str,
    exited_ok: bool,
    stdout: &str,
    stderr: &str,
) -> Value {
    let (ok, message, data) = match outcome_envelope(stdout).or_else(|| outcome_envelope(stderr)) {
        Some((status_ok, msg, data)) => {
            let ok = exited_ok && status_ok;
            let message = if !msg.is_empty() {
                msg
            } else if ok {
                format!("session {action} done")
            } else {
                format!("session {action} failed")
            };
            (ok, message, data)
        }
        None => {
            let stderr = stderr.trim();
            let stdout = stdout.trim();
            let message = if !stderr.is_empty() {
                stderr.to_string()
            } else if !stdout.is_empty() {
                stdout.to_string()
            } else {
                format!("`aoide {action}` printed no parseable envelope")
            };
            (false, message, None)
        }
    };
    let mut reply = json!({
        "ok": ok,
        "message": message,
        "action": action,
        "sessionId": session_id,
    });
    if let Some(data) = data {
        reply["data"] = data;
    }
    reply
}

/// One step, spawned: exec the core `aoide` binary
/// (`daemon::bin::core_bin()`, protocol's sibling resolver — never a bare
/// `"aoide"` relying on PATH alone) with `argv` plus `--json`, the exact
/// pattern `dispatch_usage_refresh`/`dispatch_recheck_sessions` already use.
/// This call is NOT inside `with_stage_lock` — see `protocol::bin`'s module
/// doc for why that would matter if it ever were.
fn run_session_step(session_id: &str, action: &str, argv: &[String]) -> Value {
    match std::process::Command::new(daemon::bin::core_bin())
        .args(argv)
        .arg("--json")
        .output()
    {
        Ok(out) => session_action_reply(
            session_id,
            action,
            out.status.success(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        // The first TWO argv elements only — always the command path, never
        // a value — same discipline every audit line here holds.
        Err(e) => json!({
            "ok": false,
            "message": format!("spawning `aoide {} {}`: {e}", argv[0], argv[1]),
            "action": action,
            "sessionId": session_id,
        }),
    }
}

/// One audit line per ACTION, never per step: detail is the action name and
/// the status, and nothing else — never a project name, a path, or a
/// session id. This deliberately departs from `dispatch_usage_refresh`/
/// `dispatch_recheck_sessions`, which reuse the CLI's own `message`: those
/// two commands take no arguments, this one does, and a `message` could grow
/// to quote one — house rule, an audit line never carries argument values.
/// `partial` gets its own event name so an operator scanning the log can see
/// a half-applied action without reading the message. The dispatched
/// commands are separately audited by the child processes' own `dispatch`
/// inside `aoided`; this line records only that the desk asked.
fn audit_session_action(action: &str, event: &str, outcome: &str) {
    let _ = daemon::audit(
        &daemon::default_audit_log(),
        daemon::Door::Daemon,
        daemon::EventClass::Audit,
        "shellbridge",
        event,
        &format!("session action {action}: {outcome}"),
    );
}

/// The sequencer: run one acknowledged session action's whole plan, on the
/// CALLER's thread — `handle_conn` is what detaches it. Rebuilds the plan
/// through [`session_action_args`], the SAME authority `parse_command`'s
/// wire gate already consulted; a `None` here is unreachable through the
/// wire but total by construction, never a panic. Steps run in order,
/// stopping at the first failure: a failing FIRST step returns that reply
/// unchanged (nothing ran, nothing changed); a failing LATER step means an
/// earlier step already changed the world, so the reply says so honestly
/// (`partial: true`) rather than rolling back — deleting a project the
/// operator may already want, to tidy up a failure they can see and fix in
/// one click, is worse than the partial state. No retries, no queueing: one
/// spawn per step, one reply per action.
fn dispatch_session_action(session_id: &str, action: &str, fields: &Value) -> Value {
    let Some(plan) = session_action_args(session_id, action, fields) else {
        return json!({
            "ok": false,
            "message": "unsupported session action",
            "action": action,
            "sessionId": session_id,
        });
    };

    let mut last = Value::Null;
    for (i, argv) in plan.iter().enumerate() {
        let reply = run_session_step(session_id, action, argv);
        let step_ok = reply.get("ok").and_then(Value::as_bool).unwrap_or(false);
        if !step_ok {
            if i == 0 {
                audit_session_action(action, "sessionaction-failed", "failed");
                return reply;
            }
            // Take the created name from the PLAN, never re-reading
            // `fields`, so the plan stays the single authority for what
            // actually ran.
            let name = plan[0].get(2).map(String::as_str).unwrap_or("");
            let cli_message = reply.get("message").and_then(Value::as_str).unwrap_or("");
            audit_session_action(action, "sessionaction-partial", "partial");
            return json!({
                "ok": false,
                "message": format!(
                    "project {name} created; assigning the session failed: {cli_message}"
                ),
                "partial": true,
                "action": action,
                "sessionId": session_id,
            });
        }
        last = reply;
    }
    audit_session_action(action, "sessionaction", "ok");
    last
}

/// Run shellbridge: seed the `sessions.json`/`hooks.json` stage files (v0
/// shapes) atomically, then bind the unix socket and serve commands forever.
/// Only a fatal bind failure returns (with an error document dispatch reports);
/// on success this never returns — the systemd unit is `Type=simple` and stays
/// up on the blocking accept loop.
pub fn run() -> serde_json::Value {
    let sock = socket_path();
    let stage = conducting_stage_dir();

    // Seed the two stage files with their documented shapes (empty registries).
    let sessions = json!({
        "schemaVersion": "0",
        // records: { sessionId, agent, windowAddress, cwd, state, startedAt,
        //            parentSessionId? (optional spawned-by edge, `aoide graph link`) }
        "sessions": []
    });
    let hooks = json!({
        "schemaVersion": "0",
        // records: { sessionId, phase, updatedAt }
        "hooks": []
    });

    // Seed each registry ONLY when absent/corrupt — a populated roster is
    // preserved across this restart (see [`seed_if_absent`]). The unconditional
    // re-seed this replaced was the transient-drop bug: every shellbridge restart
    // (a nixos switch / compositor restart cascades through
    // graphical-session.target) wiped all live sessions to `[]`.
    let mut wrote: Vec<String> = Vec::new();
    let s_path = stage.join("sessions.json");
    let h_path = stage.join("hooks.json");
    if let Some(p) =
        seed_if_absent(&s_path, &serde_json::to_string_pretty(&sessions).unwrap(), "sessions")
    {
        wrote.push(p);
    }
    if let Some(p) =
        seed_if_absent(&h_path, &serde_json::to_string_pretty(&hooks).unwrap(), "hooks")
    {
        wrote.push(p);
    }

    // Bind the socket. `RuntimeDirectory=aoide` on the unit creates the parent
    // dir; a stale socket from an unclean shutdown would make bind fail with
    // EADDRINUSE, so remove it first (the path is single-owner per user).
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            let _ = daemon::audit(
                &daemon::default_audit_log(),
                daemon::Door::Daemon,
                daemon::EventClass::Audit,
                "shellbridge",
                "bind-failed",
                &format!("could not bind {}: {e}", sock.display()),
            );
            return json!({
                "process": "shellbridge",
                "state": "error",
                "error": format!("bind {}: {e}", sock.display()),
                "socket": sock.to_string_lossy(),
                "stageDir": stage.to_string_lossy(),
                "wrote": wrote,
            });
        }
    };

    let _ = daemon::audit(
        &daemon::default_audit_log(),
        daemon::Door::Daemon,
        daemon::EventClass::Audit,
        "shellbridge",
        "started",
        &format!("shellbridge online; listening on {}", sock.display()),
    );

    // Spawn the Hyprland window→session event listener on a background thread:
    // it is the AUTHORITATIVE, creation-time source of each session's
    // `windowAddress` (concepts/Terminal-Commander), keeping the widget's
    // click-to-jump reliable instead of depending on the lazy hook-time backfill.
    // It runs concurrently with — and can never block or kill — the accept loop,
    // and degrades to a no-op off-Hyprland (logs once, returns).
    std::thread::spawn(crate::graph::run_hypr_window_listener);

    // Serve forever. `serve` never returns and never panics on client input.
    serve(&listener);

    // Only reached if `incoming()` ends (listener closed) — treat as a clean
    // stop so systemd's `Restart=on-failure` can bring us back.
    json!({
        "process": "shellbridge",
        "state": "stopped",
        "socket": sock.to_string_lossy(),
        "stageDir": stage.to_string_lossy(),
        "wrote": wrote,
    })
}

// ── the herald ledger ─────────────────────────────────────────────────────

/// Read `stage/herald.json`, apply `f`, write it back atomically.
///
/// Every ledger mutation goes through here. §3b made the accept loop
/// thread-per-connection (it used to be one connection at a time, which is
/// what let this read-modify-write get away with no lock of its own), so two
/// herald pushes landing on the same instant are now a real race; the
/// read-modify-write is wrapped in `with_stage_lock` to close it. Never call
/// this from inside a CLI re-exec path (`dispatch_session_action`,
/// `dispatch_recheck_sessions`, `dispatch_usage_refresh`,
/// `dispatch_rice_mode_toggle`) — holding the stage lock across a blocking
/// child-process wait is a deadlock waiting to happen; none of those paths
/// touch the herald ledger today, and that must stay true. A missing or
/// corrupt file is not an error: it reads as an empty ledger and is
/// rewritten whole, so a truncated write can never wedge notifications shut.
fn edit_ledger<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce(&mut Vec<crate::herald::Notification>) -> T,
{
    aoide_storage::fs::with_stage_lock(|| {
        let path = crate::herald::herald_path();
        let mut file: crate::herald::HeraldFile = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let out = f(&mut file.notifications);
        file.schema_version = crate::herald::HERALD_SCHEMA.to_string();
        let text = serde_json::to_string_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        aoide_storage::fs::atomic_write(&path, &format!("{text}\n"))?;
        Ok(out)
    })
}

/// File one notification. Sender text is DATA: it is deserialised into the
/// record shape and written back out, never parsed or interpreted.
fn dispatch_herald_push(notification: Value) {
    let notif: crate::herald::Notification = match serde_json::from_value(notification) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[aoide/shellbridge] herald push with a malformed record: {e}");
            return;
        }
    };
    let id = notif.id.clone();
    if let Err(e) = edit_ledger(move |list| {
        let taken = std::mem::take(list);
        *list = crate::herald::apply_push(taken, notif);
    }) {
        eprintln!("[aoide/shellbridge] could not write the herald ledger: {e}");
    } else {
        let _ = daemon::audit(
            &daemon::default_audit_log(),
            daemon::Door::Daemon,
            daemon::EventClass::Audit,
            "shellbridge",
            "herald.push",
            &format!("filed notification {id}"),
        );
    }
}

/// Drop one card from the ledger (or all of them on `*`).
fn dispatch_herald_dismiss(id: String) {
    let res = edit_ledger(|list| {
        if id == "*" {
            let n = list.len();
            list.clear();
            n > 0
        } else {
            crate::herald::apply_dismiss(list, &id)
        }
    });
    if let Err(e) = res {
        eprintln!("[aoide/shellbridge] could not write the herald ledger: {e}");
    }
}

/// Type a summons verdict into the waiting session, then drop the card.
///
/// Runs on a DETACHED thread and audits its own outcome: the injection walks
/// the stage files and writes to the session's control socket, which must never
/// block the accept loop — the same posture `dispatch_usage_refresh` and
/// `dispatch_recheck_sessions` already take. The `still awaiting` guard lives
/// inside `graph permit`'s answer path, not here, so a human who answered in
/// the terminal while the card stood is never typed over.
fn dispatch_herald_verdict(id: String, verdict: String) {
    std::thread::spawn(move || {
        let outcome = crate::graph::answer_summons(&id, &verdict);
        let _ = daemon::audit(
            &daemon::default_audit_log(),
            daemon::Door::Daemon,
            daemon::EventClass::Audit,
            "shellbridge",
            "herald.verdict",
            &outcome.message,
        );
        // The card comes down either way — an answered summons is answered
        // even if the session had already moved on and nothing was typed.
        // NOTE the id swap: the wire carries the SESSION id (that is what a
        // verdict is addressed to), while the ledger entry is keyed by the
        // CARD id. `summons_card_id` is the one place that mapping lives.
        dispatch_herald_dismiss(crate::graph::summons_card_id(&id));
    });
}

/// Send one newline-delimited JSON line to the running shellbridge.
///
/// The client half of this module: `aoide herald push` and `graph permit` reach
/// the daemon through here rather than writing `stage/herald.json` themselves,
/// so the daemon stays the single writer.
pub fn send_line(line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut stream = UnixStream::connect(socket_path())?;
    stream.write_all(line.trim_end().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// LANE IDENTITY P-ID3 (G7) — the shellbridge socket's CROSS-UID floor, pure
/// and unit-tested without a real different-uid connection (same shape
/// `aoide_secrets::broker::admin_gate` already holds: a plain `Option<u32>`
/// in, an `Option<String>` refusal reason out). `None` (admitted) only when
/// the peer's kernel-attested uid equals `my_euid` — this process's OWN
/// euid, since shellbridge always runs as the operator's own uid, the SAME
/// uid every legitimate connector already runs as (the QML herald/bar
/// widgets, `aoide herald push` off dunst's script hook, `session permit`
/// raising its own summons — every one of them same-uid, none of them a
/// DIFFERENT uid). An unidentified peer (`SO_PEERCRED` read failed) is
/// refused the same fail-closed way a mismatched uid is, never treated as
/// benign.
///
/// **This closes a CROSS-uid gap only — it does NOT stop a same-uid
/// attacker.** Under OQ1-A (LANE IDENTITY's thesis) every legitimate
/// connector above already shares this exact uid with anything hostile a
/// prompt-injected agent could run, so a same-uid process forging
/// `{"cmd":"heraldverdict",...}` is an OQ1-A-INHERENT residual this floor
/// does not close — see `CONTRACTS.md`'s identity section for the honest
/// statement of what remains open on the verdict door specifically.
fn cross_uid_gate(peer: Option<crate::graph::identity::PeerCred>, my_euid: u32) -> Option<String> {
    match peer {
        Some(p) if p.uid == my_euid => None,
        Some(p) => Some(format!(
            "shellbridge connection refused: peer uid {} does not match this process's own uid {my_euid}",
            p.uid
        )),
        None => Some(
            "shellbridge connection refused: peer uid could not be determined (SO_PEERCRED read failed)"
                .to_string(),
        ),
    }
}

fn serve(listener: &UnixListener) {
    // SAFETY: `geteuid()` takes no arguments and cannot fail — the same
    // call `identity.rs`'s own test makes.
    let my_euid = unsafe { libc::geteuid() };
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let peer = crate::graph::identity::peer_cred(&stream);
                if let Some(reason) = cross_uid_gate(peer, my_euid) {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "peercred-refused",
                        &reason,
                    );
                    continue; // Dropped, unconditionally — never reaches `handle_conn`.
                }
                std::thread::spawn(move || handle_conn(stream));
            }
            Err(e) => eprintln!("[aoide/shellbridge] accept error (continuing): {e}"),
        }
    }
}

/// Handle ONE client connection, on its OWN thread (`serve` spawns one per
/// accepted connection): read newline-delimited JSON lines and act on each.
/// Containment is now per-connection, not per-process — a panic here dies
/// with its own thread instead of unwinding into `serve`, and a slow or idle
/// connection can no longer starve any other. A read error (dropped
/// connection) ends only THIS connection, an unparseable/unknown line is
/// audited and skipped, and a focus dispatch failure is logged. No read
/// timeout is set on the accepted stream: the shared QML socket legitimately
/// idles between human gestures, and idleness was never the fault here —
/// serial accept was.
fn handle_conn(stream: UnixStream) {
    let mut reply = stream.try_clone().ok();
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            // Dropped connection / read error: done with this connection only.
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        match parse_command(&line) {
            Some(BridgeCommand::SessionAction { session_id, action, fields }) => {
                // The connection is dedicated to this one action and its reply clone is
                // the only channel the acknowledgement has. Without it the action would
                // run unacknowledged — a kill firing while the caller is told nothing
                // happened — so it does not run at all.
                let Some(mut reply) = reply.take() else {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "sessionaction-noreply",
                        &format!("session action {action}: no reply channel; not dispatched"),
                    );
                    return;
                };
                std::thread::spawn(move || {
                    use std::io::Write;
                    let _ = writeln!(reply, "{}", dispatch_session_action(&session_id, &action, &fields));
                });
                return;
            }
            Some(BridgeCommand::Focus { address }) => match crate::graph::focus_window(&address) {
                Ok(()) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "focus",
                        &format!("focused window {address}"),
                    );
                }
                Err(e) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "focus-failed",
                        &format!("{} ({}): {}", address, e.reason, e.message),
                    );
                }
            },
            Some(BridgeCommand::FocusSession { session_id }) => {
                match crate::graph::focus_session(&session_id) {
                    Ok(()) => {
                        let _ = daemon::audit(
                            &daemon::default_audit_log(),
                            daemon::Door::Daemon,
                            daemon::EventClass::Audit,
                            "shellbridge",
                            "focus",
                            &format!("focused session {session_id}"),
                        );
                    }
                    Err(e) => {
                        let _ = daemon::audit(
                            &daemon::default_audit_log(),
                            daemon::Door::Daemon,
                            daemon::EventClass::Audit,
                            "shellbridge",
                            "focus-failed",
                            &format!("session {} ({}): {}", session_id, e.reason, e.message),
                        );
                    }
                }
            }
            Some(BridgeCommand::Power { action }) => match dispatch_power(action) {
                Ok(()) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "power",
                        &format!("spawned power action {}", action.as_str()),
                    );
                }
                Err(e) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "power-failed",
                        &format!("power action {}: {e}", action.as_str()),
                    );
                }
            },
            Some(BridgeCommand::ToggleRiceMode) => match dispatch_rice_mode_toggle() {
                Ok(message) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "ricemode",
                        &message,
                    );
                }
                Err(e) => {
                    let _ = daemon::audit(
                        &daemon::default_audit_log(),
                        daemon::Door::Daemon,
                        daemon::EventClass::Audit,
                        "shellbridge",
                        "ricemode-failed",
                        &e,
                    );
                }
            },
            // Fire-and-forget: dispatch_usage_refresh audits its OWN outcome from
            // a detached thread (the re-exec's live fetch is ≤15s, too long to
            // block the accept loop inline — see the function). Nothing to match
            // on here, unlike the arms above.
            Some(BridgeCommand::RefreshUsage) => dispatch_usage_refresh(),
            // Fire-and-forget, same posture: dispatch_recheck_sessions re-execs
            // `aoide session reap` on a detached thread and audits its own outcome
            // (the sweep shells out to hyprctl, which must never block the accept
            // loop). The gadgets refresh off the resulting stage writes.
            Some(BridgeCommand::RecheckSessions) => dispatch_recheck_sessions(),
            // The ledger writes are inline: they are a read-modify-write of one
            // small local file. Concurrent pushes from different connections'
            // threads (§3b) are serialised by `edit_ledger`'s own
            // `with_stage_lock`, not by the accept loop.
            Some(BridgeCommand::HeraldPush { notification }) => {
                dispatch_herald_push(*notification)
            }
            Some(BridgeCommand::HeraldDismiss { id }) => dispatch_herald_dismiss(id),
            // Detached, like the other two fire-and-forget arms: this one walks
            // the stage files and writes to a session's control socket.
            Some(BridgeCommand::HeraldVerdict { id, verdict }) => {
                dispatch_herald_verdict(id, verdict)
            }
            None => {
                let _ = daemon::audit(
                    &daemon::default_audit_log(),
                    daemon::Door::Daemon,
                    daemon::EventClass::Audit,
                    "shellbridge",
                    "unparseable",
                    &format!("dropped one unparseable or unknown command line ({} bytes)", line.len()),
                );
            }
        }
    }
}

// ── Tests (the socket-command wire contract) ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── cross_uid_gate (LANE IDENTITY P-ID3, G7) ────────────────────────

    #[test]
    fn cross_uid_gate_admits_a_matching_euid() {
        assert_eq!(
            cross_uid_gate(Some(crate::graph::identity::PeerCred { uid: 1000, pid: 42 }), 1000),
            None
        );
    }

    #[test]
    fn cross_uid_gate_refuses_a_mismatched_uid() {
        assert!(cross_uid_gate(Some(crate::graph::identity::PeerCred { uid: 1001, pid: 42 }), 1000).is_some());
    }

    #[test]
    fn cross_uid_gate_refuses_an_unidentified_peer() {
        // Fail-closed, never a benign default — the same posture
        // `admin_gate` holds for a `SO_PEERCRED` read that failed.
        assert!(cross_uid_gate(None, 1000).is_some());
    }

    /// End-to-end against a REAL socketpair (mirrors `identity.rs`'s own
    /// `peer_cred_on_a_scratch_socketpair_matches_this_processs_own_identity`):
    /// a connection entirely local to this process reports THIS process's
    /// own euid, which `cross_uid_gate` then admits — proving the floor
    /// does not refuse the legitimate same-uid caller (the desktop QML, the
    /// dunst hook, `session permit`'s own raise — every real connector Phase
    /// 0 identified) it must never touch.
    #[test]
    fn a_real_same_process_socketpair_is_admitted() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let peer = crate::graph::identity::peer_cred(&a);
        let my_euid = unsafe { libc::geteuid() };
        assert_eq!(cross_uid_gate(peer, my_euid), None);
    }

    #[test]
    fn parse_command_accepts_a_valid_focuswindow() {
        assert_eq!(
            parse_command(r#"{"cmd":"focuswindow","address":"0x55aabb"}"#),
            Some(BridgeCommand::Focus {
                address: "0x55aabb".to_string()
            })
        );
        // Trailing newline / surrounding whitespace is tolerated (wire lines
        // arrive newline-terminated) and the address is trimmed.
        assert_eq!(
            parse_command("  {\"cmd\":\"focuswindow\",\"address\":\" 0xABC \"}\n"),
            Some(BridgeCommand::Focus {
                address: "0xABC".to_string()
            })
        );
    }

    #[test]
    fn parse_command_accepts_a_valid_focussession() {
        assert_eq!(
            parse_command(r#"{"cmd":"focussession","sessionId":"conduct-1-2"}"#),
            Some(BridgeCommand::FocusSession {
                session_id: "conduct-1-2".to_string()
            })
        );
        // Trimmed like focuswindow's address.
        assert_eq!(
            parse_command("{\"cmd\":\"focussession\",\"sessionId\":\" abc \"}\n"),
            Some(BridgeCommand::FocusSession {
                session_id: "abc".to_string()
            })
        );
        // Empty/absent sessionId → None (never dispatch a blank session jump).
        assert_eq!(parse_command(r#"{"cmd":"focussession","sessionId":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focussession"}"#), None);
    }

    #[test]
    fn parse_command_accepts_a_herald_push_and_rejects_an_unfilable_one() {
        let line = r#"{"cmd":"heraldpush","notification":{"id":"7","summary":"hi"}}"#;
        match parse_command(line) {
            Some(BridgeCommand::HeraldPush { notification }) => {
                assert_eq!(notification.get("id").unwrap(), "7");
            }
            other => panic!("expected a herald push, got {other:?}"),
        }
        // A record with no usable id could neither replace its predecessor nor
        // be dismissed later, so it never reaches the ledger.
        assert_eq!(
            parse_command(r#"{"cmd":"heraldpush","notification":{"summary":"hi"}}"#),
            None
        );
        assert_eq!(
            parse_command(r#"{"cmd":"heraldpush","notification":{"id":"  "}}"#),
            None
        );
        assert_eq!(parse_command(r#"{"cmd":"heraldpush"}"#), None);
    }

    #[test]
    fn a_verdict_is_only_ever_one_of_the_two_real_answers() {
        assert_eq!(
            parse_command(r#"{"cmd":"heraldverdict","id":"s1","verdict":"approve"}"#),
            Some(BridgeCommand::HeraldVerdict {
                id: "s1".to_string(),
                verdict: "approve".to_string(),
            })
        );
        assert_eq!(
            parse_command(r#"{"cmd":"heraldverdict","id":" s1 ","verdict":" deny "}"#),
            Some(BridgeCommand::HeraldVerdict {
                id: "s1".to_string(),
                verdict: "deny".to_string(),
            })
        );
        // A permission gate has no safe direction to default to, so anything
        // that is not exactly one of the two answers is dropped at the wire
        // rather than resolved. This is the defect the whole herald retcon
        // exists to kill — the old daemon-drawn card could not tell a click on
        // "deny" from a click anywhere else, and approved.
        for bad in [
            r#"{"cmd":"heraldverdict","id":"s1","verdict":"approved"}"#,
            r#"{"cmd":"heraldverdict","id":"s1","verdict":"APPROVE"}"#,
            r#"{"cmd":"heraldverdict","id":"s1","verdict":"yes"}"#,
            r#"{"cmd":"heraldverdict","id":"s1","verdict":""}"#,
            r#"{"cmd":"heraldverdict","id":"","verdict":"approve"}"#,
            r#"{"cmd":"heraldverdict","id":"s1"}"#,
        ] {
            assert_eq!(parse_command(bad), None, "{bad}");
        }
    }

    #[test]
    fn parse_command_accepts_a_herald_dismiss() {
        assert_eq!(
            parse_command(r#"{"cmd":"heralddismiss","id":"7"}"#),
            Some(BridgeCommand::HeraldDismiss { id: "7".to_string() })
        );
        // `*` is the clear-the-desk form.
        assert_eq!(
            parse_command(r#"{"cmd":"heralddismiss","id":"*"}"#),
            Some(BridgeCommand::HeraldDismiss { id: "*".to_string() })
        );
        assert_eq!(parse_command(r#"{"cmd":"heralddismiss","id":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"heralddismiss"}"#), None);
    }

    #[test]
    fn parse_command_accepts_every_valid_power_action() {
        let cases = [
            ("lock", PowerAction::Lock),
            ("logout", PowerAction::Logout),
            ("suspend", PowerAction::Suspend),
            ("hibernate", PowerAction::Hibernate),
            ("reboot", PowerAction::Reboot),
            ("shutdown", PowerAction::Shutdown),
        ];
        for (wire, want) in cases {
            assert_eq!(
                parse_command(&format!(r#"{{"cmd":"power","action":"{wire}"}}"#)),
                Some(BridgeCommand::Power { action: want }),
                "power action {wire} must parse"
            );
        }
        // Whitespace around the action is trimmed (wire lines arrive
        // newline-terminated), same tolerance as focuswindow's address.
        assert_eq!(
            parse_command("  {\"cmd\":\"power\",\"action\":\" lock \"}\n"),
            Some(BridgeCommand::Power {
                action: PowerAction::Lock
            })
        );
    }

    #[test]
    fn parse_command_rejects_bad_power_actions() {
        // Unknown action → None (a typo must never reach a dispatch).
        assert_eq!(parse_command(r#"{"cmd":"power","action":"explode"}"#), None);
        // Case matters — the wire contract is lowercase.
        assert_eq!(parse_command(r#"{"cmd":"power","action":"Reboot"}"#), None);
        // Empty / absent / non-string action → None.
        assert_eq!(parse_command(r#"{"cmd":"power","action":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"power"}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"power","action":42}"#), None);
    }

    #[test]
    fn parse_command_accepts_a_valid_ricemode() {
        assert_eq!(
            parse_command(r#"{"cmd":"ricemode"}"#),
            Some(BridgeCommand::ToggleRiceMode)
        );
        // No payload is expected or read — extra fields are simply ignored.
        assert_eq!(
            parse_command("  {\"cmd\":\"ricemode\"}\n"),
            Some(BridgeCommand::ToggleRiceMode)
        );
    }

    #[test]
    fn parse_command_accepts_a_valid_refreshusage() {
        assert_eq!(
            parse_command(r#"{"cmd":"refreshusage"}"#),
            Some(BridgeCommand::RefreshUsage)
        );
        // No payload is expected or read — extra fields are simply ignored,
        // and surrounding whitespace/newline is tolerated like every command.
        assert_eq!(
            parse_command("  {\"cmd\":\"refreshusage\"}\n"),
            Some(BridgeCommand::RefreshUsage)
        );
        // A typo is NOT this command (the gatekeeper rule — an unparsed command goes
        // nowhere, the `{cmd:"powermenu"}` scar).
        assert_eq!(parse_command(r#"{"cmd":"refresh"}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"usagerefresh"}"#), None);
    }

    #[test]
    fn parse_command_accepts_a_valid_rechecksessions() {
        assert_eq!(
            parse_command(r#"{"cmd":"rechecksessions"}"#),
            Some(BridgeCommand::RecheckSessions)
        );
        // No payload is expected or read — extra fields ignored, surrounding
        // whitespace/newline tolerated like every command.
        assert_eq!(
            parse_command("  {\"cmd\":\"rechecksessions\"}\n"),
            Some(BridgeCommand::RecheckSessions)
        );
        // A near-miss is NOT this command — an unparsed cmd goes nowhere.
        assert_eq!(parse_command(r#"{"cmd":"recheck"}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"recheckSession"}"#), None);
    }

    // ── classify_recheck (a quiet sweep is a successful sweep) ─────────────────

    #[test]
    fn classify_recheck_ok_envelope_returns_its_message() {
        let s = classify_recheck(
            true,
            r#"{"status":"ok","command":"session.reap","message":"reaped 1 dead session(s); dropped 1 total; decayed 0 stopped → idle; cleared 0 orphaned parent link(s); dropped 2 orphaned hook record(s)"}"#,
            "",
        );
        assert!(s.is_ok());
        assert!(s.unwrap().contains("orphaned hook record"));
    }

    #[test]
    fn classify_recheck_nothing_to_reap_still_succeeds() {
        // The common case: a periodic-cadence sweep with nothing dead. Status is
        // "ok" and the file is untouched — that is a successful recheck, NOT a
        // failure (the whole point of judging the envelope, not just exit 0).
        let s = classify_recheck(
            true,
            r#"{"status":"ok","command":"session.reap","message":"nothing to reap (all sessions live)"}"#,
            "",
        );
        assert_eq!(s, Ok("nothing to reap (all sessions live)".to_string()));
    }

    #[test]
    fn classify_recheck_error_status_and_nonzero_exit_are_failures() {
        // A real stage read/write failure exits 0-in-shape but reports "error".
        let s = classify_recheck(
            true,
            r#"{"status":"error","command":"session.reap","message":"could not write sessions.json: permission denied"}"#,
            "",
        );
        assert!(s.is_err());
        assert!(s.unwrap_err().contains("permission denied"));
        // Non-zero exit, reason spoken on stderr.
        assert_eq!(
            classify_recheck(false, "", "boom on stderr"),
            Err("boom on stderr".to_string())
        );
        // Non-zero exit, silent → still explains itself, never a blank reason.
        assert!(classify_recheck(false, "", "").unwrap_err().contains("nonzero"));
        // Exit 0 but not the JSON envelope → not a proven sweep (the ipc.rs lesson).
        assert!(classify_recheck(true, "not json at all", "").unwrap_err().contains("parseable"));
    }

    // ── classify_usage_refresh (success is the real output, not the exit) ─────

    #[test]
    fn classify_usage_refresh_ok_envelope_returns_its_message() {
        let s = classify_usage_refresh(
            true,
            r#"{"status":"ok","command":"usage","message":"today 42 tokens — state/usage.json written"}"#,
            "",
        );
        assert_eq!(s, Ok("today 42 tokens — state/usage.json written".to_string()));
    }

    #[test]
    fn classify_usage_refresh_degraded_live_still_succeeds() {
        // The whole point: a `live:{ok:false}` block (no creds / OAuth rejection
        // / transport error) is NOT a refresh failure — the file was still
        // written and the gadget renders it degraded. Status stays "ok".
        let s = classify_usage_refresh(
            true,
            r#"{"status":"ok","command":"usage","message":"written","data":{"live":{"ok":false,"error":"no ~/.claude credentials"}}}"#,
            "",
        );
        assert!(s.is_ok(), "degraded live must not read as a failed refresh: {s:?}");
    }

    #[test]
    fn classify_usage_refresh_error_status_is_a_failure() {
        // A real write failure exits 0-in-shape but reports status "error".
        let s = classify_usage_refresh(
            true,
            r#"{"status":"error","command":"usage","message":"failed to write state/usage.json: permission denied"}"#,
            "",
        );
        assert!(s.is_err());
        assert!(s.unwrap_err().contains("permission denied"));
    }

    #[test]
    fn classify_usage_refresh_nonzero_exit_is_a_failure_with_a_reason() {
        // Non-zero exit, reason spoken on stderr.
        let s = classify_usage_refresh(false, "", "boom on stderr");
        assert_eq!(s, Err("boom on stderr".to_string()));
        // Non-zero exit, silent → still explains itself, never a blank reason.
        let s = classify_usage_refresh(false, "", "");
        assert!(s.unwrap_err().contains("nonzero"));
    }

    #[test]
    fn classify_usage_refresh_unparseable_exit_zero_is_a_failure() {
        // Exit 0 alone is NOT success — output that isn't the JSON envelope
        // means the call didn't land the way we think (the ipc.rs lesson).
        let s = classify_usage_refresh(true, "not json at all", "");
        assert!(s.is_err());
        assert!(s.unwrap_err().contains("parseable"));
        // Valid JSON but no status field is likewise not a proven refresh.
        let s = classify_usage_refresh(true, r#"{"command":"usage"}"#, "");
        assert!(s.is_err());
    }

    #[test]
    fn rice_mode_toggle_target_is_a_two_way_toggle_not_a_three_way_cycle() {
        // Staging locks to declarative...
        assert_eq!(rice_mode_toggle_target(RiceMode::Staging), "declarative");
        // ...and BOTH declarative and draft unlock back to plain staging —
        // there is no generic "next draft" a bare click could cycle into.
        assert_eq!(rice_mode_toggle_target(RiceMode::Declarative), "stage");
        assert_eq!(rice_mode_toggle_target(RiceMode::Draft), "stage");
    }

    // ── rice_mode_toggle_default_song (the bar-toggle-only baseline-song fix) ──

    #[test]
    fn declarative_toggle_passes_the_env_song_explicitly_when_set() {
        assert_eq!(
            rice_mode_toggle_default_song("declarative", Some("sonata")),
            Some("sonata".to_string())
        );
        // Surrounding whitespace is trimmed, same tolerance as the wire commands.
        assert_eq!(
            rice_mode_toggle_default_song("declarative", Some("  sonata  ")),
            Some("sonata".to_string())
        );
    }

    #[test]
    fn declarative_toggle_falls_back_to_the_bare_call_when_env_is_absent_or_blank() {
        // Unset (outside the systemd service, or before a rebuild lands the
        // env var) must not turn a working toggle into a broken one.
        assert_eq!(rice_mode_toggle_default_song("declarative", None), None);
        // Present but blank/whitespace-only is treated the same as absent.
        assert_eq!(rice_mode_toggle_default_song("declarative", Some("")), None);
        assert_eq!(rice_mode_toggle_default_song("declarative", Some("   ")), None);
    }

    #[test]
    fn stage_toggle_is_unaffected_by_the_env_var_either_way() {
        // The staging direction stays on whatever's currently being edited
        // (current_staged_song()-driven, commands/mode.rs) regardless of
        // AOIDE_DEFAULT_SONG — this fix is scoped to the declarative
        // direction only.
        assert_eq!(rice_mode_toggle_default_song("stage", Some("sonata")), None);
        assert_eq!(rice_mode_toggle_default_song("stage", None), None);
    }

    #[test]
    fn parse_command_rejects_bad_or_empty_input() {
        // Empty / absent address → None (never dispatch a blank focus).
        assert_eq!(parse_command(r#"{"cmd":"focuswindow","address":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focuswindow","address":"   "}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focuswindow"}"#), None);
        // Unknown command → None.
        assert_eq!(parse_command(r#"{"cmd":"explode","address":"0x1"}"#), None);
        // Missing cmd → None.
        assert_eq!(parse_command(r#"{"address":"0x1"}"#), None);
        // Malformed / non-object JSON → None (the loop logs + ignores).
        assert_eq!(parse_command("not json at all"), None);
        assert_eq!(parse_command("{ broken"), None);
        assert_eq!(parse_command(""), None);
        assert_eq!(parse_command("[1,2,3]"), None);
    }

    // ── session actions (the acknowledged session-menu bridge) ─────────────

    /// Build a `Vec<String>` argv/plan-row from string literals — test-only
    /// sugar so the argv-exactness assertions below read as plain literals.
    fn sv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // -- parse gate: acceptance --

    #[test]
    fn parse_command_accepts_a_session_project_assignment() {
        match parse_command(
            r#"{"cmd":"sessionaction","sessionId":"s1","action":"project","fields":{"project":"aoide"}}"#,
        ) {
            Some(BridgeCommand::SessionAction { session_id, action, fields }) => {
                assert_eq!(session_id, "s1");
                assert_eq!(action, "project");
                assert_eq!(fields["project"], "aoide");
            }
            other => panic!("expected a session project assignment, got {other:?}"),
        }
    }

    #[test]
    fn parse_command_accepts_a_session_project_clear() {
        // An explicit empty STRING is the clear request, not a rejection.
        assert!(matches!(
            parse_command(
                r#"{"cmd":"sessionaction","sessionId":"s1","action":"project","fields":{"project":""}}"#
            ),
            Some(BridgeCommand::SessionAction { .. })
        ));
    }

    #[test]
    fn parse_command_accepts_a_session_kill() {
        assert!(matches!(
            parse_command(r#"{"cmd":"sessionaction","sessionId":"s1","action":"kill"}"#),
            Some(BridgeCommand::SessionAction { .. })
        ));
        // Extra unknown keys are accepted and ignored.
        assert!(matches!(
            parse_command(
                r#"{"cmd":"sessionaction","sessionId":"s1","action":"kill","fields":{"force":true}}"#
            ),
            Some(BridgeCommand::SessionAction { .. })
        ));
    }

    #[test]
    fn parse_command_accepts_a_session_undying_toggle() {
        for state in ["on", "off"] {
            match parse_command(&format!(
                r#"{{"cmd":"sessionaction","sessionId":"s1","action":"undying","fields":{{"state":"{state}"}}}}"#
            )) {
                Some(BridgeCommand::SessionAction { fields, .. }) => {
                    assert_eq!(fields["state"], state);
                }
                other => panic!("expected an undying toggle for {state}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_command_accepts_a_createproject_and_an_editproject() {
        for action in ["createproject", "editproject"] {
            let line = format!(
                r#"{{"cmd":"sessionaction","sessionId":"s1","action":"{action}","fields":{{"name":"aoide","paths":["/home/khoa/Aoide"]}}}}"#
            );
            assert!(
                matches!(parse_command(&line), Some(BridgeCommand::SessionAction { .. })),
                "{action} must parse"
            );
        }
    }

    // -- parse gate: rejection --

    #[test]
    fn parse_command_rejects_an_unknown_session_action() {
        for action in ["reboot", "", "removeproject"] {
            assert_eq!(
                parse_command(&format!(
                    r#"{{"cmd":"sessionaction","sessionId":"s1","action":"{action}"}}"#
                )),
                None,
                "{action} must be refused"
            );
        }
    }

    #[test]
    fn parse_command_rejects_a_session_action_with_no_session_id() {
        assert_eq!(parse_command(r#"{"cmd":"sessionaction","action":"kill"}"#), None);
        assert_eq!(
            parse_command(r#"{"cmd":"sessionaction","sessionId":"","action":"kill"}"#),
            None
        );
        assert_eq!(
            parse_command(r#"{"cmd":"sessionaction","sessionId":"   ","action":"kill"}"#),
            None
        );
    }

    #[test]
    fn parse_command_rejects_a_flag_shaped_session_id_or_name() {
        assert_eq!(
            parse_command(r#"{"cmd":"sessionaction","sessionId":"--id","action":"kill"}"#),
            None
        );
        assert_eq!(
            parse_command(r#"{"cmd":"sessionaction","sessionId":"-x","action":"kill"}"#),
            None
        );
        assert_eq!(
            parse_command(
                r#"{"cmd":"sessionaction","sessionId":"s1","action":"createproject","fields":{"name":"-rf","paths":["/a"]}}"#
            ),
            None
        );
    }

    #[test]
    fn parse_command_rejects_an_undying_state_that_is_not_on_or_off() {
        for fields in [r#"{"state":"yes"}"#, r#"{"state":true}"#, r#"{"on":true}"#, r#"{}"#] {
            assert_eq!(
                parse_command(&format!(
                    r#"{{"cmd":"sessionaction","sessionId":"s1","action":"undying","fields":{fields}}}"#
                )),
                None,
                "{fields} must be refused"
            );
        }
    }

    #[test]
    fn parse_command_rejects_a_project_action_with_a_missing_or_non_string_project_field() {
        // A missing key, `null`, or a non-string value never mutates
        // anything — the whitelist drops the request as unknown rather than
        // guessing at "clear".
        for fields in [r#"{}"#, r#"{"project":null}"#, r#"{"project":5}"#] {
            assert_eq!(
                parse_command(&format!(
                    r#"{{"cmd":"sessionaction","sessionId":"s1","action":"project","fields":{fields}}}"#
                )),
                None,
                "{fields} must be refused"
            );
        }
        // An absent `fields` key entirely is the same as `{}` above.
        assert_eq!(
            parse_command(r#"{"cmd":"sessionaction","sessionId":"s1","action":"project"}"#),
            None
        );
    }

    #[test]
    fn parse_command_rejects_a_project_edit_with_no_paths() {
        // An "exact replacement" with nothing to replace with is a mistake,
        // never an instruction to erase.
        for action in ["createproject", "editproject"] {
            assert_eq!(
                parse_command(&format!(
                    r#"{{"cmd":"sessionaction","sessionId":"s1","action":"{action}","fields":{{"name":"aoide","paths":[]}}}}"#
                )),
                None,
                "{action} with an empty paths list must be refused"
            );
        }
    }

    #[test]
    fn parse_command_rejects_a_relative_or_control_charactered_path() {
        // One bad element rejects the whole action.
        let cases = ["[\"work/aoide\"]", "[\"~/Aoide\"]", "[\"/home/khoa/a\\nb\"]", "[123]"];
        for paths in cases {
            let line = format!(
                "{{\"cmd\":\"sessionaction\",\"sessionId\":\"s1\",\"action\":\"createproject\",\"fields\":{{\"name\":\"aoide\",\"paths\":{paths}}}}}"
            );
            assert_eq!(parse_command(&line), None, "{paths} must be refused");
        }
    }

    #[test]
    fn parse_command_rejects_a_createproject_with_no_name() {
        assert_eq!(
            parse_command(
                r#"{"cmd":"sessionaction","sessionId":"s1","action":"createproject","fields":{"paths":["/a"]}}"#
            ),
            None
        );
        assert_eq!(
            parse_command(
                r#"{"cmd":"sessionaction","sessionId":"s1","action":"createproject","fields":{"name":"","paths":["/a"]}}"#
            ),
            None
        );
        assert_eq!(
            parse_command(
                r#"{"cmd":"sessionaction","sessionId":"s1","action":"createproject","fields":{"name":"   ","paths":["/a"]}}"#
            ),
            None
        );
    }

    // -- argv exactness --

    #[test]
    fn session_action_args_builds_the_exact_undying_argv_for_both_states() {
        assert_eq!(
            session_action_args("s1", "undying", &json!({"state":"on"})),
            Some(vec![sv(&["session", "grant", "undying", "on", "--id", "s1"])])
        );
        assert_eq!(
            session_action_args("s1", "undying", &json!({"state":"off"})),
            Some(vec![sv(&["session", "grant", "undying", "off", "--id", "s1"])])
        );
    }

    #[test]
    fn session_action_args_builds_the_exact_project_assignment_argv() {
        assert_eq!(
            session_action_args("s1", "project", &json!({"project":"aoide"})),
            Some(vec![sv(&["session", "project", "--id", "s1", "--project", "aoide"])])
        );
    }

    #[test]
    fn session_action_args_builds_the_exact_project_clear_argv() {
        assert_eq!(
            session_action_args("s1", "project", &json!({"project":""})),
            Some(vec![sv(&["session", "project", "--id", "s1", "--clear"])])
        );
    }

    #[test]
    fn session_action_args_rejects_a_missing_or_non_string_project_field() {
        // `project` must BE a JSON string: a missing key, `null`, or a
        // number all read as unknown and refuse the whole action — never as
        // an implicit clear.
        assert_eq!(session_action_args("s1", "project", &json!({})), None);
        assert_eq!(session_action_args("s1", "project", &json!({"project": null})), None);
        assert_eq!(session_action_args("s1", "project", &json!({"project": 5})), None);
    }

    #[test]
    fn session_action_args_builds_the_exact_kill_argv() {
        assert_eq!(
            session_action_args("s1", "kill", &json!({})),
            Some(vec![sv(&["session", "kill", "--id", "s1"])])
        );
    }

    #[test]
    fn session_action_args_builds_createprojects_two_argvs_in_order() {
        let plan = session_action_args(
            "s1",
            "createproject",
            &json!({"name":"aoide","paths":["/a","/b"]}),
        )
        .expect("createproject must build a plan");
        assert_eq!(
            plan,
            vec![
                sv(&["project", "add", "aoide", "/a", "/b", "--new"]),
                sv(&["session", "project", "--id", "s1", "--project", "aoide"]),
            ]
        );
        assert_eq!(plan[0].last().map(String::as_str), Some("--new"));
    }

    #[test]
    fn session_action_args_builds_the_exact_editproject_argv() {
        assert_eq!(
            session_action_args("s1", "editproject", &json!({"name":"aoide","paths":["/a","/b"]})),
            Some(vec![sv(&["project", "edit", "aoide", "/a", "/b"])])
        );
    }

    #[test]
    fn session_action_args_never_admits_whitespace_in_a_session_id() {
        assert_eq!(session_action_args("a b", "kill", &json!({})), None);
        assert_eq!(session_action_args("a\nb", "kill", &json!({})), None);
        assert_eq!(session_action_args("a\tb", "kill", &json!({})), None);
    }

    #[test]
    fn session_action_args_admits_ordinary_spaces_but_rejects_control_characters_in_a_name() {
        // "My Project" is a real, legal name across all three shapes that
        // carry one — argv elements are passed to `Command::arg` whole,
        // never through a shell, so a space is no more dangerous here than
        // in a path.
        assert_eq!(
            session_action_args("s1", "project", &json!({"project":"My Project"})),
            Some(vec![sv(&["session", "project", "--id", "s1", "--project", "My Project"])])
        );
        assert_eq!(
            session_action_args(
                "s1",
                "createproject",
                &json!({"name":"My Project","paths":["/a"]})
            ),
            Some(vec![
                sv(&["project", "add", "My Project", "/a", "--new"]),
                sv(&["session", "project", "--id", "s1", "--project", "My Project"]),
            ])
        );
        assert_eq!(
            session_action_args(
                "s1",
                "editproject",
                &json!({"name":"My Project","paths":["/a"]})
            ),
            Some(vec![sv(&["project", "edit", "My Project", "/a"])])
        );
        // A space is not a blanket whitespace exemption: control characters
        // are still refused.
        assert_eq!(
            session_action_args("s1", "project", &json!({"project":"a\u{1b}b"})),
            None
        );
        assert_eq!(session_action_args("s1", "project", &json!({"project":"a\nb"})), None);
    }

    #[test]
    fn session_action_args_admits_a_space_in_a_path_too() {
        // A PATH containing a space was always accepted — a different rule
        // ([`safe_action_path`]), same underlying reasoning.
        assert_eq!(
            session_action_args(
                "s1",
                "editproject",
                &json!({"name":"aoide","paths":["/home/khoa/My Documents"]})
            ),
            Some(vec![sv(&["project", "edit", "aoide", "/home/khoa/My Documents"])])
        );
    }

    // -- reply shaping --

    #[test]
    fn a_session_action_reply_reports_an_ok_outcome_with_its_own_message() {
        let reply = session_action_reply(
            "s1",
            "project",
            true,
            r#"{"status":"ok","command":"session.project","message":"session project updated","gated":false}"#,
            "",
        );
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["message"], "session project updated");
        assert_eq!(reply["action"], "project");
        assert_eq!(reply["sessionId"], "s1");
        assert!(reply.get("data").is_none());
    }

    #[test]
    fn a_session_action_reply_carries_the_cli_outcomes_data_verbatim() {
        // A `kill` reply can show the resolved target/pid this way.
        let reply = session_action_reply(
            "s1",
            "kill",
            true,
            r#"{"status":"ok","command":"session.kill","message":"session killed","data":{"pid":1234,"target":"s1"}}"#,
            "",
        );
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["data"], json!({"pid": 1234, "target": "s1"}));
    }

    #[test]
    fn a_session_action_reply_reports_an_error_outcome_as_not_ok() {
        let reply = session_action_reply(
            "s1",
            "kill",
            false,
            r#"{"status":"error","command":"session.kill","message":"session is not registered locally","gated":true}"#,
            "",
        );
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["message"], "session is not registered locally");
        // The `gated` marker never reaches QML and never makes a reply ok.
        assert!(reply.get("gated").is_none());
    }

    #[test]
    fn a_session_action_reply_reads_a_usage_envelope_off_stderr() {
        let reply = session_action_reply(
            "s1",
            "createproject",
            false,
            "",
            r#"{"status":"usage","command":"project.add","message":"unrecognized flag `--new` for `aoide project add`","gated":false}"#,
        );
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["message"], "unrecognized flag `--new` for `aoide project add`");
    }

    #[test]
    fn a_session_action_reply_falls_back_when_neither_stream_is_an_envelope() {
        let reply =
            session_action_reply("s1", "kill", false, "boom", "aoided must be running for session management");
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["message"], "aoided must be running for session management");

        let reply = session_action_reply("s1", "kill", false, "", "");
        assert_eq!(reply["ok"], false);
        assert_ne!(reply["message"].as_str().unwrap_or(""), "");
    }

    #[test]
    fn a_session_action_reply_is_one_wire_line() {
        let reply = session_action_reply(
            "s1",
            "project",
            true,
            r#"{"status":"ok","command":"session.project","message":"a\nb"}"#,
            "",
        );
        assert!(!reply.to_string().contains('\n'));
        assert_eq!(reply["action"], "project");
        assert_eq!(reply["sessionId"], "s1");
    }

    // ── the accept loop (§3b): idleness must never starve another connection ──

    /// Confirms `serve` spawns a thread per connection rather than serving
    /// serially: an idle, persistent client — exactly what Quickshell's own
    /// shared socket is, held open between human gestures — must never block
    /// a later client's line from ever being dispatched. This test binds its
    /// OWN listener, so `socket_path()` is never consulted and the live
    /// shellbridge socket is never touched.
    ///
    /// Client 2 sends an action the whitelist REFUSES, so the observable is
    /// the `unparseable` audit line landing in `<root>/log` — a refused line
    /// spawns no child process at all, so this test cannot reach a real
    /// binary or a live daemon under any env mishap. `daemon::bin::core_bin()`
    /// *is* redirectable via `AOIDE_CORE_BIN` for a future test wanting a
    /// real reply line, but a unit test spawning it here would be exactly the
    /// "fresh binary against the live system" this slice's hard rules forbid.
    ///
    /// This test MUST fail on the pre-§3b serial `serve`: client 2's line
    /// never reaches `handle_conn` while client 1 sits open, so the accept
    /// loop is blocked in `handle_conn(client 1)` forever.
    #[test]
    fn an_idle_persistent_client_never_blocks_the_next_one() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = aoide_test_support::EnvSaver::capture(&[
            "AOIDE_ROOT",
            "AOIDE_AUDIT_LOG",
            "AOIDE_STATE_DIR",
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
        ]);
        let root = aoide_test_support::unique_tmp("shellbridge-idle-client");
        std::env::set_var("AOIDE_ROOT", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_STATE_DIR", &root);
        std::env::set_var("AOIDE_STAGE_DIR", &root);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let sock = root.join("test-shellbridge.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || serve(&listener)); // never joined

        // Client 1: connect and hold the link open, writing nothing — the
        // exact shape of Quickshell's own shared socket idling between human
        // gestures.
        let _client1 = UnixStream::connect(&sock).unwrap();

        // Client 2: a refused sessionaction — the whitelist drops it before
        // any child process is ever spawned.
        {
            use std::io::Write;
            let mut client2 = UnixStream::connect(&sock).unwrap();
            client2
                .write_all(b"{\"cmd\":\"sessionaction\",\"sessionId\":\"s1\",\"action\":\"reboot\"}\n")
                .unwrap();
            client2.flush().unwrap();
        }

        let log = root.join("log");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut seen = false;
        while std::time::Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&log) {
                if text.contains("unparseable") {
                    seen = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            seen,
            "client 2's line was never audited within 2s — an idle client 1 is blocking \
             the accept loop (the pre-3b serial-accept regression)"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // §3b's thread-per-connection accept loop means N herald pushes on N
    // distinct connections can now run `edit_ledger` from N different
    // threads at once. `edit_ledger` wraps its read-modify-write in
    // `with_stage_lock` for exactly this reason — this test is the one that
    // would go red (a lost update: fewer than N notifications land) if that
    // lock were ever dropped.
    #[test]
    fn n_concurrent_herald_pushes_all_land_in_the_ledger() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = aoide_test_support::EnvSaver::capture(&[
            "AOIDE_ROOT",
            "AOIDE_AUDIT_LOG",
            "AOIDE_STATE_DIR",
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
        ]);
        let root = aoide_test_support::unique_tmp("shellbridge-herald-race");
        std::env::set_var("AOIDE_ROOT", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::set_var("AOIDE_STATE_DIR", &root);
        std::env::set_var("AOIDE_STAGE_DIR", &root);
        std::env::set_var("XDG_RUNTIME_DIR", &root);

        let sock = root.join("test-shellbridge-herald.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || serve(&listener)); // never joined, own listener

        const N: usize = 12;
        let senders: Vec<_> = (0..N)
            .map(|i| {
                let sock = sock.clone();
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut client = UnixStream::connect(&sock).unwrap();
                    let line = format!(
                        "{{\"cmd\":\"heraldpush\",\"notification\":{{\"id\":\"race-{i}\",\
                         \"app\":\"test\",\"summary\":\"s\",\"body\":\"b\",\
                         \"urgency\":\"normal\",\"progress\":-1,\"timeoutMs\":0,\
                         \"receivedAt\":\"now\",\"kind\":\"toast\"}}}}\n"
                    );
                    client.write_all(line.as_bytes()).unwrap();
                    client.flush().unwrap();
                })
            })
            .collect();
        for s in senders {
            s.join().unwrap();
        }

        let path = root.join("herald.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut count = 0;
        while std::time::Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(file) = serde_json::from_str::<crate::herald::HeraldFile>(&text) {
                    count = file.notifications.len();
                    if count == N {
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            count, N,
            "expected all {N} concurrent herald pushes to land in the ledger, found \
             {count} instead — a lost update means edit_ledger's read-modify-write is \
             racing under the thread-per-connection accept loop"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
