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
/// 15`, so waiting for it inline would freeze the whole accept loop
/// (session-jumps, power, ricemode all queue behind one usage click) for up to
/// 15 s. So this SPAWNS and returns immediately — the same no-block posture
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
/// Runs on a DETACHED thread. `session reap` shells out to `hyprctl clients -j`
/// for window liveness; that is normally instant, but a hung compositor query
/// must never freeze the single-threaded accept loop (session-jumps, power,
/// ricemode all queue behind one recheck click). So this SPAWNS and returns
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
            .args(["session", "reap", "--announce", "--json"])
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

/// The accept loop: one connection at a time (commands are rare). A failed
/// `accept()` is logged and the loop continues — a transient accept error must
/// never end the service.
// ── the herald ledger ─────────────────────────────────────────────────────

/// Read `stage/herald.json`, apply `f`, write it back atomically.
///
/// Every ledger mutation goes through here, in the daemon, single-threaded by
/// the accept loop — the serialisation the whole socket hop exists to buy. A
/// missing or corrupt file is not an error: it reads as an empty ledger and is
/// rewritten whole, so a truncated write can never wedge notifications shut.
fn edit_ledger<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce(&mut Vec<crate::herald::Notification>) -> T,
{
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

fn serve(listener: &UnixListener) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => handle_conn(stream),
            Err(e) => eprintln!("[aoide/shellbridge] accept error (continuing): {e}"),
        }
    }
}

/// Handle ONE client connection: read newline-delimited JSON lines and act on
/// each. Every failure is contained — a read error (dropped connection) ends
/// only THIS connection, an unparseable/unknown line is logged and skipped, and
/// a focus dispatch failure is logged. Nothing here can unwind into `serve`.
fn handle_conn(stream: UnixStream) {
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
            // small local file, and running them ON the accept loop is exactly
            // what serialises concurrent notifications.
            Some(BridgeCommand::HeraldPush { notification }) => {
                dispatch_herald_push(*notification)
            }
            Some(BridgeCommand::HeraldDismiss { id }) => dispatch_herald_dismiss(id),
            // Detached, like the other two fire-and-forget arms: this one walks
            // the stage files and writes to a session's control socket.
            Some(BridgeCommand::HeraldVerdict { id, verdict }) => {
                dispatch_herald_verdict(id, verdict)
            }
            None => eprintln!("[aoide/shellbridge] ignoring unknown/malformed command: {line}"),
        }
    }
}

// ── Tests (the socket-command wire contract) ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
}
