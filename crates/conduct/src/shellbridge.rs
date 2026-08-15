//! shellbridge's socket loop — the session/hook state bridge
//! (concepts/shellbridge).
//!
//! Registers agent sessions + window addresses and records Claude Code hook
//! phases, publishing them to `song/stage/` for Quickshell to read. Writes are
//! atomic (write-temp-then-rename) so a hot-reload never sees a torn file
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
use aoide_storage::fs::{seed_if_absent, stage_dir};
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
/// The wire shape is defined by ShellBridge.qml; the only verb today is the
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
    /// shells out; this verb is the gate through which the six endings reach
    /// hyprlock / hyprctl / systemctl.
    Power { action: PowerAction },
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
    /// are systemd verbs.
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

/// Run shellbridge: seed the `sessions.json`/`hooks.json` stage files (v0
/// shapes) atomically, then bind the unix socket and serve commands forever.
/// Only a fatal bind failure returns (with an error document dispatch reports);
/// on success this never returns — the systemd unit is `Type=simple` and stays
/// up on the blocking accept loop.
pub fn run() -> serde_json::Value {
    let sock = socket_path();
    let stage = stage_dir();

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
    fn parse_command_rejects_bad_or_empty_input() {
        // Empty / absent address → None (never dispatch a blank focus).
        assert_eq!(parse_command(r#"{"cmd":"focuswindow","address":""}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focuswindow","address":"   "}"#), None);
        assert_eq!(parse_command(r#"{"cmd":"focuswindow"}"#), None);
        // Unknown verb → None.
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
