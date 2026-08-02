//! Focus + Hyprland window discovery/reconcile/listener: `graph focus`, the
//! shared verify-then-dispatch hyprctl seam, phase-② pid-ancestry window
//! discovery, the authoritative `socket2` event listener, and the
//! untracked-terminal (`win:*`) synthetic-record reconciler.

use super::common::{require_args, stage_error};
use super::conduct::proc_cwd;
use super::doc::restage_graph;
use super::model::{
    load_stage, sessions_path, write_stage, SessionRecord, SessionsFile, STAGE_GRAPH_VERSION,
};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::fs::with_stage_lock;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// Normalise a Hyprland window address for comparison: lowercased, with any
/// leading `0x` stripped. The stored `windowAddress` and hyprctl's reported
/// addresses can disagree on case and on a present/absent `0x` prefix
/// (hyprctl reports e.g. `0x55…`); this makes the match tolerant of both.
pub(crate) fn normalize_addr(addr: &str) -> String {
    let a = addr.trim();
    let a = a
        .strip_prefix("0x")
        .or_else(|| a.strip_prefix("0X"))
        .unwrap_or(a);
    a.to_ascii_lowercase()
}

/// Does `want` name a live window in the parsed `hyprctl clients -j` array?
/// Pure over the already-decoded JSON so it is unit-testable without a
/// compositor. Matches on the normalised `address` field of any client.
fn window_present(clients: &[Value], want: &str) -> bool {
    let want = normalize_addr(want);
    clients.iter().any(|c| {
        c.get("address")
            .and_then(Value::as_str)
            .map(|a| normalize_addr(a) == want)
            .unwrap_or(false)
    })
}

/// The Hyprland workspace id of the client whose `address` matches `want` in a
/// decoded `hyprctl clients -j` array (`workspace.id` in the client JSON).
/// Pure over the decoded JSON — unit-testable without a compositor. Address
/// comparison is `0x`/case-tolerant via [`normalize_addr`] (the stored
/// `windowAddress` and hyprctl can disagree on both). `None` when the window is
/// absent from the list or carries no numeric `workspace.id` — the caller then
/// leaves the stored `workspace` untouched (degrade gracefully, never a panic).
fn client_workspace_for_address(clients: &[Value], want: &str) -> Option<i64> {
    let want = normalize_addr(want);
    if want.is_empty() {
        return None;
    }
    clients.iter().find_map(|c| {
        let a = c.get("address").and_then(Value::as_str)?;
        if normalize_addr(a) != want {
            return None;
        }
        c.get("workspace")
            .and_then(|w| w.get("id"))
            .and_then(Value::as_i64)
    })
}

/// Query `hyprctl clients -j` into a decoded JSON array. Returns `None` whenever
/// the compositor cannot be consulted authoritatively: no
/// `HYPRLAND_INSTANCE_SIGNATURE`, a missing/failed `hyprctl`, or unparseable
/// JSON. This is the single clients-reading seam every consumer shares — the
/// reaper's live set, phase-② discovery, and the window-event listener — so they
/// all degrade identically off-Hyprland (never a panic, never a false result).
pub(crate) fn hyprctl_clients() -> Option<Vec<Value>> {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return None;
    }
    let out = std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match serde_json::from_slice(&out.stdout) {
        Ok(Value::Array(a)) => Some(a),
        _ => None,
    }
}

/// `graph focus <node>` — jump to the session's window via hyprctl
/// (the Terminal-Commander session-jump flow).
///
/// `hyprctl dispatch focuswindow` exits 0 even when the target window is gone,
/// so we first list live clients (`hyprctl clients -j`) and verify the stored
/// `windowAddress` is actually present before dispatching. A vanished terminal
/// → structured `window-not-found` (exit 1), no dispatch.
pub fn focus(inv: &Invocation) -> Outcome {
    let args = match require_args(inv, &["node"]) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // Accept both `session:<id>` node ids and bare session ids.
    let id = args[0]
        .strip_prefix("session:")
        .unwrap_or(&args[0])
        .to_string();
    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error("graph.focus", e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        return Outcome::error("graph.focus", format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "node": id }));
    };
    if rec.window_address.is_empty() {
        return Outcome::error(
            "graph.focus",
            format!("session `{id}` has no windowAddress to focus"),
        )
        .with_data(json!({ "reason": "no-window-address", "node": id }));
    }
    let addr = rec.window_address.clone();

    // Verify + dispatch through the shared focus fn (the same path the
    // shellbridge socket loop drives on a widget click).
    match focus_window(&addr) {
        Ok(()) => Outcome::ok("graph.focus", format!("focused session `{id}`"))
            .changed([format!("focused window {addr}")])
            .with_data(json!({ "node": id, "windowAddress": addr, "dispatcher": "hyprctl" })),
        Err(e) => Outcome::error("graph.focus", format!("{}: {}", id, e.message)).with_data(json!({
            "reason": e.reason,
            "node": id,
            "windowAddress": addr,
        })),
    }
}

/// A structured failure from [`focus_window`]. `reason` is a stable machine
/// code (`hyprctl-unavailable` / `hyprctl-failed` / `window-not-found` /
/// `no-window-address`) reused verbatim by `graph focus`'s error envelope.
#[derive(Debug, Clone)]
pub struct FocusError {
    pub reason: &'static str,
    pub message: String,
}

/// The shared verify-then-dispatch used by BOTH `graph focus` (CLI) and the
/// shellbridge socket loop (a widget click). `hyprctl dispatch focuswindow`
/// exits 0 even when the target window is already gone, so we first list live
/// clients (`hyprctl clients -j`) and confirm the address is actually present
/// before dispatching — a vanished terminal is a `window-not-found` error, not
/// a silent no-op. Returns `Ok(())` only on a dispatched focus; every failure
/// (empty address, missing/failed hyprctl, unparseable JSON, absent window) is
/// a structured `Err` — this fn NEVER panics, so a socket loop can call it on
/// arbitrary input without risk.
pub fn focus_window(addr: &str) -> Result<(), FocusError> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(FocusError {
            reason: "no-window-address",
            message: "empty window address".to_string(),
        });
    }

    // Verify the window exists before dispatching: focuswindow can't tell us.
    let clients: Vec<Value> = match std::process::Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
    {
        Err(e) => {
            return Err(FocusError {
                reason: "hyprctl-unavailable",
                message: format!("hyprctl unavailable: {e}"),
            });
        }
        Ok(out) if !out.status.success() => {
            return Err(FocusError {
                reason: "hyprctl-failed",
                message: format!("hyprctl clients failed (exit {:?})", out.status.code()),
            });
        }
        Ok(out) => match serde_json::from_slice(&out.stdout) {
            Ok(Value::Array(a)) => a,
            _ => {
                return Err(FocusError {
                    reason: "hyprctl-failed",
                    message: "hyprctl clients: unparseable JSON".to_string(),
                });
            }
        },
    };
    if !window_present(&clients, addr) {
        return Err(FocusError {
            reason: "window-not-found",
            message: format!("window {addr} is gone (terminal closed?)"),
        });
    }

    let dispatch = format!("address:{addr}");
    match std::process::Command::new("hyprctl")
        .args(["dispatch", "focuswindow", &dispatch])
        .output()
    {
        Err(e) => Err(FocusError {
            reason: "hyprctl-unavailable",
            message: format!("hyprctl unavailable: {e}"),
        }),
        Ok(out) if !out.status.success() => Err(FocusError {
            reason: "hyprctl-failed",
            message: format!("hyprctl dispatch failed (exit {:?})", out.status.code()),
        }),
        Ok(_) => Ok(()),
    }
}

/// Resolve a `sessionId` to a live jump and dispatch it — the socket-reachable
/// counterpart to the CLI [`focus`]. shellbridge drives this on a roster
/// row-click: QML sends only the sessionId (which every row already holds), and
/// the DAEMON owns the id→window resolution, so a widget never carries a stale or
/// empty address (the bug this fixes: the old socket verb took a window address,
/// but the widgets passed a sessionId, so every tracked-row jump silently
/// no-op'd as `window-not-found`). Prefers the exact `windowAddress` (which also
/// brings its workspace forward); if that isn't resolved yet but the `workspace`
/// is known, falls back to switching to that workspace. Never panics — a socket
/// loop calls it on arbitrary input.
pub fn focus_session(id: &str) -> Result<(), FocusError> {
    let id = id.strip_prefix("session:").unwrap_or(id).trim();
    if id.is_empty() {
        return Err(FocusError {
            reason: "no-session-id",
            message: "empty session id".to_string(),
        });
    }
    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => {
            return Err(FocusError {
                reason: "stage-unreadable",
                message: "could not read sessions.json".to_string(),
            });
        }
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        return Err(FocusError {
            reason: "session-not-found",
            message: format!("unknown session `{id}`"),
        });
    };
    // Prefer the exact window — focuswindow also brings its workspace forward.
    if !rec.window_address.trim().is_empty() {
        return focus_window(&rec.window_address);
    }
    // The window isn't resolved yet (discovery is best-effort), but if we know
    // the workspace we can still take the user there.
    if let Some(ws) = rec.workspace {
        return focus_workspace(ws);
    }
    Err(FocusError {
        reason: "no-window-address",
        message: format!("session `{id}` has no window or workspace to focus"),
    })
}

/// Switch to a Hyprland workspace by numeric id (`hyprctl dispatch workspace
/// <id>`) — the fallback jump for a session whose window address isn't resolved
/// yet but whose workspace is known. Structured `Err` on a missing/failed
/// hyprctl; never panics.
pub fn focus_workspace(ws: i64) -> Result<(), FocusError> {
    match std::process::Command::new("hyprctl")
        .args(["dispatch", "workspace", &ws.to_string()])
        .output()
    {
        Err(e) => Err(FocusError {
            reason: "hyprctl-unavailable",
            message: format!("hyprctl unavailable: {e}"),
        }),
        Ok(out) if !out.status.success() => Err(FocusError {
            reason: "hyprctl-failed",
            message: format!(
                "hyprctl dispatch workspace failed (exit {:?})",
                out.status.code()
            ),
        }),
        Ok(_) => Ok(()),
    }
}

// ── Phase ②: window-address discovery (pid-ancestry ↔ hyprctl clients) ──────
//
// A conducted terminal's window is the ancestor process that owns a Hyprland
// client: conduct is exec'd (same pid) by the shell wrapper, itself a child of
// the terminal (kitty). Walking conduct's pid up the ppid chain and matching a
// pid against `hyprctl clients -j` finds that window — the first ancestor with a
// client wins. All of this is BEST-EFFORT: it must never fail or slow a conduct,
// so every impure step is guarded and an empty result just leaves the address
// unset (exactly as before this phase).

/// Read the parent pid of `pid` from `/proc/<pid>/stat`. The `comm` (2nd) field
/// is wrapped in parens and may itself contain spaces or `)`, so ppid is parsed
/// as the 2nd whitespace field AFTER the FINAL `)` (state, then ppid) — the only
/// robust way to split a stat line. `None` on any read/parse miss.
fn parent_pid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    let mut fields = after.split_whitespace();
    let _state = fields.next()?; // the process state char
    fields.next()?.parse().ok() // ppid
}

/// The pid-ancestry chain of `pid`, self first, walking up the ppid chain via
/// `/proc`. Bounded (a bad `/proc` or a self-parenting loop can never spin) and
/// stops at init (ppid ≤ 1) — the terminal is always a mid-chain ancestor.
fn pid_ancestry(pid: i32) -> Vec<i32> {
    let mut chain = Vec::new();
    let mut cur = pid;
    for _ in 0..64 {
        chain.push(cur);
        match parent_pid(cur) {
            Some(p) if p > 1 && p != cur => cur = p,
            _ => break,
        }
    }
    chain
}

/// Pure core: the window address of the nearest ancestor in `ancestry` that owns
/// a client in the decoded `hyprctl clients -j` array. Walks the ancestry from
/// self outward and returns the first client whose `pid` matches and whose
/// `address` is non-empty. Pure over the decoded JSON + the pid list, so it is
/// unit-testable with a fake client list and a fake ancestry — no `/proc`, no
/// compositor. `None` when no ancestor owns a window.
#[cfg(test)]
fn match_window_for_ancestry(ancestry: &[i32], clients: &[Value]) -> Option<String> {
    match_window_and_pid(ancestry, clients).map(|(addr, _)| addr)
}

/// Address-and-pid variant of the ancestor↔client match: also returns the
/// matched client's `pid` — the terminal window's owning process. The hook door
/// records this pid on the session so the reaper has a `/proc` liveness signal
/// that vanishes with the window (never a false reap: the pid lives exactly as
/// long as the window).
fn match_window_and_pid(ancestry: &[i32], clients: &[Value]) -> Option<(String, u32)> {
    for &pid in ancestry {
        for c in clients {
            if c.get("pid").and_then(Value::as_i64) == Some(pid as i64) {
                if let Some(addr) = c.get("address").and_then(Value::as_str) {
                    if !addr.is_empty() {
                        return Some((addr.to_string(), pid as u32));
                    }
                }
            }
        }
    }
    None
}

/// Best-effort discovery of THIS conduct process's terminal window address (see
/// the phase ② note). Guarded end-to-end: no Hyprland instance signature, a
/// missing/failed `hyprctl`, unparseable JSON, or no ancestor match each yield
/// `None` — never an error, never a slow path beyond one quick `hyprctl` call.
pub(in crate::graph) fn discover_window_address() -> Option<String> {
    discover_window().map(|(addr, _, _)| addr)
}

/// Best-effort discovery of THIS process's terminal window address AND that
/// window's owning pid (see [`discover_window_address`]). Shared by `conduct`
/// (which wants only the address) and the hook door (which records both so a
/// hook-registered Claude session becomes `graph focus`-jumpable). Guarded
/// end-to-end: no Hyprland instance signature, a missing/failed `hyprctl`,
/// unparseable JSON, or no ancestor match each yield `None` — never an error,
/// never a slow path beyond one quick `hyprctl` call.
pub(in crate::graph) fn discover_window() -> Option<(String, u32, Option<i64>)> {
    // Cheap gate + one quick `hyprctl` call, both inside the shared seam.
    let clients = hyprctl_clients()?;
    let ancestry = pid_ancestry(std::process::id() as i32);
    let (addr, pid) = match_window_and_pid(&ancestry, &clients)?;
    // Stamp the window's workspace off the SAME clients snapshot (no second
    // hyprctl call); `None` when the client carries no numeric workspace id.
    let workspace = client_workspace_for_address(&clients, &addr);
    Some((addr, pid, workspace))
}

/// Best-effort backfill of a hook-registered session's `windowAddress` (+ owning
/// pid) when it is still empty. The hook runs as a subprocess of the agent in
/// its terminal, so [`discover_window`]'s pid-ancestry ↔ `hyprctl clients` walk
/// finds that terminal window — giving a Claude Code session (which registers
/// via `SessionStart` with no window) something for `graph focus` to jump to.
/// Cheaply gated on `HYPRLAND_INSTANCE_SIGNATURE` and on the address being
/// empty (so once discovered, later hooks skip all work); a miss leaves the
/// address empty exactly as before. Only ever fills `windowAddress`/`pid` — it
/// never touches the session `state` (that is the hook phase's job).
pub(in crate::graph) fn ensure_session_window(id: &str) {
    if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
        return;
    }
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => return,
    };
    let needs_window =
        matches!(file.sessions.iter().find(|s| s.session_id == id), Some(s) if s.window_address.is_empty());
    if !needs_window {
        return;
    }
    let Some((addr, pid, workspace)) = discover_window() else {
        return;
    };
    if let Some(s) = file.sessions.iter_mut().find(|s| s.session_id == id) {
        s.window_address = addr;
        s.pid = Some(pid);
        // Stamp the workspace too when known (absent → left None, degrades
        // gracefully); the listener keeps it fresh on later moves.
        if workspace.is_some() {
            s.workspace = workspace;
        }
    }
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    let _ = write_stage(&sessions_path(), &file);
    let _ = restage_graph();
}

// ── Authoritative window capture: the Hyprland event listener ────────────────
//
// The hook-time backfill above is LAZY — a session's `windowAddress` only lands
// on the *next* hook fire, so at click time it is frequently empty and the
// widget's `graph focus` jump fails. The fix is EVENT-DRIVEN, creation-time
// capture: the shellbridge service runs a background thread reading Hyprland's
// `socket2` event stream and, the moment a window opens (or moves / retitles /
// closes), it (re)resolves every tracked session's window authoritatively. This
// is the PRIMARY source of `windowAddress`; the hook backfill stays as a
// belt-and-suspenders fallback. All of it is best-effort and off-Hyprland-safe:
// no instance signature → the listener logs once and returns, and the accept
// loop keeps serving regardless.

/// Path to the Hyprland event socket (`socket2`):
/// `$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket2.sock`. Returns
/// `None` when not under a Hyprland session (no signature, or no runtime dir) —
/// the listener then degrades to "disabled" rather than crashing.
pub fn hypr_event_socket_path() -> Option<PathBuf> {
    let sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok()?;
    if sig.trim().is_empty() {
        return None;
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok()?;
    Some(
        PathBuf::from(runtime)
            .join("hypr")
            .join(sig)
            .join(".socket2.sock"),
    )
}

/// One parsed Hyprland `socket2` event we act on (window lifecycle only). Every
/// other event line maps to `None` and is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HyprWindowEvent {
    /// A window opened / moved / retitled — (re)resolve pending session windows.
    /// `address` is the raw event address (no `0x` prefix); we resolve off the
    /// live `hyprctl clients` list rather than trusting it, so it is advisory.
    Appeared { address: String },
    /// A window closed — clear its address off whatever session stored it, so the
    /// roster stops advertising a dead jump target (the reaper then removes the
    /// record via its pid signal).
    Closed { address: String },
}

/// Parse ONE `socket2` line (`EVENT>>DATA`) into a [`HyprWindowEvent`], or `None`
/// for the many events we ignore. Pure and total (unit-tested): a line without
/// `>>`, an unhandled event name, or an empty address all yield `None` — never a
/// panic. The address is Hyprland's bare hex (e.g. `55aabb`); [`normalize_addr`]
/// reconciles it with `hyprctl`'s `0x…` form at compare time.
pub fn parse_hypr_window_event(line: &str) -> Option<HyprWindowEvent> {
    let (event, data) = line.split_once(">>")?;
    match event {
        // openwindow>>ADDR,WORKSPACE,CLASS,TITLE · movewindow>>ADDR,WORKSPACE
        // movewindowv2>>ADDR,WSID,WSNAME · windowtitle>>ADDR
        // windowtitlev2>>ADDR,TITLE — in every case ADDR is the first field.
        "openwindow" | "movewindow" | "movewindowv2" | "windowtitle" | "windowtitlev2" => {
            let addr = data.split(',').next().unwrap_or("").trim();
            if addr.is_empty() {
                return None;
            }
            Some(HyprWindowEvent::Appeared {
                address: addr.to_string(),
            })
        }
        // closewindow>>ADDR — the whole payload is the address.
        "closewindow" => {
            let addr = data.trim();
            if addr.is_empty() {
                return None;
            }
            Some(HyprWindowEvent::Closed {
                address: addr.to_string(),
            })
        }
        _ => None,
    }
}

/// (Re)resolve the `windowAddress` of every tracked session that has a recorded
/// lifecycle `pid` but no window yet, stamping the canonical `hyprctl` address
/// via the SAME pid-ancestry ↔ clients match discovery uses — AND keep every
/// already-resolved session's `workspace` id current off the same clients
/// snapshot, so a terminal dragged to another workspace re-stamps here (the
/// `movewindow`/`movewindowv2` event re-runs this pass; concepts/Terminal-
/// Commander's hover-preview bridge). Runs in the shellbridge process, so it
/// walks each session's RECORDED pid (a conduct session's own pid — the window
/// client is one of its ancestors), never its own. Cheap-guarded: zero `hyprctl`
/// work when no session has either a pending window OR a resolved one. It only
/// ever FILLS an empty address (never overwrites a good one) and only ever
/// updates `workspace` to a PRESENT id (a window momentarily absent from the
/// clients list leaves its stored workspace be — never cleared); it never
/// touches `pid` or `state`. Returns true iff `sessions.json` changed.
pub fn resolve_pending_session_windows() -> bool {
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // Work to do if a session still needs its window (empty address + a pid to
    // walk) OR already has one whose workspace we can (re)stamp. The latter is
    // what keeps `workspace` fresh across a move; without it a steady-state
    // roster would never re-stamp.
    let has_pending = file
        .sessions
        .iter()
        .any(|s| s.window_address.is_empty() && s.pid.is_some());
    let has_windowed = file.sessions.iter().any(|s| !s.window_address.is_empty());
    if !has_pending && !has_windowed {
        return false;
    }
    let Some(clients) = hyprctl_clients() else {
        return false;
    };
    let mut changed = false;
    for s in file.sessions.iter_mut() {
        if s.window_address.is_empty() {
            // Pending window: resolve it via pid-ancestry, stamping workspace off
            // the same snapshot (None → left absent, degrades gracefully).
            let Some(pid) = s.pid else {
                continue;
            };
            let ancestry = pid_ancestry(pid as i32);
            if let Some((addr, _)) = match_window_and_pid(&ancestry, &clients) {
                let ws = client_workspace_for_address(&clients, &addr);
                s.window_address = addr;
                if s.workspace != ws {
                    s.workspace = ws;
                }
                changed = true;
            }
        } else if let Some(ws) = client_workspace_for_address(&clients, &s.window_address) {
            // Resolved window still live: keep its workspace current (the
            // drag-between-workspaces re-stamp). Only a present, changed id is
            // written; a vanished window leaves the stored workspace intact.
            if s.workspace != Some(ws) {
                s.workspace = Some(ws);
                changed = true;
            }
        }
    }
    if !changed {
        return false;
    }
    if file.schema_version.is_empty() {
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
    }
    if write_stage(&sessions_path(), &file).is_ok() {
        let _ = restage_graph();
        return true;
    }
    false
}

/// Clear a closed window's address off any session that stored it (normalised
/// compare, so `0x…`/case differences still match). The record is left in place
/// for the reaper to resolve via its pid signal. Returns true iff a session was
/// cleared.
pub fn clear_closed_window(address: &str) -> bool {
    let want = normalize_addr(address);
    if want.is_empty() {
        return false;
    }
    let mut file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut changed = false;
    for s in file.sessions.iter_mut() {
        if !s.window_address.is_empty() && normalize_addr(&s.window_address) == want {
            s.window_address.clear();
            changed = true;
        }
    }
    if !changed {
        return false;
    }
    if write_stage(&sessions_path(), &file).is_ok() {
        let _ = restage_graph();
        return true;
    }
    false
}

// ── Untracked-terminal capture: publish a synthetic record per bare tty ──────
//
// The Terminals roster is the PROCESS view of every open terminal window, tracked
// or not (concepts/desktop/Terminal-Commander). A bare `kitty` running a plain
// `bash` has no Aoide hook and no `conduct` PTY, so nothing publishes it — the
// widget used to enumerate `hyprctl clients` itself and merge, violating the
// Widget–Bridge Contract ("never enumerate the system in QML"). This moves that
// enumeration into the daemon: for every LIVE terminal-class window with no
// tracked session claiming its `windowAddress`, we upsert a lightweight `shell`
// record keyed `win:<normalized-address>`, so `sessions.json` ALONE is a complete
// terminal roster the widget reads as a pure view.

/// Terminal window CLASSES we recognize as a tty (mirrors the QML `termClassRe`
/// this supersedes) — ascii-lowercased compare.
const TERMINAL_CLASSES: &[&str] = &[
    "kitty",
    "foot",
    "footclient",
    "alacritty",
    "wezterm",
    "org.wezfurlong.wezterm",
    "ghostty",
    "com.mitchellh.ghostty",
    "xterm",
    "uxterm",
    "konsole",
    "urxvt",
    "rxvt",
    "termite",
    "tilix",
    "contour",
    "rio",
    "st",
    "kgx",
    "org.gnome.console",
    "blackbox",
    "terminator",
    "sakura",
    "wave",
    "xfce4-terminal",
    "gnome-terminal",
    "qterminal",
    "lxterminal",
    "deepin-terminal",
];

/// Is a window class one we treat as a terminal (ascii-lowercased exact match
/// against [`TERMINAL_CLASSES`])? Pure — the classification seam under test.
pub(crate) fn is_terminal_class(class: &str) -> bool {
    let c = class.trim().to_ascii_lowercase();
    TERMINAL_CLASSES.contains(&c.as_str())
}

/// Is `tool` a sub-agent-dispatch tool? Claude Code's classic name is `Task`;
/// this harness's own tool is named `Agent` instead — both spawn/manage a
/// background sub-agent the same way from the hook's point of view, so both
/// gate sub-agent node creation/teardown identically.
pub(in crate::graph) fn is_subagent_tool(tool: &str) -> bool {
    matches!(tool, "Task" | "Agent")
}

/// One live terminal window distilled from a `hyprctl clients -j` client — the
/// pure-core input for [`reconcile_untracked_terminals`], so the reconciliation
/// is testable without a compositor (`cwd` is pre-read from `/proc/<pid>/cwd` by
/// the I/O wrapper).
#[derive(Debug, Clone, Default)]
pub(crate) struct TermWindow {
    pub address: String,
    pub class: String,
    pub title: String,
    pub workspace: Option<i64>,
    pub pid: Option<i32>,
    pub mapped: bool,
    pub cwd: String,
}

/// Reconcile the synthetic `win:*` terminal records against the live terminal
/// windows — the PURE CORE (fed fake `TermWindow`s in tests). Given the current
/// sessions and the live windows, returns the updated sessions plus whether it
/// changed anything.
///
/// Rules:
///   * A LIVE, mapped, terminal-class window whose (normalized) address is NOT
///     claimed by any TRACKED (non-`win:`) session gets a synthetic record keyed
///     `win:<normalized-address>` (`agent`/`kind` = "shell", `state` = "idle").
///     Upserted in place, so a re-scan never duplicates and only mutates the
///     record's live fields (`cwd`/`title`/`workspace`/`pid`/`windowAddress`).
///   * A window already claimed by a tracked session is left to that session —
///     never double-published (the tracked record carries the rich state).
///   * A synthetic `win:*` record whose window no longer appears live (closed, or
///     newly claimed by a tracked session) is REMOVED.
pub(crate) fn reconcile_untracked_terminals(
    mut sessions: Vec<SessionRecord>,
    windows: &[TermWindow],
) -> (Vec<SessionRecord>, bool) {
    // Addresses owned by a TRACKED (non-synthetic) session — a real agent/shell
    // record already represents that window, so it is never re-published.
    let tracked_addrs: HashSet<String> = sessions
        .iter()
        .filter(|s| !s.session_id.starts_with("win:"))
        .filter(|s| !s.window_address.is_empty())
        .map(|s| normalize_addr(&s.window_address))
        .collect();

    // The synthetic roster we WANT: one entry per live, mapped, terminal-class,
    // unclaimed window, keyed by normalized address.
    let mut desired: HashMap<String, &TermWindow> = HashMap::new();
    for w in windows {
        if !w.mapped || !is_terminal_class(&w.class) {
            continue;
        }
        let na = normalize_addr(&w.address);
        if na.is_empty() || tracked_addrs.contains(&na) {
            continue;
        }
        desired.insert(na, w);
    }

    let mut changed = false;

    // Drop synthetic records whose window is no longer desired (closed, or a
    // tracked session now owns the address).
    let before = sessions.len();
    sessions.retain(|s| match s.session_id.strip_prefix("win:") {
        Some(addr) => desired.contains_key(addr),
        None => true,
    });
    if sessions.len() != before {
        changed = true;
    }

    // Upsert a synthetic record per desired window.
    for (na, w) in &desired {
        let sid = format!("win:{na}");
        let want_title = if w.title.is_empty() {
            None
        } else {
            Some(w.title.clone())
        };
        let want_pid = w.pid.filter(|p| *p > 0).map(|p| p as u32);
        if let Some(rec) = sessions.iter_mut().find(|s| s.session_id == sid) {
            if rec.window_address != w.address {
                rec.window_address = w.address.clone();
                changed = true;
            }
            if rec.cwd != w.cwd {
                rec.cwd = w.cwd.clone();
                changed = true;
            }
            if rec.title != want_title {
                rec.title = want_title;
                changed = true;
            }
            if rec.workspace != w.workspace {
                rec.workspace = w.workspace;
                changed = true;
            }
            if rec.pid != want_pid {
                rec.pid = want_pid;
                changed = true;
            }
            // Keep the identity invariants a synthetic record always carries.
            if rec.agent != "shell" {
                rec.agent = "shell".to_string();
                changed = true;
            }
            if rec.state != "idle" {
                rec.state = "idle".to_string();
                changed = true;
            }
            if rec.kind.as_deref() != Some("shell") {
                rec.kind = Some("shell".to_string());
                changed = true;
            }
        } else {
            sessions.push(SessionRecord {
                session_id: sid,
                agent: "shell".to_string(),
                window_address: w.address.clone(),
                cwd: w.cwd.clone(),
                state: "idle".to_string(),
                kind: Some("shell".to_string()),
                title: want_title,
                pid: want_pid,
                workspace: w.workspace,
                ..Default::default()
            });
            changed = true;
        }
    }

    (sessions, changed)
}

/// Extract a [`TermWindow`] from one `hyprctl clients -j` client object, reading
/// its owning process's cwd from `/proc/<pid>/cwd`. `None` for a client with no
/// usable `address`. The one I/O seam over the pure [`reconcile_untracked_terminals`].
fn term_window_from_client(c: &Value) -> Option<TermWindow> {
    let address = c.get("address").and_then(Value::as_str)?.trim().to_string();
    if address.is_empty() {
        return None;
    }
    let class = c
        .get("class")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let title = c
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let workspace = c
        .get("workspace")
        .and_then(|w| w.get("id"))
        .and_then(Value::as_i64);
    let pid = c
        .get("pid")
        .and_then(Value::as_i64)
        .map(|p| p as i32)
        .filter(|p| *p > 0);
    // `mapped` defaults to true when absent — a client with no `mapped` field is
    // treated as a shown window rather than silently dropped.
    let mapped = c.get("mapped").and_then(Value::as_bool).unwrap_or(true);
    let cwd = pid.and_then(proc_cwd).unwrap_or_default();
    Some(TermWindow {
        address,
        class,
        title,
        workspace,
        pid,
        mapped,
        cwd,
    })
}

/// Publish a lightweight `shell` session record for every LIVE terminal-class
/// window that has no tracked session already claiming its `windowAddress`, and
/// remove any synthetic `win:*` record whose window has closed — so
/// `sessions.json` is a complete terminal roster and QML never enumerates
/// `hyprctl` itself. The I/O wrapper over [`reconcile_untracked_terminals`]:
/// gathers the clients, distils each into a [`TermWindow`], reconciles under the
/// stage lock, and re-stages `graph.json` only when something changed. Best-effort
/// and off-Hyprland-safe like its siblings — returns early (no panic) when
/// `hyprctl_clients()` is unavailable. Returns true iff `sessions.json` changed.
pub fn sync_untracked_terminal_windows() -> bool {
    let Some(clients) = hyprctl_clients() else {
        return false;
    };
    let windows: Vec<TermWindow> = clients.iter().filter_map(term_window_from_client).collect();
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let (sessions, changed) =
            reconcile_untracked_terminals(std::mem::take(&mut file.sessions), &windows);
        file.sessions = sessions;
        if !changed {
            return false;
        }
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        if write_stage(&sessions_path(), &file).is_ok() {
            let _ = restage_graph();
            return true;
        }
        false
    })
}

/// Is `e` a read-timeout expiry rather than a genuine socket failure? A blocking
/// read on a Unix stream whose `SO_RCVTIMEO` elapses returns `EAGAIN`, which
/// Rust surfaces as [`ErrorKind::WouldBlock`] on Unix (Windows uses `TimedOut`);
/// std documents either kind, so we accept both. Pure/testable, in the style of
/// [`is_terminal_class`] & friends — the listener uses it to tell "nothing
/// happened for 5s, re-tick" apart from "socket dropped, reconnect".
pub(crate) fn is_read_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Run the Hyprland window→session event listener FOREVER — the shellbridge
/// service spawns this on a background thread so it can never block or kill the
/// socket accept loop. It connects to the `socket2` event stream and keeps
/// `sessions.json` authoritative: an opened/moved/retitled window (re)resolves
/// pending session windows, a closed window is cleared. Degrades gracefully — no
/// Hyprland signature logs once and returns (headless/non-Hypr aoide is
/// unaffected); a failed connect or a dropped socket logs and retries after a
/// short backoff. NEVER panics. A ~5s read timeout on the connection also
/// re-ticks the untracked-terminal sync (see [`is_read_timeout`]) so a bare tty's
/// cwd/title doesn't go stale between window events.
pub fn run_hypr_window_listener() {
    use std::io::{BufRead, BufReader};
    let Some(sock) = hypr_event_socket_path() else {
        eprintln!(
            "[aoide/shellbridge] no HYPRLAND_INSTANCE_SIGNATURE — window-event listener disabled"
        );
        return;
    };
    // Populate the untracked-terminal roster once at startup, so the Terminals
    // widget has a complete tty roster the instant shellbridge comes up — not
    // only after the next window event fires.
    sync_untracked_terminal_windows();
    loop {
        match UnixStream::connect(&sock) {
            Ok(stream) => {
                // On every (re)connect, sweep any windows that opened while we
                // were not listening (service start mid-session, or a reconnect).
                resolve_pending_session_windows();
                sync_untracked_terminal_windows();
                // Coarse read timeout so a blocking read wakes every ~5s even
                // when no window event fires — the periodic tick that refreshes
                // cwd/title for bare, untracked terminals. Best-effort: if it
                // fails the listener still works, just event-driven only.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                for line in BufReader::new(stream).lines() {
                    let line = match line {
                        Ok(line) => line,
                        // Timeout expiry (no event for ~5s): stay on this SAME
                        // connection, re-tick the untracked roster, keep reading.
                        // The read itself blocked for the full 5s, so this paces
                        // itself — no busy-loop.
                        Err(e) if is_read_timeout(&e) => {
                            sync_untracked_terminal_windows();
                            continue;
                        }
                        // Any other error: socket dropped → reconnect.
                        Err(_) => break,
                    };
                    match parse_hypr_window_event(&line) {
                        Some(HyprWindowEvent::Appeared { .. }) => {
                            resolve_pending_session_windows();
                            sync_untracked_terminal_windows();
                        }
                        Some(HyprWindowEvent::Closed { address }) => {
                            clear_closed_window(&address);
                            sync_untracked_terminal_windows();
                        }
                        None => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("[aoide/shellbridge] hypr event socket connect failed ({e}); retrying");
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;

    #[test]
    fn read_timeout_predicate_distinguishes_tick_from_drop() {
        use std::io::{Error, ErrorKind};
        // A read-timeout expiry surfaces as WouldBlock on Unix — that's a tick,
        // not a failure: keep the connection.
        assert!(is_read_timeout(&Error::new(ErrorKind::WouldBlock, "timed out")));
        // Windows/std also documents TimedOut for the same event: accept it too.
        assert!(is_read_timeout(&Error::new(ErrorKind::TimedOut, "timed out")));
        // A genuine socket drop is NOT a timeout → the listener must reconnect.
        assert!(!is_read_timeout(&Error::new(
            ErrorKind::ConnectionReset,
            "peer reset"
        )));
        assert!(!is_read_timeout(&Error::new(
            ErrorKind::BrokenPipe,
            "broken pipe"
        )));
        assert!(!is_read_timeout(&Error::new(
            ErrorKind::UnexpectedEof,
            "eof"
        )));
    }
    #[test]
    fn terminal_class_is_case_insensitive_and_exact() {
        assert!(is_terminal_class("kitty"));
        assert!(is_terminal_class("Kitty"));
        assert!(is_terminal_class("org.wezfurlong.wezterm"));
        assert!(!is_terminal_class("firefox"));
        assert!(!is_terminal_class("kittyfoo"));
        assert!(!is_terminal_class(""));
    }
    #[test]
    fn untracked_terminal_synthesizes_a_win_record() {
        let (out, changed) =
            reconcile_untracked_terminals(vec![], &[term_win("0xAABB", "kitty", "/home/khoa")]);
        assert!(changed);
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.session_id, "win:aabb");
        assert_eq!(r.agent, "shell");
        assert_eq!(r.kind.as_deref(), Some("shell"));
        assert_eq!(r.state, "idle");
        assert_eq!(r.window_address, "0xAABB");
        assert_eq!(r.cwd, "/home/khoa");
        assert_eq!(r.workspace, Some(1));
        assert_eq!(r.pid, Some(4321));
    }
    #[test]
    fn window_claimed_by_tracked_session_gets_no_synthetic_duplicate() {
        // A tracked agent already owns 0xAABB (address stored 0x-prefixed here,
        // the live client reports the same) — no `win:` record is synthesized.
        let mut tracked = session("efdc", "/w", "working", "t", None);
        tracked.window_address = "0xAABB".into();
        let (out, changed) = reconcile_untracked_terminals(
            vec![tracked],
            &[term_win("0xAABB", "kitty", "/home/khoa")],
        );
        assert!(!changed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].session_id, "efdc");
        assert!(!out.iter().any(|s| s.session_id.starts_with("win:")));
    }
    #[test]
    fn closed_windows_synthetic_record_is_removed() {
        // A pre-existing synthetic record whose window no longer appears live is
        // dropped; the surviving window keeps its record.
        let stale = SessionRecord {
            session_id: "win:dead".into(),
            agent: "shell".into(),
            window_address: "0xDEAD".into(),
            state: "idle".into(),
            kind: Some("shell".into()),
            ..Default::default()
        };
        let (out, changed) =
            reconcile_untracked_terminals(vec![stale], &[term_win("0xLIVE", "foot", "/tmp")]);
        assert!(changed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].session_id, "win:live");
        assert!(!out.iter().any(|s| s.session_id == "win:dead"));
    }
    #[test]
    fn non_terminal_class_window_is_ignored() {
        let (out, changed) =
            reconcile_untracked_terminals(vec![], &[term_win("0xAABB", "firefox", "/home/khoa")]);
        assert!(!changed);
        assert!(out.is_empty());
    }
    #[test]
    fn unmapped_terminal_window_is_ignored() {
        let mut w = term_win("0xAABB", "kitty", "/home/khoa");
        w.mapped = false;
        let (out, changed) = reconcile_untracked_terminals(vec![], &[w]);
        assert!(!changed);
        assert!(out.is_empty());
    }
    #[test]
    fn rescan_is_idempotent_and_upserts_in_place() {
        let (first, _) =
            reconcile_untracked_terminals(vec![], &[term_win("0xAABB", "kitty", "/home/khoa")]);
        // A second reconcile with the same window makes no change and no duplicate.
        let (second, changed) =
            reconcile_untracked_terminals(first, &[term_win("0xAABB", "kitty", "/home/khoa")]);
        assert!(!changed);
        assert_eq!(second.len(), 1);
        // A cwd change upserts the existing record in place (still one record).
        let (third, changed3) =
            reconcile_untracked_terminals(second, &[term_win("0xAABB", "kitty", "/other")]);
        assert!(changed3);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].cwd, "/other");
    }
    #[test]
    fn focus_address_matching_is_prefix_and_case_tolerant() {
        // hyprctl reports `0x…` lowercase; the stored windowAddress may differ
        // on case and on a present/absent `0x` prefix — all must match.
        let clients = vec![
            json!({ "address": "0x55aabbccdd00", "class": "kitty" }),
            json!({ "address": "0x1234ef", "class": "foot" }),
        ];
        assert!(window_present(&clients, "0x55aabbccdd00")); // exact
        assert!(window_present(&clients, "55aabbccdd00")); // missing 0x prefix
        assert!(window_present(&clients, "0x55AABBCCDD00")); // upper case
        assert!(window_present(&clients, "55AABBCCDD00")); // both
        assert!(window_present(&clients, "0X1234EF")); // 0X + upper
                                                       // A vanished window is absent.
        assert!(!window_present(&clients, "0xdeadbeef"));
        assert!(!window_present(&clients, ""));
        // Client entry without an address field is ignored, not a false match.
        let noaddr = vec![json!({ "class": "kitty" })];
        assert!(!window_present(&noaddr, "0x1"));

        // Normalisation is idempotent and prefix-agnostic.
        assert_eq!(normalize_addr("0xABC"), "abc");
        assert_eq!(normalize_addr("abc"), "abc");
        assert_eq!(normalize_addr("  0Xabc  "), "abc");
    }
    #[test]
    fn window_discovery_matches_the_nearest_ancestor_client() {
        // conduct(pid 100) ← shell(same pid, exec) ← kitty(pid 42) ← hypr(pid 7).
        // kitty owns the window; the compositor (7) does not.
        let clients = vec![
            json!({ "pid": 42, "address": "0xKITTY", "class": "kitty" }),
            json!({ "pid": 999, "address": "0xOTHER", "class": "firefox" }),
        ];
        let ancestry = vec![100, 42, 7];
        assert_eq!(
            match_window_for_ancestry(&ancestry, &clients),
            Some("0xKITTY".to_string())
        );

        // The NEAREST ancestor with a window wins (self before its parents), even
        // if a further-up ancestor also owns a client.
        let nested = vec![
            json!({ "pid": 42, "address": "0xOUTER" }),
            json!({ "pid": 100, "address": "0xINNER" }),
        ];
        assert_eq!(
            match_window_for_ancestry(&[100, 42, 7], &nested),
            Some("0xINNER".to_string())
        );

        // No ancestor owns a window → None (address stays unset, as before).
        assert_eq!(match_window_for_ancestry(&[100, 42, 7], &[json!({ "pid": 5, "address": "0xX" })]), None);
        // A client whose pid matches but whose address is empty/absent is skipped.
        assert_eq!(
            match_window_for_ancestry(&[42], &[json!({ "pid": 42, "address": "" })]),
            None
        );
        assert_eq!(
            match_window_for_ancestry(&[42], &[json!({ "pid": 42, "class": "kitty" })]),
            None
        );
        // Empty inputs never match.
        assert_eq!(match_window_for_ancestry(&[], &clients), None);
        assert_eq!(match_window_for_ancestry(&ancestry, &[]), None);
    }
    #[test]
    fn window_discovery_also_returns_the_owning_pid() {
        // The hook door records the matched terminal pid (helps the reaper): a
        // `/proc` liveness signal that vanishes with the window, never a false
        // reap. The pid returned is the matched ancestor/client pid.
        let clients = vec![
            json!({ "pid": 42, "address": "0xKITTY", "class": "kitty" }),
            json!({ "pid": 999, "address": "0xOTHER" }),
        ];
        assert_eq!(
            match_window_and_pid(&[100, 42, 7], &clients),
            Some(("0xKITTY".to_string(), 42))
        );
        // Nearest ancestor wins, and its pid comes back with it.
        let nested = vec![
            json!({ "pid": 42, "address": "0xOUTER" }),
            json!({ "pid": 100, "address": "0xINNER" }),
        ];
        assert_eq!(
            match_window_and_pid(&[100, 42, 7], &nested),
            Some(("0xINNER".to_string(), 100))
        );
        // No match → None (address AND pid stay unset, never a partial record).
        assert_eq!(match_window_and_pid(&[5], &clients), None);
        assert_eq!(match_window_and_pid(&[42], &[json!({ "pid": 42, "address": "" })]), None);
    }
    #[test]
    fn client_workspace_lookup_reads_workspace_id_and_tolerates_address_form() {
        // `hyprctl clients -j` carries `workspace: { id, name }`; the lookup pulls
        // the numeric id for the matching window. Address match is 0x/case
        // tolerant, exactly like window_present (the stored addr may differ).
        let clients = vec![
            json!({ "address": "0x55aabb", "workspace": { "id": 3, "name": "3" } }),
            json!({ "address": "0x1234ef", "workspace": { "id": 7, "name": "seven" } }),
            // Special workspaces carry NEGATIVE ids — surfaced verbatim.
            json!({ "address": "0xdeadbe", "workspace": { "id": -99, "name": "special:magic" } }),
        ];
        assert_eq!(client_workspace_for_address(&clients, "0x55aabb"), Some(3));
        assert_eq!(client_workspace_for_address(&clients, "55AABB"), Some(3)); // no 0x + upper
        assert_eq!(client_workspace_for_address(&clients, "0X1234EF"), Some(7));
        assert_eq!(client_workspace_for_address(&clients, "0xdeadbe"), Some(-99));

        // A window absent from the list → None (leave the stored workspace be).
        assert_eq!(client_workspace_for_address(&clients, "0xnope"), None);
        // An empty address never matches.
        assert_eq!(client_workspace_for_address(&clients, ""), None);
        // A client without a workspace object (or without a numeric id) → None,
        // never a panic — degrade gracefully when Hyprland omits the field.
        let noworkspace = vec![
            json!({ "address": "0xaa" }),
            json!({ "address": "0xbb", "workspace": {} }),
            json!({ "address": "0xcc", "workspace": { "name": "3" } }),
        ];
        assert_eq!(client_workspace_for_address(&noworkspace, "0xaa"), None);
        assert_eq!(client_workspace_for_address(&noworkspace, "0xbb"), None);
        assert_eq!(client_workspace_for_address(&noworkspace, "0xcc"), None);
    }
    #[test]
    fn hypr_event_parses_window_lifecycle_and_ignores_the_rest() {
        // openwindow>>ADDR,WORKSPACE,CLASS,TITLE — address is the first field
        // (Hyprland emits it WITHOUT the `0x` prefix; a title may contain commas).
        assert_eq!(
            parse_hypr_window_event("openwindow>>55aabbccdd00,1,kitty,shell — /home/x, y"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabbccdd00".to_string()
            })
        );
        // movewindow / movewindowv2 re-check (session may have registered late).
        assert_eq!(
            parse_hypr_window_event("movewindow>>55aabb,2"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        assert_eq!(
            parse_hypr_window_event("movewindowv2>>55aabb,2,two"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        // windowtitle (old, ADDR only) and windowtitlev2 (ADDR,TITLE).
        assert_eq!(
            parse_hypr_window_event("windowtitle>>55aabb"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        assert_eq!(
            parse_hypr_window_event("windowtitlev2>>55aabb,a new title"),
            Some(HyprWindowEvent::Appeared {
                address: "55aabb".to_string()
            })
        );
        // closewindow>>ADDR — the whole payload is the address.
        assert_eq!(
            parse_hypr_window_event("closewindow>>55aabb"),
            Some(HyprWindowEvent::Closed {
                address: "55aabb".to_string()
            })
        );
        // Events we don't act on → None.
        assert_eq!(parse_hypr_window_event("workspace>>2"), None);
        assert_eq!(parse_hypr_window_event("activewindow>>kitty,shell"), None);
        assert_eq!(parse_hypr_window_event("focusedmon>>DP-1,2"), None);
        // Malformed / empty-address lines → None (never a panic, never a blank).
        assert_eq!(parse_hypr_window_event("no-delimiter-here"), None);
        assert_eq!(parse_hypr_window_event("openwindow>>"), None);
        assert_eq!(parse_hypr_window_event("openwindow>> ,1,kitty,t"), None);
        assert_eq!(parse_hypr_window_event("closewindow>>   "), None);
        assert_eq!(parse_hypr_window_event(""), None);
    }
    #[test]
    fn hypr_event_socket_path_needs_a_signature() {
        // `hypr_event_socket_path()` reads process-global env; serialise it
        // against the other env-touching tests with the crate-wide lock.
        let _guard = crate::env_lock().lock().unwrap();
        let saved_sig = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").ok();
        let saved_rt = std::env::var("XDG_RUNTIME_DIR").ok();

        // No signature → no socket (listener disables itself off-Hyprland).
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        assert_eq!(hypr_event_socket_path(), None);

        // A blank signature is treated as absent, not as a path segment.
        std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", "   ");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(hypr_event_socket_path(), None);

        // Signature + runtime dir → the documented socket2 path.
        std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", "abc123_99");
        assert_eq!(
            hypr_event_socket_path(),
            Some(PathBuf::from(
                "/run/user/1000/hypr/abc123_99/.socket2.sock"
            ))
        );

        match saved_sig {
            Some(v) => std::env::set_var("HYPRLAND_INSTANCE_SIGNATURE", v),
            None => std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE"),
        }
        match saved_rt {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
    #[test]
    fn focus_window_rejects_an_empty_address_without_touching_hyprctl() {
        // The shared focus fn is called by the socket loop on arbitrary input;
        // an empty/blank address is a structured error, never a panic and never
        // a stray `hyprctl` dispatch.
        let err = focus_window("").expect_err("empty address must error");
        assert_eq!(err.reason, "no-window-address");
        let err = focus_window("   ").expect_err("blank address must error");
        assert_eq!(err.reason, "no-window-address");
    }
    #[test]
    fn focus_window_never_succeeds_for_a_nonexistent_window() {
        // A bogus address is never a live client, so the verify step fails —
        // either `window-not-found` (hyprctl present) or `hyprctl-unavailable`
        // (no compositor / hyprctl absent, e.g. the build sandbox). Both are
        // structured Errs: the fn must NEVER report a false focus and NEVER
        // panic, whatever the environment.
        let err = focus_window("0xdeadbeefcafe").expect_err("bogus address must not focus");
        assert!(
            matches!(
                err.reason,
                "window-not-found" | "hyprctl-unavailable" | "hyprctl-failed"
            ),
            "unexpected reason {}",
            err.reason
        );
    }
    #[test]
    fn pid_ancestry_starts_at_self_and_is_bounded() {
        // Real /proc: our own ancestry begins with our pid and includes a parent.
        let me = std::process::id() as i32;
        let chain = pid_ancestry(me);
        assert_eq!(chain.first(), Some(&me), "self is first in the chain");
        assert!(chain.len() >= 2, "we always have at least one ancestor");
        assert!(chain.len() <= 64, "the walk is bounded");
        // A nonexistent pid yields just the seed (no /proc entry to walk up).
        assert_eq!(pid_ancestry(2_000_000_000), vec![2_000_000_000]);
    }
}
