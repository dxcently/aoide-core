//! `lyra secrets ask` — the rice-shaped code-entry dialog `aoide secrets
//! watch --popup` spawns instead of `zenity --entry` once
//! `aoide_secrets::watch::resolve_lyra_bin` finds this binary
//! (`crates/secrets/src/watch.rs`'s own P3 doc). A small quickshell window:
//! six individually-boxed digit inputs, grouped `[X][X][X] - [X][X][X]`
//! (the dash its OWN element, never typed into, never occupying a box),
//! auto-submitting the instant all six are filled — no chunky OK button, a
//! 30-second code doesn't need one. Esc or the window's own close button
//! cancels; a quiet, flat "Dismiss ask" text control sends a real refusal,
//! never confused with Cancel (the same "never adjacent, never share a
//! word" rule `aoide-secrets`' own zenity path already holds).
//!
//! **Output contract — byte-identical to zenity's, this is the whole
//! reason the two binaries are interchangeable
//! (`aoide_secrets::watch::run_entry_dialog`'s own doc):** the typed code on
//! stdout with exit 0 on submit; the literal string `Dismiss ask` on stdout
//! with exit 1 on dismiss; any other non-zero exit (Esc, window closed, a
//! spawn failure) for a bare cancel. `watch.rs`'s result parsing and its
//! kill-by-pid expiry path never know which binary answered — don't change
//! this contract here without updating `crates/secrets/src/watch.rs`'s
//! module doc AND `crates/secrets/README.md`'s "Popup mode" section in the
//! SAME commit.
//!
//! **The QML is paint only (root `AGENTS.md` house rule 7's "delete every
//! `.qml`" test) — the capability (entering a TOTP code) stays reachable
//! with nothing but a shell**: `aoide secrets approve <id> --totp <code>`
//! (the socket-side operator path every dialog ultimately routes through)
//! and the zenity fallback both work with this file deleted entirely. This
//! command is a bridge-first-QML-second addition to an ALREADY-reachable
//! capability, never a new one.
//!
//! **No established "spawn a fresh quickshell -p <file>" seam existed
//! before this command** — `aoide-song`'s own `quickshell reload`
//! (`song::commands::quickshell`) only ever sends IPC into an ALREADY
//! RUNNING instance (`crate::ipc::quickshell_ipc_reload`), never spawns a
//! new one. This module is the first: [`run_ask_dialog`] writes a generated
//! QML file to a scratch temp path ([`write_temp_qml`], the SAME
//! `std::env::temp_dir()` + `{pid}-{nanos}` uniqueness convention
//! `aoide-screen`'s own scratch-file tests already use) and spawns
//! `quickshell -p <path>` — never the desktop's own `shell.qml` — as a
//! genuinely standalone, one-shot process.
//!
//! **The window must be FLOATING, not tiled** (found live, this commit):
//! Hyprland tiles a bare `Window {}` toplevel by default regardless of its
//! declared `width`/`height`, and `flags: Qt.Dialog` alone did not change
//! that on this rig. Setting `minimumWidth`/`maximumWidth`/`minimumHeight`/
//! `maximumHeight` all equal to the window's own `width`/`height` (a
//! fixed-size hint) DOES trigger Hyprland's own auto-float heuristic —
//! verified live via `hyprctl clients` (`floating: 1`, the requested exact
//! size) before this doc was written. [`render_qml`] sets all four; don't
//! drop them "since `width`/`height` already say the same thing" — only the
//! min/max pair actually changes the compositor's placement decision.
//!
//! **Why `console.log`, not a file/pipe of quickshell's own** — a live
//! probe on this crate's own dev box (Quickshell 0.3.0) found `console.log`
//! output lands on the CHILD's stdout (Quickshell's own structured logger
//! writes there, not stderr) and `Qt.quit()` alone does NOT terminate the
//! process ("no receivers connected to handle it" — Quickshell is built to
//! keep running with zero windows open, the whole point of a shell
//! framework). So [`run_ask_dialog`] never waits for quickshell to exit on
//! its own: it reads stdout LINE BY LINE watching for the
//! [`RESULT_MARKER`]-prefixed line the QML's `console.log` emits, then
//! kills the child directly the instant one is found (`child.kill()`) — the
//! SAME "read until the CHILD's own contract line, then kill by the exact
//! handle" idiom this crate's sibling, `aoide_secrets::watch`, already holds
//! for zenity (`run_entry_dialog`'s own doc). A closed window (Esc, the
//! decoration's close button) ALSO emits a `CANCEL` marker line first
//! (`onClosing`/`Keys.onPressed`'s own Escape arm in [`render_qml`]) for the
//! identical reason: nothing about quickshell's own process lifecycle can be
//! trusted to end this dialog on its own.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use aoide_protocol::Door;
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["secrets", "ask"],
        summary: "Render a quickshell code-entry dialog for one parked TOTP ask -- six digit boxes grouped [X][X][X]-[X][X][X], auto-submitting once all six are filled. CLI-only: the counterpart `aoide secrets watch --popup` spawns in place of zenity when this binary resolves. Speaks zenity's own output contract (code on stdout + exit 0; `Dismiss ask` on stdout + exit 1; else non-zero) so the caller never needs to know which binary answered.",
        args: [],
        flags: [
            flag!("secret", "string", "The secret name this ask is for (display only)."),
            flag!("consumer", "string", "The consumer name asking (display only)."),
            flag!("seconds", "string", "Remaining seconds before this ask's park times out (display only, baked in at spawn -- never a live countdown, the same limitation zenity's own --text bakes)."),
            flag!("reason", "string", "Free-text context for why this ask exists (display only, self-asserted -- rendered verbatim, never interpreted)."),
            flag!("from", "string", "A pre-formatted 'from: ...' origin line (display only -- already rendered by the caller so every ask surface shows byte-identical wording, aoide-secrets' own watch::format_origin_line).")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_ask,
    ));
}

/// The prefix every result line [`render_qml`]'s `console.log` calls carry —
/// the ONE string both the QML template and [`parse_marker_line`] agree on.
const RESULT_MARKER: &str = "AOIDE_SECRETS_ASK_RESULT:";

/// `quickshell`'s own binary name — a parameter everywhere it matters
/// ([`run_ask_dialog`]/[`spawn_quickshell`]), never a hardcoded
/// `Command::new("quickshell")` inline at a call site, the SAME "tests stand
/// in a fake shim, no `PATH` mutation" discipline `aoide_secrets::watch`'s
/// own `ZENITY_CMD` constant holds.
const QUICKSHELL_CMD: &str = "quickshell";

fn handle_secrets_ask(inv: &Invocation) -> Outcome {
    let cmd = "secrets.ask";
    if inv.door != Door::Cli {
        return Outcome::usage(cmd, "secrets ask is a desktop dialog -- CLI-only");
    }
    let Some(secret) = inv.flags.get("secret").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "secrets ask requires --secret <name>");
    };
    let Some(consumer) = inv.flags.get("consumer").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "secrets ask requires --consumer <name>");
    };
    let Some(seconds) = inv.flags.get("seconds").and_then(|s| s.parse::<u64>().ok()) else {
        return Outcome::usage(cmd, "secrets ask requires --seconds <n> (a non-negative integer)");
    };
    let reason = inv.flags.get("reason").filter(|s| !s.is_empty()).map(String::as_str);
    let from_line = inv.flags.get("from").filter(|s| !s.is_empty()).map(String::as_str);

    match run_ask_dialog(QUICKSHELL_CMD, secret, consumer, seconds, reason, from_line) {
        Ok(AskResult::Approved(code)) => {
            Outcome::ok(cmd, "code entered").with_data(json!({ "result": "approved", "code": code }))
        }
        Ok(AskResult::Dismissed) => Outcome::ok(cmd, "dismissed").with_data(json!({ "result": "dismissed" })),
        Ok(AskResult::Cancelled) => Outcome::ok(cmd, "cancelled").with_data(json!({ "result": "cancelled" })),
        Err(e) => Outcome::error(cmd, e),
    }
}

/// The three shapes this command's own `console.log` marker line can carry —
/// mirrors `aoide_secrets::watch::ZenityResult` in spirit (never a bare
/// `Result`: "the user closed it," "explicitly dismissed," and "typed a
/// full code" are three different things the caller reacts to differently),
/// minus the zenity-only `SpawnError`/`CancelledExternally` variants this
/// command has no equivalent of (a `quickshell` spawn failure is reported
/// straight through as an `Err(String)` instead — module doc's own doc
/// comment on why nothing here waits for an external kill signal).
#[derive(Debug, PartialEq, Eq)]
enum AskResult {
    Approved(String),
    Dismissed,
    Cancelled,
}

/// Write the generated QML, spawn `quickshell -p <path>`, read its stdout
/// line by line for the FIRST [`RESULT_MARKER`]-prefixed line, kill the
/// child the instant one is found (module doc: quickshell never exits on
/// its own), and clean up the scratch file regardless of outcome.
fn run_ask_dialog(
    quickshell_cmd: &str,
    secret: &str,
    consumer: &str,
    seconds: u64,
    reason: Option<&str>,
    from_line: Option<&str>,
) -> Result<AskResult, String> {
    let qml_path =
        write_temp_qml(secret, consumer, seconds, reason, from_line).map_err(|e| format!("writing the dialog's QML: {e}"))?;
    let result = spawn_and_wait_for_marker(quickshell_cmd, &qml_path);
    let _ = std::fs::remove_file(&qml_path);
    result
}

/// The scratch directory a generated QML file lands in — `$XDG_RUNTIME_DIR`
/// when set (a per-user, tmpfs-backed, already-`0700` directory systemd
/// provisions on every graphical session — the SAME per-user privacy bound
/// `aoide-secrets`' own `RuntimeDirectory` relies on), else `std::env::
/// temp_dir()`. Only ever display data (a secret NAME, never a value), but
/// this crate's sibling 0600s everything it writes on principle
/// (`aoide_secrets::store`'s own `secure_file`) — matching that here costs
/// nothing and there is no reason not to.
fn scratch_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

fn write_temp_qml(
    secret: &str,
    consumer: &str,
    seconds: u64,
    reason: Option<&str>,
    from_line: Option<&str>,
) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = scratch_dir().join(format!(
        "aoide-secrets-ask-{}-{}.qml",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
    ));
    // `0600` from creation — `mode()` sets the CREATE-time mode, still
    // subject to umask, so this also matches `secure_file`'s own
    // belt-and-suspenders `set_permissions` afterward rather than trusting
    // the mode bit alone against a permissive umask.
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
    file.write_all(render_qml(secret, consumer, seconds, reason, from_line).as_bytes())?;
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// Spawn `quickshell -p <qml_path>` — [`Command::pre_exec`] arms
/// `PR_SET_PDEATHSIG` on the child BEFORE it execs into `quickshell`, so a
/// killed `lyra secrets ask` process can never orphan its own dialog window
/// (module doc's "Orphan prevention" section has the full ownership-chain
/// reasoning this function is the implementation of).
fn spawn_quickshell(quickshell_cmd: &str, qml_path: &std::path::Path) -> std::io::Result<Child> {
    use std::os::unix::process::CommandExt;

    // Captured in THIS (the lyra) process, before fork — `pre_exec`'s own
    // closure runs AFTER fork, so `libc::getpid()` there would return the
    // CHILD's own pid, not the parent's; this value has to cross the fork
    // as a captured local.
    let parent_pid = unsafe { libc::getpid() };

    let mut cmd = Command::new(quickshell_cmd);
    cmd.args(["-p", &qml_path.to_string_lossy()]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());

    // SAFETY: this closure runs in the forked CHILD, strictly between
    // `fork()` and `execve()` — the exact narrow window POSIX allows only
    // async-signal-safe calls in (no allocation, no locks, nothing Rust's
    // own runtime needs touched). `prctl`/`getppid`/`_exit` are bare
    // syscalls, all three async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // `PR_SET_PDEATHSIG` arranges for the KERNEL to send `SIGKILL`
            // to THIS process (about to become `quickshell`) the moment its
            // own parent thread — this `lyra` process — dies, for ANY
            // reason, including `aoide_secrets::watch`'s own SIGKILL on the
            // expiry/kill-by-pid path. That signal is untrappable, so this
            // crate's own best-effort cleanup (`spawn_and_wait_for_marker`'s
            // `child.kill()`) can never be relied on to run first when the
            // KILL lands on `lyra`, not on `quickshell` directly — this is
            // the mechanism that actually closes the window in that case.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The standard TOCTOU close: if the parent ALREADY died in the
            // window between `fork()` and this line running, this process
            // has already been reparented (to a subreaper, or pid 1) by the
            // time it observes it — a death signal armed AFTER that
            // reparenting never fires, since the kernel only delivers it
            // relative to the CURRENT parent at signal-delivery time, not
            // the one that existed at `fork()`. Exiting here instead of
            // proceeding into `execve()` is what closes that gap: no
            // quickshell process is ever left to orphan in the first place.
            if libc::getppid() != parent_pid {
                libc::_exit(1);
            }
            Ok(())
        });
    }

    cmd.spawn()
}

fn spawn_and_wait_for_marker(quickshell_cmd: &str, qml_path: &std::path::Path) -> Result<AskResult, String> {
    let mut child = spawn_quickshell(quickshell_cmd, qml_path).map_err(|e| {
        format!(
            "spawning quickshell: {e} -- install quickshell, or complete this ask another way: \
             `aoide secrets approve <id> --totp <code>` (or `aoide secrets watch` without --popup, \
             which falls back to zenity)"
        )
    })?;

    let stdout = child.stdout.take().expect("stdout is always piped by spawn_quickshell");
    let mut found = None;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        if let Some(result) = parse_marker_line(&line) {
            found = Some(result);
            break;
        }
    }

    // Whichever way the loop ended -- a marker was found, or the pipe
    // closed on its own (quickshell crashed, or exited some other way) --
    // the process must never be left running (module doc: `Qt.quit()`
    // alone does not end it).
    let _ = child.kill();
    let _ = child.wait();

    Ok(found.unwrap_or(AskResult::Cancelled))
}

/// Pure and total: finds [`RESULT_MARKER`] as a SUBSTRING rather than
/// requiring it at position 0, since quickshell's own structured logger
/// prefixes every line it prints (`[LEVEL] category: `, sometimes with ANSI
/// color codes ahead of that) — a live probe confirmed this, this function
/// never assumes a particular prefix shape, only that the marker appears
/// somewhere on the line.
fn parse_marker_line(line: &str) -> Option<AskResult> {
    let idx = line.find(RESULT_MARKER)?;
    let rest = line[idx + RESULT_MARKER.len()..].trim_end();
    if let Some(code) = rest.strip_prefix("CODE:") {
        Some(AskResult::Approved(code.to_string()))
    } else if rest == "DISMISS" {
        Some(AskResult::Dismissed)
    } else if rest == "CANCEL" {
        Some(AskResult::Cancelled)
    } else {
        None
    }
}

/// Escape a string for embedding inside a QML double-quoted string literal.
/// Every value this function escapes is UNTRUSTED display text — a
/// `--reason`/`--from` value is self-asserted/best-effort in origin
/// (`aoide_secrets`' own `AGENTS.md` honesty note, extended here: `comm` in
/// particular is PROCESS-CONTROLLED text ANY process can set to anything
/// via `prctl(PR_SET_NAME, ...)`), so this function's whole job is making
/// sure that text can never end its own string literal early, whatever it
/// contains. Backslash and double-quote are the classic pair, but QML's
/// strings are JavaScript strings underneath: a bare, un-escaped newline or
/// carriage return inside one is a SYNTAX ERROR (breaks the file across
/// lines, likely landing outside any string at all by the time the parser
/// resumes), and U+2028/U+2029 (LINE SEPARATOR/PARAGRAPH SEPARATOR) are
/// treated as line terminators INSIDE a JS string literal even though they
/// look like ordinary printable characters — both must be escaped for the
/// exact same reason `\n`/`\r` are. Every other C0 control character (tab
/// included) is escaped too, on the same "never let raw control bytes reach
/// generated source" principle. See `render_qml_embeds_a_hostile_reason_
/// safely_escaped`/`qml_escape_neutralizes_every_dangerous_character` for
/// the fault this closes: an unescaped newline in a `reason` used to break
/// the generated file, and the dialog never rendered at all.
fn qml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == '\u{2028}' || c == '\u{2029}' || (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render the dialog's QML — six individually-boxed digit inputs
/// (`[X][X][X] - [X][X][X]`, module doc) painted OVER a single underlying
/// `TextInput` (`codeInput`), never six separate text fields: the boxes are
/// a pure presentation layer (each renders one character of `codeInput
/// .text`, and highlights when `codeInput`'s own cursor/selection covers
/// its index) so select-all, arrow-key movement, backspace/delete,
/// clipboard copy/cut/paste, and mouse click/drag-to-select are ALL
/// inherited from the platform `TextInput` for free rather than
/// hand-reimplemented across six widgets — `codeInput.color`/
/// `selectionColor`/`selectedTextColor` are `"transparent"` and
/// `cursorVisible` is `false` so nothing of the real field paints twice
/// over the boxes' own glyphs. `codeInput.onTextChanged` calls
/// `submitIfComplete()` on every keystroke AND every paste (a paste that
/// fills all six digits submits immediately, satisfying "paste distributes
/// across all boxes" without any bespoke paste-handling code at all — the
/// validator already strips non-digits, `maximumLength: 6` already caps the
/// total). Enter also submits when full (`Keys.onPressed`); Escape cancels.
/// The context block — `release \`<secret>\` -> <consumer>`, then `for:
/// "<reason>"` when present, then the pre-formatted `from_line` when
/// present, then the countdown — mirrors `aoide_secrets::watch::
/// format_prompt_header`'s own line order (that function's doc).
fn render_qml(secret: &str, consumer: &str, seconds: u64, reason: Option<&str>, from_line: Option<&str>) -> String {
    let secret = qml_escape(secret);
    let consumer = qml_escape(consumer);

    let reason_block = reason
        .map(|r| {
            format!(
                "            Text {{ anchors.horizontalCenter: parent.horizontalCenter; text: \"for: \\\"{}\\\"\"; color: \"#a6adc8\"; font.pixelSize: 12; font.italic: true }}\n",
                qml_escape(r)
            )
        })
        .unwrap_or_default();
    let from_block = from_line
        .map(|f| {
            format!(
                "            Text {{ anchors.horizontalCenter: parent.horizontalCenter; text: \"{}\"; color: \"#7f849c\"; font.pixelSize: 11 }}\n",
                qml_escape(f)
            )
        })
        .unwrap_or_default();

    TEMPLATE
        .replace("__SECRET__", &secret)
        .replace("__CONSUMER__", &consumer)
        .replace("__SECONDS__", &seconds.to_string())
        .replace("__REASON_BLOCK__\n", &reason_block)
        .replace("__FROM_BLOCK__\n", &from_block)
        .replace("__RESULT_MARKER__", RESULT_MARKER)
}

/// The QML source, with `__TOKEN__` substitution points [`render_qml`]
/// fills in — a plain string template rather than `format!`'s `{}`/`{{}}`
/// escaping, since this file's own literal `{`/`}` braces (QML's own
/// syntax) would otherwise need doubling throughout and become nearly
/// unreadable/unreviewable at this size.
const TEMPLATE: &str = r##"import QtQuick
import QtQuick.Window
import QtQuick.Controls

Window {
    id: win
    width: 400
    height: 240
    minimumWidth: width
    maximumWidth: width
    minimumHeight: height
    maximumHeight: height
    visible: true
    title: "aoide · __SECRET__"
    color: "#1e1e2e"
    flags: Qt.Dialog

    function submitIfComplete() {
        if (codeInput.text.length === 6) {
            console.log("__RESULT_MARKER__CODE:" + codeInput.text);
        }
    }
    function dismissAsk() {
        console.log("__RESULT_MARKER__DISMISS");
    }
    onClosing: console.log("__RESULT_MARKER__CANCEL")
    Component.onCompleted: codeInput.forceActiveFocus()

    Rectangle {
        anchors.fill: parent
        color: "#1e1e2e"

        Column {
            anchors.centerIn: parent
            spacing: 12

            Text { anchors.horizontalCenter: parent.horizontalCenter; text: "release `__SECRET__` → __CONSUMER__"; color: "#cdd6f4"; font.pixelSize: 16; font.bold: true }
__REASON_BLOCK__
__FROM_BLOCK__
            Text { anchors.horizontalCenter: parent.horizontalCenter; text: "__SECONDS__s left"; color: "#7f849c"; font.pixelSize: 11 }

            Item {
                id: codeArea
                width: boxesRow.width
                height: 52
                anchors.horizontalCenter: parent.horizontalCenter

                Row {
                    id: boxesRow
                    spacing: 14
                    anchors.verticalCenter: parent.verticalCenter

                    Row {
                        spacing: 6
                        Repeater {
                            model: 3
                            Rectangle {
                                width: 40
                                height: 52
                                property int boxIndex: index
                                radius: 6
                                color: "#313244"
                                border.width: 2
                                border.color: {
                                    if (!codeInput.activeFocus) return "#45475a";
                                    if (boxIndex >= codeInput.selectionStart && boxIndex < codeInput.selectionEnd) return "#f9e2af";
                                    if (boxIndex === Math.min(codeInput.cursorPosition, 5)) return "#89b4fa";
                                    return "#45475a";
                                }
                                Text {
                                    anchors.centerIn: parent
                                    text: boxIndex < codeInput.text.length ? codeInput.text.charAt(boxIndex) : ""
                                    color: "#cdd6f4"
                                    font.pixelSize: 22
                                }
                            }
                        }
                    }

                    Text { text: "-"; color: "#a6adc8"; font.pixelSize: 20; anchors.verticalCenter: parent.verticalCenter }

                    Row {
                        spacing: 6
                        Repeater {
                            model: 3
                            Rectangle {
                                width: 40
                                height: 52
                                property int boxIndex: index + 3
                                radius: 6
                                color: "#313244"
                                border.width: 2
                                border.color: {
                                    if (!codeInput.activeFocus) return "#45475a";
                                    if (boxIndex >= codeInput.selectionStart && boxIndex < codeInput.selectionEnd) return "#f9e2af";
                                    if (boxIndex === Math.min(codeInput.cursorPosition, 5)) return "#89b4fa";
                                    return "#45475a";
                                }
                                Text {
                                    anchors.centerIn: parent
                                    text: boxIndex < codeInput.text.length ? codeInput.text.charAt(boxIndex) : ""
                                    color: "#cdd6f4"
                                    font.pixelSize: 22
                                }
                            }
                        }
                    }
                }

                TextInput {
                    id: codeInput
                    anchors.fill: parent
                    font.pixelSize: 22
                    font.family: "monospace"
                    color: "transparent"
                    selectionColor: "transparent"
                    selectedTextColor: "transparent"
                    cursorVisible: false
                    maximumLength: 6
                    validator: RegularExpressionValidator { regularExpression: /^[0-9]*$/ }
                    inputMethodHints: Qt.ImhDigitsOnly
                    onTextChanged: submitIfComplete()
                    Keys.onPressed: (event) => {
                        if (event.key === Qt.Key_Escape) {
                            console.log("__RESULT_MARKER__CANCEL");
                            event.accepted = true;
                        } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                            submitIfComplete();
                            event.accepted = true;
                        }
                    }
                }
            }

            Text {
                text: "Dismiss ask"
                color: "#7f849c"
                font.pixelSize: 12
                font.underline: dismissArea.containsMouse
                anchors.horizontalCenter: parent.horizontalCenter
                MouseArea {
                    id: dismissArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: dismissAsk()
                }
            }
        }
    }
}
"##;

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_marker_line (pure) ─────────────────────────────────────────

    #[test]
    fn parse_marker_line_reads_a_code_at_the_start_of_the_line() {
        assert_eq!(parse_marker_line("AOIDE_SECRETS_ASK_RESULT:CODE:123456"), Some(AskResult::Approved("123456".to_string())));
    }

    #[test]
    fn parse_marker_line_finds_the_marker_after_quickshells_own_log_prefix() {
        // A live probe on this dev box confirmed quickshell's structured
        // logger prefixes every console.log line (module doc) — this pins
        // that the parser is a SUBSTRING search, not an anchored one.
        assert_eq!(
            parse_marker_line(" DEBUG qml: AOIDE_SECRETS_ASK_RESULT:CODE:654321"),
            Some(AskResult::Approved("654321".to_string()))
        );
    }

    #[test]
    fn parse_marker_line_reads_dismiss_and_cancel() {
        assert_eq!(parse_marker_line("AOIDE_SECRETS_ASK_RESULT:DISMISS"), Some(AskResult::Dismissed));
        assert_eq!(parse_marker_line("AOIDE_SECRETS_ASK_RESULT:CANCEL"), Some(AskResult::Cancelled));
    }

    #[test]
    fn parse_marker_line_is_none_for_an_unrelated_line() {
        assert_eq!(parse_marker_line("INFO: Configuration Loaded"), None);
    }

    // ── render_qml (pure) ────────────────────────────────────────────────

    #[test]
    fn render_qml_embeds_secret_consumer_and_seconds() {
        let qml = render_qml("db-prod", "claude", 120, None, None);
        assert!(qml.contains("db-prod"));
        assert!(qml.contains("claude"));
        assert!(qml.contains("120s left"));
    }

    #[test]
    fn render_qml_omits_reason_and_from_blocks_when_absent() {
        let qml = render_qml("db-prod", "claude", 120, None, None);
        assert!(!qml.contains("for: \\\""));
        assert!(!qml.contains("__REASON_BLOCK__"));
        assert!(!qml.contains("__FROM_BLOCK__"));
    }

    #[test]
    fn render_qml_includes_reason_and_from_when_present() {
        let qml = render_qml("db-prod", "claude", 120, Some("sudo nixos-rebuild switch"), Some("from: khoa @ yomi-strix"));
        assert!(qml.contains("for: \\\"sudo nixos-rebuild switch\\\""));
        assert!(qml.contains("from: khoa @ yomi-strix"));
    }

    #[test]
    fn render_qml_escapes_a_double_quote_in_a_secret_name() {
        // Secret/consumer names are validated elsewhere (`policy::
        // valid_secret_name`) to never actually contain a quote, but this
        // function must still never emit a syntactically broken QML string
        // literal from whatever text arrives.
        let qml = render_qml("weird\"name", "claude", 1, None, None);
        assert!(qml.contains("weird\\\"name"));
    }

    #[test]
    fn qml_escape_neutralizes_every_dangerous_character() {
        // Backslash/quote (the classic pair) plus every character that is
        // dangerous specifically because QML strings are JS strings
        // underneath: raw newline/CR (breaks the file across physical
        // lines), tab, U+2028/U+2029 (JS line terminators even inside a
        // string literal, despite looking like ordinary printable glyphs),
        // and the remaining C0 control range.
        let hostile = "back\\slash quote\" nl\n cr\r tab\t ls\u{2028} ps\u{2029} null\u{0000} esc\u{001b}";
        let escaped = qml_escape(hostile);

        assert!(!escaped.chars().any(|c| c.is_control()), "no raw control character may survive escaping: {escaped:?}");

        // Every backslash/quote in the ESCAPED output must be part of one
        // of this function's own escape sequences (`\\`, `\"`, `\n`, `\r`,
        // `\t`, or `\u XXXX`) — strip each of those forms in turn and
        // nothing bare should remain.
        let mut stripped = escaped.clone();
        let mut i = 0;
        let mut out = String::new();
        let chars: Vec<char> = stripped.chars().collect();
        while i < chars.len() {
            if chars[i] == '\\' && i + 1 < chars.len() {
                match chars[i + 1] {
                    '\\' | '"' | 'n' | 'r' | 't' => {
                        i += 2;
                        continue;
                    }
                    'u' if i + 5 < chars.len() && chars[i + 2..i + 6].iter().all(|c| c.is_ascii_hexdigit()) => {
                        i += 6;
                        continue;
                    }
                    _ => {}
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        stripped = out;
        assert!(!stripped.contains('"'), "an unescaped quote survived: {escaped:?}");
        assert!(!stripped.contains('\\'), "an unescaped backslash survived: {escaped:?}");
    }

    #[test]
    fn qml_escape_is_the_identity_on_ordinary_text() {
        assert_eq!(qml_escape("sudo nixos-rebuild switch"), "sudo nixos-rebuild switch");
        assert_eq!(qml_escape("khoa · bash (pid 123) @ yomi-strix"), "khoa · bash (pid 123) @ yomi-strix");
    }

    #[test]
    fn render_qml_embeds_a_hostile_reason_safely_escaped() {
        // The exact fault this test closes: an unescaped newline in
        // `reason` used to split the generated file across physical lines
        // mid-string-literal, and the dialog never rendered at all. Also
        // carries a literal QML/JS injection ATTEMPT (`"]; Qt.quit(); //`)
        // — proving it lands as inert escaped text, never as source.
        let hostile = "normal\n\"]; Qt.quit(); //\u{2028}end\"";
        let qml = render_qml("db-prod", "claude", 1, Some(hostile), None);
        let escaped = qml_escape(hostile);

        let expected_line = format!("for: \\\"{escaped}\\\"");
        assert!(qml.contains(&expected_line), "expected the fully-escaped reason inline, got:\n{qml}");

        // The reason's own `Text { ... }` block must stay on ONE physical
        // source line — proof the embedded newline/LS never reintroduced a
        // raw line break into the file.
        let line = qml.lines().find(|l| l.contains("for: \\\"")).expect("the reason line must exist as ONE physical line");
        assert!(line.trim_end().ends_with('}'), "the reason's Text {{}} block must close on the same physical line: {line:?}");

        // The rest of the template must be completely unaffected —
        // structural markers appear exactly as many times as the
        // non-hostile-input tests already pin.
        assert_eq!(qml.matches("model: 3").count(), 2);
        assert_eq!(qml.matches("function submitIfComplete()").count(), 1);
    }

    #[test]
    fn render_qml_carries_six_boxes_a_dash_and_no_hardcoded_dialog_chrome() {
        let qml = render_qml("db-prod", "claude", 1, None, None);
        // Two `Repeater { model: 3 ... }` groups (each instantiated three
        // times at runtime -> six boxes total) is the QML SOURCE shape --
        // the source text itself declares the delegate once per group, not
        // once per rendered box (`Repeater`'s own semantics), so this
        // asserts on the source-level structure that PRODUCES six boxes at
        // runtime, not a literal count of six occurrences in the text.
        assert_eq!(qml.matches("model: 3").count(), 2, "expected two groups of three boxes (six total)");
        assert_eq!(qml.matches("property int boxIndex").count(), 2, "one delegate per group, each instantiated three times");
        assert!(qml.contains("boxIndex: index + 3"), "the second group's indices must continue 3..6, not restart at 0");
        assert!(qml.contains("text: \"-\""), "expected the dash separator as its own element");
        assert!(qml.contains("\"Dismiss ask\""));
        assert!(!qml.contains("Button {"), "the dismiss control is a flat text+MouseArea, never a default-styled Button");
    }

    #[test]
    fn render_qml_floats_via_fixed_size_hints_not_only_qt_dialog() {
        // The Hyprland tiling finding (module doc) — pins that BOTH the
        // dialog flag and the min==max size hint are present, since only
        // the size hint was proven to actually change placement live.
        let qml = render_qml("db-prod", "claude", 1, None, None);
        assert!(qml.contains("flags: Qt.Dialog"));
        assert!(qml.contains("minimumWidth: width"));
        assert!(qml.contains("maximumWidth: width"));
        assert!(qml.contains("minimumHeight: height"));
        assert!(qml.contains("maximumHeight: height"));
    }

    // ── handle_secrets_ask door/flag validation (no live quickshell) ─────

    fn inv(door: Door, flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = std::collections::BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation { path: vec!["secrets".to_string(), "ask".to_string()], args: vec![], flags: flag_map, door }
    }

    #[test]
    fn handle_secrets_ask_is_cli_only() {
        let i = inv(Door::Mcp, &[("secret", "t"), ("consumer", "m"), ("seconds", "1")]);
        assert_eq!(handle_secrets_ask(&i).status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_secrets_ask_requires_secret_consumer_and_seconds() {
        assert_eq!(handle_secrets_ask(&inv(Door::Cli, &[])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(handle_secrets_ask(&inv(Door::Cli, &[("secret", "t")])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(
            handle_secrets_ask(&inv(Door::Cli, &[("secret", "t"), ("consumer", "m")])).status,
            aoide_protocol::output::Status::Usage
        );
        assert_eq!(
            handle_secrets_ask(&inv(Door::Cli, &[("secret", "t"), ("consumer", "m"), ("seconds", "not-a-number")])).status,
            aoide_protocol::output::Status::Usage
        );
    }

    // ── run_ask_dialog / the output contract, via a fake quickshell shim ──
    // Same shim pattern `aoide_secrets::watch`'s own zenity/lyra tests use
    // (a tempdir executable standing in for the real binary), extended here
    // to a fake `quickshell` that prints a marker line and exits.

    fn write_shim(tag: &str, script: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-lyra-secrets-ask-shim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("quickshell-shim");
        std::fs::write(&shim, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A just-written-then-immediately-exec'd shim under heavy parallel
        // `--test-threads` contention hits a genuine `execve()`/`close()`
        // TOCTOU on this kernel — `aoide_secrets::watch`'s own shim tests
        // diagnosed and fixed the IDENTICAL flake this way (that module's
        // own `write_shim`/`shim_lock` doc has the full root-cause writeup);
        // this is that same fix, not a new one invented here.
        std::thread::sleep(std::time::Duration::from_millis(5));
        shim
    }

    fn remove_shim(shim: &std::path::Path) {
        if let Some(dir) = shim.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    /// Serializes every test below that writes a shim script and then
    /// immediately execs it, against every OTHER such test — the exact
    /// contention `aoide_secrets::watch`'s own `shim_lock()` exists to
    /// close (that function's own doc has the full diagnosis); this crate's
    /// copy of the same fix for the same reason.
    fn shim_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn run_ask_dialog_returns_approved_when_the_shim_prints_a_code() {
        let _guard = shim_lock();
        let shim = write_shim("approve", "#!/bin/sh\necho AOIDE_SECRETS_ASK_RESULT:CODE:246810\nexit 0\n");
        let result = run_ask_dialog(shim.to_str().unwrap(), "db-prod", "claude", 42, None, None).unwrap();
        assert_eq!(result, AskResult::Approved("246810".to_string()));
        remove_shim(&shim);
    }

    #[test]
    fn run_ask_dialog_returns_dismissed_when_the_shim_prints_dismiss() {
        let _guard = shim_lock();
        let shim = write_shim("dismiss", "#!/bin/sh\necho AOIDE_SECRETS_ASK_RESULT:DISMISS\nexit 0\n");
        let result = run_ask_dialog(shim.to_str().unwrap(), "db-prod", "claude", 42, None, None).unwrap();
        assert_eq!(result, AskResult::Dismissed);
        remove_shim(&shim);
    }

    #[test]
    fn run_ask_dialog_returns_cancelled_when_the_shim_never_prints_a_marker() {
        // Stands in for the "quickshell never exits on its own" case
        // (module doc): the shim exits WITHOUT a marker line, closing its
        // stdout pipe -- `spawn_and_wait_for_marker`'s read loop ends and
        // falls back to `Cancelled`, exactly as an Esc/close would.
        let _guard = shim_lock();
        let shim = write_shim("silent", "#!/bin/sh\nexit 0\n");
        let result = run_ask_dialog(shim.to_str().unwrap(), "db-prod", "claude", 42, None, None).unwrap();
        assert_eq!(result, AskResult::Cancelled);
        remove_shim(&shim);
    }

    #[test]
    fn run_ask_dialog_reports_a_spawn_error_for_a_nonexistent_binary() {
        let err = run_ask_dialog("/no/such/aoide-lyra-quickshell-shim", "db-prod", "claude", 42, None, None).unwrap_err();
        assert!(err.contains("spawning quickshell"), "{err}");
        assert!(err.contains("secrets approve"), "the error must teach the CLI fallback: {err}");
    }

    /// `run_ask_dialog`'s own body is: write the QML, spawn+wait for a
    /// marker, then `std::fs::remove_file` UNCONDITIONALLY before
    /// returning — visibly correct by inspection at four lines, and not
    /// worth a `TMPDIR`-mutating end-to-end test to re-prove: an earlier
    /// version of this test scanned the shared system temp dir for
    /// leftovers, which was racy against every OTHER test in this module
    /// also writing/cleaning its OWN `aoide-secrets-ask-*` file under
    /// `cargo test`'s parallel-by-default execution (a mutated `TMPDIR`
    /// affects every thread's `std::env::temp_dir()` call, not only the
    /// thread holding `env_lock`). What IS worth pinning, deterministically
    /// and without touching global state, is the two pieces that actually
    /// compose into that guarantee — proven separately, above and below.
    #[test]
    fn write_temp_qml_creates_a_real_file_and_two_calls_never_collide() {
        let a = write_temp_qml("db-prod", "claude", 42, None, None).unwrap();
        let b = write_temp_qml("db-prod", "claude", 42, None, None).unwrap();
        assert!(a.exists());
        assert!(b.exists());
        assert_ne!(a, b, "two calls must never collide on the same scratch path");
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();
    }

    #[test]
    fn write_temp_qml_is_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = write_temp_qml("db-prod", "claude", 42, None, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the generated QML must be owner-only, got {mode:o}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn spawn_and_wait_for_marker_never_deletes_the_file_it_was_handed() {
        // Cleanup is `run_ask_dialog`'s OWN responsibility (its doc comment)
        // — this pins that the lower-level function it delegates to plays
        // no part in that, on a caller-owned path it neither wrote nor
        // should ever remove.
        let _guard = shim_lock();
        let shim = write_shim("no-delete", "#!/bin/sh\necho AOIDE_SECRETS_ASK_RESULT:CANCEL\nexit 0\n");
        let qml_path = write_temp_qml("db-prod", "claude", 42, None, None).unwrap();
        let result = spawn_and_wait_for_marker(shim.to_str().unwrap(), &qml_path).unwrap();
        assert_eq!(result, AskResult::Cancelled);
        assert!(qml_path.exists(), "spawn_and_wait_for_marker must not delete a path it did not create");
        std::fs::remove_file(&qml_path).unwrap();
        remove_shim(&shim);
    }
}
