//! Shared quickshell code-entry dialog machinery (P-PV3) — the six-boxes-
//! plus-dash digit-entry component `lyra secrets ask` (P3) and `lyra pair
//! ask` (P-PV3) both render, REUSED, never copied (root `AGENTS.md` house
//! rule 7's "a capability enters by existing at a conventional path... never
//! by an edit to an import list"): [`render_code_entry_qml`] takes only a
//! window TITLE, a caller-built header block ([`HeaderLine`] — already-raw,
//! this function escapes it), and a RESULT_MARKER prefix — nothing about
//! either command's own wording lives here, only the entry surface itself
//! (the boxes, the dash, the underlying `TextInput`, the dismiss control,
//! Esc-cancels, auto-submit at six digits). [`run_code_entry_dialog`] is the
//! spawn/wait/parse orchestration both commands share unchanged: write the
//! generated QML to a scratch temp path, spawn `quickshell -p <path>`, read
//! its stdout for the first RESULT_MARKER-prefixed line, kill the child the
//! instant one is found (quickshell never exits on its own — `Qt.quit()`
//! alone does not terminate it, a live probe on Quickshell 0.3.0 found; see
//! the original `lyra secrets ask` incident writeup this module inherited
//! verbatim), and clean up the scratch file regardless of outcome.
//!
//! **This is a pure extraction from `commands::secrets` (P-PV3, task #132),
//! forced by a SECOND consumer** (`commands::pair`'s own `lyra pair ask`) —
//! `lyra secrets ask`'s original P3 doc has the full incident/design
//! history (orphan prevention via `PR_SET_PDEATHSIG`, the Hyprland
//! auto-float min==max size-hint finding, the `console.log`-not-a-file
//! choice) which is NOT restated here; only what changed on the move is:
//! every place that named `secret`/`consumer`/`reason`/`from` directly now
//! takes a generic `header_lines: &[HeaderLine]` the CALLER built, and the
//! generated scratch filename's prefix and the on-screen dismiss-control
//! label are both parameters instead of literals.
//!
//! **Output contract, byte-identical for every caller:** the typed code on
//! stdout with exit 0; the caller's OWN dismiss-button label on stdout with
//! exit 1; a bare Esc/window-close for exit 1 with no stdout;
//! [`EXIT_INFRA_FAILURE`] (exit 3) for a spawn failure or a quickshell that
//! exits without ever printing a recognized marker line — never folded into
//! the bare-cancel case (a killed dialog must never be silently read as a
//! user Cancel — the live incident `lyra secrets ask`'s own original doc
//! tells in full). `aoide_secrets::watch::spawn_lyra_entry` and
//! `aoide_client::pair_watch::spawn_lyra_entry` are the two readers of this
//! contract on the other side of the process boundary — don't change it
//! here without updating both callers' own docs in the same commit.
//!
//! **The QML is paint only** (root `AGENTS.md` house rule 7's "delete every
//! `.qml`" test) — every capability behind this dialog stays reachable with
//! nothing but a shell: `aoide secrets approve <id> --totp <code>` / `aoide
//! peer pair approve <id> --code <code>`, plus each caller's own zenity
//! fallback (`aoide_secrets::watch`'s `--entry`, `aoide_client::pair_watch`'s
//! own).

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The exit code that means "the dialog infrastructure itself failed" —
/// NEVER a user action, never collapsed into a bare cancel. Mirrors
/// `aoide_protocol::dialog::LYRA_INFRA_FAILURE_EXIT` byte for byte; there is
/// no shared Rust type to enforce that agreement (no crate in this
/// workspace may depend on `aoide-lyra` — root `AGENTS.md`'s core/paint
/// boundary), so both constants carry this same comment pointing at the
/// other. `3` sits clear of zenity's own real exit codes (`0`/`1`/a
/// `--timeout`-only range).
pub const EXIT_INFRA_FAILURE: i32 = 3;

pub(crate) const QUICKSHELL_CMD: &str = "quickshell";

/// The four shapes this component's own `console.log` marker line (or its
/// absence) can carry — mirrors `aoide_protocol::dialog::DialogResult` in
/// spirit: "the user closed it," "explicitly dismissed," "typed a full
/// code," and "the dialog infrastructure itself failed" are four different
/// things a caller reacts to differently. `Failed` is returned when
/// quickshell's stdout pipe closes WITHOUT ever printing a recognized
/// marker line (a crash, a QML load error) — never folded into `Cancelled`,
/// which is reserved for an ACTUAL user action (Esc, the window's close
/// button, both of which the QML itself marks with a `CANCEL` line before
/// quickshell exits).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AskResult {
    Approved(String),
    Dismissed,
    Cancelled,
    Failed(String),
}

/// One line of the dialog's header block, styled — the ONLY thing that
/// differs between `lyra secrets ask`'s "release `X` -> Y" wording and
/// `lyra pair ask`'s "pairing request from ..." wording; the six-box entry
/// component below neither knows nor cares which caller built these. Text
/// rides RAW — [`render_code_entry_qml`] is the one place `qml_escape` runs
/// on it, so a caller never double-escapes.
pub(crate) enum HeaderStyle {
    /// The main context line — 16px, bold, full-brightness.
    Bold,
    /// A secondary, self-asserted/best-effort context line (`lyra secrets
    /// ask`'s own "for: ..." reason) — 12px, italic, dimmer.
    Italic,
    /// A tertiary line (an origin/countdown/code-context line) — 11px,
    /// dimmest, no emphasis.
    Muted,
}

pub(crate) struct HeaderLine {
    pub text: String,
    pub style: HeaderStyle,
}

impl HeaderLine {
    pub fn bold(text: impl Into<String>) -> Self {
        Self { text: text.into(), style: HeaderStyle::Bold }
    }
    pub fn italic(text: impl Into<String>) -> Self {
        Self { text: text.into(), style: HeaderStyle::Italic }
    }
    pub fn muted(text: impl Into<String>) -> Self {
        Self { text: text.into(), style: HeaderStyle::Muted }
    }
}

/// Write the generated QML, spawn `quickshell -p <path>`, read its stdout
/// for the first `result_marker`-prefixed line, kill the child the instant
/// one is found, and clean up the scratch file regardless of outcome —
/// `commands::secrets::run_ask_dialog`'s original body, generalized over
/// which command is calling (`file_prefix` names the scratch file,
/// `dismiss_text` is the on-screen control's label, `result_marker` is the
/// caller's own marker prefix).
pub(crate) fn run_code_entry_dialog(
    quickshell_cmd: &str,
    file_prefix: &str,
    window_title: &str,
    header_lines: &[HeaderLine],
    dismiss_text: &str,
    result_marker: &str,
) -> Result<AskResult, String> {
    let qml = render_code_entry_qml(window_title, header_lines, dismiss_text, result_marker);
    let qml_path = write_temp_qml(file_prefix, &qml).map_err(|e| format!("writing the dialog's QML: {e}"))?;
    let result = spawn_and_wait_for_marker(quickshell_cmd, &qml_path, result_marker);
    let _ = std::fs::remove_file(&qml_path);
    result
}

/// The CONFIRM variant (P-PV3 revert, task #132) — same orchestration as
/// [`run_code_entry_dialog`], [`render_code_confirm_qml`] in place of
/// [`render_code_entry_qml`]: no boxes, no `TextInput`, `code` rendered
/// large as plain display text, two actions (a clean Approve, the quiet
/// flat `dismiss_text` control). This is `lyra pair ask`'s ORIGINAL sibling
/// on the outbound (requester) side of the pairing ceremony — that
/// direction generates its own code locally and only needs the operator to
/// confirm they saw it, never to retype a code that arrived from
/// elsewhere (`crates/client/src/pair_watch.rs`'s own module doc has the
/// full reasoning for why the two pairing directions get two different
/// dialog shapes sharing this one visual family).
pub(crate) fn run_code_confirm_dialog(
    quickshell_cmd: &str,
    file_prefix: &str,
    window_title: &str,
    header_lines: &[HeaderLine],
    code: &str,
    dismiss_text: &str,
    result_marker: &str,
) -> Result<AskResult, String> {
    let qml = render_code_confirm_qml(window_title, header_lines, code, dismiss_text, result_marker);
    let qml_path = write_temp_qml(file_prefix, &qml).map_err(|e| format!("writing the dialog's QML: {e}"))?;
    let result = spawn_and_wait_for_marker(quickshell_cmd, &qml_path, result_marker);
    let _ = std::fs::remove_file(&qml_path);
    result
}

/// The scratch directory a generated QML file lands in — `$XDG_RUNTIME_DIR`
/// when set (a per-user, tmpfs-backed, already-`0700` directory systemd
/// provisions on every graphical session), else `std::env::temp_dir()`.
fn scratch_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

fn write_temp_qml(file_prefix: &str, contents: &str) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = scratch_dir().join(format!(
        "{file_prefix}-{}-{}.qml",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
    ));
    // `0600` from creation, then `set_permissions` again (belt-and-
    // suspenders against a permissive umask) — only ever display data (a
    // secret/peer NAME, never a value), but costs nothing to hold to the
    // same standard `aoide_secrets::store::secure_file` does.
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
    file.write_all(contents.as_bytes())?;
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

/// Spawn `quickshell -p <qml_path>` — [`Command::pre_exec`] arms
/// `PR_SET_PDEATHSIG` on the child BEFORE it execs into `quickshell`, so a
/// killed dialog process can never orphan its own window (`lyra secrets
/// ask`'s original P3 doc has the full ownership-chain reasoning, unchanged
/// by this move).
fn spawn_quickshell(quickshell_cmd: &str, qml_path: &std::path::Path) -> std::io::Result<Child> {
    use std::os::unix::process::CommandExt;

    let parent_pid = unsafe { libc::getpid() };

    let mut cmd = Command::new(quickshell_cmd);
    cmd.args(["-p", &qml_path.to_string_lossy()]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());

    // SAFETY: this closure runs in the forked CHILD, strictly between
    // `fork()` and `execve()` — the narrow async-signal-safe window; every
    // call inside is a bare syscall.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                libc::_exit(1);
            }
            Ok(())
        });
    }

    cmd.spawn()
}

fn spawn_and_wait_for_marker(quickshell_cmd: &str, qml_path: &std::path::Path, result_marker: &str) -> Result<AskResult, String> {
    let mut child = spawn_quickshell(quickshell_cmd, qml_path).map_err(|e| {
        format!(
            "spawning quickshell: {e} -- install quickshell, or complete this ask another way (the zenity fallback, \
             or the equivalent CLI command)"
        )
    })?;

    let stdout = child.stdout.take().expect("stdout is always piped by spawn_quickshell");
    let mut found = None;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        if let Some(result) = parse_marker_line(&line, result_marker) {
            found = Some(result);
            break;
        }
    }

    let _ = child.kill();
    let status = child.wait();

    match found {
        Some(result) => Ok(result),
        None => Ok(AskResult::Failed(match status {
            Ok(status) => format!("quickshell exited ({status}) without ever completing the ask -- no result marker was seen on its stdout"),
            Err(e) => format!("quickshell's exit status could not be read after its stdout closed: {e}"),
        })),
    }
}

/// Pure and total: finds `result_marker` as a SUBSTRING rather than
/// requiring it at position 0, since quickshell's own structured logger
/// prefixes every line it prints.
fn parse_marker_line(line: &str, result_marker: &str) -> Option<AskResult> {
    let idx = line.find(result_marker)?;
    let rest = line[idx + result_marker.len()..].trim_end();
    if let Some(code) = rest.strip_prefix("CODE:") {
        Some(AskResult::Approved(code.to_string()))
    } else if rest == "APPROVE" {
        // The confirm variant's own marker (P-PV3 revert, task #132) — no
        // value was ever typed, so `Approved` carries an empty string, the
        // same "irrelevant payload" shape a zenity `--question`'s plain OK
        // produces on stdout.
        Some(AskResult::Approved(String::new()))
    } else if rest == "DISMISS" {
        Some(AskResult::Dismissed)
    } else if rest == "CANCEL" {
        Some(AskResult::Cancelled)
    } else {
        None
    }
}

/// Escape a string for embedding inside a QML double-quoted string literal —
/// every value this function escapes is UNTRUSTED display text (a peer
/// name, an origin address, a self-asserted reason). See the original `lyra
/// secrets ask` doc (P3) for the full character-by-character reasoning
/// (backslash/quote, raw newline/CR being a QML/JS syntax error, U+2028/
/// U+2029 being JS line terminators despite looking printable, the
/// remaining C0 control range) — unchanged by this move.
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

fn header_line_qml(line: &HeaderLine) -> String {
    let (color, size, extra) = match line.style {
        HeaderStyle::Bold => ("#cdd6f4", 16, "; font.bold: true"),
        HeaderStyle::Italic => ("#a6adc8", 12, "; font.italic: true"),
        HeaderStyle::Muted => ("#7f849c", 11, ""),
    };
    format!(
        "            Text {{ anchors.horizontalCenter: parent.horizontalCenter; text: \"{}\"; color: \"{color}\"; font.pixelSize: {size}{extra} }}\n",
        qml_escape(&line.text)
    )
}

/// Render the dialog's QML — six individually-boxed digit inputs
/// (`[X][X][X] - [X][X][X]`) painted OVER a single underlying `TextInput`
/// (`codeInput`), never six separate text fields: the boxes are a pure
/// presentation layer so select-all, arrow-key movement, backspace/delete,
/// clipboard copy/cut/paste, and mouse click/drag-to-select are ALL
/// inherited from the platform `TextInput` for free. `codeInput
/// .onTextChanged` calls `submitIfComplete()` on every keystroke AND every
/// paste; Enter also submits when full; Escape cancels. See `lyra secrets
/// ask`'s original P3 doc for the Hyprland auto-float finding
/// (`minimumWidth`/`maximumWidth`/`minimumHeight`/`maximumHeight` all equal
/// to the window's own `width`/`height` — a fixed-size hint — is what
/// actually triggers the compositor's auto-float heuristic, `flags:
/// Qt.Dialog` alone did not) and the `console.log`-not-a-file choice —
/// unchanged by this move.
pub(crate) fn render_code_entry_qml(window_title: &str, header_lines: &[HeaderLine], dismiss_text: &str, result_marker: &str) -> String {
    let header_block: String = header_lines.iter().map(header_line_qml).collect();

    TEMPLATE
        .replace("__TITLE__", &qml_escape(window_title))
        .replace("__HEADER_BLOCK__\n", &header_block)
        .replace("__DISMISS_TEXT__", &qml_escape(dismiss_text))
        .replace("__RESULT_MARKER__", result_marker)
}

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
    title: "__TITLE__"
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

__HEADER_BLOCK__

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
                text: "__DISMISS_TEXT__"
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

/// Render the CONFIRM variant's QML (P-PV3 revert, task #132) — same
/// visual family as [`render_code_entry_qml`] (title, header lines, fixed-
/// size float hints, the flat dismiss control) but the six-box `TextInput`
/// is replaced by `code` rendered as large plain display text, and two
/// actions: a filled "Approve" rectangle button and the quiet flat
/// `dismiss_text` control underneath. Esc cancels (the Rectangle holds
/// keyboard focus, same "Keys on the one focused item" shape
/// [`render_code_entry_qml`]'s own `codeInput` holds). `code` is UNTRUSTED-
/// ADJACENT in the sense that it is this instance's OWN locally-derived
/// value (never peer-supplied) but still routed through [`qml_escape`] on
/// principle, the same "escape every value this function touches, don't
/// special-case one as trusted" posture `header_line_qml` already holds.
pub(crate) fn render_code_confirm_qml(window_title: &str, header_lines: &[HeaderLine], code: &str, dismiss_text: &str, result_marker: &str) -> String {
    let header_block: String = header_lines.iter().map(header_line_qml).collect();

    CONFIRM_TEMPLATE
        .replace("__TITLE__", &qml_escape(window_title))
        .replace("__HEADER_BLOCK__\n", &header_block)
        .replace("__CODE__", &qml_escape(code))
        .replace("__DISMISS_TEXT__", &qml_escape(dismiss_text))
        .replace("__RESULT_MARKER__", result_marker)
}

const CONFIRM_TEMPLATE: &str = r##"import QtQuick
import QtQuick.Window
import QtQuick.Controls

Window {
    id: win
    width: 400
    height: 220
    minimumWidth: width
    maximumWidth: width
    minimumHeight: height
    maximumHeight: height
    visible: true
    title: "__TITLE__"
    color: "#1e1e2e"
    flags: Qt.Dialog

    function approveAsk() {
        console.log("__RESULT_MARKER__APPROVE");
    }
    function dismissAsk() {
        console.log("__RESULT_MARKER__DISMISS");
    }
    onClosing: console.log("__RESULT_MARKER__CANCEL")
    Component.onCompleted: keyCatcher.forceActiveFocus()

    Rectangle {
        id: keyCatcher
        anchors.fill: parent
        color: "#1e1e2e"
        focus: true
        Keys.onPressed: (event) => {
            if (event.key === Qt.Key_Escape) {
                console.log("__RESULT_MARKER__CANCEL");
                event.accepted = true;
            }
        }

        Column {
            anchors.centerIn: parent
            spacing: 14

__HEADER_BLOCK__

            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: "__CODE__"
                color: "#89b4fa"
                font.pixelSize: 30
                font.bold: true
                font.family: "monospace"
            }

            Rectangle {
                id: approveButton
                anchors.horizontalCenter: parent.horizontalCenter
                width: 110
                height: 38
                radius: 6
                color: approveArea.containsMouse ? "#89b4fa" : "#313244"
                border.width: 1
                border.color: "#89b4fa"
                Text {
                    anchors.centerIn: parent
                    text: "Approve"
                    color: approveArea.containsMouse ? "#1e1e2e" : "#cdd6f4"
                    font.pixelSize: 14
                    font.bold: true
                }
                MouseArea {
                    id: approveArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: approveAsk()
                }
            }

            Text {
                text: "__DISMISS_TEXT__"
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
        assert_eq!(parse_marker_line("MARK:CODE:123456", "MARK:"), Some(AskResult::Approved("123456".to_string())));
    }

    #[test]
    fn parse_marker_line_finds_the_marker_after_a_log_prefix() {
        assert_eq!(parse_marker_line(" DEBUG qml: MARK:CODE:654321", "MARK:"), Some(AskResult::Approved("654321".to_string())));
    }

    #[test]
    fn parse_marker_line_reads_dismiss_and_cancel() {
        assert_eq!(parse_marker_line("MARK:DISMISS", "MARK:"), Some(AskResult::Dismissed));
        assert_eq!(parse_marker_line("MARK:CANCEL", "MARK:"), Some(AskResult::Cancelled));
    }

    #[test]
    fn parse_marker_line_reads_approve_as_an_empty_approved() {
        // The confirm variant's own marker (P-PV3 revert) — no value was
        // ever typed, so this must be `Approved("")`, never a distinct
        // variant the caller has to special-case.
        assert_eq!(parse_marker_line("MARK:APPROVE", "MARK:"), Some(AskResult::Approved(String::new())));
    }

    #[test]
    fn parse_marker_line_is_none_for_an_unrelated_line() {
        assert_eq!(parse_marker_line("INFO: Configuration Loaded", "MARK:"), None);
    }

    #[test]
    fn parse_marker_line_respects_its_own_marker_never_a_different_callers() {
        // Two callers (secrets/pair) share this reader with two DIFFERENT
        // markers — a line carrying one marker must never match a search
        // for the other, or a stray log line from one dialog could be
        // misread as a result from the other.
        assert_eq!(parse_marker_line("AOIDE_SECRETS_ASK_RESULT:CODE:111111", "AOIDE_PAIR_ASK_RESULT:"), None);
    }

    // ── render_code_entry_qml (pure) ─────────────────────────────────────

    #[test]
    fn render_embeds_title_and_every_header_line_with_its_own_style() {
        let qml = render_code_entry_qml(
            "aoide · box-a",
            &[HeaderLine::bold("pairing request from `box-a`"), HeaderLine::italic("for: \"a reason\""), HeaderLine::muted("code: 111-222")],
            "Reject request",
            "MARK:",
        );
        assert!(qml.contains("title: \"aoide · box-a\""));
        assert!(qml.contains("pairing request from `box-a`"));
        assert!(qml.contains("font.bold: true"));
        assert!(qml.contains("for: \\\"a reason\\\""));
        assert!(qml.contains("font.italic: true"));
        assert!(qml.contains("code: 111-222"));
        assert!(qml.contains("\"Reject request\""));
    }

    #[test]
    fn render_omits_nothing_but_the_placeholder_when_header_lines_is_empty() {
        let qml = render_code_entry_qml("t", &[], "Dismiss ask", "MARK:");
        assert!(!qml.contains("__HEADER_BLOCK__"));
        assert!(!qml.contains("__TITLE__"));
        assert!(!qml.contains("__DISMISS_TEXT__"));
        assert!(!qml.contains("__RESULT_MARKER__"));
    }

    #[test]
    fn render_carries_six_boxes_a_dash_and_no_hardcoded_dialog_chrome() {
        let qml = render_code_entry_qml("t", &[HeaderLine::bold("x")], "Dismiss ask", "MARK:");
        assert_eq!(qml.matches("model: 3").count(), 2, "expected two groups of three boxes (six total)");
        assert_eq!(qml.matches("property int boxIndex").count(), 2);
        assert!(qml.contains("boxIndex: index + 3"), "the second group's indices must continue 3..6, not restart at 0");
        assert!(qml.contains("text: \"-\""), "expected the dash separator as its own element");
        assert!(!qml.contains("Button {"), "the dismiss control is a flat text+MouseArea, never a default-styled Button");
    }

    #[test]
    fn render_floats_via_fixed_size_hints_not_only_qt_dialog() {
        let qml = render_code_entry_qml("t", &[HeaderLine::bold("x")], "Dismiss ask", "MARK:");
        assert!(qml.contains("flags: Qt.Dialog"));
        assert!(qml.contains("minimumWidth: width"));
        assert!(qml.contains("maximumWidth: width"));
        assert!(qml.contains("minimumHeight: height"));
        assert!(qml.contains("maximumHeight: height"));
    }

    #[test]
    fn render_uses_the_callers_own_result_marker_and_dismiss_text() {
        let qml = render_code_entry_qml("t", &[HeaderLine::bold("x")], "Reject request", "AOIDE_PAIR_ASK_RESULT:");
        assert!(qml.contains("AOIDE_PAIR_ASK_RESULT:CODE:"));
        assert!(qml.contains("AOIDE_PAIR_ASK_RESULT:DISMISS"));
        assert!(qml.contains("AOIDE_PAIR_ASK_RESULT:CANCEL"));
        assert!(qml.contains("\"Reject request\""));
        assert!(!qml.contains("Dismiss ask"));
    }

    // ── render_code_confirm_qml (pure, P-PV3 revert) ──────────────────────

    #[test]
    fn render_confirm_embeds_title_header_code_and_dismiss_text() {
        let qml = render_code_confirm_qml("aoide · box-b", &[HeaderLine::bold("confirm pairing with `box-b`")], "740-729", "Reject request", "MARK:");
        assert!(qml.contains("title: \"aoide · box-b\""));
        assert!(qml.contains("confirm pairing with `box-b`"));
        assert!(qml.contains("text: \"740-729\""), "the code must render as plain display text: {qml}");
        assert!(qml.contains("\"Reject request\""));
        assert!(qml.contains("\"Approve\""));
    }

    #[test]
    fn render_confirm_carries_no_box_or_text_input_chrome() {
        // The whole point of the revert: no six-box entry surface, no
        // underlying TextInput to type into — a plain Approve button and a
        // dismiss control only.
        let qml = render_code_confirm_qml("t", &[HeaderLine::bold("x")], "111-222", "Dismiss ask", "MARK:");
        assert!(!qml.contains("model: 3"), "confirm must carry no digit-box repeaters: {qml}");
        assert!(!qml.contains("TextInput"), "confirm must carry no typed-entry field: {qml}");
        assert!(!qml.contains("boxIndex"));
    }

    #[test]
    fn render_confirm_uses_the_callers_own_result_marker_and_approve_dismiss_cancel_markers() {
        let qml = render_code_confirm_qml("t", &[HeaderLine::bold("x")], "111-222", "Reject request", "AOIDE_PAIR_ASK_RESULT:");
        assert!(qml.contains("AOIDE_PAIR_ASK_RESULT:APPROVE"));
        assert!(qml.contains("AOIDE_PAIR_ASK_RESULT:DISMISS"));
        assert!(qml.contains("AOIDE_PAIR_ASK_RESULT:CANCEL"));
    }

    #[test]
    fn render_confirm_floats_via_fixed_size_hints_and_escapes_a_hostile_code() {
        let hostile = "111\"; Qt.quit(); //\u{2028}222";
        let qml = render_code_confirm_qml("t", &[HeaderLine::bold("x")], hostile, "Dismiss ask", "MARK:");
        assert!(qml.contains("flags: Qt.Dialog"));
        assert!(qml.contains("minimumWidth: width"));
        assert!(qml.contains(&qml_escape(hostile)), "the code must be escaped, never embedded raw: {qml}");
    }

    #[test]
    fn qml_escape_neutralizes_every_dangerous_character() {
        let hostile = "back\\slash quote\" nl\n cr\r tab\t ls\u{2028} ps\u{2029} null\u{0000} esc\u{001b}";
        let escaped = qml_escape(hostile);
        assert!(!escaped.chars().any(|c| c.is_control()), "no raw control character may survive escaping: {escaped:?}");

        let chars: Vec<char> = escaped.chars().collect();
        let mut i = 0;
        let mut out = String::new();
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
        assert!(!out.contains('"'), "an unescaped quote survived: {escaped:?}");
        assert!(!out.contains('\\'), "an unescaped backslash survived: {escaped:?}");
    }

    #[test]
    fn qml_escape_is_the_identity_on_ordinary_text() {
        assert_eq!(qml_escape("sudo nixos-rebuild switch"), "sudo nixos-rebuild switch");
        assert_eq!(qml_escape("khoa · bash (pid 123) @ yomi-strix"), "khoa · bash (pid 123) @ yomi-strix");
    }

    #[test]
    fn render_embeds_a_hostile_header_line_safely_escaped_on_one_physical_line() {
        let hostile = "normal\n\"]; Qt.quit(); //\u{2028}end\"";
        let qml = render_code_entry_qml("t", &[HeaderLine::bold(hostile)], "Dismiss ask", "MARK:");
        let escaped = qml_escape(hostile);
        let line = qml.lines().find(|l| l.contains(&escaped)).expect("the header line must exist as ONE physical line");
        assert!(line.trim_end().ends_with('}'), "the header's Text {{}} block must close on the same physical line: {line:?}");
        assert_eq!(qml.matches("model: 3").count(), 2);
    }

    // ── run_code_entry_dialog / the output contract, via a fake quickshell
    // shim — same pattern `aoide_secrets::watch`'s own zenity/lyra tests use.

    fn write_shim(tag: &str, script: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-lyra-dialog-qml-shim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("quickshell-shim");
        std::fs::write(&shim, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Serialized against every other shim test below by `shim_lock` — a
        // just-written-then-immediately-exec'd shim under heavy parallel
        // `--test-threads` contention hits a genuine `execve()`/`close()`
        // TOCTOU on this kernel (`aoide_secrets::watch`'s own `shim_lock`
        // doc has the full diagnosis); this is that same fix.
        std::thread::sleep(std::time::Duration::from_millis(5));
        shim
    }

    fn remove_shim(shim: &std::path::Path) {
        if let Some(dir) = shim.parent() {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    fn shim_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn run_code_entry_dialog_returns_approved_when_the_shim_prints_a_code() {
        let _guard = shim_lock();
        let shim = write_shim("approve", "#!/bin/sh\necho MARK:CODE:246810\nexit 0\n");
        let result = run_code_entry_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-test", "t", &[HeaderLine::bold("x")], "Dismiss ask", "MARK:").unwrap();
        assert_eq!(result, AskResult::Approved("246810".to_string()));
        remove_shim(&shim);
    }

    #[test]
    fn run_code_entry_dialog_returns_dismissed_when_the_shim_prints_dismiss() {
        let _guard = shim_lock();
        let shim = write_shim("dismiss", "#!/bin/sh\necho MARK:DISMISS\nexit 0\n");
        let result = run_code_entry_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-test", "t", &[HeaderLine::bold("x")], "Dismiss ask", "MARK:").unwrap();
        assert_eq!(result, AskResult::Dismissed);
        remove_shim(&shim);
    }

    #[test]
    fn run_code_entry_dialog_returns_failed_when_the_shim_never_prints_a_marker() {
        let _guard = shim_lock();
        let shim = write_shim("silent", "#!/bin/sh\nexit 0\n");
        let result = run_code_entry_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-test", "t", &[HeaderLine::bold("x")], "Dismiss ask", "MARK:").unwrap();
        assert!(matches!(result, AskResult::Failed(_)), "expected Failed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_code_entry_dialog_genuine_cancel_via_the_cancel_marker_is_still_cancelled_not_failed() {
        let _guard = shim_lock();
        let shim = write_shim("real-cancel", "#!/bin/sh\necho MARK:CANCEL\nexit 0\n");
        let result = run_code_entry_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-test", "t", &[HeaderLine::bold("x")], "Dismiss ask", "MARK:").unwrap();
        assert_eq!(result, AskResult::Cancelled);
        remove_shim(&shim);
    }

    #[test]
    fn run_code_entry_dialog_reports_a_spawn_error_for_a_nonexistent_binary() {
        let err = run_code_entry_dialog("/no/such/aoide-lyra-quickshell-shim", "aoide-dialog-qml-test", "t", &[], "Dismiss ask", "MARK:").unwrap_err();
        assert!(err.contains("spawning quickshell"), "{err}");
    }

    // ── run_code_confirm_dialog / the output contract (P-PV3 revert) ──────

    #[test]
    fn run_code_confirm_dialog_returns_approved_with_no_typed_value_when_the_shim_approves() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-approve", "#!/bin/sh\necho MARK:APPROVE\nexit 0\n");
        let result = run_code_confirm_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-confirm-test", "t", &[HeaderLine::bold("x")], "111-222", "Dismiss ask", "MARK:").unwrap();
        assert_eq!(result, AskResult::Approved(String::new()));
        remove_shim(&shim);
    }

    #[test]
    fn run_code_confirm_dialog_returns_dismissed_when_the_shim_prints_dismiss() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-dismiss", "#!/bin/sh\necho MARK:DISMISS\nexit 0\n");
        let result = run_code_confirm_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-confirm-test", "t", &[HeaderLine::bold("x")], "111-222", "Dismiss ask", "MARK:").unwrap();
        assert_eq!(result, AskResult::Dismissed);
        remove_shim(&shim);
    }

    #[test]
    fn run_code_confirm_dialog_returns_cancelled_when_the_shim_prints_cancel() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-cancel", "#!/bin/sh\necho MARK:CANCEL\nexit 0\n");
        let result = run_code_confirm_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-confirm-test", "t", &[HeaderLine::bold("x")], "111-222", "Dismiss ask", "MARK:").unwrap();
        assert_eq!(result, AskResult::Cancelled);
        remove_shim(&shim);
    }

    #[test]
    fn run_code_confirm_dialog_returns_failed_when_the_shim_never_prints_a_marker() {
        let _guard = shim_lock();
        let shim = write_shim("confirm-silent", "#!/bin/sh\nexit 0\n");
        let result = run_code_confirm_dialog(shim.to_str().unwrap(), "aoide-dialog-qml-confirm-test", "t", &[HeaderLine::bold("x")], "111-222", "Dismiss ask", "MARK:").unwrap();
        assert!(matches!(result, AskResult::Failed(_)), "expected Failed, got {result:?}");
        remove_shim(&shim);
    }

    #[test]
    fn run_code_confirm_dialog_reports_a_spawn_error_for_a_nonexistent_binary() {
        let err =
            run_code_confirm_dialog("/no/such/aoide-lyra-quickshell-confirm-shim", "aoide-dialog-qml-confirm-test", "t", &[], "111-222", "Dismiss ask", "MARK:")
                .unwrap_err();
        assert!(err.contains("spawning quickshell"), "{err}");
    }

    #[test]
    fn write_temp_qml_creates_a_real_file_and_two_calls_never_collide() {
        let a = write_temp_qml("aoide-dialog-qml-test", "content-a").unwrap();
        let b = write_temp_qml("aoide-dialog-qml-test", "content-b").unwrap();
        assert!(a.exists());
        assert!(b.exists());
        assert_ne!(a, b, "two calls must never collide on the same scratch path");
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();
    }

    #[test]
    fn write_temp_qml_is_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = write_temp_qml("aoide-dialog-qml-test", "content").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the generated QML must be owner-only, got {mode:o}");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn spawn_and_wait_for_marker_never_deletes_the_file_it_was_handed() {
        let _guard = shim_lock();
        let shim = write_shim("no-delete", "#!/bin/sh\necho MARK:CANCEL\nexit 0\n");
        let qml_path = write_temp_qml("aoide-dialog-qml-test", "content").unwrap();
        let result = spawn_and_wait_for_marker(shim.to_str().unwrap(), &qml_path, "MARK:").unwrap();
        assert_eq!(result, AskResult::Cancelled);
        assert!(qml_path.exists(), "spawn_and_wait_for_marker must not delete a path it did not create");
        std::fs::remove_file(&qml_path).unwrap();
        remove_shim(&shim);
    }
}
