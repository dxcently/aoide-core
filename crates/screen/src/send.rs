//! `aoide screen send <capture> --session <id>` — hand a `screen shot`
//! capture (with its comment + OCR text) to another session. THE PAYOFF of
//! the `screen` command family: capture → ocr → SEND.
//!
//! This is deliberately a THIN composer + router over an ALREADY-GATED
//! door, never a second injection path: it composes the message, then calls
//! [`aoide_conduct::graph::session_send`] DIRECTLY (a same-process function
//! call via a synthesized [`Invocation`] — never a subprocess shell-out to
//! `aoide send`). That function is `aoide send`'s own handler:
//! HELD pending approval by default, `--yes` (or autogate) delivers, every
//! outcome audited. `screen send` inherits ALL of that for free — no second
//! gate exists anywhere in this file.
//!
//! ── A2A attachment: DEFERRED ─────────────────────────────────────────────
//! Real binary attachment (A2A `FilePart`) is NOT built here — see the
//! `aoide-a2a-workstream` design note. The capture's absolute path rides
//! inside the composed message as plain TEXT; a same-machine receiving
//! agent opens the file directly. Cross-host binary transfer is deferred.

use super::capture::Sidecar;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── Pure: message composition (the exhaustively-tested core) ───────────────

/// Resolve the EFFECTIVE comment for a send: an explicit operator `--comment`
/// always wins over the sidecar's own stored comment; a blank string on
/// either side counts as absent (never emits an empty `comment:` line).
/// Neither present → `None`, and [`compose_message`] omits the line entirely.
fn effective_comment(operator: Option<&str>, sidecar: Option<&str>) -> Option<String> {
    operator
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| sidecar.map(str::trim).filter(|s| !s.is_empty()))
        .map(str::to_string)
}

/// Build the message body a receiving agent parses: the absolute capture
/// path ALWAYS present (the one thing every send carries — the local
/// attachment a same-machine agent opens directly), then an optional
/// `comment:` line, then optional OCR text as its own labelled block (so a
/// receiving agent gets the words on-screen without re-OCRing the same
/// capture). Pure — exhaustively unit-tested over all four presence
/// combinations, `song::ipc`'s "the pure core gets the exhaustive tests"
/// convention.
pub fn compose_message(path: &str, comment: Option<&str>, ocr_text: Option<&str>) -> String {
    let mut lines = vec![format!("screenshot: {path}")];
    if let Some(c) = comment.map(str::trim).filter(|s| !s.is_empty()) {
        lines.push(format!("comment: {c}"));
    }
    if let Some(t) = ocr_text.map(str::trim).filter(|s| !s.is_empty()) {
        lines.push(format!("ocr text:\n{t}"));
    }
    lines.join("\n")
}

// ── Sidecar read: best-effort enrichment, never blocks the send ────────────

/// What reading `<capture>.json` produced. The image is the payload; the
/// sidecar is only ever enrichment — `Missing`/`Corrupt` degrade the send to
/// a bare path (still delivered) rather than failing it, distinct from
/// `screen ocr`'s own stance (there the sidecar's `origin`/`scale` are
/// load-bearing for the coordinate transform, so it hard-errors instead).
#[derive(Debug, Clone, PartialEq)]
enum SidecarRead {
    Ok {
        comment: Option<String>,
        ocr_text: Option<String>,
    },
    Missing,
    Corrupt,
}

impl SidecarRead {
    /// The `data.sidecarStatus` tag — a distinct, machine-checkable reason
    /// code for each of the three cases, even though only `Corrupt`/`Missing`
    /// are in any sense "wrong" (neither blocks delivery).
    fn tag(&self) -> &'static str {
        match self {
            SidecarRead::Ok { .. } => "ok",
            SidecarRead::Missing => "missing",
            SidecarRead::Corrupt => "corrupt",
        }
    }
}

/// Extract the OCR block's `text` field straight from the sidecar's
/// `ocr: Option<Value>` (phase 3's `{ text, words }` shape). Never fails —
/// `None` for "no OCR run yet" and for a shape that doesn't match (a
/// hand-edited sidecar), alike; `screen send` only ever wants the plain text.
fn ocr_text_of(ocr: &Option<Value>) -> Option<String> {
    ocr.as_ref()
        .and_then(|v| v.get("text"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

/// Read `<capture>.json` (same `dest.with_extension("json")` convention
/// `screen shot`/`screen ocr` both use) and pull the two enrichment fields.
fn read_sidecar(capture: &Path) -> SidecarRead {
    let sidecar_path = capture.with_extension("json");
    let text = match std::fs::read_to_string(&sidecar_path) {
        Ok(t) => t,
        Err(_) => return SidecarRead::Missing,
    };
    match serde_json::from_str::<Sidecar>(&text) {
        Ok(sc) => SidecarRead::Ok {
            comment: sc.comment,
            ocr_text: ocr_text_of(&sc.ocr),
        },
        Err(_) => SidecarRead::Corrupt,
    }
}

// ── Routing: compose, then hand off to the ONE gate that applies ───────────

/// The pieces of `send()`'s own state neither router needs to re-derive —
/// threaded through as one reference instead of four loose parameters
/// (keeps `send_to_session`/`wrap` under clippy's too-many-arguments
/// threshold without losing any of the fields).
struct SendCtx<'a> {
    cmd: &'a str,
    path: &'a Path,
    sidecar_status: &'static str,
}

/// Wrap an inner [`Outcome`] (from [`aoide_conduct::graph::session_send`])
/// into `screen.send`'s own envelope. The inner `status`/`message`/`changed`
/// ride through UNCHANGED — a failed delivery is never silently reported as
/// ok — `data` is relabelled with what a `screen send` caller actually
/// wants (target/composed message/delivery state/sidecar-enrichment
/// status), and the entire inner payload nests at `data.inner` so nothing
/// the underlying door reported (a session's `title`/`gate`) is ever lost.
fn wrap(ctx: &SendCtx, kind: &'static str, target: &str, message: &str, state: &'static str, inner: Outcome) -> Outcome {
    Outcome::new(ctx.cmd, inner.status, inner.message.clone())
        .changed(inner.changed.clone())
        .with_data(json!({
            "target": { "kind": kind, "id": target },
            "message": message,
            "state": state,
            "sidecarStatus": ctx.sidecar_status,
            "path": ctx.path.to_string_lossy(),
            "inner": inner.data,
        }))
}

/// Route `--session <id>`: synthesize the EXACT `Invocation` `aoide graph
/// send --id <id> --submit [--yes] -- <message>` would parse into, and call
/// [`aoide_conduct::graph::session_send`] directly. `submit: true` is FIXED, not a
/// flag on `screen send` — a handed-off capture is a complete message meant
/// to be acted on the instant it's approved (like pressing Enter after
/// pasting text to a colleague), not partial text left sitting in the
/// target's prompt. `aoide send` itself keeps the raw `--submit` knob
/// for anyone who needs that choice; `screen send` doesn't add a second one
/// (YAGNI).
fn send_to_session(inv: &Invocation, ctx: &SendCtx, id: &str, message: &str, yes: bool, audit_log: Option<&str>) -> Outcome {
    let mut flags = BTreeMap::new();
    flags.insert("id".to_string(), id.to_string());
    flags.insert("submit".to_string(), "true".to_string());
    if yes {
        flags.insert("yes".to_string(), "true".to_string());
    }
    if let Some(log) = audit_log {
        flags.insert("audit-log".to_string(), log.to_string());
    }
    let sub_inv = Invocation {
        path: vec!["send".to_string()],
        args: vec![message.to_string()],
        flags,
        door: inv.door,
    };
    let inner = aoide_conduct::graph::session_send(&sub_inv);
    let state: &'static str = if inner.status != Status::Ok {
        "error"
    } else {
        match inner.data.as_ref().and_then(|d| d.get("state")).and_then(Value::as_str) {
            Some("pending") => "held",
            Some("delivered") => "delivered",
            _ => "unknown",
        }
    };
    wrap(ctx, "session", id, message, state, inner)
}

// ── `aoide screen send` ─────────────────────────────────────────────────

/// `aoide screen send <capture> --session <id> [--comment "text"] [--yes]
/// [--json]` — see the module header for the full design.
pub fn send(inv: &Invocation) -> Outcome {
    let cmd = "screen.send";
    let usage = |msg: &str| {
        Outcome::usage(
            cmd,
            format!(
                "{msg} — usage: aoide {} <capture> --session <id> [--comment \"text\"] [--yes] [--json]",
                inv.path.join(" ")
            ),
        )
    };

    let Some(capture_arg) = inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return usage("a capture path is required");
    };
    let capture_path = PathBuf::from(capture_arg);

    let session_id = inv.flags.get("session").cloned().unwrap_or_default();
    if session_id.is_empty() {
        return usage("--session <id> is required");
    }

    if !capture_path.is_file() {
        return Outcome::error(cmd, format!("no such capture file: {}", capture_path.display()))
            .with_data(json!({ "reason": "capture-not-found" }));
    }
    // Absolute — a receiving agent (a different cwd, possibly a different
    // conducted terminal entirely) must be able to open the path literally
    // as written, not relative to THIS process's cwd.
    let abs_path = std::fs::canonicalize(&capture_path).unwrap_or_else(|_| capture_path.clone());

    let sidecar = read_sidecar(&capture_path);
    let (sidecar_comment, ocr_text) = match &sidecar {
        SidecarRead::Ok { comment, ocr_text } => (comment.as_deref(), ocr_text.as_deref()),
        SidecarRead::Missing | SidecarRead::Corrupt => (None, None),
    };
    let operator_comment = inv.flags.get("comment").cloned();
    let comment = effective_comment(operator_comment.as_deref(), sidecar_comment);
    let message = compose_message(&abs_path.to_string_lossy(), comment.as_deref(), ocr_text);

    let yes = inv.flag_present("yes");
    let audit_log = inv.flags.get("audit-log").cloned();

    let ctx = SendCtx { cmd, path: &abs_path, sidecar_status: sidecar.tag() };
    send_to_session(inv, &ctx, &session_id, &message, yes, audit_log.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::Door;

    fn test_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["screen".to_string(), "send".to_string()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: Door::Cli,
        }
    }

    // ── compose_message: all four presence combinations, exhaustively ───

    #[test]
    fn compose_neither_comment_nor_ocr_is_just_the_path() {
        assert_eq!(compose_message("/tmp/shot.png", None, None), "screenshot: /tmp/shot.png");
    }

    #[test]
    fn compose_comment_only() {
        assert_eq!(
            compose_message("/tmp/shot.png", Some("look at this"), None),
            "screenshot: /tmp/shot.png\ncomment: look at this"
        );
    }

    #[test]
    fn compose_ocr_only() {
        assert_eq!(
            compose_message("/tmp/shot.png", None, Some("Save\nCancel")),
            "screenshot: /tmp/shot.png\nocr text:\nSave\nCancel"
        );
    }

    #[test]
    fn compose_comment_and_ocr_both() {
        assert_eq!(
            compose_message("/tmp/shot.png", Some("weird dialog"), Some("Save\nCancel")),
            "screenshot: /tmp/shot.png\ncomment: weird dialog\nocr text:\nSave\nCancel"
        );
    }

    #[test]
    fn compose_blank_comment_and_blank_ocr_are_treated_as_absent() {
        // Whitespace-only strings must not emit an empty labelled line.
        assert_eq!(compose_message("/tmp/shot.png", Some("   "), Some("\n\t")), "screenshot: /tmp/shot.png");
    }

    // ── effective_comment: the operator-overrides-sidecar fallback ──────

    #[test]
    fn effective_comment_operator_wins_when_both_present() {
        assert_eq!(effective_comment(Some("override"), Some("stored")), Some("override".to_string()));
    }

    #[test]
    fn effective_comment_falls_back_to_sidecar_when_operator_absent() {
        assert_eq!(effective_comment(None, Some("stored")), Some("stored".to_string()));
    }

    #[test]
    fn effective_comment_operator_blank_falls_back_to_sidecar() {
        assert_eq!(effective_comment(Some("  "), Some("stored")), Some("stored".to_string()));
    }

    #[test]
    fn effective_comment_neither_present_is_none() {
        assert_eq!(effective_comment(None, None), None);
        assert_eq!(effective_comment(Some(""), Some("")), None);
    }

    // ── read_sidecar: ok / missing / corrupt, real temp files ───────────

    fn tmp_capture(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aoide-screen-send-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        p.set_extension("png");
        p
    }

    #[test]
    fn read_sidecar_pulls_comment_and_ocr_text_from_a_real_sidecar() {
        let capture = tmp_capture("ok");
        std::fs::write(&capture, b"fake").unwrap();
        let sidecar_path = capture.with_extension("json");
        std::fs::write(
            &sidecar_path,
            r#"{"schemaVersion":"0","capturedAt":"2026-08-16T00:00:00Z",
               "origin":{"x":0,"y":0},"size":{"w":1,"h":1},"scale":1.0,
               "format":"png","quality":80,"comment":"hi",
               "ocr":{"text":"Save\nCancel","words":[]}}"#,
        )
        .unwrap();

        let got = read_sidecar(&capture);
        assert_eq!(got.tag(), "ok");
        assert_eq!(got, SidecarRead::Ok { comment: Some("hi".to_string()), ocr_text: Some("Save\nCancel".to_string()) });

        let _ = std::fs::remove_file(&capture);
        let _ = std::fs::remove_file(&sidecar_path);
    }

    #[test]
    fn read_sidecar_missing_degrades_to_missing_not_a_panic() {
        let capture = tmp_capture("missing");
        std::fs::write(&capture, b"fake").unwrap();
        // Deliberately no sidecar written next to it.
        assert_eq!(read_sidecar(&capture), SidecarRead::Missing);
        let _ = std::fs::remove_file(&capture);
    }

    #[test]
    fn read_sidecar_corrupt_json_degrades_to_corrupt_not_a_panic() {
        let capture = tmp_capture("corrupt");
        std::fs::write(&capture, b"fake").unwrap();
        let sidecar_path = capture.with_extension("json");
        std::fs::write(&sidecar_path, b"{ this is not valid json").unwrap();

        assert_eq!(read_sidecar(&capture), SidecarRead::Corrupt);

        let _ = std::fs::remove_file(&capture);
        let _ = std::fs::remove_file(&sidecar_path);
    }

    #[test]
    fn read_sidecar_ok_with_no_comment_and_no_ocr_yet() {
        let capture = tmp_capture("bare");
        std::fs::write(&capture, b"fake").unwrap();
        let sidecar_path = capture.with_extension("json");
        std::fs::write(
            &sidecar_path,
            r#"{"schemaVersion":"0","capturedAt":"2026-08-16T00:00:00Z",
               "origin":{"x":0,"y":0},"size":{"w":1,"h":1},"scale":1.0,
               "format":"png","quality":80}"#,
        )
        .unwrap();

        assert_eq!(read_sidecar(&capture), SidecarRead::Ok { comment: None, ocr_text: None });

        let _ = std::fs::remove_file(&capture);
        let _ = std::fs::remove_file(&sidecar_path);
    }

    // ── send(): usage / mutual exclusion / capture-not-found ────────────

    #[test]
    fn send_with_no_capture_arg_is_a_usage_error() {
        let out = send(&test_invocation(&[], &[("session", "s1")]));
        assert_eq!(out.status, Status::Usage);
    }

    #[test]
    fn send_with_no_session_flag_is_a_usage_error() {
        let out = send(&test_invocation(&["/tmp/whatever.png"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("--session"), "{}", out.message);
    }

    #[test]
    fn send_with_an_empty_session_value_is_a_usage_error() {
        let out = send(&test_invocation(&["/tmp/whatever.png"], &[("session", "")]));
        assert_eq!(out.status, Status::Usage);
    }

    #[test]
    fn send_with_a_missing_capture_file_is_a_clean_error_not_a_panic() {
        let out = send(&test_invocation(&["/nonexistent/path/shot.png"], &[("session", "s1")]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "capture-not-found");
    }

    // ── send(): the safety-critical gate proof — --session WITHOUT --yes
    // is held pending, and genuinely delivers NOTHING. Synthetic
    // UnixListener fixture only, exactly `graph::send`'s own precedent —
    // never against a real live agent session (HARD RULE 7).

    fn write_conductable_session(id: &str, socket: &Path) {
        let mut file = aoide_conduct::graph::SessionsFile::default();
        file.sessions.push(aoide_conduct::graph::SessionRecord {
            session_id: id.to_string(),
            conductable: Some(true),
            socket: Some(socket.to_string_lossy().into_owned()),
            ..Default::default()
        });
        aoide_conduct::graph::write_stage(&aoide_conduct::graph::sessions_path(), &file).unwrap();
    }

    #[test]
    fn session_target_without_yes_is_held_pending_and_delivers_nothing() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = aoide_test_support::EnvSaver::capture(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);

        let root = aoide_test_support::unique_tmp("screen-send-held");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        let id = "target-session";
        let socket_path = root.join("target.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        write_conductable_session(id, &socket_path);

        let capture = root.join("shot.png");
        std::fs::write(&capture, b"fake").unwrap();
        std::fs::write(
            capture.with_extension("json"),
            r#"{"schemaVersion":"0","capturedAt":"2026-08-16T00:00:00Z",
               "origin":{"x":0,"y":0},"size":{"w":1,"h":1},"scale":1.0,
               "format":"png","quality":80,"comment":"a weird popup",
               "ocr":{"text":"Save\nCancel","words":[]}}"#,
        )
        .unwrap();

        let out = send(&test_invocation(&[capture.to_str().unwrap()], &[("session", id)]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["state"], "held");
        assert_eq!(data["target"]["kind"], "session");
        assert_eq!(data["target"]["id"], id);
        assert_eq!(data["sidecarStatus"], "ok");
        let msg = data["message"].as_str().unwrap();
        assert!(msg.contains("a weird popup"), "{msg}");
        assert!(msg.contains("Save\nCancel"), "{msg}");
        assert_eq!(data["inner"]["delivered"], false);

        // Genuinely held: nothing connected to the listener.
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a held send must deliver nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn session_target_with_yes_delivers_through_the_gate_in_a_synthetic_fixture() {
        // Same synthetic-listener technique as the held test above and as
        // `graph::send`'s own `send_yes_delivers_and_autorenames_the_title`
        // — a local test fixture, NEVER a real live agent session.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = aoide_test_support::EnvSaver::capture(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_SESSION_ID",
        ]);
        // No sender attribution in scope here — a real ambient AOIDE_SESSION_ID
        // (P6 provenance, `graph/send.rs::resolve_sender`) would otherwise
        // prefix the delivered bytes and break the plain `starts_with`
        // assertion below.
        std::env::remove_var("AOIDE_SESSION_ID");

        let root = aoide_test_support::unique_tmp("screen-send-yes");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        let id = "target-session-2";
        let socket_path = root.join("target2.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        write_conductable_session(id, &socket_path);

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let capture = root.join("shot.png");
        std::fs::write(&capture, b"fake").unwrap();
        // No sidecar at all this time — proves --yes delivery still works
        // when enrichment degrades to Missing (just the bare path).

        let out = send(&test_invocation(&[capture.to_str().unwrap()], &[("session", id), ("yes", "true")]));
        let got = acc.join().unwrap();

        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["state"], "delivered");
        assert_eq!(data["sidecarStatus"], "missing");
        let delivered_text = String::from_utf8(got).unwrap();
        // submit:true appended the target's CR submit byte; the path is absolute.
        assert!(delivered_text.starts_with("screenshot: "), "{delivered_text}");
        assert!(delivered_text.ends_with('\r'), "{delivered_text:?}");

        let _ = std::fs::remove_dir_all(&root);
    }
}
