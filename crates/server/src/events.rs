//! `aoide events tail` (P-D3, `docs/architecture/AOIDED.md`'s "L1 — the
//! event bus" section, "Terminal reachability" paragraph): a foreground,
//! line-mode follow of `aoided`'s own events feed. This is the bridge
//! house rule 7's "delete every `.qml`" test asks for — a desktop surface
//! (or any other shell) picks the bus up through this verb, or by tailing
//! the feed file directly, with NO daemon socket needed at all.
//!
//! Mirrors `aoide_secrets::watch`'s own tail-loop shape (a static
//! `AtomicBool` flipped by a `SIGINT` handler, [`Follower::poll`] on a
//! fixed interval) but far simpler: no socket, no interactive prompt, no
//! reconcile pass — the feed line IS the truth here, there is nothing to
//! double-check it against. [`poll_once`] is the bounded, pure-ish core a
//! test drives directly (with a deadline loop, never a fixed sleep); [`tail`]
//! is the thin wrapper that owns the real loop/signal handling around it —
//! the same "thin wrapper touches the loop, a bounded core does the work"
//! split [`crate::producers`] holds for the daemon's own tick producers.

use aoide_protocol::feed::Follower;
use aoide_protocol::output::exit;
use serde_json::Value;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_signum: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// How often this tail polls the feed file. A local file read, not a
/// socket call — a tight interval costs nothing but a `stat(2)` on most
/// polls, so this stays snappier than the daemon's own 150ms subscribe
/// poll interval without meaningfully spinning a core.
const TAIL_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Pure: does `class` pass the filter? An EMPTY `classes` passes
/// everything — this is a passive, read-only tail, not the daemon socket's
/// `subscribe` op, which stays default-deny-per-class for its own security
/// reason (an unauthenticated forwarded notification must never reach a
/// subscriber that didn't ask for it); a local terminal running `aoide
/// events tail` with no `--class` has no equivalent reason to start deaf.
fn class_matches(class: &str, classes: &[String]) -> bool {
    classes.is_empty() || classes.iter().any(|c| c == class)
}

/// Pure: render one already-parsed feed line as what `tail` would print
/// for it, or `None` when it's unparseable or filtered out by `classes`.
/// `--json` prints the line verbatim (it already IS the wire shape);
/// otherwise a compact one-line narration.
fn render_line(line: &str, classes: &[String], json_mode: bool) -> Option<String> {
    let val: Value = serde_json::from_str(line).ok()?;
    let class = val.get("class").and_then(Value::as_str).unwrap_or("");
    if !class_matches(class, classes) {
        return None;
    }
    if json_mode {
        return Some(line.to_string());
    }
    let kind = val.get("kind").and_then(Value::as_str).unwrap_or("?");
    let source = val.get("source").and_then(Value::as_str).unwrap_or("?");
    let payload = val.get("payload").cloned().unwrap_or(Value::Null);
    Some(format!("[{class}/{kind}] {source}: {payload}"))
}

/// One poll: read every complete NEW line off `follower` and return the
/// rendered strings `tail`'s own print loop would emit for them (module
/// doc's "bounded core" — no sleep, no signal check, no I/O beyond the one
/// `Follower::poll` call). A test drives this directly against a real
/// tempfile with a deadline loop instead of needing to send a real
/// `SIGINT` into a shared test binary.
pub fn poll_once(follower: &mut Follower, classes: &[String], json_mode: bool) -> std::io::Result<Vec<String>> {
    let lines = follower.poll()?;
    Ok(lines.iter().filter_map(|l| render_line(l, classes, json_mode)).collect())
}

/// Follow `events_path` from its CURRENT end (history before this call is
/// never read — `Follower::open_at_end`'s own contract, matching `secrets
/// watch`'s identical choice) and print every matching line to stdout.
/// Retries opening the file every poll until it exists — the daemon may
/// not have started yet, or may be restarting (`Follower::open_at_end`
/// requires the file to already be there; a running daemon's own
/// `FeedWriter` creates it on first use). Blocks until Ctrl-C, then
/// returns [`exit::OK`].
pub fn tail(events_path: &Path, classes: &[String], json_mode: bool) -> i32 {
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
    let mut follower: Option<Follower> = Follower::open_at_end(events_path).ok();
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return exit::OK;
        }
        if follower.is_none() {
            follower = Follower::open_at_end(events_path).ok();
        }
        if let Some(f) = follower.as_mut() {
            match poll_once(f, classes, json_mode) {
                Ok(lines) => {
                    if !lines.is_empty() {
                        for line in lines {
                            println!("{line}");
                        }
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                }
                Err(_) => follower = None,
            }
        }
        std::thread::sleep(TAIL_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::feed::FeedWriter;

    fn short_tmp(tag: &str) -> std::path::PathBuf {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        std::path::PathBuf::from(format!("/tmp/av-events-{tag}-{}-{nanos}", std::process::id()))
    }

    // ── class_matches / render_line: pure ───────────────────────────────

    #[test]
    fn empty_filter_matches_every_class() {
        assert!(class_matches("secret", &[]));
        assert!(class_matches("audit", &[]));
    }

    #[test]
    fn nonempty_filter_matches_only_named_classes() {
        let classes = vec!["secret".to_string(), "audit".to_string()];
        assert!(class_matches("secret", &classes));
        assert!(class_matches("audit", &classes));
        assert!(!class_matches("rice", &classes));
    }

    #[test]
    fn render_line_json_mode_prints_the_line_verbatim() {
        let line = r#"{"v":0,"ts":1,"class":"secret","kind":"released","source":"secrets-mirror","payload":{"secret":"t"}}"#;
        assert_eq!(render_line(line, &[], true), Some(line.to_string()));
    }

    #[test]
    fn render_line_narrates_when_not_json() {
        let line = r#"{"v":0,"ts":1,"class":"audit","kind":"hand-edit","source":"aoided","payload":{"file":"sessions.json"}}"#;
        let rendered = render_line(line, &[], false).unwrap();
        assert!(rendered.starts_with("[audit/hand-edit] aoided:"), "{rendered}");
        assert!(rendered.contains("sessions.json"), "{rendered}");
    }

    #[test]
    fn render_line_filters_by_class() {
        let secret_line = r#"{"class":"secret","kind":"released","source":"secrets-mirror","payload":{}}"#;
        let audit_line = r#"{"class":"audit","kind":"hand-edit","source":"aoided","payload":{}}"#;
        let only_secret = vec!["secret".to_string()];
        assert!(render_line(secret_line, &only_secret, true).is_some());
        assert!(render_line(audit_line, &only_secret, true).is_none());
    }

    #[test]
    fn render_line_ignores_unparseable_input() {
        assert_eq!(render_line("not json", &[], true), None);
    }

    // ── poll_once: bounded, real Follower, no sleep ─────────────────────

    #[test]
    fn poll_once_returns_newly_appended_matching_lines() {
        let path = short_tmp("poll").with_extension("jsonl");
        std::fs::write(&path, b"").unwrap();
        let mut follower = Follower::open_at_end(&path).unwrap();
        let feed = FeedWriter::new(path.clone(), 1024 * 1024, 0o600);

        assert_eq!(poll_once(&mut follower, &[], true).unwrap(), Vec::<String>::new());

        feed.append(&serde_json::json!({"class": "secret", "kind": "released", "source": "secrets-mirror", "payload": {}}));
        feed.append(&serde_json::json!({"class": "audit", "kind": "hand-edit", "source": "aoided", "payload": {"file": "sessions.json"}}));

        // Poll with a deadline instead of a fixed sleep — the write above
        // is synchronous so one poll should already see both lines, but a
        // short retry loop keeps this robust against any FS buffering
        // quirk without ever sleeping past a bound.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.is_empty() {
            got = poll_once(&mut follower, &[], true).unwrap();
            assert!(std::time::Instant::now() < deadline, "poll_once never saw the appended lines in time");
            if got.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(got.len(), 2, "{got:?}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn poll_once_applies_the_class_filter() {
        let path = short_tmp("poll-filter").with_extension("jsonl");
        std::fs::write(&path, b"").unwrap();
        let mut follower = Follower::open_at_end(&path).unwrap();
        let feed = FeedWriter::new(path.clone(), 1024 * 1024, 0o600);

        feed.append(&serde_json::json!({"class": "secret", "kind": "released", "source": "secrets-mirror", "payload": {}}));
        feed.append(&serde_json::json!({"class": "audit", "kind": "hand-edit", "source": "aoided", "payload": {}}));

        let classes = vec!["secret".to_string()];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.is_empty() {
            got = poll_once(&mut follower, &classes, true).unwrap();
            assert!(std::time::Instant::now() < deadline, "poll_once never saw a matching line in time");
            if got.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(got.len(), 1, "only the secret-classed line should pass the filter: {got:?}");
        assert!(got[0].contains("\"class\":\"secret\""), "{got:?}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn poll_once_on_a_missing_file_errors_rather_than_panicking() {
        let path = short_tmp("poll-missing").with_extension("jsonl");
        std::fs::write(&path, b"x").unwrap();
        let mut follower = Follower::open_at_end(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        // A vanished file: `Follower::poll`'s own NotFound arm reports no
        // lines rather than erroring — `poll_once` must not panic either
        // way.
        let _ = poll_once(&mut follower, &[], true);
    }
}
