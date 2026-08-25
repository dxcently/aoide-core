//! `aoided`'s own tick-loop producers (P-D3, `docs/architecture/AOIDED.md`'s
//! "L1 — the event bus" section): the secrets-feed mirror ("ONE BUS: the
//! secrets mirror") and the #69 hand-edit watcher. Both are plain,
//! bounded, side-effect-scoped structs whose `tick`/`sweep` methods
//! [`crate::daemon::run_loop`] calls once per tick — no threads, no
//! sleeping, no signal handling live in here, the same "thin wrapper
//! touches the real clock/loop, a pure/bounded core does the actual work"
//! split `aoide_protocol::feed`'s own `Follower`/`FeedWriter` already hold
//! (a caller loops; these two structs never loop themselves).
//!
//! ## The secrets mirror
//!
//! [`SecretsMirror`] tails the secrets broker's OWN events feed (module
//! doc's own resolution functions below) with a
//! [`aoide_protocol::feed::Follower`] and re-publishes every line matching
//! one of the crate's five notable outcomes — `released`/`parked`/
//! `completed`/`dismissed`/`expired` (`aoide-secrets`'s `broker::
//! emit_notify` module doc names these as the crate's ONLY five) — onto
//! the daemon's own feed as a name-only mirror record. **This module
//! deliberately does NOT depend on `aoide-secrets`'s wire/record types for
//! either the path resolution or the parsing**, even though this crate
//! already carries an `aoide-secrets` dependency for an unrelated reason
//! (the A2A door's inbound bearer resolve, `a2a.rs`) — the phase brief for
//! this producer is explicit that the mirror must resolve the broker's
//! events-feed location BY CONVENTION/ENV (mirroring, not importing,
//! `aoide_secrets::socket`'s two resolution functions — [`secrets_socket_path`]/
//! [`secrets_events_path`] below are that convention, re-derived) and parse
//! each line as a bare `serde_json::Value`, reading ONLY the four known
//! field names ([`SECRETS_MIRROR_FIELDS`]) — never a typed struct, and
//! never the parsed object wholesale. This is what makes "never copy an
//! unknown field" a STRUCTURAL property of [`mirror_secrets_line`] rather
//! than a discipline someone could quietly break by widening a shared
//! struct: there is no struct to widen.
//!
//! ## The hand-edit watcher (#69)
//!
//! [`HandEditWatcher`] holds a small (mtime, len) baseline per watched
//! stage file and fires one event per file whose on-disk state no longer
//! matches its baseline — [`HandEditWatcher::sweep`] then re-baselines
//! every file it just checked, matching or not, so a genuine change is
//! reported exactly once. [`HandEditWatcher::note_own_write`] lets a
//! FUTURE writer (no daemon-side write path exists yet this phase — P-D6's
//! graph residency is the first one) update a single file's baseline
//! without going through a full `sweep`, so a write the daemon itself just
//! made is folded into the baseline instead of being reported back to
//! itself as a "hand" edit on the very next tick.

use aoide_protocol::feed::{FeedWriter, Follower};
use aoide_protocol::{audit::now_secs, EventClass};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ── the secrets-feed mirror ──────────────────────────────────────────────

/// The secrets broker's socket path — the SAME resolution
/// `aoide_secrets::socket::socket_path` documents (`AOIDE_SECRETS_SOCKET`
/// env override, else the canonical deployed path
/// `/run/aoide-secrets/secrets.sock`), reimplemented here rather than
/// imported (module doc: the mirror must not depend on that crate's own
/// types for this).
pub fn secrets_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_SECRETS_SOCKET") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("/run/aoide-secrets/secrets.sock")
}

/// The secrets broker's own events feed path — the SAME resolution
/// `aoide_secrets::socket::events_path` documents (`AOIDE_SECRETS_EVENTS`
/// env override, else a sibling of the resolved socket path named
/// `events.jsonl`), reimplemented here for the same reason
/// [`secrets_socket_path`] is.
pub fn secrets_events_path() -> PathBuf {
    if let Ok(p) = std::env::var("AOIDE_SECRETS_EVENTS") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    match secrets_socket_path().parent() {
        Some(parent) => parent.join("events.jsonl"),
        None => PathBuf::from("events.jsonl"),
    }
}

/// The five broker outcomes this mirror recognizes — `aoide-secrets`'s
/// `broker::emit_notify` module doc's own list, restated here since this
/// module never imports that crate's code to read it from.
const SECRETS_MIRROR_KINDS: [&str; 5] = ["released", "parked", "completed", "dismissed", "expired"];

/// The ONLY field names ever copied out of a parsed secrets-feed line and
/// into a mirror record's `payload` — `id`/`secret`/`consumer`/
/// `timeoutSecs`, `docs/architecture/AOIDED.md`'s "ONE BUS" section's own
/// list. A field not named here can never ride the mirror, structurally —
/// this is the array [`mirror_secrets_line`] loops over instead of ever
/// cloning the parsed object's whole map.
const SECRETS_MIRROR_FIELDS: [&str; 4] = ["id", "secret", "consumer", "timeoutSecs"];

/// Parse one secrets-broker events-feed LINE and build the daemon's own
/// name-only mirror record, or `None` when the line doesn't parse as JSON,
/// carries no recognized `event` field, or names an event outside the five
/// known kinds. Copies fields BY NAME only ([`SECRETS_MIRROR_FIELDS`]) —
/// never the parsed object wholesale — so an unknown extra field on the
/// source line is structurally impossible to mirror (module doc, and the
/// phase's own test requirement).
fn mirror_secrets_line(line: &str) -> Option<Value> {
    let parsed: Value = serde_json::from_str(line).ok()?;
    let event = parsed.get("event").and_then(Value::as_str)?;
    if !SECRETS_MIRROR_KINDS.contains(&event) {
        return None;
    }
    let mut payload = serde_json::Map::new();
    for field in SECRETS_MIRROR_FIELDS {
        if let Some(v) = parsed.get(field) {
            payload.insert(field.to_string(), v.clone());
        }
    }
    Some(json!({
        "v": 0,
        "ts": now_secs(),
        "class": serde_json::to_value(EventClass::Secret).unwrap_or_else(|_| json!("secret")),
        "kind": event,
        "source": "secrets-mirror",
        "payload": Value::Object(payload),
    }))
}

/// Tails the secrets broker's own events feed and re-publishes every
/// recognized line onto the daemon's feed via a caller-supplied
/// [`FeedWriter`]. One instance per daemon process, constructed once at
/// [`crate::daemon::run_loop`] startup and ticked every daemon tick.
pub struct SecretsMirror {
    events_path: PathBuf,
    follower: Option<Follower>,
}

impl SecretsMirror {
    /// `events_path` is resolved ONCE by the caller (this crate's own
    /// "resolve once, pass as a parameter" discipline,
    /// `crate::daemon`'s module doc) — typically [`secrets_events_path`]'s
    /// result, though a test passes an arbitrary tempdir path directly.
    pub fn new(events_path: PathBuf) -> Self {
        Self { events_path, follower: None }
    }

    /// One tick: read every complete NEW line since the last tick and
    /// append a mirror record for each one [`mirror_secrets_line`]
    /// recognizes. The broker being absent, or its events file not
    /// existing yet, is a QUIET skip — [`Follower::open_at_end`] simply
    /// fails and this tick tries again next time (module doc's "ONE BUS"
    /// section: "Broker absent/file missing = quiet skip, retry next
    /// tick").
    pub fn tick(&mut self, feed: &FeedWriter) {
        if self.follower.is_none() {
            self.follower = Follower::open_at_end(&self.events_path).ok();
        }
        let Some(f) = self.follower.as_mut() else { return };
        match f.poll() {
            Ok(lines) => {
                for line in lines {
                    if let Some(mirrored) = mirror_secrets_line(&line) {
                        feed.append(&mirrored);
                    }
                }
            }
            // A read error past the initial open (e.g. the file vanished
            // mid-poll) drops the follower — the next tick's `is_none()`
            // check above retries opening it fresh, the same recovery
            // `stream_subscribe` already gives a dropped subscriber.
            Err(_) => self.follower = None,
        }
    }
}

// ── the #69 hand-edit watcher ────────────────────────────────────────────

/// One file's `(mtime, len)`, or `None` when the file doesn't exist.
type FileStat = Option<(SystemTime, u64)>;

fn stat(path: &Path) -> FileStat {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// A tick-driven stat sweep over a fixed roster of broker-owned files
/// (`docs/architecture/AOIDED.md`'s "The first producer: the hand-edit
/// watcher (#69)" section) — [`crate::daemon::stage_roster`] supplies the
/// six real stage-file paths in production; a test passes an arbitrary
/// list of tempfiles instead.
pub struct HandEditWatcher {
    files: Vec<PathBuf>,
    baseline: HashMap<PathBuf, FileStat>,
}

impl HandEditWatcher {
    /// The baseline is seeded from each file's CURRENT on-disk state —
    /// nothing fires for a pre-existing file's own history at daemon
    /// startup, only a change the watcher itself observes across two
    /// ticks.
    pub fn new(files: Vec<PathBuf>) -> Self {
        let baseline = files.iter().map(|p| (p.clone(), stat(p))).collect();
        Self { files, baseline }
    }

    /// Record that the daemon itself just wrote `path` — folds its
    /// CURRENT on-disk state into the baseline so the next [`sweep`](Self::sweep)
    /// does not treat this write as a hand edit. No daemon-side write path
    /// exists yet this phase (P-D6's graph residency is the first one);
    /// this method is the seam that phase wires into, proved by this
    /// module's own tests rather than by a live caller yet.
    pub fn note_own_write(&mut self, path: &Path) {
        self.baseline.insert(path.to_path_buf(), stat(path));
    }

    /// One sweep: for every watched file whose current `(mtime, len)`
    /// differs from its baseline — created, deleted, or modified — record
    /// it as a hand-edit and re-baseline to the new state, so the SAME
    /// change is never reported twice. Returns the base filenames (never
    /// the full path — `docs/architecture/AOIDED.md`'s own example payload,
    /// `{"file":"sessions.json"}`) of every file that changed, in roster
    /// order.
    pub fn sweep(&mut self) -> Vec<String> {
        let mut edited = Vec::new();
        for path in &self.files {
            let current = stat(path);
            let previous = self.baseline.get(path).copied().flatten();
            if current != previous {
                let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.to_string_lossy().to_string());
                edited.push(name);
            }
            self.baseline.insert(path.clone(), current);
        }
        edited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short_tmp(tag: &str) -> PathBuf {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        PathBuf::from(format!("/tmp/av-producers-{tag}-{}-{nanos}", std::process::id()))
    }

    // ── mirror_secrets_line: the five known shapes ──────────────────────

    #[test]
    fn mirrors_released_by_name_only() {
        let line = r#"{"event":"released","secret":"totp","consumer":"melete"}"#;
        let m = mirror_secrets_line(line).expect("released must mirror");
        assert_eq!(m["class"], "secret");
        assert_eq!(m["source"], "secrets-mirror");
        assert_eq!(m["kind"], "released");
        assert_eq!(m["payload"]["secret"], "totp");
        assert_eq!(m["payload"]["consumer"], "melete");
        assert!(m["payload"].get("id").is_none(), "{m}");
    }

    #[test]
    fn mirrors_parked_including_id_and_timeout() {
        let line = r#"{"event":"parked","id":"a3f1-2","secret":"totp","consumer":"melete","timeoutSecs":300}"#;
        let m = mirror_secrets_line(line).expect("parked must mirror");
        assert_eq!(m["kind"], "parked");
        assert_eq!(m["payload"]["id"], "a3f1-2");
        assert_eq!(m["payload"]["secret"], "totp");
        assert_eq!(m["payload"]["consumer"], "melete");
        assert_eq!(m["payload"]["timeoutSecs"], 300);
    }

    #[test]
    fn mirrors_completed() {
        let line = r#"{"event":"completed","id":"9","secret":"db","consumer":"agent"}"#;
        let m = mirror_secrets_line(line).expect("completed must mirror");
        assert_eq!(m["kind"], "completed");
        assert_eq!(m["payload"]["id"], "9");
    }

    #[test]
    fn mirrors_dismissed() {
        let line = r#"{"event":"dismissed","id":"9","secret":"db"}"#;
        let m = mirror_secrets_line(line).expect("dismissed must mirror");
        assert_eq!(m["kind"], "dismissed");
        assert!(m["payload"].get("consumer").is_none(), "{m}");
    }

    #[test]
    fn mirrors_expired() {
        let line = r#"{"event":"expired","id":"9","secret":"db","consumer":"agent"}"#;
        let m = mirror_secrets_line(line).expect("expired must mirror");
        assert_eq!(m["kind"], "expired");
    }

    /// The phase entry's own hard requirement: an unknown extra field on
    /// the source line is structurally impossible to mirror.
    #[test]
    fn unknown_field_never_rides_the_mirror() {
        let line = r#"{"event":"released","secret":"totp","consumer":"melete","value":"super-secret-value","extra":"whatever"}"#;
        let m = mirror_secrets_line(line).expect("released must still mirror");
        let payload = m["payload"].as_object().expect("payload is an object");
        assert_eq!(payload.len(), 2, "only secret+consumer expected: {payload:?}");
        assert!(!payload.contains_key("value"), "{payload:?}");
        assert!(!payload.contains_key("extra"), "{payload:?}");
    }

    #[test]
    fn unrecognized_event_kind_does_not_mirror() {
        assert!(mirror_secrets_line(r#"{"event":"age-identity-minted"}"#).is_none());
        assert!(mirror_secrets_line(r#"{"event":"something-new","secret":"x"}"#).is_none());
    }

    #[test]
    fn malformed_line_does_not_mirror() {
        assert!(mirror_secrets_line("not json at all").is_none());
        assert!(mirror_secrets_line(r#"{"no_event_field":true}"#).is_none());
    }

    // ── SecretsMirror::tick ──────────────────────────────────────────────

    #[test]
    fn secrets_mirror_forwards_matching_lines_onto_the_daemon_feed() {
        let secrets_events = short_tmp("secrets-events").with_extension("jsonl");
        let daemon_events = short_tmp("daemon-events").with_extension("jsonl");
        // Pre-existing HISTORY on the broker's feed, written before this
        // mirror ever starts — `Follower::open_at_end` must never replay
        // it (matches `secrets watch`'s own choice, and every other
        // Follower consumer in this workstream).
        std::fs::write(&secrets_events, b"{\"event\":\"released\",\"secret\":\"pre-existing\",\"consumer\":\"m\"}\n").unwrap();

        let mut mirror = SecretsMirror::new(secrets_events.clone());
        let feed = FeedWriter::new(daemon_events.clone(), 1024 * 1024, 0o600);

        mirror.tick(&feed);
        assert!(!daemon_events.exists() || std::fs::read_to_string(&daemon_events).unwrap().is_empty(), "history before the mirror started must never replay");

        let mut f = std::fs::OpenOptions::new().append(true).open(&secrets_events).unwrap();
        use std::io::Write;
        writeln!(f, r#"{{"event":"released","secret":"t","consumer":"m"}}"#).unwrap();
        writeln!(f, r#"{{"event":"age-identity-minted"}}"#).unwrap(); // never mirrored
        mirror.tick(&feed);

        let contents = std::fs::read_to_string(&daemon_events).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1, "only the recognized event mirrors: {contents}");
        let mirrored: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(mirrored["kind"], "released");
        assert_eq!(mirrored["source"], "secrets-mirror");

        std::fs::remove_file(&secrets_events).ok();
        std::fs::remove_file(&daemon_events).ok();
    }

    /// Broker absent/file missing: a quiet skip, never a panic, ready to
    /// pick up the moment the file appears on a later tick.
    #[test]
    fn secrets_mirror_quietly_skips_when_the_broker_feed_is_absent() {
        let secrets_events = short_tmp("missing-broker").with_extension("jsonl");
        let daemon_events = short_tmp("missing-broker-daemon").with_extension("jsonl");
        let mut mirror = SecretsMirror::new(secrets_events.clone());
        let feed = FeedWriter::new(daemon_events.clone(), 1024 * 1024, 0o600);

        mirror.tick(&feed); // must not panic
        assert!(!daemon_events.exists(), "nothing should have been appended");

        // The broker "starts" later — the (empty) file appears, and this
        // tick is what successfully opens the follower (module doc's own
        // "retry next tick" contract) — AT its current end, so a line
        // written only AFTER this point is what the next tick must see.
        std::fs::write(&secrets_events, b"").unwrap();
        mirror.tick(&feed);

        let mut f = std::fs::OpenOptions::new().append(true).open(&secrets_events).unwrap();
        use std::io::Write;
        writeln!(f, r#"{{"event":"released","secret":"t","consumer":"m"}}"#).unwrap();
        mirror.tick(&feed);

        let contents = std::fs::read_to_string(&daemon_events).unwrap();
        assert!(contents.contains("\"kind\":\"released\""), "{contents}");

        std::fs::remove_file(&secrets_events).ok();
        std::fs::remove_file(&daemon_events).ok();
    }

    // ── HandEditWatcher ───────────────────────────────────────────────────

    #[test]
    fn hand_edit_watcher_fires_on_an_out_of_band_mtime_change() {
        let path = short_tmp("hand-edit");
        std::fs::write(&path, b"{}").unwrap();
        let mut w = HandEditWatcher::new(vec![path.clone()]);

        // Nothing changed since construction — no false positive on startup.
        assert_eq!(w.sweep(), Vec::<String>::new());

        // An OUT-OF-BAND edit (nobody called note_own_write for it).
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, b"{\"hand\":\"edited\"}").unwrap();
        let fired = w.sweep();
        assert_eq!(fired, vec![path.file_name().unwrap().to_string_lossy().to_string()]);

        // Re-baselined: sweeping again with no further change is quiet.
        assert_eq!(w.sweep(), Vec::<String>::new());

        std::fs::remove_file(&path).ok();
    }

    /// The daemon's own write, folded in via `note_own_write`, must NOT
    /// fire on the next sweep.
    #[test]
    fn hand_edit_watcher_does_not_fire_on_the_daemons_own_write() {
        let path = short_tmp("own-write");
        std::fs::write(&path, b"{}").unwrap();
        let mut w = HandEditWatcher::new(vec![path.clone()]);
        assert_eq!(w.sweep(), Vec::<String>::new());

        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, b"{\"daemon\":\"wrote-this\"}").unwrap();
        w.note_own_write(&path); // simulates the future P-D6 write path
        assert_eq!(w.sweep(), Vec::<String>::new(), "the daemon's own write must not be reported as a hand edit");

        // A LATER out-of-band edit still fires normally — note_own_write
        // suppresses exactly one transition, not the file forever.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&path, b"{\"hand\":\"edited-after\"}").unwrap();
        assert_eq!(w.sweep().len(), 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hand_edit_watcher_reports_a_deleted_file_once() {
        let path = short_tmp("deleted");
        std::fs::write(&path, b"{}").unwrap();
        let mut w = HandEditWatcher::new(vec![path.clone()]);
        assert_eq!(w.sweep(), Vec::<String>::new());

        std::fs::remove_file(&path).unwrap();
        assert_eq!(w.sweep().len(), 1, "a deletion is itself a change worth reporting");
        assert_eq!(w.sweep(), Vec::<String>::new(), "re-baselined to 'absent' — no repeat");
    }

    #[test]
    fn hand_edit_watcher_sweeps_multiple_files_independently() {
        let a = short_tmp("multi-a");
        let b = short_tmp("multi-b");
        std::fs::write(&a, b"{}").unwrap();
        std::fs::write(&b, b"{}").unwrap();
        let mut w = HandEditWatcher::new(vec![a.clone(), b.clone()]);
        assert_eq!(w.sweep(), Vec::<String>::new());

        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&b, b"{\"changed\":true}").unwrap();
        let fired = w.sweep();
        assert_eq!(fired, vec![b.file_name().unwrap().to_string_lossy().to_string()]);

        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }
}
