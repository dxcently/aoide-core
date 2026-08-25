//! The append-only JSON-lines feed primitive: one writer half
//! ([`FeedWriter`]), one reader half ([`Follower`]) — the pattern `aoide-
//! secrets` proved live under `ProtectHome=true` sandboxing and broker
//! restarts (`docs/architecture/AOIDED.md`'s "L1 — the event bus" section,
//! P-D1), extracted here so `aoided`'s own event bus and any other future
//! producer/consumer pair can share it rather than re-deriving the same
//! two halves. `aoide-protocol` is the DAG leaf every domain crate already
//! depends on (`aoide-secrets` depends on `aoide-protocol`/`libc`/`serde`/
//! `serde_json` only — its own `AGENTS.md` invariant), so it is the only
//! crate that can host a shared primitive here without adding a new
//! dependency edge; this module adds none of its own (`serde_json` and
//! `std` only).
//!
//! **This is a pure extraction — [`Follower`] moved verbatim from
//! `aoide_secrets::watch::Follower`, generalized away from secrets-specific
//! naming and doc references only, never its mechanics.** `aoide-secrets`
//! consumes it via `pub use aoide_protocol::feed::Follower` at the old path
//! (`pkgs/aoide/crates/AGENTS.md`'s "no cross-crate copying" — a moved
//! symbol is re-exported, never duplicated); its own `broker::
//! append_events_feed` delegates to [`FeedWriter`] instead of reimplementing
//! the append. Every external spelling — `watch::Follower`, `broker::
//! append_events_feed`'s own behavior, the events feed's on-disk shape —
//! stays byte-identical.
//!
//! One feed, one writer process, any number of readers: a [`FeedWriter`]
//! appends one JSON object per line, capped and truncated-in-place rather
//! than rotated (below); a [`Follower`] tails it from EOF, delta-reads
//! only, and transparently reopens across both an in-place truncation and
//! a delete-and-recreate (a producer restart under a `RuntimeDirectory=`
//! that gets wiped between runs).

use serde_json::Value;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

// ── the writer half ──────────────────────────────────────────────────────

/// Appends one JSON object per line to a capped, append-only file — the
/// mechanics of `aoide-secrets`' `broker::append_events_feed`
/// (`broker.rs:1151` as of P-D1), generalized to any caller. Best-effort,
/// always: every failure is `eprintln!`'d and swallowed, never propagated
/// — a notification write must never fail or block the caller's own hot
/// path (the exact posture `aoide-secrets`' `emit_notify` already required
/// of it).
pub struct FeedWriter {
    path: PathBuf,
    cap: u64,
    create_mode: u32,
}

impl FeedWriter {
    /// `path` is the feed file; `cap` is the byte size past which the next
    /// [`FeedWriter::append`] truncates the file to empty FIRST rather than
    /// growing it further (the feed is ephemeral cues, not an unbounded
    /// audit trail — that stays `aoide_protocol::audit`, unbounded, on a
    /// different path entirely); `create_mode` is the Unix permission bits
    /// applied via an EXPLICIT `chmod` the one time this writer creates the
    /// file (never left to the process umask — a caller sharing the file
    /// with a specific group, the way `aoide-secrets` shares its own feed
    /// with `aoide-secrets-access`, needs the mode to be exactly what it
    /// asked for).
    pub fn new(path: PathBuf, cap: u64, create_mode: u32) -> Self {
        Self { path, cap, create_mode }
    }

    /// Append one line: `payload` serialized compactly, plus a trailing
    /// `\n`. Creates the parent directory and the file itself on first use;
    /// chmods to `create_mode` only on the write that actually creates the
    /// file (checked via `exists()` immediately before opening) — every
    /// later append reuses whatever permissions are already there, even if
    /// something else changed them since. Past `cap`, this truncates the
    /// file to empty before writing the new line rather than rotating it —
    /// [`Follower::poll`]'s own `len() < pos` reopen-at-0 branch is what
    /// makes that transparent to a live tail.
    pub fn append(&self, payload: &Value) {
        if let Some(parent) = self.path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("[aoide/feed] could not create the feed directory: {e}");
                return;
            }
        }
        let existed = self.path.exists();
        let over_cap = std::fs::metadata(&self.path).map(|m| m.len() >= self.cap).unwrap_or(false);

        let mut opts = std::fs::OpenOptions::new();
        opts.create(true);
        if over_cap {
            opts.write(true).truncate(true);
        } else {
            opts.append(true);
        }
        let mut f = match opts.open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[aoide/feed] could not open the feed file: {e}");
                return;
            }
        };
        if !existed {
            if let Err(e) = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.create_mode)) {
                eprintln!("[aoide/feed] could not chmod the feed file to {:o}: {e}", self.create_mode);
            }
        }
        let mut line = payload.to_string();
        line.push('\n');
        if let Err(e) = f.write_all(line.as_bytes()) {
            eprintln!("[aoide/feed] could not write the feed file: {e}");
        }
    }
}

// ── the reader half ──────────────────────────────────────────────────────

/// Tail-follows one file from EOF, delta-reads only — NEVER re-reads from
/// the start. Moved verbatim from `aoide_secrets::watch::Follower` (P-D1);
/// see this module's own doc for the shim `aoide-secrets` now consumes it
/// through. **`poll` stats the PATH itself and compares `(dev, ino)`
/// against the open fd on every call**: a producer restart under a
/// `RuntimeDirectory=`-shaped tmpfs unlinks the file and a fresh process
/// creates a brand-new inode at the same path, and the OLD fd's own
/// `metadata().len()` freezes at deletion-time forever after — a
/// length-only comparison can never see that a same-or-larger replacement
/// landed, so every event after a restart would silently vanish into a
/// permanently frozen read position with no error at all. A partial
/// trailing line (no `\n` yet) is held across polls, never parsed early.
pub struct Follower {
    path: PathBuf,
    file: File,
    pos: u64,
    partial: String,
}

impl Follower {
    /// Open `path`, seek to its CURRENT end, and start following from
    /// there — history before this call is never read.
    pub fn open_at_end(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { path: path.to_path_buf(), file, pos: len, partial: String::new() })
    }

    /// One poll: `stat(2)` the PATH (never only the open fd — see this
    /// struct's own doc for why). If the path now names a different
    /// `(dev, ino)` than the open fd — a new inode landed at the same path
    /// — reopen at 0 and start following the new file, the same state
    /// reset the truncation branch below already performs. If the path
    /// doesn't exist yet (mid-restart, before the new file lands), this
    /// poll simply reports no lines; the reopen fires on the next poll
    /// that finds the path back. Once confirmed to be reading the right
    /// inode, read exactly the new bytes and return every COMPLETE line
    /// found (a trailing partial line is held for the next poll); no
    /// growth returns an empty `Vec`, no read syscall at all. `len() <
    /// pos` on the (possibly just-reopened) fd still covers an in-place
    /// truncation of the SAME inode (a [`FeedWriter`] past its own cap) —
    /// reopen and start again from 0 rather than sit at a now-meaningless
    /// offset forever.
    pub fn poll(&mut self) -> std::io::Result<Vec<String>> {
        match std::fs::metadata(&self.path) {
            Ok(path_meta) => {
                let fd_meta = self.file.metadata()?;
                if (path_meta.dev(), path_meta.ino()) != (fd_meta.dev(), fd_meta.ino()) {
                    self.file = File::open(&self.path)?;
                    self.pos = 0;
                    self.partial.clear();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }

        let len = self.file.metadata()?.len();
        if len < self.pos {
            self.file = File::open(&self.path)?;
            self.pos = 0;
            self.partial.clear();
        }
        let len = self.file.metadata()?.len();
        if len == self.pos {
            return Ok(Vec::new());
        }
        self.file.seek(SeekFrom::Start(self.pos))?;
        let mut buf = Vec::new();
        (&self.file).take(len - self.pos).read_to_end(&mut buf)?;
        self.pos += buf.len() as u64;
        self.partial.push_str(&String::from_utf8_lossy(&buf));

        let mut lines = Vec::new();
        while let Some(idx) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=idx).collect();
            lines.push(line.trim_end_matches('\n').to_string());
        }
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aoide-protocol-feed-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    // ── Follower ──────────────────────────────────────────────────────

    #[test]
    fn follower_growth_reads_only_the_delta() {
        let path = tmp_path("growth");
        std::fs::write(&path, b"before this point\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"line one\nline two\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["line one".to_string(), "line two".to_string()]);

        file.write_all(b"line three\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["line three".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_open_at_end_skips_pre_existing_content() {
        let path = tmp_path("skip-history");
        std::fs::write(&path, b"history line 1\nhistory line 2\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new(), "must never re-read from the start");
        std::fs::remove_file(&path).ok();
    }

    /// The daemon-restart transparency: a delete-and-recreate at the same
    /// path lands a brand-new `(dev, ino)`, which `poll` must notice even
    /// though the old fd's own `metadata().len()` stays frozen at
    /// deletion-time.
    #[test]
    fn follower_survives_delete_and_recreate() {
        let path = tmp_path("delete-recreate");
        std::fs::write(&path, b"before restart\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"after restart\n").unwrap();
        assert_eq!(
            f.poll().unwrap(),
            vec!["after restart".to_string()],
            "a delete-and-recreate at the same path must not leave the follower deaf"
        );

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"one more\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["one more".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_survives_rename_away_and_recreate() {
        let path = tmp_path("rename-away");
        let moved = tmp_path("rename-away-moved");
        std::fs::write(&path, b"before rename\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"after rename\n").unwrap();
        assert_eq!(
            f.poll().unwrap(),
            vec!["after rename".to_string()],
            "a rename-away-and-recreate at the same path must not leave the follower deaf"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&moved).ok();
    }

    #[test]
    fn follower_truncation_in_place_reopens_at_zero() {
        let path = tmp_path("truncate");
        std::fs::write(&path, b"aaaaaaaaaaaaaaaaaaaa\n").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new());

        // Replace with a SHORTER file (simulates a FeedWriter's own
        // past-cap truncate-in-place).
        std::fs::write(&path, b"fresh\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["fresh".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn follower_holds_a_partial_trailing_line_until_the_newline_arrives() {
        let path = tmp_path("partial");
        std::fs::write(&path, b"").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"no newline yet").unwrap();
        assert_eq!(f.poll().unwrap(), Vec::<String>::new(), "a partial line must not be returned early");

        file.write_all(b" - now complete\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec!["no newline yet - now complete".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    // ── FeedWriter ────────────────────────────────────────────────────

    #[test]
    fn feed_writer_creates_the_file_at_the_given_mode() {
        let path = tmp_path("writer-perms");
        FeedWriter::new(path.clone(), 1024, 0o640).append(&json!({"event": "x"}));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "expected the create_mode to be applied, got {mode:o}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn feed_writer_does_not_rechmod_an_existing_file() {
        let path = tmp_path("writer-no-rechmod");
        let writer = FeedWriter::new(path.clone(), 1024, 0o640);
        writer.append(&json!({"event": "x"}));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        writer.append(&json!({"event": "y"}));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a later append must not re-chmod an already-existing file, got {mode:o}");
        std::fs::remove_file(&path).ok();
    }

    /// Cap-truncate behavior: past `cap`, the next append truncates the
    /// file to empty FIRST rather than growing it further.
    #[test]
    fn feed_writer_truncates_once_the_cap_is_exceeded() {
        let path = tmp_path("writer-cap");
        let cap: u64 = 1024;
        std::fs::write(&path, vec![b'x'; (cap + 1) as usize]).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > cap);

        FeedWriter::new(path.clone(), cap, 0o640).append(&json!({"event": "released"}));

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains('x'), "the oversized padding must be gone after truncation: {contents}");
        assert!(contents.contains("\"event\":\"released\""), "{contents}");
        assert!(
            (contents.len() as u64) < cap,
            "the file must be back under the cap right after truncating, got {} bytes",
            contents.len()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn feed_writer_and_follower_round_trip() {
        let path = tmp_path("round-trip");
        let writer = FeedWriter::new(path.clone(), 1024 * 1024, 0o640);
        std::fs::write(&path, b"").unwrap();
        let mut f = Follower::open_at_end(&path).unwrap();

        writer.append(&json!({"event": "parked", "id": "1"}));
        let lines = f.poll().unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(serde_json::from_str::<Value>(&lines[0]).unwrap(), json!({"event": "parked", "id": "1"}));

        std::fs::remove_file(&path).ok();
    }
}
