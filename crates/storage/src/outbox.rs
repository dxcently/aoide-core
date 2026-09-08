//! `state/outbox/<node>/` — the per-node BSO-style spool (MAIL.md
//! "Outbox", P-M2): one JSON file per pending envelope, named
//! `<msgid>.json` ([`OutboxEntry`] — the sealed envelope plus this box's
//! own delivery bookkeeping), one `link.json` per node holding that LINK's
//! own backoff state, and one `.bsy` lock file a drain holds for the
//! link's whole dial+POST+record cycle so a second, concurrent drain of
//! the SAME link skips rather than double-drives it (ruling 3).
//!
//! **Two locks, two different jobs — never conflated (the P-M2 brief's own
//! drain pseudocode).** Every entry/link-state MUTATION *and* READ here
//! goes through [`with_lock`] — this module's own copy of
//! [`crate::mail::with_lock`]'s shape (a tiny per-module copy, not a reach
//! into mail's — that one also runs mail's OWN migrations, which have
//! nothing to do with the outbox), itself wrapping
//! [`crate::fs::try_stage_lock`] — the SAME global, fail-closed lock
//! `mail::with_lock` wraps. That lock is file I/O only, held for
//! microseconds, and released before this module's callers ever dial
//! anywhere. `.bsy` ([`try_take_link_lock`]) is a SEPARATE, per-node,
//! NON-BLOCKING (`LOCK_EX|LOCK_NB`) lock a drain holds ACROSS the whole
//! network round trip for that one link — never the other way around:
//! holding the global stage lock across an ssh dial would wedge every
//! other `aoide` command on the box, which is exactly why `.bsy` exists as
//! a second, cheaper mechanism instead of widening the first one's scope.
//!
//! Ownership (`pkgs/aoide/crates/AGENTS.md`'s ruling 1, "spool in storage,
//! wire lane in client, bridge through conduct"): the spool lives here, in
//! `aoide-storage` — pure file CRUD, no network, no HTTP, no tunnel. The
//! actual dial+POST (the drain) lives in `aoide-client`; this module knows
//! nothing about `aoide/mailDeposit` and never will.

use crate::fs::{atomic_write, state_dir, try_stage_lock};
use crate::mail::Envelope;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// The floor [`aoide_protocol::dialog::next_spawn_backoff`] doubles up
/// from for an outbox link (ruling 7: "reuse `next_spawn_backoff`, floor
/// raised to one drain interval instead of that module's 1s"). Mirrors
/// `aoide-server::daemon`'s own drain cadence (~12s, the same interval
/// `REAP_EVERY_TICKS` already established for the internal reap sweep) —
/// re-derived here rather than imported, since `storage` sits below
/// `server` in the crate DAG (the same "a tiny per-module copy of a small
/// numeric convention" precedent `client/src/tunnel.rs`'s own doc states).
/// Backing off faster than the sweep itself fires would never actually
/// skip a dial, so anything shorter than this floor is pointless.
pub const DRAIN_BACKOFF_FLOOR_SECS: u64 = 12;

/// `$AOIDE_STATE_DIR/outbox/` (ordinary [`state_dir`] resolution).
pub fn outbox_dir() -> PathBuf {
    state_dir().join("outbox")
}

fn node_dir(node: &str) -> PathBuf {
    outbox_dir().join(node)
}

fn entry_path(node: &str, msgid: &str) -> PathBuf {
    node_dir(node).join(format!("{msgid}.json"))
}

fn link_path(node: &str) -> PathBuf {
    node_dir(node).join("link.json")
}

fn bsy_path(node: &str) -> PathBuf {
    node_dir(node).join(".bsy")
}

/// One spooled, not-yet-retired envelope plus this box's own delivery
/// bookkeeping for it. The envelope is stored VERBATIM, byte-identical to
/// what was sealed at mint time — a retry resends the exact same signed
/// bytes, never re-mints (a re-mint would also mint a fresh, different
/// `msgid`, defeating the far end's dedup).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxEntry {
    pub envelope: Envelope,
    #[serde(default)]
    pub tries: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_try_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_outcome: String,
    /// Set once a deposit attempt returns a JSON-RPC REFUSAL — never for a
    /// transport failure, which backs the LINK off instead (the drain
    /// pseudocode's own distinction). A refused entry stays in the spool
    /// forever (the kill-list: no auto-eviction, no quota, no expiry) but
    /// a drain skips it on sight; only `mail outbox rm` retires it.
    #[serde(default)]
    pub refused: bool,
}

impl OutboxEntry {
    /// A fresh entry for a just-minted envelope — zero tries, no recorded
    /// outcome yet.
    pub fn fresh(envelope: Envelope) -> Self {
        Self { envelope, tries: 0, last_try_at: String::new(), last_outcome: String::new(), refused: false }
    }
}

/// One node's own outbound-link backoff state — present ONLY while a
/// backoff is active; ABSENT means "not held off," the ordinary state for
/// a link that has never failed, or has just succeeded (spec: "clears on
/// success" — see [`clear_link_state`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkState {
    /// The backoff duration, in seconds, that produced `next_attempt_at` —
    /// what the NEXT consecutive failure doubles from.
    pub backoff_secs: u64,
    /// This link should not be dialed again before this instant (ISO-8601
    /// UTC). `now < next_attempt_at` is a drain's "held off, skip" signal
    /// ([`is_held_off`]).
    pub next_attempt_at: String,
    pub last_outcome: String,
}

/// This module's own fail-closed lock wrapper — see the module doc's "two
/// locks" section for why this is a small per-module copy of
/// [`crate::mail::with_lock`]'s shape rather than a call into it.
fn with_lock<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match try_stage_lock(f) {
        Ok(inner) => inner,
        Err(lock_err) => Err(lock_err),
    }
}

/// Every node name with a non-empty outbox directory — what a drain sweep
/// (`aoide-conduct::mail_bridge::drain_all`) walks, and what bare `mail
/// outbox` (no `<node>` argument) lists across. Tolerant of a missing
/// `state/outbox/` (no node has ever had anything spooled) — an empty
/// `Vec`, never an error.
pub fn nodes_with_outbox() -> Result<Vec<String>, String> {
    with_lock(|| {
        let dir = outbox_dir();
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        let mut out = Vec::new();
        for entry in read_dir {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    out.push(name.to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    })
}

/// Spool one entry — `mail send`'s write-before-attempt (spec item 8).
/// Overwrites any existing file of the same `msgid` (only possible if a
/// caller somehow re-mints the identical envelope; ordinary operation
/// never does).
pub fn write_entry(node: &str, entry: &OutboxEntry) -> Result<(), String> {
    let node = node.to_string();
    let entry = entry.clone();
    with_lock(move || {
        let dir = node_dir(&node);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry_path(&node, &entry.envelope.msgid);
        let json = serde_json::to_string_pretty(&entry).map_err(|e| e.to_string())?;
        atomic_write(&path, &json).map_err(|e| format!("{}: {e}", path.display()))
    })
}

/// Every entry spooled for `node`, oldest first (`header.mintedAt`, ties
/// broken by `msgid` for determinism) — the drain's own iteration order.
/// A malformed entry file is skipped, not an error, the same tolerant-read
/// discipline [`crate::mail`]'s own `read_entries_unlocked` holds. Missing
/// directory (nothing ever spooled to this node) is an empty `Vec`.
pub fn list_entries(node: &str) -> Result<Vec<OutboxEntry>, String> {
    let node = node.to_string();
    with_lock(move || {
        let dir = node_dir(&node);
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("{}: {e}", dir.display())),
        };
        let mut out = Vec::new();
        for dir_entry in read_dir {
            let dir_entry = dir_entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            let path = dir_entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("link.json") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some(".bsy") {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&path) else { continue };
            if let Ok(parsed) = serde_json::from_str::<OutboxEntry>(&raw) {
                out.push(parsed);
            }
        }
        out.sort_by(|a: &OutboxEntry, b: &OutboxEntry| {
            a.envelope
                .header
                .minted_at
                .cmp(&b.envelope.header.minted_at)
                .then_with(|| a.envelope.msgid.cmp(&b.envelope.msgid))
        });
        Ok(out)
    })
}

/// Retire one entry — a valid ack (spec item 7) or explicit `mail outbox
/// rm`, never anything else (the kill-list: no auto-eviction). `Ok(false)`
/// when nothing named `msgid` was spooled (already retired, or never was)
/// — not an error, so a retry racing an ack's own retirement is a no-op,
/// not a failure.
pub fn remove_entry(node: &str, msgid: &str) -> Result<bool, String> {
    let node = node.to_string();
    let msgid = msgid.to_string();
    with_lock(move || {
        let path = entry_path(&node, &msgid);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    })
}

/// Retire the one local outbox entry `ack` confirms (spec item 7: "a
/// receipt whose verified signer is that entry's `to.node` and whose text
/// names that entry's `msgid`"). `Ok(None)` — never an error — covers
/// every way an ack fails to match: `ack` is not a receipt at all, no
/// entry was ever spooled under `ack.header.from.node`, or `ack.text`
/// names a `msgid` that node's spool doesn't hold (wrong text, an
/// already-retired entry, or a stale replay).
///
/// The two checks fall out of ONE path lookup rather than needing to be
/// stated separately: an outbox entry is always spooled under the exact
/// node its own `envelope.header.to.node` names ([`write_entry`]'s only
/// caller convention), so indexing by `ack.header.from.node` — the
/// receipt's ORIGIN, already proven genuine by [`crate::mail::deposit`]'s
/// own origin-signature check before this function is ever reached, never
/// re-verified here — IS "verified signer is entry's `to.node`"; and
/// [`entry_path`] keying the file by `msgid` makes `ack.text` naming the
/// wrong one a plain miss, never a partial match. A forged ack (wrong
/// signer) never gets this far — [`crate::mail::deposit`] would have
/// already refused it as `unverified-origin`.
pub fn retire_by_ack(ack: &Envelope) -> Result<Option<String>, String> {
    if ack.header.kind != crate::mail::ENTRY_TYPE_RECEIPT {
        return Ok(None);
    }
    let acked_msgid = ack.text.clone();
    if remove_entry(&ack.header.from.node, &acked_msgid)? {
        Ok(Some(acked_msgid))
    } else {
        Ok(None)
    }
}

/// This link's current backoff state, if any (`None` = not held off).
pub fn read_link_state(node: &str) -> Result<Option<LinkState>, String> {
    let node = node.to_string();
    with_lock(move || {
        let path = link_path(&node);
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                serde_json::from_str(&raw).map(Some).map_err(|e| format!("{}: {e}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    })
}

fn write_link_state(node: &str, state: &LinkState) -> Result<(), String> {
    let node = node.to_string();
    let state = state.clone();
    with_lock(move || {
        let dir = node_dir(&node);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = link_path(&node);
        let json = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
        atomic_write(&path, &json).map_err(|e| format!("{}: {e}", path.display()))
    })
}

/// Clear a link's backoff — spec's "clears on success." Removing the file
/// entirely (rather than resetting fields) is what makes [`read_link_state`]
/// return `None`, the ordinary not-held-off state.
pub fn clear_link_state(node: &str) -> Result<(), String> {
    let node = node.to_string();
    with_lock(move || {
        let path = link_path(&node);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    })
}

/// Is this link currently held off (a prior TRANSPORT failure's backoff
/// hasn't elapsed yet)? `now_epoch` is the caller's own "now" — the same
/// testability shape `a2a::verify_signed_request`'s own `now_epoch`
/// parameter holds. A `next_attempt_at` that fails to parse is treated as
/// NOT held off (fail-open on a corrupt link file — a spool held off
/// forever by a hand-edit bug is worse than one extra premature dial).
pub fn is_held_off(state: &LinkState, now_epoch: i64) -> bool {
    crate::time::parse_iso_utc(&state.next_attempt_at).is_some_and(|next| now_epoch < next)
}

/// Advance (or start) `node`'s backoff after a TRANSPORT failure — doubles
/// via [`aoide_protocol::dialog::next_spawn_backoff`] from whatever the
/// existing state recorded, or from [`DRAIN_BACKOFF_FLOOR_SECS`] on a
/// link's first-ever failure (mirrors `client::pair_watch`'s own
/// `SPAWN_BACKOFF_INITIAL`-then-`next_spawn_backoff` sequencing: the floor
/// itself is the FIRST backoff, only a SECOND consecutive failure doubles
/// it). Writes and returns the new state. `now_epoch` is the caller's own
/// "now."
pub fn back_off(node: &str, now_epoch: i64, outcome: &str) -> Result<LinkState, String> {
    let existing = read_link_state(node)?;
    let floor = Duration::from_secs(DRAIN_BACKOFF_FLOOR_SECS);
    let this_backoff = match existing {
        Some(s) => aoide_protocol::dialog::next_spawn_backoff(Duration::from_secs(s.backoff_secs).max(floor)),
        None => floor,
    };
    let state = LinkState {
        backoff_secs: this_backoff.as_secs(),
        next_attempt_at: crate::time::iso_utc_from_epoch(now_epoch + this_backoff.as_secs() as i64),
        last_outcome: outcome.to_string(),
    };
    write_link_state(node, &state)?;
    Ok(state)
}

/// The `.bsy` guard (ruling 3: `LOCK_EX|LOCK_NB`, never blocking) — a drain
/// holds this across its whole dial+POST+record cycle for one link.
/// Dropping it releases the flock immediately, on every path including an
/// early return — a drain that errors out partway still frees the link for
/// the next attempt rather than wedging it until process exit.
pub struct LinkLockGuard {
    file: std::fs::File,
}

impl Drop for LinkLockGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Try to take `node`'s `.bsy` lock, NON-BLOCKING (ruling 3 — FidoNet's own
/// meta-rule: a busy link is SKIPPED, never queued behind it; queueing
/// would let one wedged drain starve every later one). `Ok(None)` is the
/// ordinary "another drain already holds this link" outcome, never an
/// error; `Err` only when the lock file itself can't be created or opened.
pub fn try_take_link_lock(node: &str) -> Result<Option<LinkLockGuard>, String> {
    use std::os::unix::io::AsRawFd;
    let dir = node_dir(node);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = bsy_path(node);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(Some(LinkLockGuard { file }));
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::{Address, Header};

    fn root(tag: &str) -> (aoide_test_support::EnvSaver, std::path::PathBuf) {
        aoide_test_support::isolated_mail_root(tag)
    }

    fn envelope(from_node: &str, to_node: &str, msgid: &str) -> Envelope {
        Envelope {
            header: Header {
                version: "1".to_string(),
                from: Address { node: from_node.to_string(), name: "alice".to_string() },
                to: Address { node: to_node.to_string(), name: "bob".to_string() },
                kind: "letter".to_string(),
                minted_at: "2026-09-07T00:00:00Z".to_string(),
                origin_mesh: String::new(),
            },
            text: "hi".to_string(),
            sig: "ab".repeat(32),
            msgid: msgid.to_string(),
        }
    }

    /// A receipt "signed by" `from_node` (this fixture never checks a real
    /// signature — [`retire_by_ack`] trusts its caller to have already done
    /// that, exactly as [`crate::mail::deposit`]'s own origin check does
    /// upstream of it in production), acking `acked_msgid` back to
    /// `to_node`.
    fn ack_envelope(from_node: &str, to_node: &str, acked_msgid: &str) -> Envelope {
        Envelope {
            header: Header {
                version: "1".to_string(),
                from: Address { node: from_node.to_string(), name: "bob".to_string() },
                to: Address { node: to_node.to_string(), name: "alice".to_string() },
                kind: crate::mail::ENTRY_TYPE_RECEIPT.to_string(),
                minted_at: "2026-09-07T00:05:00Z".to_string(),
                origin_mesh: String::new(),
            },
            text: acked_msgid.to_string(),
            sig: "cd".repeat(32),
            msgid: format!("ack-of-{acked_msgid}"),
        }
    }

    #[test]
    fn an_outbox_entry_round_trips_through_the_spool() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-roundtrip");

        let entry = OutboxEntry::fresh(envelope("here", "there", "msg-1"));
        write_entry("there", &entry).unwrap();

        let listed = list_entries("there").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].envelope.msgid, "msg-1");
        assert_eq!(listed[0].tries, 0);

        assert!(remove_entry("there", "msg-1").unwrap(), "a real entry retires");
        assert!(list_entries("there").unwrap().is_empty());
        assert!(!remove_entry("there", "msg-1").unwrap(), "retiring twice is a clean no-op, not an error");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_valid_ack_retires_exactly_its_own_entry() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-ack-retires-its-own");

        write_entry("there", &OutboxEntry::fresh(envelope("here", "there", "msg-x"))).unwrap();
        write_entry("there", &OutboxEntry::fresh(envelope("here", "there", "msg-y"))).unwrap();

        let ack = ack_envelope("there", "here", "msg-x");
        let retired = retire_by_ack(&ack).unwrap();
        assert_eq!(retired, Some("msg-x".to_string()));

        let remaining = list_entries("there").unwrap();
        assert_eq!(remaining.len(), 1, "only the acked entry retires");
        assert_eq!(remaining[0].envelope.msgid, "msg-y", "the other entry is untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ack_signed_by_the_wrong_node_retires_nothing() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-ack-wrong-signer");

        // The entry lives under "there" (that's who the original letter was
        // addressed to); an ack claiming to be FROM a third node "mallory"
        // is exactly the shape `crate::mail::deposit`'s own origin check
        // would already have refused as `unverified-origin` upstream — this
        // test pins that `retire_by_ack` ALSO can't be fooled if it were
        // ever reached with one anyway (defense in depth, not the only
        // guard).
        write_entry("there", &OutboxEntry::fresh(envelope("here", "there", "msg-x"))).unwrap();

        let ack = ack_envelope("mallory", "here", "msg-x");
        let retired = retire_by_ack(&ack).unwrap();
        assert_eq!(retired, None, "a different signer's ack matches no spooled entry");

        assert_eq!(list_entries("there").unwrap().len(), 1, "the real entry survives untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ack_naming_another_msgid_retires_nothing() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-ack-wrong-msgid");

        write_entry("there", &OutboxEntry::fresh(envelope("here", "there", "msg-x"))).unwrap();

        // Correct signer, wrong text — a typo, or an ack for some entry
        // this box never spooled toward "there".
        let ack = ack_envelope("there", "here", "msg-does-not-exist");
        let retired = retire_by_ack(&ack).unwrap();
        assert_eq!(retired, None, "the signer is right but the named msgid matches nothing");

        assert_eq!(list_entries("there").unwrap().len(), 1, "msg-x is untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_entries_orders_oldest_first_by_minted_at() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-order");

        let mut newer = envelope("here", "there", "msg-new");
        newer.header.minted_at = "2026-09-07T01:00:00Z".to_string();
        let mut older = envelope("here", "there", "msg-old");
        older.header.minted_at = "2026-09-06T00:00:00Z".to_string();

        write_entry("there", &OutboxEntry::fresh(newer)).unwrap();
        write_entry("there", &OutboxEntry::fresh(older)).unwrap();

        let listed = list_entries("there").unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].envelope.msgid, "msg-old", "oldest mintedAt sorts first");
        assert_eq!(listed[1].envelope.msgid, "msg-new");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn link_backoff_doubles_on_failure_and_clears_on_success() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-backoff");

        assert!(read_link_state("there").unwrap().is_none(), "no failure yet — not held off");

        let first = back_off("there", 1_000, "transport-error").unwrap();
        assert_eq!(first.backoff_secs, DRAIN_BACKOFF_FLOOR_SECS, "the first failure backs off by the floor, not the floor doubled");

        let second = back_off("there", 1_000 + first.backoff_secs as i64, "transport-error").unwrap();
        assert_eq!(second.backoff_secs, DRAIN_BACKOFF_FLOOR_SECS * 2, "a second consecutive failure doubles");

        clear_link_state("there").unwrap();
        assert!(read_link_state("there").unwrap().is_none(), "success clears the link entirely");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_held_off_reads_the_recorded_deadline() {
        let state = LinkState {
            backoff_secs: 12,
            next_attempt_at: crate::time::iso_utc_from_epoch(2_000),
            last_outcome: "transport-error".to_string(),
        };
        assert!(is_held_off(&state, 1_500), "before the deadline: held off");
        assert!(!is_held_off(&state, 2_500), "past the deadline: no longer held off");
    }

    #[test]
    fn every_outbox_mutation_refuses_when_the_lock_cannot_be_taken() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-lock-eisdir");

        // Force `.stage.lock` to be a directory so opening it for the flock
        // fails with EISDIR — the same technique
        // `mail::an_unwritable_lock_path_makes_every_mail_write_err` uses for
        // the SAME underlying `try_stage_lock`.
        std::fs::create_dir_all(crate::fs::stage_dir().join(".stage.lock")).unwrap();

        let entry = OutboxEntry::fresh(envelope("here", "there", "msg-1"));
        assert!(write_entry("there", &entry).is_err());
        assert!(list_entries("there").is_err());
        assert!(back_off("there", 1_000, "transport-error").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_drain_on_one_link_does_not_run_concurrently() {
        // Ruling 3: `.bsy` is `LOCK_EX|LOCK_NB` — a second, concurrent taker
        // SKIPS rather than blocks behind the first, so a wedged drain can
        // never starve every later one. This is the non-blocking claim
        // itself; the "first finishes untouched" half is exercised by
        // `aoide-client`'s own drain tests, which hold this exact guard for
        // real network calls.
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-bsy-non-blocking");

        let first = try_take_link_lock("there").unwrap();
        assert!(first.is_some(), "the first taker succeeds");

        let second = try_take_link_lock("there").unwrap();
        assert!(second.is_none(), "a second, concurrent taker is skipped, never blocked");

        drop(first);
        let third = try_take_link_lock("there").unwrap();
        assert!(third.is_some(), "releasing the first frees the link for the next taker");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
