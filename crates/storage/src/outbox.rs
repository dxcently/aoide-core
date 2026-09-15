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

/// The ceiling [`back_off`] doubles up TO and never past — a link stuck on a
/// permanent transport failure (a missing `ssh` binary, a dead host) is
/// re-probed on this schedule instead of doubling forever. Deliberately its
/// OWN constant, not [`aoide_protocol::dialog::SPAWN_BACKOFF_MAX`] (60s,
/// what [`aoide_protocol::dialog::next_spawn_backoff`] itself caps at): a
/// permanently dead outbox link hammered every 60s forever is the exact
/// waste this ceiling exists to stop, so the outbox's own schedule is
/// longer than that unrelated spawn-retry convention.
pub const BACKOFF_CEILING_SECS: u64 = 900;

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

/// One node's pending-ack marker for `acked_msgid` — its CONTENT is the
/// pending ack entry's own msgid (its file stem, what [`entry_path`]
/// keys on), never empty, never binary data. Its sole job is making "is
/// an ack for this msgid already sitting undelivered in this node's
/// spool" a stat-plus-one-small-read instead of a directory scan (mail
/// register §26 outbox fix, review round 2): the live osaka spool holds
/// 16.5k+ entries, and walking/parsing every one of them under the
/// crate-wide stage lock on every ack deposit is exactly the
/// O(n)-under-a-shared-lock hazard the review flagged. `.ack/` is a
/// sibling of the entry files, never itself globbed by [`list_entries`]
/// (extension-filtered to `.json`, and `.ack` is a directory, not a
/// `.json` file) or drained.
///
/// Storing the entry's msgid (review round 3), not leaving the marker
/// content-free, is what lets [`has_pending_ack_unlocked`] verify the
/// entry it names is STILL actually there rather than trusting the
/// marker's mere existence: an out-of-band mover (the planned archive
/// script, deliberately out of THIS pass's scope, is expected to `mv`
/// receipts straight out of a node's directory) has no reason to know
/// `.ack/` exists at all, and never needs to — the gate self-heals a
/// marker whose entry has vanished instead of suppressing that
/// `acked_msgid`'s ack forever.
fn ack_marker_path(node: &str, acked_msgid: &str) -> PathBuf {
    node_dir(node).join(".ack").join(acked_msgid)
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
    /// a drain skips it on sight. **Parked, not condemned**: a policy
    /// refusal is remediable (the far end's `allows` can be granted), so
    /// [`unpark_entry`]/[`unpark_refused`] clear this flag and the next
    /// drain attempts the entry again; only `mail outbox rm` retires it.
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

/// Raw write of one entry file — assumes the caller already holds the
/// lock. The one place [`write_entry`] and [`write_ack_if_absent`] both
/// funnel their actual disk write through, so the two never drift on shape.
fn write_entry_unlocked(node: &str, entry: &OutboxEntry) -> Result<(), String> {
    let dir = node_dir(node);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = entry_path(node, &entry.envelope.msgid);
    let json = serde_json::to_string_pretty(entry).map_err(|e| e.to_string())?;
    atomic_write(&path, &json).map_err(|e| format!("{}: {e}", path.display()))
}

/// Spool one entry — `mail send`'s write-before-attempt (spec item 8).
/// Overwrites any existing file of the same `msgid` (only possible if a
/// caller somehow re-mints the identical envelope; ordinary operation
/// never does).
pub fn write_entry(node: &str, entry: &OutboxEntry) -> Result<(), String> {
    let node = node.to_string();
    let entry = entry.clone();
    with_lock(move || write_entry_unlocked(&node, &entry))
}

/// Is a pending (not yet delivered) ack already covering `acked_msgid`
/// sitting in `node`'s spool? Reads [`ack_marker_path`]'s one small file
/// (never a directory scan — review round 2, mail register §26) and,
/// critically, does NOT trust its mere existence (review round 3): the
/// marker names the entry it covers, and this function verifies that
/// entry is STILL actually spooled (`entry_path(node, marker content)`
/// exists) before answering `true`. A marker whose entry is gone — an
/// out-of-band mover took the entry file directly, the marker write
/// itself was interrupted leaving empty/garbage content, or anything
/// else made it stale — is treated as NOT pending and deleted right
/// here, in the same locked section, so the very call that discovers
/// the orphan also heals it: the next line in [`write_ack_if_absent`]
/// then spools normally instead of being suppressed forever. Assumes
/// the caller already holds the lock (matches this module's other
/// `*_unlocked` helpers).
fn has_pending_ack_unlocked(node: &str, acked_msgid: &str) -> Result<bool, String> {
    let marker = ack_marker_path(node, acked_msgid);
    let content = match std::fs::read_to_string(&marker) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => {
            // Unreadable marker — treat exactly like a stale one.
            let _ = std::fs::remove_file(&marker);
            return Ok(false);
        }
    };
    let entry_msgid = content.trim();
    if !entry_msgid.is_empty() && entry_path(node, entry_msgid).exists() {
        return Ok(true);
    }
    // Malformed (empty) content, or the entry it names is no longer
    // spooled — self-heal by removing the orphan.
    let _ = std::fs::remove_file(&marker);
    Ok(false)
}

/// Spool a freshly minted ack UNLESS an ack for the same `acked_msgid` is
/// already sitting in `node`'s spool, undelivered — the gate the outbox
/// investigation's fix calls for: a sender that keeps redelivering the same
/// letter (because its own earlier ack never arrived — MAIL.md spec item 5,
/// exactly the case [`crate::mail::DepositOutcome::Duplicate`]'s
/// `filed_letter` flag exists for) used to mint a BRAND-NEW ack envelope,
/// fresh `mintedAt` and fresh `msgid`, on every single redelivery, even
/// while the first one sat here the whole time, undelivered — one
/// permanent duplicate file per redelivery, unbounded. Checked and written
/// in the SAME lock acquisition (never two separate calls), so two racing
/// redeliveries can never both observe "nothing pending" and both spool.
///
/// Deliberately NOT a permanent ledger: once the pending ack is actually
/// delivered ([`mail_wire::drain_node`]'s own `Delivered` arm removes a
/// receipt-kind entry outright on confirmation — this crate has no
/// `mail_wire`, hence the doc reference rather than a link), the NEXT
/// redelivery correctly finds nothing pending here and spools again — spec
/// item 5's "a duplicate re-sends the ack because the sender's earlier one
/// evidently never arrived" must stay true for a REAL loss (the far end's
/// receiver never durably recorded a genuinely-delivered ack); this gate
/// only closes the narrower "one is still sitting right here" case. Returns
/// `true` when `entry` was newly spooled, `false` when a pending ack for
/// `acked_msgid` already covered it and nothing was written.
pub fn write_ack_if_absent(node: &str, acked_msgid: &str, entry: &OutboxEntry) -> Result<bool, String> {
    let node = node.to_string();
    let acked_msgid = acked_msgid.to_string();
    let entry = entry.clone();
    with_lock(move || {
        if has_pending_ack_unlocked(&node, &acked_msgid)? {
            return Ok(false);
        }
        write_entry_unlocked(&node, &entry)?;
        // The marker is written AFTER the entry, deliberately: a crash
        // between the two leaves a real, undelivered ack entry with no
        // marker — the next redelivery just spools a harmless second one
        // — rather than a marker with no entry behind it, which would
        // block every future redelivery forever with nothing to retire it.
        // Content is the entry's own msgid (review round 3), not empty —
        // what lets `has_pending_ack_unlocked` verify the entry it names
        // is still actually there rather than trusting existence alone.
        let marker = ack_marker_path(&node, &acked_msgid);
        if let Some(parent) = marker.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::write(&marker, entry.envelope.msgid.as_bytes())
            .map_err(|e| format!("{}: {e}", marker.display()))?;
        Ok(true)
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
        // If this is an ack (receipt-kind) entry, clear its pending-ack
        // marker in the SAME locked section — one file read (this entry
        // only, never a directory scan), so every retirement path (a
        // drain's own `Delivered` confirmation, an explicit `mail outbox
        // rm`, a test's manual simulation of delivery) uniformly lets a
        // later redelivery of the same acked_msgid correctly respool,
        // without every caller needing to know about the marker at all.
        // `has_pending_ack_unlocked`'s own self-healing already covers the
        // ordinary "entry vanished out-of-band, marker never told" case —
        // this is the fast path for when the entry is right here.
        match std::fs::read_to_string(&path).ok().and_then(|raw| serde_json::from_str::<OutboxEntry>(&raw).ok()) {
            Some(parsed) if parsed.envelope.header.kind == crate::mail::ENTRY_TYPE_RECEIPT => {
                let _ = std::fs::remove_file(ack_marker_path(&node, &parsed.envelope.text));
            }
            Some(_) => {
                // An ordinary (letter) entry never carries a marker.
            }
            None => {
                // The entry couldn't be read or parsed at all (review
                // round 3 NIT) — rare (corruption, or a caller racing its
                // own prior removal). Its content can't tell us the
                // `acked_msgid` it covered, so fall back to a scan of
                // ONLY `.ack/` (never the whole node directory — removal
                // is rare, unlike the hot deposit path this must stay
                // O(1) for) looking for a marker whose content names
                // THIS entry's own msgid, and clear it if found.
                clear_marker_pointing_to_msgid(&node, &msgid);
            }
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    })
}

/// Un-park one entry — the operator's answer to a remediable policy
/// refusal (`aoide mail outbox retry <msgid>`). A refusal is a PARKED
/// state, not a verdict: the far end's `allows` set can be granted after
/// the fact (`aoide node allow <sender> <cap> on` ON THE RECEIVING HOST),
/// so the entry must be retriable without re-minting it (the stored
/// envelope's signed bytes are what the far end dedups on — see
/// [`OutboxEntry`]'s own doc).
///
/// Clears `refused`, records `last_outcome = "retry requested"` so the
/// spool's own history says why this entry is suddenly being dialed again,
/// and deliberately leaves `tries` exactly where it was: the attempt
/// counter counts ATTEMPTS, and an un-park performs none. `Ok(false)` when
/// nothing named `msgid` was spooled, or it was there but was not parked
/// at all (already un-parked, or never refused) — never an error, the same
/// "a redundant ask is a clean no-op" discipline [`remove_entry`] holds.
///
/// Read-modify-write in ONE locked section, through the same
/// [`write_entry_unlocked`] atomic path every other spool write uses, so a
/// concurrent drain can never observe a half-updated entry.
pub fn unpark_entry(node: &str, msgid: &str) -> Result<bool, String> {
    let node = node.to_string();
    let msgid = msgid.to_string();
    with_lock(move || {
        let path = entry_path(&node, &msgid);
        let Ok(raw) = std::fs::read_to_string(&path) else { return Ok(false) };
        let Ok(mut entry) = serde_json::from_str::<OutboxEntry>(&raw) else { return Ok(false) };
        if !entry.refused {
            return Ok(false);
        }
        entry.refused = false;
        entry.last_outcome = "retry requested".to_string();
        write_entry_unlocked(&node, &entry)?;
        Ok(true)
    })
}

/// Un-park EVERY parked entry for `node` — `aoide mail outbox retry
/// --refused [<node>]`. Returns how many were actually un-parked (0 for a
/// node with nothing parked, a node that has never spooled anything, or an
/// unknown node name), never an error for any of those.
///
/// One `list_entries` read, then one [`unpark_entry`] per parked row: each
/// re-reads and re-writes its OWN single entry under the lock, so a drain
/// running concurrently can neither be starved (no lock is held across the
/// whole sweep) nor lose an entry it is in the middle of recording (every
/// mutation is read-modify-write of one file). An entry that vanishes
/// between the listing and its own un-park (a concurrent `mail outbox rm`,
/// or a real ack retiring it) simply does not count — no error.
pub fn unpark_refused(node: &str) -> Result<usize, String> {
    let parked: Vec<String> = list_entries(node)?
        .into_iter()
        .filter(|e| e.refused)
        .map(|e| e.envelope.msgid)
        .collect();
    let mut n = 0;
    for msgid in parked {
        if unpark_entry(node, &msgid)? {
            n += 1;
        }
    }
    Ok(n)
}

/// Fallback for [`remove_entry`]'s rare unreadable/unparsable-entry case
/// (review round 3 NIT): scan `<node>/.ack/` (only that small
/// subdirectory, never the node's whole spool) for a marker whose
/// content equals `msgid` — the entry being removed — and delete it.
/// Tolerant of a missing `.ack/` (nothing to do) and of any individual
/// marker being unreadable (skipped, not an error) — this is a
/// best-effort cleanup, never load-bearing for correctness the way
/// `has_pending_ack_unlocked`'s own self-heal already is.
fn clear_marker_pointing_to_msgid(node: &str, msgid: &str) {
    let dir = node_dir(node).join(".ack");
    let Ok(read_dir) = std::fs::read_dir(&dir) else { return };
    for dir_entry in read_dir.flatten() {
        let path = dir_entry.path();
        if std::fs::read_to_string(&path).map(|c| c.trim() == msgid).unwrap_or(false) {
            let _ = std::fs::remove_file(&path);
        }
    }
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
/// from whatever the existing state recorded, capped at
/// [`BACKOFF_CEILING_SECS`] (mirrors `client::pair_watch`'s own
/// `SPAWN_BACKOFF_INITIAL`-then-doubling sequencing: the floor itself is
/// the FIRST backoff, only a SECOND consecutive failure doubles it), or
/// from [`DRAIN_BACKOFF_FLOOR_SECS`] on a link's first-ever failure. A
/// plain `saturating_mul(2).min(ceiling)` here rather than
/// [`aoide_protocol::dialog::next_spawn_backoff`] — that helper's own cap
/// (`SPAWN_BACKOFF_MAX`, 60s) is the wrong ceiling for a link that stays
/// down for a long time, not this backoff's own doubling rule. Writes and
/// returns the new state. `now_epoch` is the caller's own "now."
pub fn back_off(node: &str, now_epoch: i64, outcome: &str) -> Result<LinkState, String> {
    let existing = read_link_state(node)?;
    let floor = Duration::from_secs(DRAIN_BACKOFF_FLOOR_SECS);
    let ceiling = Duration::from_secs(BACKOFF_CEILING_SECS);
    let this_backoff = match existing {
        Some(s) => Duration::from_secs(s.backoff_secs).max(floor).saturating_mul(2).min(ceiling),
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

    /// `aoide mail outbox retry <msgid>`'s storage half: a parked entry
    /// comes back un-parked with `tries` UNTOUCHED (an un-park is not an
    /// attempt), its outcome recording why it is being dialed again.
    #[test]
    fn unpark_entry_flips_refused_and_preserves_tries() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-unpark-entry");

        let mut parked = OutboxEntry::fresh(envelope("here", "there", "msg-park"));
        parked.tries = 4;
        parked.last_try_at = "2026-09-07T00:00:00Z".to_string();
        parked.last_outcome = "refused: bad-msgid".to_string();
        parked.refused = true;
        write_entry("there", &parked).unwrap();

        assert!(unpark_entry("there", "msg-park").unwrap(), "a parked entry un-parks");

        let after = list_entries("there").unwrap();
        assert_eq!(after.len(), 1, "an un-park never removes the entry — the spool is the record");
        assert!(!after[0].refused, "refused is cleared");
        assert_eq!(after[0].tries, 4, "un-parking is not an attempt — tries is preserved exactly");
        assert_eq!(after[0].last_try_at, "2026-09-07T00:00:00Z", "the last real attempt's timestamp is untouched");
        assert_eq!(after[0].last_outcome, "retry requested", "the spool's own history says why it is dialed again");
        assert_eq!(after[0].envelope.msgid, "msg-park", "the stored envelope is untouched — a retry resends the same signed bytes");

        assert!(!unpark_entry("there", "msg-park").unwrap(), "un-parking an already-live entry is a clean no-op");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unpark_entry_on_an_unknown_msgid_is_ok_false() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-unpark-unknown");

        assert!(!unpark_entry("there", "never-spooled").unwrap(), "no such msgid is Ok(false), never an error");
        assert_eq!(unpark_refused("there").unwrap(), 0, "a node with nothing spooled has nothing parked");

        // An entry that was never refused is not "un-parked" either — the
        // flag was already clear, so there is nothing to report.
        write_entry("there", &OutboxEntry::fresh(envelope("here", "there", "msg-live"))).unwrap();
        assert!(!unpark_entry("there", "msg-live").unwrap());
        assert_eq!(list_entries("there").unwrap()[0].last_outcome, "", "a non-parked entry is never rewritten");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unpark_refused_sweeps_only_the_parked_entries_of_one_node() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-unpark-refused-sweep");

        let mut parked_a = OutboxEntry::fresh(envelope("here", "there", "msg-parked-a"));
        parked_a.refused = true;
        parked_a.tries = 1;
        let mut parked_b = OutboxEntry::fresh(envelope("here", "there", "msg-parked-b"));
        parked_b.refused = true;
        write_entry("there", &parked_a).unwrap();
        write_entry("there", &parked_b).unwrap();
        write_entry("there", &OutboxEntry::fresh(envelope("here", "there", "msg-never-refused"))).unwrap();

        // Another node's parked entry is NEVER touched by a sweep of this one.
        let mut elsewhere = OutboxEntry::fresh(envelope("here", "elsewhere", "msg-parked-elsewhere"));
        elsewhere.refused = true;
        write_entry("elsewhere", &elsewhere).unwrap();

        assert_eq!(unpark_refused("there").unwrap(), 2, "both parked entries, and only they, un-park");
        let there = list_entries("there").unwrap();
        assert_eq!(there.len(), 3, "nothing is removed by a sweep");
        assert!(there.iter().all(|e| !e.refused), "every parked entry on the node is live again");
        assert_eq!(there.iter().find(|e| e.envelope.msgid == "msg-parked-a").unwrap().tries, 1);
        assert_eq!(unpark_refused("there").unwrap(), 0, "a second sweep finds nothing left to un-park");

        assert!(list_entries("elsewhere").unwrap()[0].refused, "another node's parked entry is untouched");

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

    /// A `receipt` entry acking `acked_msgid`, addressed back to `to_node`
    /// — the shape `write_ack_if_absent` scans for.
    fn ack_for(to_node: &str, acked_msgid: &str, minted_at: &str) -> Envelope {
        Envelope {
            header: Header {
                version: "1".to_string(),
                from: Address { node: "here".to_string(), name: "bob".to_string() },
                to: Address { node: to_node.to_string(), name: "alice".to_string() },
                kind: crate::mail::ENTRY_TYPE_RECEIPT.to_string(),
                minted_at: minted_at.to_string(),
                origin_mesh: String::new(),
            },
            text: acked_msgid.to_string(),
            sig: "ef".repeat(32),
            msgid: format!("ack-{minted_at}"),
        }
    }

    #[test]
    fn write_ack_if_absent_spools_once_while_pending_then_again_after_delivery() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("write-ack-if-absent");

        // The first mint for a redelivered letter's ack spools normally.
        let first = OutboxEntry::fresh(ack_for("there", "acked-msgid", "2026-09-13T00:00:00Z"));
        assert!(write_ack_if_absent("there", "acked-msgid", &first).unwrap(), "the first ack for this msgid spools");
        assert_eq!(list_entries("there").unwrap().len(), 1);

        // Ten further redeliveries of the SAME letter, while the first ack
        // is still sitting here undelivered, must spool NOTHING new — this
        // is the outbox investigation's own bug: 16.5k duplicate receipts
        // from exactly this loop.
        for i in 0..10 {
            let redelivered = OutboxEntry::fresh(ack_for("there", "acked-msgid", &format!("2026-09-13T00:0{i}:00Z")));
            assert!(
                !write_ack_if_absent("there", "acked-msgid", &redelivered).unwrap(),
                "a pending ack for the same acked_msgid must block a second spool"
            );
        }
        assert_eq!(list_entries("there").unwrap().len(), 1, "ten redeliveries while pending spool nothing new");

        // Once the pending ack is actually delivered (removed — mirrors
        // `mail_wire::drain_node`'s own `Delivered` arm), a LATER
        // redelivery must be free to respool — spec item 5's "a duplicate
        // re-sends the ack because the sender's earlier one evidently never
        // arrived" must still hold for a genuine loss.
        remove_entry("there", &first.envelope.msgid).unwrap();
        assert!(list_entries("there").unwrap().is_empty());

        let after_delivery = OutboxEntry::fresh(ack_for("there", "acked-msgid", "2026-09-13T01:00:00Z"));
        assert!(
            write_ack_if_absent("there", "acked-msgid", &after_delivery).unwrap(),
            "once the earlier ack is gone, a fresh redelivery must respool it"
        );
        assert_eq!(list_entries("there").unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_ack_if_absent_does_not_enumerate_the_spool_directory() {
        // Review round 2 (mail register §26): `has_pending_ack_unlocked`
        // must be a single `exists()` stat on the marker, never a
        // directory scan — the live osaka spool holds 16.5k+ files, and
        // this is exactly the O(n)-under-the-shared-stage-lock hazard the
        // review flagged. Proven here by seeding the node's directory
        // with a pile of entries that a directory scan would have to open
        // and parse — including files a naive scan would choke or hang
        // on (unreadable garbage, and a directory to recurse into) — and
        // asserting the gate still answers correctly regardless.
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("write-ack-if-absent-no-scan");

        // A pile of unrelated, perfectly ordinary entries.
        for i in 0..200 {
            let letter = envelope("here", "there", &format!("unrelated-{i}"));
            write_entry("there", &OutboxEntry::fresh(letter)).unwrap();
        }
        // A file a naive directory scan would try to open and parse as
        // JSON and choke on.
        std::fs::write(node_dir("there").join("garbage.json"), b"not json at all").unwrap();
        // A subdirectory a naive scan might try to recurse into.
        std::fs::create_dir_all(node_dir("there").join("some-subdir")).unwrap();

        // No ack for "acked-msgid" has ever been spooled — the marker
        // does not exist — so the gate must say "not pending" despite the
        // directory being full of unrelated files.
        assert!(
            !has_pending_ack_unlocked("there", "acked-msgid").unwrap(),
            "no marker means not pending, regardless of what else is in the directory"
        );

        let ack = OutboxEntry::fresh(ack_for("there", "acked-msgid", "2026-09-13T00:00:00Z"));
        assert!(write_ack_if_absent("there", "acked-msgid", &ack).unwrap());

        // Now it IS pending — again, correctly answered without needing
        // to find the one matching entry among the 200+ unrelated files.
        assert!(has_pending_ack_unlocked("there", "acked-msgid").unwrap());
        assert!(
            !write_ack_if_absent("there", "acked-msgid", &ack).unwrap(),
            "still pending — a redelivery spools nothing new"
        );

        // A DIFFERENT acked_msgid was never spooled either, even though
        // an ack for a different one now sits in the same directory.
        assert!(!has_pending_ack_unlocked("there", "some-other-msgid").unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_orphaned_marker_self_heals_and_a_later_redelivery_respools() {
        // Review round 3: the planned (out-of-scope-for-this-fix) archive
        // script will `mv` receipt entries straight out of a node's
        // directory, never touching `.ack/` — it doesn't know it exists
        // and never needs to. A marker left behind by that MUST NOT
        // suppress a genuinely-lost ack's respool forever; the gate has
        // to notice its named entry is gone and self-heal.
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("write-ack-if-absent-orphan-marker");

        let first = OutboxEntry::fresh(ack_for("there", "acked-msgid", "2026-09-13T00:00:00Z"));
        assert!(write_ack_if_absent("there", "acked-msgid", &first).unwrap());
        assert_eq!(list_entries("there").unwrap().len(), 1);
        let marker = ack_marker_path("there", "acked-msgid");
        assert!(marker.exists(), "write_ack_if_absent always leaves a marker behind a fresh spool");

        // Simulate the out-of-band mover: the entry file is removed
        // DIRECTLY, never through `remove_entry` — so the marker is left
        // behind, orphaned, still naming a msgid that no longer exists.
        std::fs::remove_file(node_dir("there").join(format!("{}.json", first.envelope.msgid))).unwrap();
        assert!(list_entries("there").unwrap().is_empty(), "the entry is really gone");
        assert!(marker.exists(), "nothing cleared the marker — it is genuinely orphaned");

        // A later redelivery of the SAME acked_msgid must not be
        // suppressed by the orphan — it respools, exactly like a genuine
        // loss (spec item 5).
        let redelivered = OutboxEntry::fresh(ack_for("there", "acked-msgid", "2026-09-13T00:05:00Z"));
        assert!(
            write_ack_if_absent("there", "acked-msgid", &redelivered).unwrap(),
            "an orphaned marker must never block a real redelivery forever"
        );
        assert_eq!(list_entries("there").unwrap().len(), 1);

        // The stale marker was healed away and replaced by one naming the
        // freshly spooled entry — not left pointing at the vanished one.
        let content = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(content, redelivered.envelope.msgid, "the marker now names the entry actually sitting here");

        // And the gate correctly reports pending again for the new entry.
        assert!(has_pending_ack_unlocked("there", "acked-msgid").unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn back_off_never_exceeds_the_ceiling() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("outbox-backoff-ceiling");

        // A link stuck on a permanent transport failure — many consecutive
        // failures in a row must converge to BACKOFF_CEILING_SECS and never
        // grow past it, so a dead link is re-probed on a schedule instead
        // of the raw doubling this used to do forever.
        let mut now = 1_000_i64;
        let mut last = back_off("there", now, "transport-error").unwrap();
        for _ in 0..20 {
            now += last.backoff_secs as i64;
            last = back_off("there", now, "transport-error").unwrap();
            assert!(last.backoff_secs <= BACKOFF_CEILING_SECS, "backoff must never exceed the ceiling");
        }
        assert_eq!(last.backoff_secs, BACKOFF_CEILING_SECS, "repeated failures converge to the ceiling");

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
