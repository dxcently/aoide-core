//! `state/mail/` — the addressed, signed, append-only mailbase
//! (`docs/architecture/MAIL.md`, phase P-M1). Absorbs the old per-host
//! `inbox.json` receipt log (MAIL.md decision 8): today's two delivery
//! seams (`conduct/graph/send.rs`, `server/a2a.rs`) file a `receipt` entry
//! here instead, and a box's own `mail send --to self/<name>` files a
//! `letter`. **No wire, no outbox, no transit, no zones, no doorbell, no
//! `--hold` — those are P-M2 through P-M5** (MAIL.md's own Phases section);
//! nothing here reads a mesh declaration, opens a socket, or injects a byte
//! into a pty.
//!
//! ## The envelope
//!
//! [`Header`] is the closed, eight-field canonical string MAIL.md's "The
//! envelope" section defines — `version · from.node · from.name · to.node
//! · to.name · type · mintedAt · originMesh`, NUL-joined, **verbatim bytes**
//! (no trim, no case fold, no JSON — [`canonical_header_bytes`], not
//! `wire_auth::canonical_string`, which folds both). [`Envelope`] is that
//! header plus `text`, `sig` (origin's ed25519 over `header ‖ 0x00 ‖ text`),
//! and `msgid` (hex sha256 over `sig ‖ header ‖ 0x00 ‖ text` — no separator
//! before `header`, one before `text`; see [`seal`]). Deliberately absent:
//! the wire envelope's sibling `mesh`/`transit` fields — those are routing
//! facts that mean nothing until a mesh declaration exists (P-M4), and
//! `header.origin_mesh` (always `""` here, since P-M1 has no mesh config)
//! stands in for them wherever P-M1 renders a "mesh" column, since mesh and
//! originMesh are defined to start equal and nothing in this phase can ever
//! diverge them.
//!
//! `self` resolves at mint time through [`crate::display::local_host_name`]
//! — the literal `"self"` never enters a header, a signature, or a `msgid`
//! (architect's ruling 3); `--to self/<name>` is surface sugar the command
//! layer resolves before calling [`file_letter`].
//!
//! ## The store
//!
//! Three files under `state_dir()/mail/` (MAIL.md "Store"):
//!
//! ```text
//! base.jsonl      append-only, one Entry per line, immutable once written
//! cursors.json    { "<name>": { "seq": n, "readers": [sessionId, …] } }
//! seen.jsonl      one {"msgid","receivedAt"} per line, append-only
//! ```
//!
//! **Write order, under the lock, no other:** [`truncate_torn_tail`] →
//! append the entry → `fsync` → append to `seen.jsonl` ([`append_base_line`]
//! then [`append_seen_line`], both inside [`file_entry`]). A `seen` line
//! whose `msgid` is absent from the base is a crash between the two writes,
//! and that `msgid` is accepted again — the reverse order would lose mail.
//! Only the write path truncates a torn tail (ruling 9); every reader here
//! ([`read_entries_unlocked`]) tolerates and skips a malformed trailing
//! line and writes nothing, exactly as [`crate::ledger::read_ledger`]
//! already does — `crate::ledger`'s `append_ledger_entry`/`read_ledger`
//! pair is this crate's existing append-only-JSONL precedent; this module
//! adds the fsync-before-seen ordering and the torn-tail truncation that
//! precedent doesn't need.
//!
//! **Every mutation AND every read funnels through [`with_lock`]**, one
//! process-wide [`crate::fs::try_stage_lock`] acquisition — the SAME
//! `.stage.lock` [`crate::fs::with_stage_lock`] already flocks; a second
//! lock file under `state/mail/` would be a new abstraction for zero added
//! correctness. Unlike that fail-open sibling, a write that cannot take
//! this lock **fails** (`Err`) rather than running anyway (architect's
//! ruling 1) — the one behavioural change this phase makes to the locking
//! story, confined to mail's own writers. `with_lock` also runs
//! [`migrate_if_needed`] first, every time, so the very first store touch
//! by ANY command — read or write — performs the one-shot `inbox.json` →
//! `inbox.json.migrated` field-mapping under the SAME critical section
//! (ruling 2), and every call after that sees the old file already gone
//! and does nothing.
//!
//! ## Commands this phase ships
//!
//! `storage/src/commands.rs::register_mail` wires `mail`, `mail send`
//! (`--to self/<name>` only), `mail read`, `mail show`, `mail mark`,
//! `mail rm`. `mail outbox`/`mail route`/`--hold`/`--transit` are later
//! phases and are not registered yet.

use crate::display;
use crate::fs::{atomic_write, state_dir};
use crate::identity;
use crate::stage::{load_stage, write_stage};
use crate::time::{now_iso_utc, parse_iso_utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::Write as _;
use std::path::PathBuf;

/// The canonical header's `version` field for this phase. Bumps only if the
/// eight-field shape itself changes — independent of `CONTRACTS.md`'s crate
/// version (ruling 4: no bump this phase).
pub const ENVELOPE_VERSION: &str = "1";
/// `Header.kind`/`Entry.kind`'s value for a `mail send`-filed letter.
pub const ENTRY_TYPE_LETTER: &str = "letter";
/// `Header.kind`/`Entry.kind`'s value for a delivery receipt (what
/// `inbox.json` carried, per MAIL.md "Store").
pub const ENTRY_TYPE_RECEIPT: &str = "receipt";

/// `<node>/<name>` — one side of a header. Free text on both sides; nothing
/// here validates against a mesh declaration (P-M1 has none) or clamps
/// grammar (rendering's job, P-M5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub node: String,
    pub name: String,
}

/// The eight closed canonical-header fields (MAIL.md "The envelope").
/// [`canonical_header_bytes`] is the ONLY place their signed byte order is
/// defined; every other reader of this struct goes through JSON field names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub version: String,
    pub from: Address,
    pub to: Address,
    #[serde(rename = "type")]
    pub kind: String,
    pub minted_at: String,
    /// The zone the origin posted in. Always `""` in P-M1 — there is no
    /// mesh declaration yet to post into (kept as a real field, not
    /// omitted, because it is part of the closed eight-field header
    /// MAIL.md's byte formula signs; a later phase's mesh-aware sender
    /// simply stops leaving it blank).
    pub origin_mesh: String,
}

/// The signed, immutable unit that moves (MAIL.md "The envelope"). No
/// `mesh`/`transit` fields — see this module's doc for why those wait for
/// P-M4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub header: Header,
    pub text: String,
    /// Hex ed25519 signature over `header ‖ 0x00 ‖ text` ([`seal`]).
    pub sig: String,
    /// Hex sha256 over `sig ‖ header ‖ 0x00 ‖ text` ([`seal`]).
    pub msgid: String,
}

/// One `base.jsonl` line: an envelope plus local, never-signed facts
/// (MAIL.md "Store").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// Local to this node, like an NNTP article number — never crosses a
    /// link. `last line's seq + 1`, read under the lock ([`next_seq`]).
    pub seq: u64,
    pub received_at: String,
    /// Mirrors `envelope.header.kind` — cheap filtering without parsing
    /// the full envelope (the JSON shape MAIL.md's "Store" example shows).
    #[serde(rename = "type")]
    pub kind: String,
    /// The hop that deposited it; always `"self"` in P-M1 — there is no
    /// other hop yet.
    pub via: String,
    pub envelope: Envelope,
}

/// A reader's high-water mark over one name (MAIL.md "Store"; the NNTP
/// `.newsrc` shape). `readers` records who has read this name — the P-M5
/// doorbell's targeting list, populated starting now even though nothing
/// reads it yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub readers: Vec<String>,
}

/// `cursors.json`'s whole shape is this bare map — no wrapper, no schema
/// version (MAIL.md shows it unwrapped; this module does not add one).
pub type Cursors = BTreeMap<String, Cursor>;

/// One `seen.jsonl` line — dedup memory, outlives `mail rm` pruning by
/// design (MAIL.md "Store": "keep-all... `mail rm` never touches
/// `seen.jsonl`").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeenEntry {
    msgid: String,
    received_at: String,
}

/// `$AOIDE_STATE_DIR/mail/` (ordinary [`state_dir`] resolution — see that
/// function's own doc for the `AOIDE_STATE_DIR`-then-`AOIDE_ROOT/state`
/// precedence every state file shares).
pub fn mail_dir() -> PathBuf {
    state_dir().join("mail")
}
pub fn base_path() -> PathBuf {
    mail_dir().join("base.jsonl")
}
pub fn cursors_path() -> PathBuf {
    mail_dir().join("cursors.json")
}
pub fn seen_path() -> PathBuf {
    mail_dir().join("seen.jsonl")
}

/// The pre-mail `state/inbox.json` path, recomputed directly rather than
/// through the now-deleted `inbox` module — `inbox.rs`'s own
/// `inbox_path()` was exactly this.
fn legacy_inbox_path() -> PathBuf {
    state_dir().join("inbox.json")
}

/// Just enough of the old `InboxFile`/`InboxEntry` shape to field-map it
/// once (ruling 7/8: `context` and the read flag are both dropped, so
/// neither is declared here — an unknown field is simply ignored by serde,
/// never an error).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyInboxEntry {
    #[serde(default)]
    from: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    received_at: String,
}

#[derive(Debug, Default, Deserialize)]
struct LegacyInboxFile {
    #[serde(default)]
    entries: Vec<LegacyInboxEntry>,
}

/// Hex-encode raw bytes, lowercase, no separator. A small local copy, not a
/// reach into `identity.rs`'s or `wire_auth.rs`'s own private copies — this
/// crate's established convention (`wire_auth.rs`'s own doc on its copy) is
/// a tiny per-module copy over a shared `pub` utility.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string to raw bytes — `None` on an odd length or any
/// non-hex-digit character, never a panic (feeds on a stored/tampered
/// field in the msgid-recomputation check, never trusted as well-formed).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// The canonical header string, **verbatim bytes**: the eight fields
/// NUL-joined in MAIL.md's fixed order, no trim, no case fold, no JSON — so
/// key order and whitespace can never make two hops disagree, and no hop
/// can change the case of a name without breaking the signature. The ONLY
/// place this order is defined; [`seal`] and [`compute_msgid`] both go
/// through here rather than assembling the string twice.
fn canonical_header_bytes(h: &Header) -> Vec<u8> {
    [
        h.version.as_str(),
        h.from.node.as_str(),
        h.from.name.as_str(),
        h.to.node.as_str(),
        h.to.name.as_str(),
        h.kind.as_str(),
        h.minted_at.as_str(),
        h.origin_mesh.as_str(),
    ]
    .join("\0")
    .into_bytes()
}

/// Recompute `msgid` from a (possibly tampered) header/text/sig triple —
/// `hex sha256 over sig ‖ header ‖ 0x00 ‖ text`, no separator before
/// `header`, one before `text` (MAIL.md "The envelope"). `None` only when
/// `sig_hex` itself doesn't decode; a bad/tampered `header` or `text` still
/// recomputes cleanly, just to a DIFFERENT `msgid` — that mismatch is the
/// tamper-evidence this function exists to make checkable.
fn compute_msgid(header: &Header, text: &str, sig_hex: &str) -> Option<String> {
    let sig_bytes = hex_decode(sig_hex)?;
    let header_bytes = canonical_header_bytes(header);
    let mut input = Vec::with_capacity(sig_bytes.len() + header_bytes.len() + 1 + text.len());
    input.extend_from_slice(&sig_bytes);
    input.extend_from_slice(&header_bytes);
    input.push(0u8);
    input.extend_from_slice(text.as_bytes());
    Some(hex_encode(&Sha256::digest(&input)))
}

/// Sign `header ‖ 0x00 ‖ text` with `kp` and derive `msgid` from the result
/// — the one place a fresh envelope is sealed. Origin-signed only (ruling
/// 6): P-M1 never verifies anyone else's signature, since there is no one
/// else yet.
fn seal(header: &Header, text: &str, kp: &identity::Keypair) -> (String, String) {
    let mut sig_input = canonical_header_bytes(header);
    sig_input.push(0u8);
    sig_input.extend_from_slice(text.as_bytes());
    let sig_hex = hex_encode(&kp.sign(&sig_input).to_bytes());
    let msgid = compute_msgid(header, text, &sig_hex)
        .expect("a signature this function just hex-encoded always decodes");
    (sig_hex, msgid)
}

/// Fail-closed choke point EVERY mail operation, read or write, funnels
/// through exactly once at its own top level: takes the shared stage lock
/// ([`crate::fs::try_stage_lock`]), runs [`migrate_if_needed`], then `f`.
/// **Never call this from inside a function that is itself only ever
/// reached through `with_lock`** — `try_stage_lock` opens a fresh fd per
/// call and is not re-entrant (same contract `with_stage_lock` documents),
/// so nesting it deadlocks a real second acquisition and merely
/// double-locks/unlocks in the best case. Every raw helper below
/// (`read_entries_unlocked`, `append_base_line`, `next_seq`, …) is written
/// assuming its caller already holds this lock.
fn with_lock<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match crate::fs::try_stage_lock(move || {
        ensure_mail_dir()?;
        migrate_if_needed()?;
        f()
    }) {
        Ok(inner) => inner,
        Err(lock_err) => Err(lock_err),
    }
}

fn ensure_mail_dir() -> Result<(), String> {
    let dir = mail_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// One-shot, idempotent `inbox.json` → typed `receipt` entries, run under
/// the SAME lock acquisition as whichever operation triggered it (ruling
/// 2) — never hung off [`crate::fs::migrate_root_once`], which stays
/// exactly as `a30d25f` left it. Checking `legacy_inbox_path()`'s mere
/// existence as the "already migrated?" test is what makes a concurrent
/// second opener a clean no-op: the first opener's rename (at the end of
/// this function, inside the same critical section) is the one fact a
/// second, lock-serialized caller observes.
///
/// The old per-entry `read` flag has no high-water-mark counterpart and is
/// not carried (ruling 8: every migrated entry is unread once); `context`
/// is dropped too (ruling 7) — [`LegacyInboxEntry`] never declares either
/// field, so there is nothing to carry even by accident.
///
/// A crash between appending row N and the rename below leaves `inbox.json`
/// in place, so a retry re-enters this same loop over the same rows —
/// [`seal`] is deterministic, so a row already filed recomputes the exact
/// same `msgid`. Reading `seen.jsonl` into a set ONCE before the loop and
/// skipping a row already in it is what makes that retry file each legacy
/// row exactly once instead of duplicating rows `1..N`.
fn migrate_if_needed() -> Result<(), String> {
    let old_path = legacy_inbox_path();
    let raw = match std::fs::read_to_string(&old_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", old_path.display())),
    };
    let legacy: LegacyInboxFile = serde_json::from_str(&raw)
        .map_err(|e| format!("{}: unreadable legacy inbox: {e}", old_path.display()))?;

    let node = display::local_host_name();
    let (kp, _) = identity::load_or_mint().map_err(|e| e.to_string())?;
    let already_seen = read_seen_msgids_unlocked()?;

    for row in &legacy.entries {
        let header = Header {
            version: ENVELOPE_VERSION.to_string(),
            from: Address { node: node.clone(), name: row.from.clone() },
            to: Address { node: node.clone(), name: row.target.clone() },
            kind: ENTRY_TYPE_RECEIPT.to_string(),
            minted_at: row.received_at.clone(),
            origin_mesh: String::new(),
        };
        let (sig, msgid) = seal(&header, &row.text, &kp);
        if already_seen.contains(&msgid) {
            continue;
        }
        let envelope = Envelope { header, text: row.text.clone(), sig, msgid: msgid.clone() };
        let entry = Entry {
            seq: next_seq()?,
            received_at: row.received_at.clone(),
            kind: ENTRY_TYPE_RECEIPT.to_string(),
            via: "self".to_string(),
            envelope,
        };
        append_base_line(&entry)?;
        append_seen_line(&msgid, &row.received_at)?;
    }

    let migrated_path = match old_path.parent() {
        Some(p) => p.join("inbox.json.migrated"),
        None => return Err(format!("{}: no parent directory", old_path.display())),
    };
    if !migrated_path.exists() {
        std::fs::rename(&old_path, &migrated_path).map_err(|e| {
            format!("{}: rename to {}: {e}", old_path.display(), migrated_path.display())
        })?;
    }
    Ok(())
}

/// Tolerant whole-file read of `base.jsonl` — skips a malformed line
/// (including a torn tail) rather than erroring, exactly like
/// [`crate::ledger::read_ledger`]; never truncates (ruling 9, only the
/// write path does that). **Raw — assumes the caller already holds the
/// lock**, same contract every other function in this "unlocked" family
/// shares.
fn read_entries_unlocked() -> Result<Vec<Entry>, String> {
    let path = base_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    Ok(raw.lines().filter_map(|l| serde_json::from_str::<Entry>(l).ok()).collect())
}

/// Tolerant whole-file read of `seen.jsonl`'s `msgid` column into a set —
/// same skip-malformed-lines contract as [`read_entries_unlocked`]. Raw —
/// assumes the caller already holds the lock. [`migrate_if_needed`] reads
/// this ONCE before its row loop, not per row, so retrying after a crash
/// mid-migration stays one lookup per row rather than one file read.
fn read_seen_msgids_unlocked() -> Result<HashSet<String>, String> {
    let path = seen_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    Ok(raw.lines().filter_map(|l| serde_json::from_str::<SeenEntry>(l).ok()).map(|s| s.msgid).collect())
}

/// `last line's seq + 1`, read under the lock (MAIL.md "Store"). Raw —
/// assumes the caller already holds the lock and has already truncated any
/// torn tail (every caller here is [`file_entry`]/[`migrate_if_needed`],
/// both reached only through [`with_lock`]).
fn next_seq() -> Result<u64, String> {
    Ok(read_entries_unlocked()?.last().map(|e| e.seq + 1).unwrap_or(1))
}

/// Truncate `base.jsonl` back to its last complete (`\n`-terminated) line —
/// the write path's half of "a crash safe log" (MAIL.md "Store"). A
/// `serde_json`-written line never contains a raw `0x0A` byte inside itself
/// (a newline in a JSON string is always the two-byte escape `\n`), so a
/// literal newline byte in this file only ever marks a line we ourselves
/// terminated — "does the file end in `\n`" is therefore a sound torn-tail
/// signal, not a heuristic. A missing file is not torn, it is simply empty.
fn truncate_torn_tail(path: &std::path::Path) -> Result<(), String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return Ok(());
    }
    let cut = bytes.iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.set_len(cut as u64).map_err(|e| format!("{}: {e}", path.display()))
}

/// Append one line to `base.jsonl`: truncate any torn tail, append,
/// `fsync`. Raw — assumes the caller already holds the lock.
fn append_base_line(entry: &Entry) -> Result<(), String> {
    let path = base_path();
    truncate_torn_tail(&path)?;
    let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    f.write_all(b"\n").map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

/// Append one line to `seen.jsonl` — no `fsync` (only the base write needs
/// the crash-safety guarantee; the write-order rule only requires this
/// happen AFTER the base append returns, which every caller already
/// ensures by calling it second). Raw — assumes the caller holds the lock.
fn append_seen_line(msgid: &str, received_at: &str) -> Result<(), String> {
    let path = seen_path();
    let seen = SeenEntry { msgid: msgid.to_string(), received_at: received_at.to_string() };
    let line = serde_json::to_string(&seen).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    f.write_all(b"\n").map_err(|e| e.to_string())
}

fn load_cursors() -> Result<Cursors, String> {
    load_stage(&cursors_path())
}
fn save_cursors(c: &Cursors) -> Result<(), String> {
    write_stage(&cursors_path(), c)
}

/// Record `reader_session` as having read this cursor's name, if given and
/// not already present — best-effort attribution the same way conduct's
/// own `--from`/`AOIDE_SESSION_ID` is (house rule doc, `graph/send.rs`'s
/// `resolve_sender`): a session id an absent caller simply has none of, in
/// which case only `seq` still advances.
fn record_reader(cursor: &mut Cursor, reader_session: Option<&str>) {
    if let Some(s) = reader_session {
        if !s.is_empty() && !cursor.readers.iter().any(|r| r == s) {
            cursor.readers.push(s.to_string());
        }
    }
}

/// Mint + seal + file one entry (letter or receipt), always `via: "self"`
/// (P-M1 has no other hop) — the one place [`append_base_line`] and
/// [`append_seen_line`] are called together, in that order. Raw — called
/// only from inside [`with_lock`]'s closure (`file_letter`/`file_receipt`/
/// [`migrate_if_needed`]'s own inline copy of this same shape).
fn file_entry(kind: &str, from: Address, to: Address, text: &str) -> Result<Entry, String> {
    let (kp, _) = identity::load_or_mint().map_err(|e| e.to_string())?;
    let header = Header {
        version: ENVELOPE_VERSION.to_string(),
        from,
        to,
        kind: kind.to_string(),
        minted_at: now_iso_utc(),
        origin_mesh: String::new(),
    };
    let (sig, msgid) = seal(&header, text, &kp);
    let envelope = Envelope { header, text: text.to_string(), sig, msgid: msgid.clone() };
    let entry = Entry {
        seq: next_seq()?,
        received_at: now_iso_utc(),
        kind: kind.to_string(),
        via: "self".to_string(),
        envelope,
    };
    append_base_line(&entry)?;
    append_seen_line(&msgid, &entry.received_at)?;
    Ok(entry)
}

/// File one delivery receipt — `mail::file_receipt`, the direct replacement
/// for the two `inbox::receive` writer seams (`conduct/graph/send.rs`,
/// `server/a2a.rs`). **Three arguments, not `inbox::receive`'s four**:
/// `context` is dropped, not carried (ruling 7) — the canonical header
/// stays the closed eight fields, and the retiring field was a reserved
/// passthrough nothing ever set or read. Signed by this box's own identity,
/// minting it on first use if none exists yet (ruling 6); best-effort by
/// design at BOTH call sites, same as before — a failed filing must never
/// turn an already-succeeded delivery into a reported failure, which is why
/// this still returns a real `Result` rather than swallowing the error
/// itself: the caller decides whether/how to surface it.
pub fn file_receipt(from: &str, to_name: &str, text: &str) -> Result<(), String> {
    let node = display::local_host_name();
    let from_addr = Address { node: node.clone(), name: from.to_string() };
    let to_addr = Address { node, name: to_name.to_string() };
    let text = text.to_string();
    with_lock(move || file_entry(ENTRY_TYPE_RECEIPT, from_addr, to_addr, &text).map(|_| ()))
}

/// File one letter — `mail send`'s engine. P-M1 only ever calls this with
/// `to_name` resolved from `--to self/<name>`; the command layer is what
/// refuses any other node (there is nowhere else to route to yet).
pub fn file_letter(from_name: &str, to_name: &str, text: &str) -> Result<Entry, String> {
    let node = display::local_host_name();
    let from_addr = Address { node: node.clone(), name: from_name.to_string() };
    let to_addr = Address { node, name: to_name.to_string() };
    let text = text.to_string();
    with_lock(move || file_entry(ENTRY_TYPE_LETTER, from_addr, to_addr, &text))
}

/// The whole base, tolerantly parsed, in file order. The one PUBLIC,
/// locked reader — everything else in this module that needs entries calls
/// the raw [`read_entries_unlocked`] instead, from inside its own
/// [`with_lock`] closure.
pub fn read_base() -> Result<Vec<Entry>, String> {
    with_lock(read_entries_unlocked)
}

/// `mail read --for <name> [--reread]`: entries filed to `name`, newest
/// last, advancing that name's cursor to the highest `seq` returned
/// (`--reread` widens what is PRINTED — every entry for `name`, not just
/// the unread ones — but the cursor still only ever advances forward, so a
/// plain `mail read --for X` right after never reprints what `--reread`
/// just showed). Records `reader_session` on the cursor when given
/// (MAIL.md "Store": "records the reader's session id").
pub fn read_for(name: &str, reread: bool, reader_session: Option<&str>) -> Result<Vec<Entry>, String> {
    let name = name.to_string();
    let reader_session = reader_session.map(|s| s.to_string());
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let mut cursors = load_cursors()?;
        let cursor = cursors.entry(name.clone()).or_default();
        let floor = if reread { 0 } else { cursor.seq };
        let mut matched: Vec<Entry> =
            entries.into_iter().filter(|e| e.envelope.header.to.name == name && e.seq > floor).collect();
        matched.sort_by_key(|e| e.seq);
        if let Some(max_seq) = matched.iter().map(|e| e.seq).max() {
            if max_seq > cursor.seq {
                cursor.seq = max_seq;
            }
        }
        record_reader(cursor, reader_session.as_deref());
        save_cursors(&cursors)?;
        Ok(matched)
    })
}

/// `mail read --all-names [--reread]`: the same as [`read_for`], run once
/// per name that appears anywhere in the base, results concatenated in
/// `seq` order.
pub fn read_all_names(reread: bool, reader_session: Option<&str>) -> Result<Vec<Entry>, String> {
    let reader_session = reader_session.map(|s| s.to_string());
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let mut cursors = load_cursors()?;
        let mut names: Vec<String> =
            entries.iter().map(|e| e.envelope.header.to.name.clone()).collect();
        names.sort();
        names.dedup();

        let mut out = Vec::new();
        for name in names {
            let cursor = cursors.entry(name.clone()).or_default();
            let floor = if reread { 0 } else { cursor.seq };
            let mut matched: Vec<Entry> = entries
                .iter()
                .filter(|e| e.envelope.header.to.name == name && e.seq > floor)
                .cloned()
                .collect();
            if let Some(max_seq) = matched.iter().map(|e| e.seq).max() {
                if max_seq > cursor.seq {
                    cursor.seq = max_seq;
                }
            }
            record_reader(cursor, reader_session.as_deref());
            out.append(&mut matched);
        }
        out.sort_by_key(|e| e.seq);
        save_cursors(&cursors)?;
        Ok(out)
    })
}

/// `mail mark --for <name>`: advance the cursor to the current max `seq`
/// under `name` without printing anything. Returns the cursor's resulting
/// `seq`. A name with nothing filed under it yet is a clean no-op (the
/// cursor stays at 0), not an error — same "a mailbox exists by being
/// named" tolerance MAIL.md's "Addressing and filing" section states for
/// `mail send`/`mail read` alike.
pub fn mark(name: &str, reader_session: Option<&str>) -> Result<u64, String> {
    let name = name.to_string();
    let reader_session = reader_session.map(|s| s.to_string());
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let max_seq = entries
            .iter()
            .filter(|e| e.envelope.header.to.name == name)
            .map(|e| e.seq)
            .max()
            .unwrap_or(0);
        let mut cursors = load_cursors()?;
        let cursor = cursors.entry(name.clone()).or_default();
        if max_seq > cursor.seq {
            cursor.seq = max_seq;
        }
        record_reader(cursor, reader_session.as_deref());
        let result = cursor.seq;
        save_cursors(&cursors)?;
        Ok(result)
    })
}

/// `mail show <msgid>`: one entry by its exact `msgid`, or `None` — no
/// cursor effect (this is a peek, not a read; MAIL.md's Commands table
/// lists it without the "print + advance cursor" annotation `mail read`
/// carries).
pub fn show(msgid: &str) -> Result<Option<Entry>, String> {
    let msgid = msgid.to_string();
    with_lock(move || Ok(read_entries_unlocked()?.into_iter().find(|e| e.envelope.msgid == msgid)))
}

/// `aoide mail`'s bare listing: names with unread mail (MAIL.md ruling 11 —
/// the "caller's own new letters" half needs the reader binding and is
/// P-M5's; this is the names half only).
pub fn names_with_unread() -> Result<Vec<String>, String> {
    with_lock(|| {
        let entries = read_entries_unlocked()?;
        let cursors = load_cursors()?;
        let mut max_by_name: BTreeMap<String, u64> = BTreeMap::new();
        for e in &entries {
            let slot = max_by_name.entry(e.envelope.header.to.name.clone()).or_insert(0);
            if e.seq > *slot {
                *slot = e.seq;
            }
        }
        let mut names: Vec<String> = max_by_name
            .into_iter()
            .filter(|(name, max_seq)| cursors.get(name).map(|c| c.seq).unwrap_or(0) < *max_seq)
            .map(|(name, _)| name)
            .collect();
        names.sort();
        Ok(names)
    })
}

/// `mail rm --older-than <Nd|Nh>`: the only pruning (MAIL.md "Store",
/// "Keep-all"). Rewrites `base.jsonl` atomically with the survivors,
/// preserving each one's original `seq` — never renumbers, so a reader's
/// cursor comparisons stay valid across a prune. Never touches
/// `seen.jsonl`: a pruned letter re-offered later is still a duplicate
/// (the RFC 5537 §3.3 coupling MAIL.md names). An entry whose
/// `receivedAt` fails to parse is KEPT, not guessed at.
pub fn rm_older_than(max_age_secs: u64) -> Result<usize, String> {
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let cutoff = parse_iso_utc(&now_iso_utc()).unwrap_or(0) - max_age_secs as i64;
        let (keep, dropped): (Vec<Entry>, Vec<Entry>) = entries.into_iter().partition(|e| {
            match parse_iso_utc(&e.received_at) {
                Some(epoch) => epoch >= cutoff,
                None => true,
            }
        });
        let mut body = String::new();
        for e in &keep {
            body.push_str(&serde_json::to_string(e).map_err(|err| err.to_string())?);
            body.push('\n');
        }
        atomic_write(&base_path(), &body).map_err(|e| e.to_string())?;
        Ok(dropped.len())
    })
}

/// `--older-than <Nd|Nh>`: a positive integer followed by exactly one unit
/// letter, `d` (days) or `h` (hours) — `"7d"`, `"12h"`. Returns the
/// threshold in seconds; anything else (empty, no digits, a zero count, a
/// third unit, trailing junk) is `None`, a usage error before anything
/// runs. Ported verbatim from `song/src/commands/take.rs::parse_older_than`
/// (architect's ruling 10) rather than shared: `storage` may not depend on
/// `song`, and the two crates live in different workspaces after the
/// crate split.
pub fn parse_older_than(raw: &str) -> Option<u64> {
    if raw.len() < 2 {
        return None;
    }
    let (digits, unit) = raw.split_at(raw.len() - 1);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    if n == 0 {
        return None;
    }
    match unit {
        "d" => Some(n * 86400),
        "h" => Some(n * 3600),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> (aoide_test_support::EnvSaver, PathBuf) {
        aoide_test_support::isolated_mail_root(tag)
    }

    fn header(from: &str, to: &str, text_kind: &str, minted_at: &str) -> Header {
        Header {
            version: ENVELOPE_VERSION.to_string(),
            from: Address { node: "yomi".to_string(), name: from.to_string() },
            to: Address { node: "yomi".to_string(), name: to.to_string() },
            kind: text_kind.to_string(),
            minted_at: minted_at.to_string(),
            origin_mesh: String::new(),
        }
    }

    #[test]
    fn no_fixture_escapes_the_test_root() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("no-escape");

        file_letter("alice", "bob", "hi").unwrap();

        assert!(base_path().starts_with(&dir), "base.jsonl must land under the isolated root");
        assert!(
            !base_path().to_string_lossy().contains("/.aoide/"),
            "must never resolve into a real ~/.aoide tree"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_only_invariants_hold_across_multiple_files() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("append-only");

        let e1 = file_letter("alice", "bob", "one").unwrap();
        let e2 = file_letter("alice", "bob", "two").unwrap();
        let e3 = file_letter("alice", "carol", "three").unwrap();

        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
        assert_eq!(e3.seq, 3);

        let all = read_base().unwrap();
        assert_eq!(all.len(), 3, "every filed entry survives, none overwritten");
        assert_eq!(all[0].envelope.text, "one");
        assert_eq!(all[1].envelope.text, "two");
        assert_eq!(all[2].envelope.text, "three");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_tail_is_truncated_before_the_next_append() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("torn-tail");

        let good = file_letter("alice", "bob", "good line").unwrap();

        // Simulate a crash mid-write: a partial line with NO trailing newline.
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(base_path()).unwrap();
            f.write_all(br#"{"seq":99,"receivedAt":"broke"#).unwrap();
        }
        let raw_before = std::fs::read_to_string(base_path()).unwrap();
        assert!(!raw_before.ends_with('\n'), "the fixture really did leave a torn tail");

        let next = file_letter("alice", "bob", "after the crash").unwrap();
        assert_eq!(next.seq, good.seq + 1, "the torn tail's bogus seq 99 must never be counted");

        let all = read_base().unwrap();
        assert_eq!(all.len(), 2, "the torn line is gone, not folded in as a third entry");
        assert_eq!(all[0].envelope.text, "good line");
        assert_eq!(all[1].envelope.text, "after the crash");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_seen_line_with_no_base_entry_is_re_acceptable() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("base-before-seen");

        // Simulate the exact crash window MAIL.md describes: base written,
        // seen not yet appended.
        let h = header("alice", "bob", ENTRY_TYPE_LETTER, &now_iso_utc());
        let (kp, _) = identity::load_or_mint().unwrap();
        let (sig, msgid) = seal(&h, "orphaned", &kp);
        let envelope = Envelope { header: h, text: "orphaned".to_string(), sig, msgid: msgid.clone() };
        let entry = Entry { seq: 1, received_at: now_iso_utc(), kind: ENTRY_TYPE_LETTER.to_string(), via: "self".to_string(), envelope };
        std::fs::create_dir_all(mail_dir()).unwrap();
        append_base_line(&entry).unwrap();

        let seen_raw = std::fs::read_to_string(seen_path()).unwrap_or_default();
        assert!(!seen_raw.contains(&msgid), "seen.jsonl must not yet know this msgid");

        // The base entry must still read back cleanly — a read never
        // consults seen.jsonl to decide whether a base line is valid.
        let all = read_base().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].envelope.msgid, msgid);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unwritable_lock_path_makes_every_mail_write_err() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("unwritable-lock");

        // Force `stage_dir()/.stage.lock` to be a directory, so opening it
        // for writing fails cleanly (EISDIR) rather than ever taking the flock.
        std::fs::create_dir_all(crate::fs::stage_dir()).unwrap();
        std::fs::create_dir_all(crate::fs::stage_dir().join(".stage.lock")).unwrap();

        let err = file_letter("alice", "bob", "should never land").unwrap_err();
        assert!(!err.is_empty());
        assert!(read_entries_unlocked().unwrap().is_empty(), "nothing was ever appended");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_held_lock_serializes_a_second_writer_behind_the_first_rather_than_failing_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("held-lock");
        std::fs::create_dir_all(crate::fs::stage_dir()).unwrap();

        use std::os::unix::io::AsRawFd;
        let lock_path = crate::fs::stage_dir().join(".stage.lock");
        let held = std::fs::OpenOptions::new().create(true).write(true).open(&lock_path).unwrap();
        let rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(rc, 0, "test setup must actually hold the lock");

        let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let released_writer = released.clone();
        let handle = std::thread::spawn(move || {
            let out = file_letter("alice", "bob", "waited its turn");
            // The write must not observe itself completing before the
            // holder released — proven by the holder flipping the flag
            // strictly before it unlocks, below.
            assert!(released_writer.load(std::sync::atomic::Ordering::SeqCst));
            out
        });

        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!handle.is_finished(), "a genuinely held lock must block the second writer, not fail it");

        released.store(true, std::sync::atomic::Ordering::SeqCst);
        unsafe {
            libc::flock(held.as_raw_fd(), libc::LOCK_UN);
        }
        drop(held);

        let result = handle.join().unwrap();
        assert!(result.is_ok(), "the second writer must succeed once the lock frees up, not error");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cursor_advances_on_read_and_records_the_reader() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-advance");

        file_letter("alice", "bob", "one").unwrap();
        file_letter("alice", "bob", "two").unwrap();

        let got = read_for("bob", false, Some("sess-1")).unwrap();
        assert_eq!(got.len(), 2);

        let cursors = load_cursors().unwrap();
        let c = cursors.get("bob").unwrap();
        assert_eq!(c.seq, 2);
        assert_eq!(c.readers, vec!["sess-1".to_string()]);

        // A second read with nothing new returns nothing, and does not
        // duplicate the reader.
        let again = read_for("bob", false, Some("sess-1")).unwrap();
        assert!(again.is_empty());
        let cursors = load_cursors().unwrap();
        assert_eq!(cursors.get("bob").unwrap().readers.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_maps_legacy_inbox_rows_into_typed_receipts() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("migration");

        let legacy = serde_json::json!({
            "schemaVersion": "0",
            "entries": [
                { "from": "alice", "target": "sess-1", "text": "hi", "receivedAt": "2026-08-21T00:00:00Z", "read": false },
                { "from": "", "target": "sess-2", "text": "anon ping", "receivedAt": "2026-08-21T00:01:00Z", "read": true }
            ]
        });
        std::fs::create_dir_all(state_dir()).unwrap();
        std::fs::write(legacy_inbox_path(), serde_json::to_string(&legacy).unwrap()).unwrap();

        let all = read_base().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].kind, ENTRY_TYPE_RECEIPT);
        assert_eq!(all[0].envelope.header.from.name, "alice");
        assert_eq!(all[0].envelope.header.to.name, "sess-1");
        assert_eq!(all[0].envelope.text, "hi");
        assert_eq!(all[0].received_at, "2026-08-21T00:00:00Z");
        assert_eq!(all[1].envelope.header.from.name, "");

        assert!(!legacy_inbox_path().exists(), "the old file is renamed away");
        assert!(state_dir().join("inbox.json.migrated").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_migration_interrupted_after_some_rows_files_each_legacy_row_exactly_once_on_retry() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("migration-retry");

        let legacy = serde_json::json!({
            "entries": [
                { "from": "alice", "target": "sess-1", "text": "first", "receivedAt": "2026-08-21T00:00:00Z" },
                { "from": "bob", "target": "sess-2", "text": "second", "receivedAt": "2026-08-21T00:01:00Z" }
            ]
        });
        std::fs::create_dir_all(state_dir()).unwrap();
        std::fs::write(legacy_inbox_path(), serde_json::to_string(&legacy).unwrap()).unwrap();

        // Simulate a crash after row 1 was filed but before the rename:
        // hand-build exactly the entry a first partial attempt would have
        // produced for row 1, and seed base.jsonl/seen.jsonl with it
        // directly. inbox.json stays present, as it would after a real
        // crash — nothing here goes through `migrate_if_needed`.
        std::fs::create_dir_all(mail_dir()).unwrap();
        let node = display::local_host_name();
        let (kp, _) = identity::load_or_mint().unwrap();
        let row1_header = Header {
            version: ENVELOPE_VERSION.to_string(),
            from: Address { node: node.clone(), name: "alice".to_string() },
            to: Address { node: node.clone(), name: "sess-1".to_string() },
            kind: ENTRY_TYPE_RECEIPT.to_string(),
            minted_at: "2026-08-21T00:00:00Z".to_string(),
            origin_mesh: String::new(),
        };
        let (sig, row1_msgid) = seal(&row1_header, "first", &kp);
        let row1_entry = Entry {
            seq: 1,
            received_at: "2026-08-21T00:00:00Z".to_string(),
            kind: ENTRY_TYPE_RECEIPT.to_string(),
            via: "self".to_string(),
            envelope: Envelope { header: row1_header, text: "first".to_string(), sig, msgid: row1_msgid.clone() },
        };
        std::fs::write(base_path(), format!("{}\n", serde_json::to_string(&row1_entry).unwrap())).unwrap();
        std::fs::write(
            seen_path(),
            format!(
                "{}\n",
                serde_json::to_string(&SeenEntry {
                    msgid: row1_msgid.clone(),
                    received_at: "2026-08-21T00:00:00Z".to_string()
                })
                .unwrap()
            ),
        )
        .unwrap();

        // Retry: inbox.json is still present, exactly as after a crash.
        let all = read_base().unwrap();
        assert_eq!(all.len(), 2, "row 1 must not be duplicated, row 2 must be filed");
        assert_eq!(all[0].envelope.msgid, row1_msgid, "the pre-seeded row 1 is untouched");
        assert_eq!(all[1].envelope.header.from.name, "bob");
        assert_eq!(all[1].envelope.text, "second");

        assert!(!legacy_inbox_path().exists(), "the retry still completes the rename");
        assert!(state_dir().join("inbox.json.migrated").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_concurrent_second_opener_never_double_migrates() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("migration-race");

        let legacy = serde_json::json!({
            "entries": [{ "from": "alice", "target": "sess-1", "text": "hi", "receivedAt": "2026-08-21T00:00:00Z" }]
        });
        std::fs::create_dir_all(state_dir()).unwrap();
        std::fs::write(legacy_inbox_path(), serde_json::to_string(&legacy).unwrap()).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b1 = barrier.clone();
        let t1 = std::thread::spawn(move || {
            b1.wait();
            names_with_unread()
        });
        let b2 = barrier.clone();
        let t2 = std::thread::spawn(move || {
            b2.wait();
            names_with_unread()
        });
        t1.join().unwrap().unwrap();
        t2.join().unwrap().unwrap();

        let all = read_base().unwrap();
        assert_eq!(all.len(), 1, "the lock must serialize the two opens, never migrate twice");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_seen_set_survives_rm() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("seen-survives-rm");

        let e1 = file_letter("alice", "bob", "old").unwrap();
        // Backdate it so `rm --older-than` actually prunes it.
        {
            let mut all = read_entries_unlocked().unwrap();
            all[0].received_at = "2000-01-01T00:00:00Z".to_string();
            let mut body = String::new();
            for e in &all {
                body.push_str(&serde_json::to_string(e).unwrap());
                body.push('\n');
            }
            std::fs::write(base_path(), body).unwrap();
        }

        let removed = rm_older_than(60).unwrap();
        assert_eq!(removed, 1);
        assert!(read_base().unwrap().is_empty());

        let seen_raw = std::fs::read_to_string(seen_path()).unwrap();
        assert!(seen_raw.contains(&e1.envelope.msgid), "seen.jsonl must still remember the pruned msgid");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn msgid_recomputation_rejects_a_tampered_field() {
        // Pure/in-memory only (`mint_ephemeral` never touches disk) — no
        // isolated root needed for this one.
        let h = header("alice", "bob", ENTRY_TYPE_LETTER, "2026-09-06T00:00:00Z");
        let kp = identity::mint_ephemeral().unwrap();
        let (sig, msgid) = seal(&h, "hello", &kp);
        assert_eq!(compute_msgid(&h, "hello", &sig).unwrap(), msgid, "an untampered recompute matches");

        assert_ne!(
            compute_msgid(&h, "HELLO", &sig).unwrap(),
            msgid,
            "a tampered text must change the recomputed msgid"
        );

        let mut tampered_header = h.clone();
        tampered_header.to.name = "carol".to_string();
        assert_ne!(
            compute_msgid(&tampered_header, "hello", &sig).unwrap(),
            msgid,
            "a tampered header field must change the recomputed msgid"
        );
    }

    #[test]
    fn canonical_header_is_byte_exact_case_and_whitespace_change_the_msgid() {
        let h1 = header("alice", "bob", ENTRY_TYPE_LETTER, "2026-09-06T00:00:00Z");
        let mut h2 = h1.clone();
        h2.to.name = "Bob".to_string(); // case differs

        let kp = identity::mint_ephemeral().unwrap();
        let (sig1, msgid1) = seal(&h1, "hello", &kp);
        let msgid2 = compute_msgid(&h2, "hello", &sig1).unwrap();
        assert_ne!(msgid1, msgid2, "case must not fold in the canonical header");

        let mut h3 = h1.clone();
        h3.to.name = " bob".to_string(); // leading whitespace differs
        let msgid3 = compute_msgid(&h3, "hello", &sig1).unwrap();
        assert_ne!(msgid1, msgid3, "whitespace must not trim in the canonical header");

        assert_ne!(
            canonical_header_bytes(&h1),
            canonical_header_bytes(&h2),
            "the two headers' verbatim bytes must differ"
        );
    }
}
