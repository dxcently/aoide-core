//! `state/mail/` — the addressed, signed, append-only mailbase
//! (`docs/architecture/MAIL.md`). Absorbs the old per-host `inbox.json`
//! receipt log (MAIL.md decision 8): today's two LOCAL delivery seams
//! (`conduct/graph/send.rs`, `server/a2a.rs`) file a `receipt` entry here,
//! and `mail send` files a `letter` — locally via [`file_letter`] for
//! `self/<name>`, or over the wire for a direct paired edge (P-M2): the
//! sender mints with [`mint_outbound_letter`] and spools the sealed
//! [`Envelope`] into [`crate::outbox`]; the far door's `aoide/mailDeposit`
//! arm calls [`deposit`] here to verify and file it, ONLY ever via a
//! [`file_received_entry`] (never re-minted — the envelope arrives already
//! sealed). **No transit, no zones, no `--hold`** — those are P-M3/P-M4
//! (MAIL.md's own Phases section); nothing here reads a mesh declaration.
//! The doorbell's own latch and its targeting queries ([`arms`],
//! [`ring_targets`], [`stamp_rung`], [`armed_names_for_reader`],
//! [`enrol_reader`]) live here (P-M5a-1); the ring itself — injecting a byte
//! into a pty — is `aoide-conduct`'s (P-M5a-2).
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
//! facts nothing here consults yet (P-M4's zone check, MAIL.md step 3,
//! still skipped entirely rather than stubbed even now that a mesh CAN be
//! declared, task #135), and `header.origin_mesh` (always `""` here) stands
//! in for them wherever P-M1/P-M2 render a "mesh" column, since mesh and
//! originMesh are defined to start equal and nothing before P-M4 can ever
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
//! cursors.json    { "<name>": { "<reader>": { "seq": n } } }
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
//! [`migrate_if_needed`] and [`migrate_cursors_if_needed`] first, every
//! time, so the very first store touch by ANY command — read or write —
//! performs the one-shot `inbox.json` → `inbox.json.migrated` field-mapping
//! AND the one-shot flat-to-per-reader `cursors.json` rewrite, both under
//! the SAME critical section (ruling 2), and every call after that sees
//! both already done and does nothing.
//!
//! ## Origin, hop, and hop-forgery
//!
//! Two independent lookups (P-M2 spec item 3), on purpose: the HOP (the
//! caller of `aoide/mailDeposit`) is whichever node record's stored pubkey
//! verified the *connection* signature (`a2a::verify_signed_request`,
//! threaded through as `ctx.signed_node_name`) — this module never
//! consults it directly, only receives it as `via`. The ORIGIN is
//! `header.from.node`, checked in [`verify_origin_signature`] against the
//! ONE key `nodes.json` has on record under that exact name — never the
//! connection path's try-every-verified-key ladder, or a paired node
//! signing as another paired node's name would verify and file under the
//! wrong identity. Origin and hop always coincide today (only direct edges
//! exist); the split is written now for P-M4's transit hops, where they
//! will not.
//!
//! ## Commands
//!
//! `aoide_client::commands::register_mail` wires `mail`, `mail send`
//! (`--to self/<name>` or `--to <node>/<name>` for a direct verified edge),
//! `mail read`, `mail show`, `mail mark`, `mail rm`, `mail outbox`, `mail
//! outbox rm` — moved out of this crate's own `commands.rs` at P-M2 because
//! sending over a direct edge needs the wire lane (`aoide-client`'s own
//! domain); this module stays the mailbase's storage layer regardless of
//! which crate dispatches into it. `mail route`/`--hold`/`--transit` are
//! later phases and are not registered yet.

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

/// Which entry kinds ARM a reader's doorbell. A `receipt` (a delivery
/// record, or a deposit ack filed under the origin's name) never does.
pub fn arms(kind: &str) -> bool {
    kind == ENTRY_TYPE_LETTER
}

/// `<node>/<name>` — one side of a header. `from.name` and a receipt's
/// `to.name` stay free text — attribution only, nothing here validates
/// them against a mesh declaration (P-M1 has none). A letter's `to.name`
/// is grammar-validated at filing instead ([`file_letter`],
/// [`mint_outbound_letter`]), never clamped.
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

/// One reader's high-water mark, like an NNTP `.newsrc` line (MAIL.md
/// "Store").
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Mark {
    #[serde(default)]
    pub seq: u64,
    /// The doorbell latch (MAIL.md "Delivery and the doorbell"): the highest
    /// arming `seq` this reader has been rung for. Armed again only once
    /// `seq` (the reader's own read) reaches it. Zero = never rung; omitted
    /// from disk while zero so an unrung file is byte-identical to before.
    #[serde(default, skip_serializing_if = "u64_is_zero")]
    pub rung: u64,
}

fn u64_is_zero(v: &u64) -> bool {
    *v == 0
}

/// One name's readers, each with its own high-water mark (MAIL.md "Store":
/// "a name maps to a set of readers, each with its own high-water mark").
/// The key set IS the doorbell's enrolment list: a reader is enrolled by
/// having a key here, [`Mark::rung`] is that reader's latch, and
/// [`ring_targets`] reads both to decide who is armed.
pub type Cursor = BTreeMap<String, Mark>;

/// `cursors.json`'s whole shape is this bare map of maps — no wrapper, no
/// schema version (MAIL.md shows it unwrapped; this module does not add
/// one).
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
        migrate_cursors_if_needed()?;
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

/// One-shot, idempotent flat-to-per-reader `cursors.json` rewrite, run under
/// the SAME lock acquisition as [`migrate_if_needed`] (MAIL.md "Store": "A
/// `cursors.json` carrying the flat `{ "<name>": { "seq", "readers" } }`
/// shape migrates on first open under the same lock: each recorded reader
/// inherits the name's old `seq`, and a name with no recorded reader keeps
/// its mark under the name itself"). Read as untyped JSON, never as
/// [`Cursors`] — the old shape's `{"seq": n, "readers": [...]}` does not
/// deserialize as a reader-keyed [`Cursor`], so a typed load here would
/// error instead of migrate.
///
/// A name is old-shape iff its value has a `seq` field that is a bare JSON
/// *number* — the new shape only ever nests `seq` inside a per-reader
/// object, even for a reader literally named `"seq"`. That per-name shape
/// check is what makes a second call a clean no-op with no sentinel file to
/// consult: every name this rewrites no longer matches the old-shape test
/// on the next pass, so nobody re-reads what they had already read.
fn migrate_cursors_if_needed() -> Result<(), String> {
    let path = cursors_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let top: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&raw)
        .map_err(|e| format!("{}: unreadable cursors: {e}", path.display()))?;

    let mut rewritten = false;
    let mut out = Cursors::new();
    for (name, value) in top {
        match value.get("seq").and_then(serde_json::Value::as_u64) {
            Some(old_seq) => {
                // Old flat shape: `{ "seq": n, "readers": [...] }`.
                rewritten = true;
                let readers: Vec<String> = value
                    .get("readers")
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(serde_json::Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut cursor = Cursor::new();
                if readers.is_empty() {
                    cursor.insert(name.clone(), Mark { seq: old_seq, rung: 0 });
                } else {
                    for reader in readers {
                        cursor.insert(reader, Mark { seq: old_seq, rung: 0 });
                    }
                }
                out.insert(name, cursor);
            }
            None => {
                // Already the new per-reader shape — parse it as such and
                // pass it through untouched.
                let cursor: Cursor = serde_json::from_value(value)
                    .map_err(|e| format!("{}: unreadable cursor for {name:?}: {e}", path.display()))?;
                out.insert(name, cursor);
            }
        }
    }

    if rewritten {
        save_cursors(&out)?;
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

/// The reader identity a cursor mutation is attributed to: `reader_session`
/// when given and non-empty, and `name` itself otherwise (MAIL.md "Store":
/// "a reader is identified by its conducting session id... and by the
/// mailbox name itself when that is unset — so a stray read from an
/// unconducted terminal advances a pseudo-reader and never a live agent's
/// mark"). Every caller resolves this once per name, before looking at any
/// entry under it — never re-derived per row.
fn reader_id(name: &str, reader_session: Option<&str>) -> String {
    match reader_session {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => name.to_string(),
    }
}

/// Mint + seal + file one entry (letter or receipt) ORIGINATING on this box
/// — `via` names the hop that deposited it, `"self"` for everything this
/// box mints for itself (P-M1's every caller; a remotely-deposited envelope
/// is filed by [`file_received_entry`] instead, which skips minting
/// entirely since the envelope already arrived sealed). The one place
/// [`append_base_line`] and [`append_seen_line`] are called together, in
/// that order. Raw — called only from inside [`with_lock`]'s closure
/// (`file_letter`/`file_receipt`/[`migrate_if_needed`]'s own inline copy of
/// this same shape).
fn file_entry(kind: &str, from: Address, to: Address, text: &str, via: &str) -> Result<Entry, String> {
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
        via: via.to_string(),
        envelope,
    };
    append_base_line(&entry)?;
    append_seen_line(&msgid, &entry.received_at)?;
    Ok(entry)
}

/// File an envelope that arrived ALREADY SEALED over the wire (P-M2,
/// `aoide/mailDeposit`) — the received-mail counterpart to [`file_entry`]:
/// no minting, no signing, the envelope's own `sig`/`msgid` are filed
/// verbatim exactly as the origin produced them. `via` is the HOP's
/// resolved name (`ctx.signed_node_name`, never a name read out of the
/// envelope itself — the door already resolved this by key before calling
/// here). Raw — called only from inside [`with_lock`]'s closure
/// ([`deposit`]'s own).
fn file_received_entry(envelope: Envelope, via: &str) -> Result<Entry, String> {
    let entry = Entry {
        seq: next_seq()?,
        received_at: now_iso_utc(),
        kind: envelope.header.kind.clone(),
        via: via.to_string(),
        envelope,
    };
    append_base_line(&entry)?;
    append_seen_line(&entry.envelope.msgid, &entry.received_at)?;
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
/// itself: the caller decides whether/how to surface it. Always `via:
/// "self"` — both call sites file a LOCAL delivery, never a remote one.
pub fn file_receipt(from: &str, to_name: &str, text: &str) -> Result<(), String> {
    let node = display::local_host_name();
    let from_addr = Address { node: node.clone(), name: from.to_string() };
    let to_addr = Address { node, name: to_name.to_string() };
    let text = text.to_string();
    with_lock(move || file_entry(ENTRY_TYPE_RECEIPT, from_addr, to_addr, &text, "self").map(|_| ()))
}

/// File one letter locally — `mail send --to self/<name>`'s engine, and the
/// same-node-loopback path of a `--to <node>/<name>` send whose `<node>` is
/// this box's own name (P-M2's `--to` resolution happens one layer up, in
/// the command handler). Always `via: "self"`.
pub fn file_letter(from_name: &str, to_name: &str, text: &str) -> Result<Entry, String> {
    if !crate::node_store::valid_node_name(to_name) {
        return Err("invalid mailbox name: must match ^[a-z0-9][a-z0-9-]*$".to_string());
    }
    let node = display::local_host_name();
    let from_addr = Address { node: node.clone(), name: from_name.to_string() };
    let to_addr = Address { node, name: to_name.to_string() };
    let text = text.to_string();
    with_lock(move || file_entry(ENTRY_TYPE_LETTER, from_addr, to_addr, &text, "self"))
}

/// File a letter ADDRESSED TO A REMOTE NODE — mints and seals exactly like
/// [`file_letter`] (this box IS the origin), but the caller supplies
/// `to_node` directly rather than this box's own name, since the whole
/// point is a `to` that names somewhere else. Returns the sealed
/// [`Envelope`] (not an [`Entry`] — nothing is filed into THIS box's own
/// mailbase; a letter to another node is never also a local copy) for the
/// caller to hand to the outbox. `mail send`'s command layer is what
/// decides self vs. remote and calls the matching one of these two.
pub fn mint_outbound_letter(from_name: &str, to_node: &str, to_name: &str, text: &str) -> Result<Envelope, String> {
    if !crate::node_store::valid_node_name(to_name) {
        return Err("invalid mailbox name: must match ^[a-z0-9][a-z0-9-]*$".to_string());
    }
    let (kp, _) = identity::load_or_mint().map_err(|e| e.to_string())?;
    let header = Header {
        version: ENVELOPE_VERSION.to_string(),
        from: Address { node: display::local_host_name(), name: from_name.to_string() },
        to: Address { node: to_node.to_string(), name: to_name.to_string() },
        kind: ENTRY_TYPE_LETTER.to_string(),
        minted_at: now_iso_utc(),
        origin_mesh: String::new(),
    };
    let (sig, msgid) = seal(&header, text, &kp);
    Ok(Envelope { header, text: text.to_string(), sig, msgid })
}

/// Mint a receipt envelope ACKing `acked_msgid` back to `to` — the ack this
/// box spools to its own outbox once it has filed someone else's letter
/// (MAIL.md, spec item 6: "acks are ordinary envelopes, type=receipt,
/// to=origin, text=acked msgid, signed by destination"). `from_name` is the
/// mailbox that received the letter (the identity doing the acking);
/// `to` is the original letter's own `header.from` (origin, not hop —
/// P-M2's two lookups stay distinct even here). Not filed into this box's
/// own mailbase (an ack is outbound-only until IT is deposited somewhere,
/// same as [`mint_outbound_letter`]).
pub fn mint_ack(from_name: &str, to: Address, acked_msgid: &str) -> Result<Envelope, String> {
    let (kp, _) = identity::load_or_mint().map_err(|e| e.to_string())?;
    let header = Header {
        version: ENVELOPE_VERSION.to_string(),
        from: Address { node: display::local_host_name(), name: from_name.to_string() },
        to,
        kind: ENTRY_TYPE_RECEIPT.to_string(),
        minted_at: now_iso_utc(),
        origin_mesh: String::new(),
    };
    let (sig, msgid) = seal(&header, acked_msgid, &kp);
    Ok(Envelope { header, text: acked_msgid.to_string(), sig, msgid })
}

/// Verify `envelope`'s origin signature against the ONE key `nodes.json`
/// has on record for `header.from.node` (P-M2 spec item 3) — a DIFFERENT
/// question from `a2a::verify_signed_request`'s "which verified node's key
/// verifies this connection," and deliberately not reused for it: this
/// tries EXACTLY the one key on record under the CLAIMED origin name, never
/// every verified key, so a paired node signing as another paired node's
/// name is refused rather than silently verifying and filing under the
/// wrong identity. Collapses "no node named `from.node`," "that node has no
/// recorded key," and "the key on record doesn't verify" into the SAME
/// `false` — same non-oracle discipline `verify_signed_request`'s own doc
/// states for its ladder ("never an existence oracle over the registry").
/// In P-M2 the origin and the hop always coincide (only direct edges
/// exist); this two-lookup shape is written now for P-M4's transit hops,
/// where they will not.
pub fn verify_origin_signature(envelope: &Envelope) -> bool {
    let nodes = crate::node_store::load_nodes();
    let Some(node) = nodes.iter().find(|n| n.name == envelope.header.from.node) else {
        return false;
    };
    let Some(pubkey_hex) = node.pubkey.as_deref() else {
        return false;
    };
    let mut sig_input = canonical_header_bytes(&envelope.header);
    sig_input.push(0u8);
    sig_input.extend_from_slice(envelope.text.as_bytes());
    crate::wire_auth::verify_signature_hex(pubkey_hex, &sig_input, &envelope.sig)
}

/// The outcome of [`deposit`]'s policy chain, once the caller has already
/// cleared admission (verified + `message` — the door's job, before ever
/// calling here; MAIL.md's zone check, step 3, is P-M4's and is skipped
/// entirely, not stubbed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositOutcome {
    /// A fresh envelope, filed. `msgid` is its own, for the caller to ack
    /// (a letter) or simply acknowledge process (a receipt).
    Filed { msgid: String, kind: String },
    /// A `msgid` already in `seen.jsonl`. `filed_letter` is `true` when the
    /// ORIGINAL filing was a `letter` — the destination re-spools its ack
    /// in that case (spec item 5: "a lost ack is the ordinary reason for a
    /// re-offer"), never for a duplicate receipt (nothing acks an ack).
    Duplicate { filed_letter: bool },
    /// `msgid` does not recompute from `(header, text, sig)` — tampered or
    /// corrupt in transit.
    BadMsgid,
    /// [`verify_origin_signature`] returned `false`.
    UnverifiedOrigin,
}

/// `aoide/mailDeposit`'s policy chain from "msgid recomputes" onward (spec
/// item 4) — admission (verified caller holding `message`) already ran in
/// the door, above this. Runs entirely under [`with_lock`]: recompute,
/// verify, dedup, and file are all local-disk checks, never network I/O, so
/// holding the lock across all four costs nothing a caller need avoid
/// (contrast the OUTBOX drain, which must never hold this lock across an
/// ssh dial). `via` is the hop's resolved name (`ctx.signed_node_name`).
pub fn deposit(envelope: Envelope, via: &str) -> Result<DepositOutcome, String> {
    with_lock(move || {
        let Some(recomputed) = compute_msgid(&envelope.header, &envelope.text, &envelope.sig) else {
            return Ok(DepositOutcome::BadMsgid);
        };
        if recomputed != envelope.msgid {
            return Ok(DepositOutcome::BadMsgid);
        }
        if !verify_origin_signature(&envelope) {
            return Ok(DepositOutcome::UnverifiedOrigin);
        }
        let seen = read_seen_msgids_unlocked()?;
        if seen.contains(&envelope.msgid) {
            // Re-derive whether the already-filed entry was a letter,
            // without a second full parse of `base.jsonl` beyond what a
            // tolerant scan already costs — `read_entries_unlocked` skips
            // malformed lines the same way `read_seen_msgids_unlocked`
            // does, so this stays consistent with what's actually on disk.
            let filed_letter = read_entries_unlocked()?
                .iter()
                .any(|e| e.envelope.msgid == envelope.msgid && e.kind == ENTRY_TYPE_LETTER);
            return Ok(DepositOutcome::Duplicate { filed_letter });
        }
        let kind = envelope.header.kind.clone();
        let msgid = envelope.msgid.clone();
        file_received_entry(envelope, via)?;
        Ok(DepositOutcome::Filed { msgid, kind })
    })
}

/// The whole base, tolerantly parsed, in file order. The one PUBLIC,
/// locked reader — everything else in this module that needs entries calls
/// the raw [`read_entries_unlocked`] instead, from inside its own
/// [`with_lock`] closure.
pub fn read_base() -> Result<Vec<Entry>, String> {
    with_lock(read_entries_unlocked)
}

/// `mail read --for <name> [--reread]`: entries filed to `name`, newest
/// last, advancing ONLY the calling reader's mark under `name` to the
/// highest `seq` returned (`--reread` widens what is PRINTED — every entry
/// for `name`, not just the unread ones — but the mark still only ever
/// advances forward, so a plain `mail read --for X` right after never
/// reprints what `--reread` just showed). A second reader's mark under the
/// same name is untouched, and it still sees every entry it has not itself
/// read (MAIL.md "Store": "a read advances only the caller's... two agents
/// sharing a mailbox never consume each other's mail").
pub fn read_for(name: &str, reread: bool, reader_session: Option<&str>) -> Result<Vec<Entry>, String> {
    let name = name.to_string();
    let reader_session = reader_session.map(|s| s.to_string());
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let mut cursors = load_cursors()?;
        let reader = reader_id(&name, reader_session.as_deref());
        let cursor = cursors.entry(name.clone()).or_default();
        let mark = cursor.entry(reader).or_default();
        let floor = if reread { 0 } else { mark.seq };
        let mut matched: Vec<Entry> =
            entries.into_iter().filter(|e| e.envelope.header.to.name == name && e.seq > floor).collect();
        matched.sort_by_key(|e| e.seq);
        if let Some(max_seq) = matched.iter().map(|e| e.seq).max() {
            if max_seq > mark.seq {
                mark.seq = max_seq;
            }
        }
        save_cursors(&cursors)?;
        Ok(matched)
    })
}

/// `mail read --all-names [--reread]`: the same as [`read_for`], run once
/// per name that appears anywhere in the base, results concatenated in
/// `seq` order. Each name's reader identity is resolved separately (an
/// unconducted caller's pseudo-reader differs per name, since it falls back
/// to the name itself), but only ever once per name — never per entry.
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
            let reader = reader_id(&name, reader_session.as_deref());
            let cursor = cursors.entry(name.clone()).or_default();
            let mark = cursor.entry(reader).or_default();
            let floor = if reread { 0 } else { mark.seq };
            let mut matched: Vec<Entry> = entries
                .iter()
                .filter(|e| e.envelope.header.to.name == name && e.seq > floor)
                .cloned()
                .collect();
            if let Some(max_seq) = matched.iter().map(|e| e.seq).max() {
                if max_seq > mark.seq {
                    mark.seq = max_seq;
                }
            }
            out.append(&mut matched);
        }
        out.sort_by_key(|e| e.seq);
        save_cursors(&cursors)?;
        Ok(out)
    })
}

/// `mail mark --for <name>`: advance ONLY the caller's mark under `name` to
/// the current max `seq`, without printing anything. Returns that mark's
/// resulting `seq`. A name with nothing filed under it yet is a clean no-op
/// (the mark stays at 0), not an error — same "a mailbox exists by being
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
        let reader = reader_id(&name, reader_session.as_deref());
        let cursor = cursors.entry(name.clone()).or_default();
        let reader_mark = cursor.entry(reader).or_default();
        if max_seq > reader_mark.seq {
            reader_mark.seq = max_seq;
        }
        let result = reader_mark.seq;
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

/// `aoide mail`'s bare listing: names with mail unread BY THIS READER
/// (MAIL.md ruling 11 — the "caller's own new letters" half needs the
/// reader binding and is P-M5's; this is the names half only). A peek, like
/// [`show`] — it never mutates a cursor, only compares against the
/// caller's own mark under each name.
pub fn names_with_unread(reader_session: Option<&str>) -> Result<Vec<String>, String> {
    let reader_session = reader_session.map(|s| s.to_string());
    with_lock(move || {
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
            .filter(|(name, max_seq)| {
                let reader = reader_id(name, reader_session.as_deref());
                let read_through = cursors.get(name).and_then(|c| c.get(&reader)).map(|m| m.seq).unwrap_or(0);
                read_through < *max_seq
            })
            .map(|(name, _)| name)
            .collect();
        names.sort();
        Ok(names)
    })
}

/// One doorbell poll's targets for `name` (MAIL.md "Delivery and the
/// doorbell") — the ringer's one read of "who do I wake, and how many real
/// readers even exist to wake." `armed` pairs each armed reader with the
/// arming high-water mark it is armed FOR, so a caller's own
/// [`stamp_rung`] has the exact `seq` to latch without a second scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingTargets {
    /// (reader key, highest arming seq) for every reader that is armed.
    pub armed: Vec<(String, u64)>,
    /// Reader keys under this name other than the pseudo-reader.
    pub enrolled: usize,
}

/// Who is armed under `name`, and how many real (non-pseudo) readers are
/// enrolled at all (MAIL.md "Delivery and the doorbell"). The pseudo-reader
/// (cursor key == `name` itself, the identity an unconducted caller reads
/// under) is never armed and never counts toward `enrolled` — it is
/// nobody's terminal to ring, and its presence must never suppress the
/// ringer's petname fallback. A reader is armed once unread arming mail
/// ([`arms`], currently `letter` only) exists beyond both what it has read
/// (`mark.seq`) and what it was last rung for (`mark.rung`): rung once, a
/// reader stays latched until its own read catches up to that point, and
/// re-arms only on the next arming entry after that. Read-only.
pub fn ring_targets(name: &str) -> Result<RingTargets, String> {
    let name = name.to_string();
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let max_arm = entries
            .iter()
            .filter(|e| e.envelope.header.to.name == name && arms(&e.kind))
            .map(|e| e.seq)
            .max()
            .unwrap_or(0);
        let cursors = load_cursors()?;
        let mut armed = Vec::new();
        let mut enrolled = 0usize;
        if let Some(cursor) = cursors.get(&name) {
            for (reader, mark) in cursor {
                if *reader == name {
                    continue;
                }
                enrolled += 1;
                if max_arm > mark.seq && mark.rung <= mark.seq {
                    armed.push((reader.clone(), max_arm));
                }
            }
        }
        Ok(RingTargets { armed, enrolled })
    })
}

/// Latch `reader`'s ring for `name` at `seq` (MAIL.md "Delivery and the
/// doorbell") — the ringer's own write, made only once a nudge has actually
/// reached a socket and never before (a failed write must leave the reader
/// armed for the next trigger). `rung` only ever advances (`rung =
/// max(rung, seq)`); `seq` — the reader's own read mark — is never touched
/// here, since reading and being rung are two different events on the same
/// [`Mark`]. `reader` must already be a key under `name`'s cursor map: this
/// stamps an existing mark, it never inserts one — an unenrolled reader is
/// an error, never a silent enrolment. [`enrol_reader`] is the seam that
/// enrols.
pub fn stamp_rung(name: &str, reader: &str, seq: u64) -> Result<(), String> {
    let name = name.to_string();
    let reader = reader.to_string();
    with_lock(move || {
        let mut cursors = load_cursors()?;
        let mark = cursors
            .get_mut(&name)
            .and_then(|c| c.get_mut(&reader))
            .ok_or_else(|| format!("{reader}: not an enrolled reader of {name}"))?;
        if seq > mark.rung {
            mark.rung = seq;
        }
        save_cursors(&cursors)?;
        Ok(())
    })
}

/// Every name where `reader` (a session/wrap id) is currently armed, paired
/// with the arming high-water mark it is armed for, sorted by name — the
/// Stop-hook replay's own read (MAIL.md "Delivery and the doorbell"): the
/// reader that just went idle asks "what should ring me now" across every
/// mailbox at once, not one name at a time. The same armed rule as
/// [`ring_targets`]; a name under which `reader` is that name's OWN
/// pseudo-reader (`reader == name`) is excluded there exactly as it would
/// be from that name's own [`ring_targets`] call.
pub fn armed_names_for_reader(reader: &str) -> Result<Vec<(String, u64)>, String> {
    let reader = reader.to_string();
    with_lock(move || {
        let entries = read_entries_unlocked()?;
        let cursors = load_cursors()?;
        let mut out = Vec::new();
        for (name, cursor) in &cursors {
            if name == &reader {
                continue;
            }
            let Some(mark) = cursor.get(&reader) else { continue };
            let max_arm = entries
                .iter()
                .filter(|e| &e.envelope.header.to.name == name && arms(&e.kind))
                .map(|e| e.seq)
                .max()
                .unwrap_or(0);
            if max_arm > mark.seq && mark.rung <= mark.seq {
                out.push((name.clone(), max_arm));
            }
        }
        Ok(out)
    })
}

/// Enrol `reader` under `name` with a fresh, unread, unrung [`Mark`] —
/// idempotent, and never moves a mark already there (MAIL.md "Delivery and
/// the doorbell"): the ringer's petname fallback calls this on its resolved
/// target BEFORE stamping, so a fallback target latches on its next ring
/// exactly like any reader that arrived by reading. Refuses `reader ==
/// name` (the pseudo-reader is never enrolled — it is not a target) and an
/// invalid `name`; writes nothing in either case.
pub fn enrol_reader(name: &str, reader: &str) -> Result<(), String> {
    if !crate::node_store::valid_node_name(name) {
        return Err("invalid mailbox name: must match ^[a-z0-9][a-z0-9-]*$".to_string());
    }
    if reader == name {
        return Err(format!("{reader}: the pseudo-reader is never enrolled"));
    }
    let name = name.to_string();
    let reader = reader.to_string();
    with_lock(move || {
        let mut cursors = load_cursors()?;
        cursors.entry(name).or_default().entry(reader).or_default();
        save_cursors(&cursors)?;
        Ok(())
    })
}

/// Cross-process serializer for the ring (`conduct::graph::doorbell`,
/// MAIL.md "Delivery and the doorbell"): `flock`s a DEDICATED `.ring.lock`
/// file in [`mail_dir`] for the whole closure — never the `.stage.lock`
/// [`with_lock`]'s callers take. A ring holds this lock across real socket
/// I/O (one write per armed target, plus the submit-keystroke delay), which
/// can run for tens of milliseconds per target; every OTHER mail primitive
/// in this module holds `.stage.lock` only for an in-memory read-modify-write
/// of `base.jsonl`/`cursors.json`, microseconds at most. Sharing one lock
/// file would make a single slow ring stall every unrelated stage writer on
/// the desktop (session starts, hook phases, the reaper) for its whole
/// duration — a hazard nothing before the ring created, so the ring gets its
/// own file rather than widening `.stage.lock`'s blast radius.
///
/// Blocking (`LOCK_EX`): a second filer's ring queues behind the first
/// rather than racing it, so two letters filed to the same name in quick
/// succession still ring the target at most once each, in order (P-M5a-2
/// "a concurrent burst of filers rings once"). Fail-closed like
/// [`crate::fs::try_stage_lock`]: if the lock file can't be opened or
/// locked, the ring is refused rather than run unlocked.
pub fn with_ring_lock<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    crate::fs::lock_path(mail_dir().join(".ring.lock"), f)
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

        let envelope = mint_outbound_letter("alice", "elsewhere", "carol", "hi").unwrap();
        crate::outbox::write_entry("elsewhere", &crate::outbox::OutboxEntry::fresh(envelope)).unwrap();
        let outbox_dir = crate::outbox::outbox_dir();
        assert!(outbox_dir.starts_with(&dir), "state/outbox must land under the isolated root");
        assert!(
            !outbox_dir.to_string_lossy().contains("/.aoide/"),
            "must never resolve into a real ~/.aoide tree"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn origin_verification_is_bound_to_the_key_on_record_for_from_node() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("origin-verification");

        let alice_kp = identity::mint_ephemeral().unwrap();
        let mallory_kp = identity::mint_ephemeral().unwrap();
        let mut nodes = Vec::new();
        crate::node_store::upsert_paired_node(
            &mut nodes,
            "alice-host",
            "https://alice",
            &alice_kp.info().pubkey_hex,
            "2026-09-06T00:00:00Z",
            &["message".to_string()],
        );
        crate::node_store::upsert_paired_node(
            &mut nodes,
            "mallory-host",
            "https://mallory",
            &mallory_kp.info().pubkey_hex,
            "2026-09-06T00:00:00Z",
            &["message".to_string()],
        );
        crate::node_store::save_nodes(&nodes).unwrap();

        let mut genuine_header = header("alice", "bob", ENTRY_TYPE_LETTER, "2026-09-06T00:00:00Z");
        genuine_header.from.node = "alice-host".to_string();
        let (genuine_sig, genuine_msgid) = seal(&genuine_header, "hello", &alice_kp);
        let genuine = Envelope {
            header: genuine_header.clone(),
            text: "hello".to_string(),
            sig: genuine_sig,
            msgid: genuine_msgid,
        };
        assert!(verify_origin_signature(&genuine), "alice-host signing as itself must verify");

        // Mallory signs a header CLAIMING to be alice-host — the exact
        // forgery spec item 3 rules out: only the ONE key on record for
        // that exact `from.node` is ever tried, never every verified
        // node's key.
        let (forged_sig, forged_msgid) = seal(&genuine_header, "hello", &mallory_kp);
        let forged = Envelope { header: genuine_header, text: "hello".to_string(), sig: forged_sig, msgid: forged_msgid };
        assert!(
            !verify_origin_signature(&forged),
            "a different paired node signing as alice-host must NOT verify"
        );

        // No key on record at all for this `from.node`.
        let mut unknown_header = header("alice", "bob", ENTRY_TYPE_LETTER, "2026-09-06T00:00:00Z");
        unknown_header.from.node = "nobody-host".to_string();
        let (unknown_sig, unknown_msgid) = seal(&unknown_header, "hello", &alice_kp);
        let unknown =
            Envelope { header: unknown_header, text: "hello".to_string(), sig: unknown_sig, msgid: unknown_msgid };
        assert!(
            !verify_origin_signature(&unknown),
            "no key on record for from.node must refuse, never fall back to any other key"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_msgid_that_does_not_recompute_is_rejected() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("deposit-bad-msgid");

        let kp = identity::mint_ephemeral().unwrap();
        let mut nodes = Vec::new();
        crate::node_store::upsert_paired_node(
            &mut nodes,
            "alice-host",
            "https://alice",
            &kp.info().pubkey_hex,
            "2026-09-06T00:00:00Z",
            &["message".to_string()],
        );
        crate::node_store::save_nodes(&nodes).unwrap();

        let mut h = header("alice", "bob", ENTRY_TYPE_LETTER, "2026-09-06T00:00:00Z");
        h.from.node = "alice-host".to_string();
        let (sig, msgid) = seal(&h, "hello", &kp);
        let mut envelope = Envelope { header: h, text: "hello".to_string(), sig, msgid };
        envelope.msgid = "not-the-real-msgid".to_string(); // tampered after sealing

        let outcome = deposit(envelope, "alice-host").unwrap();
        assert_eq!(outcome, DepositOutcome::BadMsgid);
        assert!(read_base().unwrap().is_empty(), "a bad-msgid deposit must never file");

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
    fn a_readers_own_read_leaves_a_second_readers_mark_untouched() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-per-reader");

        file_letter("alice", "bob", "one").unwrap();
        file_letter("alice", "bob", "two").unwrap();

        let got = read_for("bob", false, Some("sess-1")).unwrap();
        assert_eq!(got.len(), 2);

        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.get("sess-1").unwrap().seq, 2);
        assert!(cursor.get("sess-2").is_none(), "a second reader has no mark until it reads");

        // A second reader, same name: still sees every entry — sess-1's
        // read never touched it.
        let got2 = read_for("bob", false, Some("sess-2")).unwrap();
        assert_eq!(got2.len(), 2, "a second reader consumes nothing sess-1 already read");

        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.get("sess-1").unwrap().seq, 2, "sess-1's mark is untouched by sess-2's read");
        assert_eq!(cursor.get("sess-2").unwrap().seq, 2);

        // sess-1 reading again with nothing new returns nothing, and does
        // not duplicate anything.
        let again = read_for("bob", false, Some("sess-1")).unwrap();
        assert!(again.is_empty());
        assert_eq!(load_cursors().unwrap().get("bob").unwrap().len(), 2, "still exactly two readers");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_readers_own_read_all_names_leaves_a_second_readers_mark_untouched_across_names() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("all-names-cursor-per-reader");

        file_letter("alice", "bob", "one").unwrap();
        file_letter("alice", "bob", "two").unwrap();
        file_letter("alice", "carol", "three").unwrap();

        let got = read_all_names(false, Some("sess-1")).unwrap();
        assert_eq!(got.len(), 3, "sess-1's first read_all_names sees every entry, across every name");

        let cursors = load_cursors().unwrap();
        assert_eq!(cursors.get("bob").unwrap().get("sess-1").unwrap().seq, 2);
        assert_eq!(cursors.get("carol").unwrap().get("sess-1").unwrap().seq, 3);
        assert!(cursors.get("bob").unwrap().get("sess-2").is_none(), "a second reader has no mark until it reads");
        assert!(cursors.get("carol").unwrap().get("sess-2").is_none());

        // A second reader, same names: still sees every entry — sess-1's
        // read_all_names never touched it.
        let got2 = read_all_names(false, Some("sess-2")).unwrap();
        assert_eq!(got2.len(), 3, "a second reader consumes nothing sess-1 already read, across every name");

        let cursors = load_cursors().unwrap();
        assert_eq!(cursors.get("bob").unwrap().get("sess-1").unwrap().seq, 2, "sess-1's mark under bob is untouched by sess-2's read_all_names");
        assert_eq!(cursors.get("carol").unwrap().get("sess-1").unwrap().seq, 3, "sess-1's mark under carol is untouched by sess-2's read_all_names");
        assert_eq!(cursors.get("bob").unwrap().get("sess-2").unwrap().seq, 2);
        assert_eq!(cursors.get("carol").unwrap().get("sess-2").unwrap().seq, 3);

        // sess-1 reading again with nothing new returns nothing.
        let again = read_all_names(false, Some("sess-1")).unwrap();
        assert!(again.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unconducted_read_advances_only_the_name_keyed_pseudo_reader() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-unconducted");

        file_letter("alice", "bob", "one").unwrap();

        // A conducted reader reads first.
        let got = read_for("bob", false, Some("sess-1")).unwrap();
        assert_eq!(got.len(), 1);

        // An unconducted read (no session id) still sees the letter: its
        // pseudo-reader, keyed by the mailbox name itself, has never read
        // anything, and is not sess-1.
        let got_unconducted = read_for("bob", false, None).unwrap();
        assert_eq!(got_unconducted.len(), 1, "the pseudo-reader has its own, fresh mark");

        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.get("sess-1").unwrap().seq, 1, "the conducted reader's mark is untouched");
        assert_eq!(cursor.get("bob").unwrap().seq, 1, "the pseudo-reader is keyed by the mailbox name");

        // A second unconducted read now sees nothing new.
        let got_again = read_for("bob", false, None).unwrap();
        assert!(got_again.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_flat_cursors_file_migrates_each_listed_reader_inheriting_the_old_seq() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-migration");

        std::fs::create_dir_all(mail_dir()).unwrap();
        let flat = serde_json::json!({
            "bob": { "seq": 5, "readers": ["sess-1", "sess-2"] },
            "carol": { "seq": 3, "readers": [] }
        });
        std::fs::write(cursors_path(), serde_json::to_string(&flat).unwrap()).unwrap();

        // Any store touch migrates it, under the same lock.
        read_base().unwrap();

        let cursors = load_cursors().unwrap();
        let bob = cursors.get("bob").unwrap();
        assert_eq!(bob.get("sess-1").unwrap().seq, 5, "each listed reader inherits the name's old seq");
        assert_eq!(bob.get("sess-2").unwrap().seq, 5);
        let carol = cursors.get("carol").unwrap();
        assert_eq!(carol.len(), 1, "no listed reader: exactly one reader, the name itself");
        assert_eq!(carol.get("carol").unwrap().seq, 3, "a name with no listed reader keeps its mark under the name");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrating_cursors_twice_is_the_same_as_once() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-migration-idempotent");

        std::fs::create_dir_all(mail_dir()).unwrap();
        let flat = serde_json::json!({ "bob": { "seq": 5, "readers": ["sess-1"] } });
        std::fs::write(cursors_path(), serde_json::to_string(&flat).unwrap()).unwrap();

        read_base().unwrap();
        let once = load_cursors().unwrap();

        read_base().unwrap();
        let twice = load_cursors().unwrap();

        assert_eq!(once, twice, "a second open must not undo or redo the migration");
        assert_eq!(twice.get("bob").unwrap().get("sess-1").unwrap().seq, 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reader_named_seq_is_not_confused_with_the_flat_shape_in_either_direction() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-migration-seq-reader");

        std::fs::create_dir_all(mail_dir()).unwrap();
        let flat = serde_json::json!({ "bob": { "seq": 5, "readers": ["seq"] } });
        std::fs::write(cursors_path(), serde_json::to_string(&flat).unwrap()).unwrap();

        // A legacy row naming a reader "seq" must migrate exactly like any
        // other reader — the old-shape test looks at the per-NAME value's
        // own `seq` field, never at what a reader happens to be called.
        read_base().unwrap();
        let once = load_cursors().unwrap();
        let bob = once.get("bob").unwrap();
        assert_eq!(bob.len(), 1, "the only listed reader is the one literally named \"seq\"");
        assert_eq!(bob.get("seq").unwrap().seq, 5, "a reader named seq inherits the old seq like any other");

        let raw = std::fs::read_to_string(cursors_path()).unwrap();
        let raw_json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            raw_json["bob"],
            serde_json::json!({ "seq": { "seq": 5 } }),
            "the migrated shape nests seq inside the reader object, never as a bare number"
        );

        // A second pass must not mistake this reader's own nested
        // `{"seq":5}` for the old flat shape's bare `seq` field and
        // re-migrate (or otherwise disturb) it.
        read_base().unwrap();
        let twice = load_cursors().unwrap();
        assert_eq!(once, twice, "a reader named seq must be left untouched by a second migration pass");
        assert_eq!(twice.get("bob").unwrap().get("seq").unwrap().seq, 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reread_returns_everything_for_the_caller_without_moving_another_readers_mark() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-reread");

        file_letter("alice", "bob", "one").unwrap();
        file_letter("alice", "bob", "two").unwrap();

        read_for("bob", false, Some("sess-1")).unwrap();
        read_for("bob", false, Some("sess-2")).unwrap();

        let reread = read_for("bob", true, Some("sess-1")).unwrap();
        assert_eq!(reread.len(), 2, "--reread returns every entry for the caller, not just new ones");

        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.get("sess-1").unwrap().seq, 2, "reread still only ever advances forward");
        assert_eq!(cursor.get("sess-2").unwrap().seq, 2, "a reread by sess-1 never moves sess-2's mark");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_advances_only_the_callers_mark() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("cursor-mark");

        file_letter("alice", "bob", "one").unwrap();
        file_letter("alice", "bob", "two").unwrap();

        let seq = mark("bob", Some("sess-1")).unwrap();
        assert_eq!(seq, 2);

        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.get("sess-1").unwrap().seq, 2);
        assert!(cursor.get("sess-2").is_none(), "mark never touches a reader that never called it");

        // sess-2 still sees both letters as new — mark is scoped to sess-1.
        let got = read_for("bob", false, Some("sess-2")).unwrap();
        assert_eq!(got.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_fully_read_by_one_reader_is_still_unread_for_another_reader() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("names-unread-per-reader");

        file_letter("alice", "bob", "one").unwrap();

        // Reader A reads bob all the way to the end.
        let got = read_for("bob", false, Some("sess-1")).unwrap();
        assert_eq!(got.len(), 1);

        assert_eq!(
            names_with_unread(Some("sess-1")).unwrap(),
            Vec::<String>::new(),
            "sess-1 fully read bob and must not see it as unread"
        );
        assert_eq!(
            names_with_unread(Some("sess-2")).unwrap(),
            vec!["bob".to_string()],
            "sess-2 has never read bob — it must still be unread for this reader"
        );

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
            names_with_unread(None)
        });
        let b2 = barrier.clone();
        let t2 = std::thread::spawn(move || {
            b2.wait();
            names_with_unread(None)
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
    fn sign_and_verify_round_trip_over_the_canonical_header() {
        // Pure/in-memory only — exercises exactly the bytes
        // `verify_origin_signature` binds itself to (canonical header ‖
        // 0x00 ‖ text), independent of any node lookup; the lookup half is
        // `origin_verification_is_bound_to_the_key_on_record_for_from_node`'s
        // job.
        let h = header("alice", "bob", ENTRY_TYPE_LETTER, "2026-09-06T00:00:00Z");
        let kp = identity::mint_ephemeral().unwrap();
        let (sig, _msgid) = seal(&h, "hello", &kp);

        let mut sig_input = canonical_header_bytes(&h);
        sig_input.push(0u8);
        sig_input.extend_from_slice(b"hello");

        assert!(
            crate::wire_auth::verify_signature_hex(&kp.info().pubkey_hex, &sig_input, &sig),
            "a correctly-sealed envelope's signature must verify against its own signer's pubkey"
        );

        let other = identity::mint_ephemeral().unwrap();
        assert!(
            !crate::wire_auth::verify_signature_hex(&other.info().pubkey_hex, &sig_input, &sig),
            "the same signature must not verify against a DIFFERENT signer's pubkey"
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

    #[test]
    fn a_ring_target_is_armed_only_while_unread_arming_mail_exists_beyond_the_last_ring() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-armed-basic");

        enrol_reader("bob", "sess-1").unwrap();
        let before = ring_targets("bob").unwrap();
        assert!(before.armed.is_empty(), "no arming mail at all: nothing armed");
        assert_eq!(before.enrolled, 1);

        file_letter("alice", "bob", "one").unwrap();
        let after = ring_targets("bob").unwrap();
        assert_eq!(
            after.armed,
            vec![("sess-1".to_string(), 1)],
            "unread arming mail beyond the last ring arms the reader"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_readers_own_read_rearms_the_ring() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-rearm");

        read_for("bob", false, Some("sess-1")).unwrap(); // enrols sess-1, seq 0
        file_letter("alice", "bob", "one").unwrap(); // seq 1, arming
        let t1 = ring_targets("bob").unwrap();
        assert_eq!(t1.armed, vec![("sess-1".to_string(), 1)], "an unread letter arms");

        stamp_rung("bob", "sess-1", 1).unwrap();
        let t2 = ring_targets("bob").unwrap();
        assert!(t2.armed.is_empty(), "latched at seq 1 with no newer arming mail: not armed");

        read_for("bob", false, Some("sess-1")).unwrap(); // seq catches up to 1
        file_letter("alice", "bob", "two").unwrap(); // seq 2, new arming mail
        let t3 = ring_targets("bob").unwrap();
        assert_eq!(
            t3.armed,
            vec![("sess-1".to_string(), 2)],
            "the reader's own read caught up to the rung point; the next arming entry re-arms it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_hundred_letters_ring_once_until_mail_read() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-hundred");

        enrol_reader("bob", "sess-1").unwrap();
        file_letter("alice", "bob", "seed").unwrap(); // seq 1
        stamp_rung("bob", "sess-1", 1).unwrap();

        for i in 0..100 {
            file_letter("alice", "bob", &format!("letter {i}")).unwrap();
        }
        let t = ring_targets("bob").unwrap();
        assert!(t.armed.is_empty(), "a hundred more arming letters never re-arm a latched, still-unread reader");

        read_for("bob", false, Some("sess-1")).unwrap(); // seq catches up to 101
        file_letter("alice", "bob", "the one that rings").unwrap(); // seq 102
        let t2 = ring_targets("bob").unwrap();
        assert_eq!(t2.armed, vec![("sess-1".to_string(), 102)], "only mail after the read re-arms");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pseudo_reader_is_never_a_ring_target_and_does_not_count_as_enrolled() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-pseudo-reader");

        file_letter("alice", "bob", "one").unwrap();
        read_for("bob", false, None).unwrap(); // enrols only the pseudo-reader, key "bob"

        let t = ring_targets("bob").unwrap();
        assert_eq!(t.enrolled, 0, "the pseudo-reader is never counted as enrolled");
        assert!(t.armed.is_empty(), "the pseudo-reader is never a ring target");

        // Unread arming mail piles up for it too — still never a target.
        file_letter("alice", "bob", "two").unwrap();
        let t2 = ring_targets("bob").unwrap();
        assert!(t2.armed.is_empty(), "still never a target, even with unread arming mail outstanding");
        assert_eq!(t2.enrolled, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_latched_reader_still_counts_as_enrolled() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-latched-enrolled");

        enrol_reader("bob", "sess-1").unwrap();
        file_letter("alice", "bob", "one").unwrap();
        stamp_rung("bob", "sess-1", 1).unwrap();

        let t = ring_targets("bob").unwrap();
        assert!(t.armed.is_empty(), "latched immediately after stamping, before any read: not armed");
        assert_eq!(t.enrolled, 1, "a latched reader is still enrolled");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mark_without_rung_reads_as_armed_and_the_file_gains_no_rung_until_stamped() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-legacy-mark");

        std::fs::create_dir_all(mail_dir()).unwrap();
        let legacy = serde_json::json!({ "bob": { "sess-1": { "seq": 0 } } });
        std::fs::write(cursors_path(), serde_json::to_string(&legacy).unwrap()).unwrap();

        file_letter("alice", "bob", "one").unwrap();

        let t = ring_targets("bob").unwrap();
        assert_eq!(
            t.armed,
            vec![("sess-1".to_string(), 1)],
            "a mark with no `rung` on disk defaults to 0, which is <= seq(0): armed"
        );

        read_for("bob", false, Some("sess-1")).unwrap();
        let raw = std::fs::read_to_string(cursors_path()).unwrap();
        assert!(!raw.contains("rung"), "a read alone must never write an unrung mark's `rung` field");

        stamp_rung("bob", "sess-1", 1).unwrap();
        let raw = std::fs::read_to_string(cursors_path()).unwrap();
        assert!(raw.contains("rung"), "stamping a nonzero rung must appear on disk");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamping_a_rung_never_moves_seq_and_a_second_reader_is_untouched() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("stamp-seq-untouched");

        file_letter("alice", "bob", "one").unwrap();
        read_for("bob", false, Some("sess-1")).unwrap(); // seq 1
        enrol_reader("bob", "sess-2").unwrap(); // seq 0, rung 0

        stamp_rung("bob", "sess-1", 5).unwrap(); // stamped beyond the current seq, on purpose

        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.get("sess-1").unwrap().seq, 1, "stamp_rung never moves seq");
        assert_eq!(cursor.get("sess-1").unwrap().rung, 5);
        assert_eq!(cursor.get("sess-2").unwrap().seq, 0, "a second reader is untouched by another reader's stamp");
        assert_eq!(cursor.get("sess-2").unwrap().rung, 0);

        stamp_rung("bob", "sess-1", 2).unwrap(); // lower than the current rung
        let cursors = load_cursors().unwrap();
        assert_eq!(cursors.get("bob").unwrap().get("sess-1").unwrap().rung, 5, "rung only ever advances");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamping_an_unenrolled_reader_is_an_error_not_an_insertion() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("stamp-unenrolled");

        // No cursor map for "bob" at all yet.
        let err = stamp_rung("bob", "sess-1", 1).unwrap_err();
        assert!(!err.is_empty());
        assert!(load_cursors().unwrap().get("bob").is_none(), "stamping an unenrolled reader must insert nothing");

        // A cursor map exists for the name, but not this reader.
        enrol_reader("bob", "sess-2").unwrap();
        let err2 = stamp_rung("bob", "sess-1", 1).unwrap_err();
        assert!(!err2.is_empty());
        let cursors = load_cursors().unwrap();
        assert!(cursors.get("bob").unwrap().get("sess-1").is_none(), "stamping an unenrolled reader must never insert one");
        assert_eq!(cursors.get("bob").unwrap().len(), 1, "only the already-enrolled reader exists");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_receipt_never_arms_a_reader() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("ring-receipt-never-arms");

        read_for("bob", false, Some("sess-1")).unwrap();
        file_receipt("x", "bob", "t").unwrap();

        let t = ring_targets("bob").unwrap();
        assert!(t.armed.is_empty(), "a receipt never arms a reader");

        file_letter("alice", "bob", "a real letter").unwrap();
        let t2 = ring_targets("bob").unwrap();
        assert_eq!(t2.armed, vec![("sess-1".to_string(), 2)], "a letter arms; the receipt filed before it never counted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn armed_names_for_reader_lists_only_names_where_this_reader_is_armed() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("armed-names-for-reader");

        read_for("bob", false, Some("sess-1")).unwrap();
        read_for("carol", false, Some("sess-1")).unwrap();
        file_letter("alice", "bob", "one").unwrap(); // arms bob for sess-1; carol gets nothing new

        let armed = armed_names_for_reader("sess-1").unwrap();
        assert_eq!(armed, vec![("bob".to_string(), 1)], "only the name with unread arming mail for this reader is listed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_letter_to_an_invalid_name_is_refused_before_anything_is_written() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("invalid-name-refused");

        for bad in ["Bob", "$(x)", "-lead", "a\nb"] {
            assert!(file_letter("alice", bad, "hi").is_err(), "file_letter must refuse {bad:?}");
            assert!(
                mint_outbound_letter("alice", "elsewhere", bad, "hi").is_err(),
                "mint_outbound_letter must refuse {bad:?}"
            );
        }

        assert!(!base_path().exists(), "a refused name must never write base.jsonl");
        assert!(!seen_path().exists(), "a refused name must never write seen.jsonl");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_letter_to_a_name_outside_the_grammar_stays_readable() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("old-name-outside-grammar");

        let h = header("alice", "Old_Name", ENTRY_TYPE_LETTER, &now_iso_utc());
        let (kp, _) = identity::load_or_mint().unwrap();
        let (sig, msgid) = seal(&h, "grandfathered", &kp);
        let envelope = Envelope { header: h, text: "grandfathered".to_string(), sig, msgid: msgid.clone() };
        let entry = Entry {
            seq: 1,
            received_at: now_iso_utc(),
            kind: ENTRY_TYPE_LETTER.to_string(),
            via: "self".to_string(),
            envelope,
        };
        std::fs::create_dir_all(mail_dir()).unwrap();
        append_base_line(&entry).unwrap();
        append_seen_line(&msgid, &entry.received_at).unwrap();

        let got = read_for("Old_Name", false, None).unwrap();
        assert_eq!(got.len(), 1, "a pre-existing off-grammar name stays filed and readable forever");
        assert_eq!(got[0].envelope.msgid, msgid);

        let shown = show(&msgid).unwrap();
        assert!(shown.is_some(), "show must still find a grandfathered entry by msgid");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrolling_a_reader_is_idempotent_and_starts_unread_and_unrung() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let (_env, dir) = root("enrol-idempotent");

        enrol_reader("bob", "sess-1").unwrap();
        enrol_reader("bob", "sess-1").unwrap();
        let cursors = load_cursors().unwrap();
        let cursor = cursors.get("bob").unwrap();
        assert_eq!(cursor.len(), 1, "enrolling twice creates exactly one key");
        assert_eq!(cursor.get("sess-1").unwrap().seq, 0);
        assert_eq!(cursor.get("sess-1").unwrap().rung, 0);

        file_letter("alice", "bob", "one").unwrap();
        read_for("bob", false, Some("sess-1")).unwrap(); // seq -> 1
        enrol_reader("bob", "sess-1").unwrap(); // must not reset the mark
        let cursors = load_cursors().unwrap();
        assert_eq!(
            cursors.get("bob").unwrap().get("sess-1").unwrap().seq,
            1,
            "enrolling an already-enrolled reader never moves its mark"
        );

        let err = enrol_reader("bob", "bob").unwrap_err();
        assert!(!err.is_empty(), "the pseudo-reader is never enrolled");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
