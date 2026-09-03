//! `state/inbox.json` — the durable per-host message inbox (messaging plan
//! P-C6): every message that actually LANDED in a local session — however it
//! got there — is filed here, so a headless agent joining late (or a human
//! checking in) can read what arrived while nobody was watching.
//!
//! **[`receive`] is called from exactly TWO sites — every OTHER call in the
//! tree reaches one of these two, never adds a third:**
//!
//! 1. `aoide_conduct::graph::send::deliver_local`'s success path — the
//!    place a message lands in an ALREADY-REGISTERED session's pty
//!    (CONTRACTS.md §4). Covers a direct `graph send --id`, a `graph send
//!    --to <local target>` (re-drives `deliver_local` unchanged), `graph
//!    pending approve`'s re-drive (same door, in-process), AND the A2A
//!    server's `do_inject` (`crates/server/src/a2a.rs`) — `do_inject`
//!    builds a `graph send --id` [`aoide_protocol::Invocation`] and calls
//!    `aoide_conduct::graph::session_send` directly, which for a same-box
//!    `contextId` always resolves to `deliver_local` too (there is no
//!    `--to` flag in that Invocation, so the local branch is the ONLY
//!    branch it can take). `do_inject` files no entry of its own — adding
//!    one would double-count every message it delivers into an existing
//!    session.
//! 2. `aoide-server`'s `spawn_inject_prompt` (`crates/server/src/a2a.rs`) —
//!    the FIRST turn of a brand-new A2A-spawned session (`do_spawn`, fired
//!    whenever an incoming `message/send` carries no `contextId` or asks to
//!    spawn). This one does NOT go through `session_send`/`deliver_local`:
//!    the target `SessionRecord` doesn't exist in `sessions.json` yet at
//!    the moment the prompt is typed — it is written by the SPAWNED CHILD
//!    ITSELF once its own `aoide conduct` process starts up, which is a
//!    race `spawn_inject_prompt`'s own connect-and-retry loop exists to
//!    survive in the first place. Going through the session registry here
//!    would just trade the socket race for a registration race, so this
//!    site talks to the raw socket directly and files its own inbox entry
//!    right after the write, best-effort, same tolerance as the rest of
//!    that function (a write error is already swallowed there).
//!
//! Together these cover "one queue, two writers... no second
//! implementation" the same way `pending.json` already established
//! (CONTRACTS.md §4's `pending.json` section) — except doubled here: TWO
//! genuinely distinct filing sites, not because two doors both write, but
//! because one door (A2A) has two genuinely different delivery mechanics
//! (an existing session's socket vs. a session that doesn't have a
//! registry entry yet).
//!
//! `deliver_remote` (an OUTBOUND `--to peer/<x>` send to another box) never
//! calls [`receive`] — there is nothing to file on THIS host: the message
//! lands in the REMOTE peer's OWN inbox, via whichever of that peer's own
//! two sites actually delivers it.
//!
//! **Cap + oldest-drop**: [`INBOX_CAP`] mirrors `herald.rs`'s `LEDGER_CAP`
//! precedent exactly (fold-and-cap, oldest entries fall off the front) —
//! see [`apply_receive`].
//!
//! **`context` is deliberately opaque.** It exists for a planned Mneme
//! (memory-manager) integration (#14/#16) that does not exist yet: v0
//! carries whatever `serde_json::Value` a future producer sets, round-trips
//! it byte-for-byte, and never reads or interprets it. No current call site
//! sets it — every [`receive`] call in this tree passes `None`.
//!
//! **Not built here (deferred, one flagged line each, per the plan):**
//! - No conductor pane — rides a later phase.
//! - No outbox retry for a peer that was unreachable at send time — the
//!   sender already gets a clean error from `deliver_remote`; nothing queues
//!   a retry.

use crate::fs::{state_dir, with_stage_lock};
use crate::stage::{load_stage, write_stage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// Schema version of `inbox.json` — bumped only on a breaking shape change.
pub const INBOX_SCHEMA: &str = "0";

/// How many entries the inbox keeps. Matches `herald::LEDGER_CAP`'s
/// fold-and-cap shape (see [`apply_receive`]); the number itself is
/// independent (a message inbox and a notification ledger have no reason to
/// share a depth), chosen generously since a message is worth keeping
/// longer than a toast.
pub const INBOX_CAP: usize = 200;

/// One filed message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxEntry {
    /// The resolved sender attribution, or empty for an anonymous/unknown
    /// sender (local: `resolve_sender`'s output; A2A: the door has no
    /// caller identity to offer today — #51 owns real provenance, this
    /// never invents any). Always present in the JSON, unlike `context`.
    #[serde(default)]
    pub from: String,
    /// The target session id the message was delivered into.
    pub target: String,
    /// The delivered text, unprefixed (the raw message, not the
    /// provenance-prefixed/submit-keystroke-suffixed payload that actually
    /// hit the socket).
    pub text: String,
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    #[serde(default)]
    pub read: bool,
    /// Reserved, opaque passthrough for a future Mneme integration (see the
    /// module doc) — v0 never sets or reads this field's contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

/// `inbox.json` container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxFile {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub entries: Vec<InboxEntry>,
}

/// `~/Aoide/state/inbox.json` — durable, per-host, NOT song-scoped (same
/// tier as `usage.json`/`peers.json`, never reset by a stage reseed).
pub fn inbox_path() -> PathBuf {
    state_dir().join("inbox.json")
}

/// Fold one incoming message into the list. Pure, so the cap/oldest-drop
/// rule is tested without a filesystem — mirrors `herald::apply_push`'s
/// shape, minus the stack-tag/id replace rule (nothing here) since every
/// message is distinct: there is no notion of one message "superseding"
/// another the way a repeated toast does.
pub fn apply_receive(mut list: Vec<InboxEntry>, incoming: InboxEntry) -> Vec<InboxEntry> {
    list.push(incoming);
    if list.len() > INBOX_CAP {
        let excess = list.len() - INBOX_CAP;
        list.drain(..excess);
    }
    list
}

/// File one delivered message. Best-effort by design at the call site (a
/// failed inbox write must never turn an ALREADY-SUCCEEDED delivery into a
/// reported failure) — this function itself still reports a real `Result`
/// so the caller decides how to surface it.
///
/// Reuses [`with_stage_lock`] — the SAME flock every stage-file
/// read-modify-write already serialises against, even though `inbox.json`
/// itself lives under `state/`, not `stage/`. One process-wide lock file is
/// enough to keep every inbox writer from racing every other one (the only
/// requirement); a second lock file for the `state/` tree would be a new
/// abstraction for zero added correctness.
pub fn receive(from: &str, target: &str, text: &str, context: Option<Value>) -> Result<(), String> {
    let path = inbox_path();
    with_stage_lock(move || {
        let mut file: InboxFile = load_stage(&path)?;
        file.schema_version = INBOX_SCHEMA.to_string();
        let entry = InboxEntry {
            from: from.to_string(),
            target: target.to_string(),
            text: text.to_string(),
            received_at: crate::time::now_iso_utc(),
            read: false,
            context,
        };
        file.entries = apply_receive(file.entries, entry);
        write_stage(&path, &file)
    })
}

/// Read the current inbox (empty when the file is absent — same tolerance
/// as every other stage/state file).
pub fn load() -> Result<InboxFile, String> {
    load_stage(&inbox_path())
}

/// Mark the entry at array position `index` read, under the lock (read
/// fresh, write back — same discipline `pending.rs`'s
/// `take_pending_entry` uses). Returns the entry as it now stands.
///
/// **Id semantics (documented divergence from `pending.rs`'s precedent):**
/// `index` is the entry's POSITION in the full stored array, exactly like
/// `pending list`'s `id`. But unlike a pending entry — which is REMOVED on
/// resolution, so every other entry's position shifts the moment ANY one
/// resolves — marking an inbox entry read does not remove it, so positions
/// stay stable across repeated `inbox read` calls. The one thing that CAN
/// still shift a position is [`apply_receive`]'s cap: a new message arriving
/// after your `inbox list` snapshot pushes the array past [`INBOX_CAP`] and
/// drops the oldest entry, shifting everyone after it down by one — the
/// same "re-list if you're racing a concurrent writer" discipline
/// `pending.rs` documents, just triggered by the cap instead of every
/// resolution.
pub fn mark_read(index: usize) -> Result<InboxEntry, String> {
    let path = inbox_path();
    with_stage_lock(move || {
        let mut file: InboxFile = load_stage(&path)?;
        let entry = file
            .entries
            .get_mut(index)
            .ok_or_else(|| format!("no inbox entry at index {index}"))?;
        entry.read = true;
        let out = entry.clone();
        write_stage(&path, &file)?;
        Ok(out)
    })
}

/// Empty the inbox. Returns how many entries were dropped.
pub fn clear() -> Result<usize, String> {
    let path = inbox_path();
    with_stage_lock(move || {
        let mut file: InboxFile = load_stage(&path)?;
        let n = file.entries.len();
        file.entries.clear();
        file.schema_version = INBOX_SCHEMA.to_string();
        write_stage(&path, &file)?;
        Ok(n)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(target: &str, text: &str) -> InboxEntry {
        InboxEntry {
            from: "sender".to_string(),
            target: target.to_string(),
            text: text.to_string(),
            received_at: "2026-08-21T00:00:00Z".to_string(),
            read: false,
            context: None,
        }
    }

    #[test]
    fn apply_receive_appends_and_never_drops_below_the_cap() {
        let mut list = Vec::new();
        for i in 0..10 {
            list = apply_receive(list, entry("t", &i.to_string()));
        }
        assert_eq!(list.len(), 10);
        assert_eq!(list[0].text, "0");
        assert_eq!(list[9].text, "9");
    }

    #[test]
    fn apply_receive_caps_and_drops_the_oldest_first() {
        let mut list = Vec::new();
        for i in 0..(INBOX_CAP + 7) {
            list = apply_receive(list, entry("t", &i.to_string()));
        }
        assert_eq!(list.len(), INBOX_CAP);
        assert_eq!(list.first().unwrap().text, "7", "the oldest 7 fell off");
        assert_eq!(list.last().unwrap().text, (INBOX_CAP + 6).to_string());
    }

    #[test]
    fn context_round_trips_byte_exact_through_json() {
        let mut e = entry("t", "hello");
        e.context = Some(serde_json::json!({"nested": [1, 2, "x"], "flag": true}));
        let s = serde_json::to_string(&e).unwrap();
        let back: InboxEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.context, e.context);
        assert_eq!(back, e);
    }

    #[test]
    fn a_missing_context_never_serializes_the_key() {
        let e = entry("t", "hello");
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.as_object().unwrap().get("context").is_none());
    }

    #[test]
    fn receive_writes_atomically_and_load_round_trips() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("aoide-inbox-recv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        receive("alice", "sess-1", "hello there", None).unwrap();
        receive("", "sess-1", "anonymous ping", None).unwrap();

        let file = load().unwrap();
        assert_eq!(file.schema_version, INBOX_SCHEMA);
        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[0].from, "alice");
        assert_eq!(file.entries[0].target, "sess-1");
        assert!(!file.entries[0].read);
        assert_eq!(file.entries[1].from, "");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_read_flips_only_the_named_index_and_positions_stay_stable() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("aoide-inbox-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        receive("a", "s", "one", None).unwrap();
        receive("b", "s", "two", None).unwrap();
        receive("c", "s", "three", None).unwrap();

        let marked = mark_read(1).unwrap();
        assert!(marked.read);
        assert_eq!(marked.text, "two");

        let file = load().unwrap();
        assert!(!file.entries[0].read, "index 0 untouched");
        assert!(file.entries[1].read);
        assert!(!file.entries[2].read, "index 2 untouched");
        // Positions did not shift — index 1 is still "two" after the mark.
        assert_eq!(file.entries[1].text, "two");

        // Re-marking the same index again is idempotent, not an error.
        assert!(mark_read(1).unwrap().read);

        // Out of range is a clean error.
        assert!(mark_read(99).is_err());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_empties_and_reports_how_many_were_dropped() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("aoide-inbox-clear-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        receive("a", "s", "one", None).unwrap();
        receive("b", "s", "two", None).unwrap();
        assert_eq!(clear().unwrap(), 2);
        assert!(load().unwrap().entries.is_empty());
        assert_eq!(clear().unwrap(), 0, "clearing an empty inbox is a clean no-op");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_on_a_missing_file_is_an_empty_ok() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("aoide-inbox-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        let file = load().unwrap();
        assert!(file.entries.is_empty());

        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
