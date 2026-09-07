//! The take store: `songbook/<song>/drafts/<draft>/takes/` when routed into
//! a draft, `songbook/<song>/takes/` when staged directly with no draft
//! (`lyra reload` design, settled 2026-08-31 — takes/back's staging-mode
//! reach; see [`takes_dir`]) — full-content snapshots of the routed scope's
//! livery/cover/widget bodies, minted on every rehearsal write, forming a
//! TREE (not a line) so `rice back --mark <letter>` can revert to any mark
//! and keep editing without destroying what came after it
//! (`references/fleshing-out-aoide-ricing.md` §5.2, phase A; the
//! branch-from-any-mark ask this store exists to answer).
//!
//! **The model, in one sentence:** a take carries `parent: Option<u32>`
//! (`None` only for the very first take of a scope); the number is a single
//! monotone counter, NEVER renumbered and NEVER per-branch; a per-scope
//! `takes/head.json` cursor names where the NEXT take will hang. Reverting
//! moves the cursor; the next snapshot parents off wherever it points.
//! Branching needs no name, no registry, no command — two takes sharing a
//! parent simply IS a branch, discovered by scanning the directory this
//! module already reads, never indexed.
//!
//! **Marks live OUTSIDE the take record**, in a `takes/marks.json` map
//! (`{"A": 9}`) — overruling this feature's own plan, which first tried a
//! `mark` field on `TakeRecord` (advisor verdict, fork 4). A field would
//! make moving a letter a TWO-file rewrite (clear the old take's field,
//! stamp the new one); a crash between those two writes either duplicates
//! the letter (both takes claim it) or loses it (neither does), and no
//! atomic fix exists for two sequential file writes. The map makes a move
//! ONE `atomic_write` of one file. The second win: take records stay
//! write-once from the moment `save_take` first writes them — nothing ever
//! opens a take file to mutate it — which keeps drift comparison (a
//! parse-and-compare against a take's `livery`/`cover`) and any future
//! content-hashing trivially safe, because "the file on disk" and "the take
//! as minted" are never allowed to diverge.
//!
//! **Every function here is UNLOCKED.** `crate::fs::with_stage_lock` is
//! documented not re-entrant (`fs.rs`), so this module never calls it
//! itself — take-number allocation (read max, write max+1) is exactly the
//! read-modify-write race the lock exists for, but wrapping it in HERE would
//! deadlock the very first caller (a later revert/snapshot mutator) that
//! wraps its own multi-step body in one `with_stage_lock` and calls these
//! cores inside it. Locking is entirely the caller's job, once, around the
//! whole mutation — these are the pure primitives it composes.
//!
//! Pure fs + serde only: no `Outcome`, no CLI, no domain validation (song/
//! draft name checks are `crate::compose::valid_song_name`'s job, one layer
//! up, exactly like every other `draft_dir` consumer).

use crate::fs::{atomic_write, draft_dir, songbook_dir};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A take store's root, either of two places depending on `draft`
/// (`lyra reload` design, settled 2026-08-31 — the staging-mode take/back
/// reach): `songbook/<song>/drafts/<draft>/takes/`, nested under the draft
/// it snapshots, when routed into one; `songbook/<song>/takes/`, a sibling
/// of `drafts/`, when the song is staged directly with no draft routed —
/// staging mode has no draft directory to nest under, so its takes hang off
/// the song itself. `None` is NOT "no draft yet" in some third sense; it IS
/// the staging-mode scope, resolved by [`crate::commands`-level callers]
/// (`aoide-song`'s `commands/take.rs::resolve_scope`) straight off
/// `mode.json`'s own `mode`/`draft` fields.
pub fn takes_dir(song: &str, draft: Option<&str>) -> PathBuf {
    match draft {
        Some(d) => draft_dir(song, d).join("takes"),
        None => songbook_dir(song).join("takes"),
    }
}

/// One take's record file: `takes/NNNN.json`, 4-digit zero-padded. The pad
/// is cosmetic only — [`list_takes`]/[`next_take_number`] sort by the
/// PARSED `take` field, never the filename, so a 5th-digit take (`10000`)
/// still orders correctly once the store outgrows the pad width.
pub fn take_path(song: &str, draft: Option<&str>, n: u32) -> PathBuf {
    takes_dir(song, draft).join(format!("{n:04}.json"))
}

/// The per-scope head cursor: `takes/head.json` — where the NEXT take will
/// hang. Per-scope (song when staged, draft when drafted), not a field on
/// the global `mode.json` marker (advisor verdict, fork 3): the cursor is
/// state that must survive a mode round-trip through Staging/Declarative/
/// Draft and back; a marker field would be torn down on every such
/// transition and lose the cursor.
pub fn head_path(song: &str, draft: Option<&str>) -> PathBuf {
    takes_dir(song, draft).join("head.json")
}

/// The mark map: `takes/marks.json`, a flat `{"<letter>": <take>}` object —
/// see the module doc for why marks live here and not on `TakeRecord`.
pub fn marks_path(song: &str, draft: Option<&str>) -> PathBuf {
    takes_dir(song, draft).join("marks.json")
}

/// One take: a full-content snapshot of the routed draft's `livery.json`
/// (and `cover.json`, when the stage had one) at the moment it was minted,
/// plus the tree edge (`parent`) and provenance (`at`/`session_id`/`cause`).
/// Write-once once [`save_take`] has landed it — see the module doc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TakeRecord {
    pub take: u32,
    /// `None` only for a draft's very first take. Ancestry is derived by
    /// walking this back to `None` ([`ancestry`]) — never indexed, never a
    /// stored children list (a child list is one scan of the same
    /// directory [`list_takes`] already reads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    /// ISO-8601 UTC (`crate::time::now_iso_utc`), stamped once at mint time.
    #[serde(default)]
    pub at: String,
    /// The minting session's id, when `AOIDE_SESSION_ID` was set — additive/
    /// v0-safe, mirrors `SessionRecord`'s optional fields
    /// (`crate::records::SessionRecord`).
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// What minted this take: `"stage"`, `"cover-set"`, `"explicit"`,
    /// `"drift"` — the take-store's own event vocabulary, distinct from an
    /// `Outcome` reason string (this crate has no `Outcome`).
    #[serde(default)]
    pub cause: String,
    #[serde(default)]
    pub livery: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover: Option<Value>,
    /// `{ "<songbook-relative widgets/ path>": "<utf-8 file content>" }` —
    /// the song's widget QML bodies at mint time (`lyra reload` design,
    /// settled 2026-08-31: "Takes gain WIDGET BODIES in both modes", closing
    /// the gap that widget QML was never snapshotted). Song-scoped, not
    /// draft-scoped, matching the fact that widget bodies themselves are
    /// song-scoped (a draft forks the dress — livery+cover — never the
    /// widgets). `#[serde(default)]` reads an old take file predating this
    /// field as `{}` (via [`default_widgets`]), the same "no widgets" shape
    /// a fresh capture of a widget-less song produces — so an old take never
    /// spuriously reads as "widgets changed" against a new one.
    #[serde(default = "default_widgets")]
    pub widgets: Value,
}

fn default_widgets() -> Value {
    Value::Object(serde_json::Map::new())
}

/// The bare shape of `head.json` — one optional field so an absent/corrupt
/// file and a present-but-empty one both fall through [`load_head`]'s same
/// "no claimed head" branch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HeadFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    head: Option<u32>,
}

/// Read one take by number. `None` on a missing file, invalid JSON, or a
/// path that fails to parse as a `TakeRecord` — the same tolerate-missing
/// discipline `node_store::load_nodes` / `mode::load_mode_marker` use for
/// any other stage-adjacent file: an absent take is "not there", never an
/// error this deep in the store.
pub fn load_take(song: &str, draft: Option<&str>, n: u32) -> Option<TakeRecord> {
    let raw = std::fs::read_to_string(take_path(song, draft, n)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Atomic-write one take record to its `NNNN.json`. Takes are write-once in
/// practice (nothing ever calls this twice for the same `record.take`), but
/// nothing here enforces that — the caller allocating the number via
/// [`next_take_number`] under its own lock is what makes it true.
pub fn save_take(song: &str, draft: Option<&str>, record: &TakeRecord) -> Result<(), String> {
    let body = serde_json::to_string_pretty(record)
        .map_err(|e| format!("serialize take {}: {e}", record.take))?
        + "\n";
    let path = take_path(song, draft, record.take);
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Every take on disk, sorted by the PARSED `take` number — never by
/// filename. Filename-lexicographic order breaks the instant a store
/// crosses five digits (`"10000.json"` sorts before `"0002.json"` as a
/// string), which would silently reorder `rice take list`'s tree and hand
/// `next_take_number` the wrong maximum.
///
/// A directory entry whose stem isn't all-digits (`head.json`, `marks.json`,
/// a stray `NNNN.tmp.<pid>` atomic-write leftover — its stem is
/// `"NNNN.tmp"`, which fails the digit test) is silently skipped, as is any
/// `NNNN.json` that fails to parse as a `TakeRecord` — a half-written or
/// hand-corrupted take is dropped from the listing rather than wedging
/// every reader of the store.
pub fn list_takes(song: &str, draft: Option<&str>) -> Vec<TakeRecord> {
    let dir = takes_dir(song, draft);
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<TakeRecord> = read
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let stem = path.file_stem()?.to_str()?;
            if stem.is_empty() || !stem.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let raw = std::fs::read_to_string(&path).ok()?;
            serde_json::from_str::<TakeRecord>(&raw).ok()
        })
        .collect();
    out.sort_by_key(|t| t.take);
    out
}

/// The next take number to mint: the highest existing `take` plus one, or
/// `1` for an empty store. Gap-tolerant by construction — a store holding
/// `0001` and `0004` (takes `0002`/`0003` pruned away) yields `5`, never
/// "the first free gap"; a take number is a mint timestamp, not a slot to
/// reuse.
pub fn next_take_number(song: &str, draft: Option<&str>) -> u32 {
    list_takes(song, draft)
        .iter()
        .map(|t| t.take)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1)
}

/// The current head: the take the next snapshot will parent off, and the
/// take a bare revert-undo (§5.2) resolves against. An absent `head.json`
/// falls back to the highest existing take number, exactly as an absent
/// take store falls back to `None` — but so does a PRESENT `head.json`
/// naming a take that no longer exists (a crash between pruning a take and
/// rewriting the head that pointed at it, or a hand edit): a stale head
/// must never wedge the store on its own (advisor verdict, D3a), so both
/// cases fall back the same way, by construction, rather than the caller
/// having to special-case "file present but pointing at nothing".
pub fn load_head(song: &str, draft: Option<&str>) -> Option<u32> {
    let takes = list_takes(song, draft);
    let claimed = std::fs::read_to_string(head_path(song, draft))
        .ok()
        .and_then(|raw| serde_json::from_str::<HeadFile>(&raw).ok())
        .and_then(|h| h.head);
    match claimed {
        Some(n) if takes.iter().any(|t| t.take == n) => Some(n),
        _ => takes.iter().map(|t| t.take).max(),
    }
}

/// Atomic-write the head cursor.
pub fn save_head(song: &str, draft: Option<&str>, n: u32) -> Result<(), String> {
    let body = serde_json::to_string_pretty(&HeadFile { head: Some(n) })
        .map_err(|e| format!("serialize head.json: {e}"))?
        + "\n";
    let path = head_path(song, draft);
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Read the mark map, tolerating a missing/corrupt file as empty — the same
/// "absent means nothing registered yet" discipline every other stage-
/// adjacent registry in this crate uses. Callers that need marks to only
/// ever name a take that still exists (A6/A7/A5's read paths) filter this
/// against [`list_takes`] themselves; pruning is the only writer that
/// removes a stale entry ([`save_marks`] after a prune's own rewrite).
pub fn load_marks(song: &str, draft: Option<&str>) -> BTreeMap<String, u32> {
    std::fs::read_to_string(marks_path(song, draft))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Atomic-write the mark map — ONE write for the whole map, which is the
/// entire point of storing marks this way: stamping a letter, or moving one
/// off a take and onto another, is a single `atomic_write` of one file, not
/// two sequential take-record rewrites that a crash could tear in half.
pub fn save_marks(song: &str, draft: Option<&str>, marks: &BTreeMap<String, u32>) -> Result<(), String> {
    let body = serde_json::to_string_pretty(marks)
        .map_err(|e| format!("serialize marks.json: {e}"))?
        + "\n";
    let path = marks_path(song, draft);
    atomic_write(&path, &body).map_err(|e| format!("{}: {e}", path.display()))
}

/// Walk `parent` from `n` back to the root (`None`), inclusive of `n`
/// itself. Two different takes' ancestries sharing a tail is exactly what a
/// branch looks like from this function's point of view — it needs no
/// notion of "branch" to answer "what does this take descend from".
///
/// Cycle-guarded: a hand-edited take file could self-parent (or form a
/// longer loop), which would otherwise spin forever. The walk aborts the
/// instant it revisits a take number, and is additionally capped at
/// `takes.len() + 1` steps as a belt-and-suspenders bound — a store with
/// `k` records can never have a genuine acyclic chain longer than `k`.
pub fn ancestry(takes: &[TakeRecord], n: u32) -> Vec<u32> {
    let cap = takes.len() + 1;
    let mut out = Vec::new();
    let mut current = Some(n);
    while let Some(cur) = current {
        if out.len() >= cap || out.contains(&cur) {
            break;
        }
        out.push(cur);
        current = takes.iter().find(|t| t.take == cur).and_then(|t| t.parent);
    }
    out
}

/// Every take whose `parent` is `n`, ascending. Derived by one scan, never
/// stored — the plan's whole argument for why a parent pointer is enough
/// and a children index would be redundant machinery.
pub fn children(takes: &[TakeRecord], n: u32) -> Vec<u32> {
    let mut out: Vec<u32> = takes
        .iter()
        .filter(|t| t.parent == Some(n))
        .map(|t| t.take)
        .collect();
    out.sort_unstable();
    out
}

/// The prune splice (§7.1): drop `removed` from the list and re-parent its
/// direct children onto `removed`'s own parent, so pruning a take never
/// orphans or breaks the ancestry of anything that survives it — ancestry
/// degrades to "further back", never to broken. Pure and IO-free so the
/// caller (A9's `rice take prune`) gets this already unit-tested and can
/// drive the actual file deletion off its return value without re-deriving
/// the splice itself.
pub fn reparent(takes: &[TakeRecord], removed: u32) -> Vec<TakeRecord> {
    let removed_parent = takes.iter().find(|t| t.take == removed).and_then(|t| t.parent);
    takes
        .iter()
        .filter(|t| t.take != removed)
        .cloned()
        .map(|mut t| {
            if t.parent == Some(removed) {
                t.parent = removed_parent;
            }
            t
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────
//
// Every env-touching test takes the crate-wide `env_lock` AND an `EnvSaver`
// (`mode.rs`'s canonical shape) since `AOIDE_STAGE_DIR` is process-global.

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::{env_lock, unique_tmp, EnvSaver};

    /// Point `AOIDE_STAGE_DIR` at a fresh `<tmp>/stage` and return
    /// `(song, draft)` args every helper below threads straight into
    /// `takes_dir`/`take_path`/etc. — the song tree resolves as `<tmp>`,
    /// the stage's sibling, exactly like `fs.rs`'s own precedent tests.
    fn routed(tag: &str) -> (String, String) {
        let root = unique_tmp(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        ("sonata".to_string(), "neon-night".to_string())
    }

    fn rec(take: u32, parent: Option<u32>) -> TakeRecord {
        TakeRecord {
            take,
            parent,
            at: "2026-08-18T00:00:00Z".to_string(),
            session_id: None,
            cause: "stage".to_string(),
            livery: serde_json::json!({ "schemaVersion": "0" }),
            cover: None,
            widgets: default_widgets(),
        }
    }

    // ── save/load: a record round-trips through atomic_write, parent intact ──

    #[test]
    fn a_take_record_round_trips_through_atomic_write_with_its_parent_pointer_intact() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-roundtrip");

        let mut record = rec(9, Some(1));
        record.session_id = Some("sess-abc".to_string());
        record.cover = Some(serde_json::json!({ "path": "x.png" }));
        save_take(&song, Some(&draft), &record).unwrap();

        let back = load_take(&song, Some(&draft), 9).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.parent, Some(1), "the parent pointer survives the round trip");

        // A take with no parent omits the field entirely rather than writing
        // a literal `null` — matches ModeMarker's additive discipline.
        let raw = std::fs::read_to_string(take_path(&song, Some(&draft), 9)).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["parent"], 1);
        assert_eq!(v["sessionId"], "sess-abc");

        let root_take = rec(1, None);
        save_take(&song, Some(&draft), &root_take).unwrap();
        let raw_root = std::fs::read_to_string(take_path(&song, Some(&draft), 1)).unwrap();
        let v_root: Value = serde_json::from_str(&raw_root).unwrap();
        assert!(v_root.get("parent").is_none(), "no parent is omitted, not null");
    }

    #[test]
    fn load_take_is_none_for_a_missing_or_corrupt_file() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-missing");

        assert!(load_take(&song, Some(&draft), 1).is_none());

        std::fs::create_dir_all(takes_dir(&song, Some(&draft))).unwrap();
        std::fs::write(take_path(&song, Some(&draft), 2), "not json").unwrap();
        assert!(load_take(&song, Some(&draft), 2).is_none());
    }

    // ── next_take_number: gap-tolerant, numeric, never filename order ──────

    #[test]
    fn next_take_number_is_one_for_an_empty_store() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-next-empty");
        assert_eq!(next_take_number(&song, Some(&draft)), 1);
    }

    #[test]
    fn next_take_number_is_gap_tolerant_not_first_free_slot() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-next-gap");
        save_take(&song, Some(&draft), &rec(1, None)).unwrap();
        save_take(&song, Some(&draft), &rec(4, Some(1))).unwrap();
        // Takes 2/3 are absent (pruned, or never minted) — the next number is
        // one past the HIGHEST surviving take, not the first empty slot (2).
        assert_eq!(next_take_number(&song, Some(&draft)), 5);
    }

    #[test]
    fn list_and_next_sort_by_parsed_number_not_filename_lexical_order() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-numeric-sort");
        // "10000.json" < "0002.json" as strings — a lexicographic sort would
        // put 10000 first and hand next_take_number the wrong maximum.
        save_take(&song, Some(&draft), &rec(2, None)).unwrap();
        save_take(&song, Some(&draft), &rec(10000, Some(2))).unwrap();
        save_take(&song, Some(&draft), &rec(9, Some(2))).unwrap();

        let numbers: Vec<u32> = list_takes(&song, Some(&draft)).iter().map(|t| t.take).collect();
        assert_eq!(numbers, vec![2, 9, 10000], "sorted numerically, not lexically");
        assert_eq!(next_take_number(&song, Some(&draft)), 10001);
    }

    #[test]
    fn list_takes_skips_head_marks_and_unparseable_entries() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-list-skip");
        save_take(&song, Some(&draft), &rec(1, None)).unwrap();
        save_head(&song, Some(&draft), 1).unwrap();
        save_marks(&song, Some(&draft), &BTreeMap::from([("A".to_string(), 1u32)])).unwrap();
        std::fs::write(take_path(&song, Some(&draft), 2), "garbage, not a take").unwrap();

        let numbers: Vec<u32> = list_takes(&song, Some(&draft)).iter().map(|t| t.take).collect();
        assert_eq!(numbers, vec![1], "head.json/marks.json/a corrupt NNNN.json are all skipped");
    }

    // ── load_head: absent falls back to max; a STALE head does too (D3a) ───

    #[test]
    fn load_head_is_none_for_an_empty_store_and_falls_back_to_max_when_absent() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-head-absent-empty");
        assert_eq!(load_head(&song, Some(&draft)), None, "nothing minted yet");

        save_take(&song, Some(&draft), &rec(1, None)).unwrap();
        save_take(&song, Some(&draft), &rec(2, Some(1))).unwrap();
        // No head.json was ever written — falls back to the highest take.
        assert_eq!(load_head(&song, Some(&draft)), Some(2));
    }

    #[test]
    fn load_head_falls_back_to_max_when_the_claimed_head_take_no_longer_exists() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-head-stale");
        save_take(&song, Some(&draft), &rec(1, None)).unwrap();
        save_take(&song, Some(&draft), &rec(2, Some(1))).unwrap();
        save_take(&song, Some(&draft), &rec(5, Some(2))).unwrap();
        // A crash mid-prune (or a hand edit) leaves head.json naming a take
        // that no longer exists — this must not wedge the store.
        save_head(&song, Some(&draft), 999).unwrap();

        assert_eq!(load_head(&song, Some(&draft)), Some(5), "stale head falls back to the maximum surviving take");
    }

    #[test]
    fn save_head_round_trips_a_valid_claim() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-head-valid");
        save_take(&song, Some(&draft), &rec(1, None)).unwrap();
        save_take(&song, Some(&draft), &rec(2, Some(1))).unwrap();
        save_head(&song, Some(&draft), 1).unwrap();
        assert_eq!(load_head(&song, Some(&draft)), Some(1), "an existing claimed head is honored, not maxed");
    }

    // ── marks.json: one atomic write moves a letter ─────────────────────────

    #[test]
    fn marks_round_trip_and_moving_a_letter_is_one_atomic_write_of_the_map() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-marks-move");

        let mut marks = BTreeMap::new();
        marks.insert("A".to_string(), 9u32);
        save_marks(&song, Some(&draft), &marks).unwrap();
        assert_eq!(load_marks(&song, Some(&draft)).get("A"), Some(&9));

        // "Moving" a letter is: mutate the in-memory map, then ONE save —
        // never a rewrite of the take files it used to/now names.
        marks.insert("A".to_string(), 14u32);
        save_marks(&song, Some(&draft), &marks).unwrap();

        let after = load_marks(&song, Some(&draft));
        assert_eq!(after.get("A"), Some(&14), "the letter now points at the new take");
        assert_eq!(after.len(), 1, "moving overwrote the entry, it did not duplicate it");
    }

    #[test]
    fn load_marks_tolerates_a_missing_or_corrupt_file_as_empty() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (song, draft) = routed("takes-marks-missing");
        assert!(load_marks(&song, Some(&draft)).is_empty());

        std::fs::create_dir_all(takes_dir(&song, Some(&draft))).unwrap();
        std::fs::write(marks_path(&song, Some(&draft)), "not json").unwrap();
        assert!(load_marks(&song, Some(&draft)).is_empty());
    }

    // ── ancestry: walks a branch back to the root; cycle-guarded ───────────

    #[test]
    fn ancestry_walks_both_branches_of_a_fork_back_to_the_same_root() {
        // 1 <- 9 <- 17
        //        \- 21
        let takes = vec![rec(1, None), rec(9, Some(1)), rec(17, Some(9)), rec(21, Some(9))];
        assert_eq!(ancestry(&takes, 17), vec![17, 9, 1]);
        assert_eq!(ancestry(&takes, 21), vec![21, 9, 1]);
    }

    #[test]
    fn ancestry_refuses_to_loop_on_a_self_parented_record() {
        let takes = vec![rec(1, None), rec(5, Some(5))];
        assert_eq!(ancestry(&takes, 5), vec![5], "a self-parented record stops after one step");
    }

    #[test]
    fn ancestry_refuses_to_loop_on_a_longer_cycle() {
        let takes = vec![rec(2, Some(3)), rec(3, Some(2))];
        let out = ancestry(&takes, 2);
        assert!(out.len() <= takes.len() + 1);
        assert_eq!(out, vec![2, 3], "walks once around the cycle then stops");
    }

    // ── children: the two branches under a shared parent ───────────────────

    #[test]
    fn children_finds_both_branches_under_a_shared_parent() {
        let takes = vec![rec(1, None), rec(9, Some(1)), rec(17, Some(9)), rec(21, Some(9))];
        assert_eq!(children(&takes, 9), vec![17, 21]);
        assert_eq!(children(&takes, 21), Vec::<u32>::new(), "a leaf has no children");
    }

    // ── reparent: the prune splice, grandchildren survive ──────────────────

    #[test]
    fn reparent_splices_children_onto_the_pruned_takes_own_parent() {
        // 1 <- 9 <- 17 <- 25
        //             \- 26
        let takes = vec![
            rec(1, None),
            rec(9, Some(1)),
            rec(17, Some(9)),
            rec(25, Some(17)),
            rec(26, Some(17)),
        ];
        let spliced = reparent(&takes, 17);

        assert_eq!(spliced.len(), 4, "the pruned take itself is dropped");
        assert!(spliced.iter().all(|t| t.take != 17));
        let find = |n: u32| spliced.iter().find(|t| t.take == n).unwrap().clone();
        assert_eq!(find(25).parent, Some(9), "grandchild re-parents to 17's own parent");
        assert_eq!(find(26).parent, Some(9));
        assert_eq!(find(9).parent, Some(1), "untouched ancestor is unchanged");

        // Ancestry still resolves cleanly through the splice.
        assert_eq!(ancestry(&spliced, 25), vec![25, 9, 1]);
    }

    #[test]
    fn reparent_on_a_root_take_leaves_its_children_rootless() {
        let takes = vec![rec(1, None), rec(2, Some(1)), rec(3, Some(1))];
        let spliced = reparent(&takes, 1);
        assert_eq!(spliced.len(), 2);
        let find = |n: u32| spliced.iter().find(|t| t.take == n).unwrap().clone();
        assert_eq!(find(2).parent, None, "pruning the root leaves its children as new roots");
        assert_eq!(find(3).parent, None);
    }
}
