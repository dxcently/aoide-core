//! `rice take` — the explicit snapshot verb, and the two mutator cores every
//! later take verb (`rice back`, `rice take mark`, the auto-take hooks in
//! `rice stage`/`cover set`) is built on
//! (`references/fleshing-out-aoide-ricing.md` §5.2, phase A; the
//! branch-from-any-mark ask this whole feature exists to answer).
//!
//! **Locking discipline (advisor verdict, defect D2) — read this before
//! adding a caller.** [`snapshot_unlocked`] and [`snapshot_if_drifted_unlocked`]
//! never take `aoide_storage::fs::with_stage_lock` themselves — allocating a
//! take number is a read-max/write-max+1 race exactly like the lock exists
//! for, but the lock is documented **not re-entrant**
//! (`aoide-storage/src/fs.rs`). If these cores locked internally, `rice
//! back` (a later step) — which must snapshot-if-drifted, write the revert,
//! AND advance the head cursor as one atomic unit — would either deadlock
//! wrapping its whole body in a second acquire, or (worse, silently) run the
//! rest of its body unlocked if it called the cores without wrapping at all.
//! [`snapshot`] is the ONLY locked entrypoint here — a single
//! `with_stage_lock` around [`snapshot_unlocked`], fine for any caller whose
//! write isn't already folded into someone else's locked mutator. That
//! covers this file's own `rice take` handler AND `rice stage`/`cover
//! set`'s auto-take hooks (phase A3, `commands/rice.rs`/`commands/cover.rs`)
//! — both call [`snapshot`] plainly, unconditionally, on every successful
//! Draft-mode write. [`snapshot_if_drifted_unlocked`] carries NO locked
//! counterpart at all, deliberately not reintroduced, because it has
//! exactly ONE sanctioned caller: `rice back` (a later step), which must
//! snapshot-if-drifted, write the revert, AND advance the head cursor as
//! ONE atomic unit — the drift check has to fold into that SAME single
//! lock, not a second acquire, so it stays `_unlocked` and `rice back`
//! wraps `with_stage_lock` around its own whole body itself. The auto-take
//! hooks are NOT a second caller of the drift check: a take records every
//! write, not just the ones that changed something
//! (`aoide_storage::takes`' own module doc: "minted on every rehearsal
//! write") — a content-identical restage still mints, and the resulting
//! noise is `rice take prune`'s problem (phase A9, §7.1), not write-time
//! suppression's. The drift check's whole reason to exist is different: A5
//! calls it because a revert is ABOUT TO OVERWRITE the stage and must
//! preserve un-taken edits before destroying them. A3's hooks run AFTER a
//! write has already landed — nothing is about to be destroyed — so that
//! rationale never applied to them, and reusing the drift core there was
//! this file's own earlier mistake, corrected before landing.
//!
//! Everything else about the model — the parent pointer, the flat monotone
//! counter, the head cursor — lives in `aoide_storage::takes`; this module
//! is CLI + orchestration on top of that pure store.
//!
//! **Command-name threading (phase A3, advisor-flagged).** [`snapshot_unlocked`],
//! [`snapshot`], and [`snapshot_if_drifted_unlocked`] all take a `cmd: &str`
//! first argument — the SAME dotted command name [`resolve_draft`] already
//! threads through, not the take-store's own `cause` vocabulary. This was
//! harmless while `rice take` (cmd `"rice.take"`) was the only caller: every
//! refusal `Outcome` these cores build could safely hardcode that string.
//! Phase A3 adds a SECOND caller — the auto-take hooks in `rice stage`/
//! `cover set` — so a refusal bubbling out of an auto-take must report the
//! command that actually invoked it (`"rice.stage"`, `"cover.set"`), not
//! `"rice.take"`. Every caller passes its own dotted name straight through,
//! exactly like [`resolve_draft(cmd)`] already did and following the
//! `no_resolvable_song(cmd)` precedent in `draft.rs`.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
use aoide_storage::fs as shellbridge;
use aoide_storage::mode::{self, RiceMode};
use aoide_storage::takes::{self, TakeRecord};
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "take"],
        summary: "Snapshot the routed draft's current livery+cover as a new take, hanging off the current head. Draft mode only — takes live inside the draft.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_rice_take,
    ));
}

/// The shared "must be routed into a draft" guard every take verb starts
/// with: takes live inside `songbook/<song>/drafts/<draft>/takes/`
/// ([`aoide_storage::takes::takes_dir`]), so nothing about them is
/// resolvable outside `Draft` mode — a `Staging`/`Declarative` stage has no
/// draft directory to nest a `takes/` under at all. `mode.json`'s `draft`
/// field is `Some` **iff** `mode == Draft` (`aoide_storage::mode`'s own
/// module doc records the invariant); this reads that fact rather than
/// re-deriving it, and hands back both names together since every caller
/// needs the pair in the same breath. `cmd` is the caller's own dotted
/// command name (`rice.take`, `rice.back`, …) so the refusal's `Outcome`
/// carries the command that actually issued it, not this shared helper's.
pub(crate) fn resolve_draft(cmd: &str) -> Result<(String, String), Outcome> {
    let marker = mode::load_mode_marker();
    match (marker.mode, marker.song, marker.draft) {
        (RiceMode::Draft, Some(song), Some(draft)) => Ok((song, draft)),
        _ => Err(Outcome::error(
            cmd,
            "not in draft mode — takes only exist inside a routed draft \
             (`aoide rice mode draft <name>` first)",
        )
        .with_data(json!({ "reason": "not-in-draft-mode" }))),
    }
}

/// Read the routed draft's CURRENT `livery.json` (required — an absent or
/// unparseable stage livery is refused, there is nothing to snapshot) and
/// `cover.json` (optional — absent simply means no cover, not an error).
/// Both are read straight off [`aoide_storage::fs::stage_dir`], not the
/// draft directory itself: while `Draft` mode is routed, `stage/livery.json`
/// IS the draft's live content (a symlink `aoide_storage::fs::atomic_write`
/// resolves transparently, and a plain `read_to_string` follows the same
/// way) — reading the stage is reading the draft, with zero extra
/// symlink-awareness needed here.
fn read_staged_content(cmd: &str) -> Result<(Value, Option<Value>), Outcome> {
    let stage = shellbridge::stage_dir();
    let livery_path = stage.join("livery.json");
    let raw = std::fs::read_to_string(&livery_path).map_err(|e| {
        Outcome::error(
            cmd,
            format!("nothing staged to snapshot: cannot read {} ({e})", livery_path.display()),
        )
        .with_data(json!({
            "reason": "no-staged-livery",
            "expected": livery_path.to_string_lossy(),
        }))
    })?;
    let livery: Value = serde_json::from_str(&raw).map_err(|e| {
        Outcome::error(cmd, format!("staged livery.json is not valid JSON: {e}")).with_data(json!({
            "reason": "invalid-json",
            "notes": livery_path.to_string_lossy(),
        }))
    })?;

    let cover_path = stage.join("cover.json");
    let cover: Option<Value> = if cover_path.is_file() {
        std::fs::read_to_string(&cover_path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
    } else {
        None
    };

    Ok((livery, cover))
}

/// The unlocked snapshot core (see the module doc for why it is unlocked):
/// read the routed draft's current content, allocate the next take number,
/// stamp it as a child of whatever the head cursor currently names, write
/// the record, and advance the head to it. `cmd` is the caller's own dotted
/// command name (`"rice.take"`, `"rice.stage"`, `"cover.set"`, …), threaded
/// into every `Outcome` this builds so a refusal reports who actually asked
/// — see the module doc's "command-name threading" note. `cause` is the
/// take-store's own event vocabulary (`"explicit"`, `"stage"`, `"cover-set"`,
/// `"drift"` — distinct from an `Outcome` reason string,
/// `aoide_storage::takes`' `TakeRecord::cause` doc explains why).
pub(crate) fn snapshot_unlocked(cmd: &str, cause: &str) -> Result<TakeRecord, Outcome> {
    let (song, draft) = resolve_draft(cmd)?;
    let (livery, cover) = read_staged_content(cmd)?;

    let take = takes::next_take_number(&song, &draft);
    let record = TakeRecord {
        take,
        parent: takes::load_head(&song, &draft),
        at: aoide_storage::time::now_iso_utc(),
        session_id: std::env::var("AOIDE_SESSION_ID").ok(),
        cause: cause.to_string(),
        livery,
        cover,
    };

    takes::save_take(&song, &draft, &record).map_err(|e| {
        Outcome::error(cmd, format!("failed to write take {take}: {e}"))
            .with_data(json!({ "reason": "write-failed" }))
    })?;
    takes::save_head(&song, &draft, take).map_err(|e| {
        Outcome::error(cmd, format!("failed to advance the head cursor: {e}"))
            .with_data(json!({ "reason": "write-failed" }))
    })?;

    Ok(record)
}

/// `rice take`'s locked entrypoint: exactly ONE `with_stage_lock` around
/// [`snapshot_unlocked`]'s whole read-allocate-write. Safe to call from any
/// site that is not itself already inside a locked mutator — see the module
/// doc for the rule and who must NOT call this. `cmd`/`cause` pass straight
/// through to [`snapshot_unlocked`].
pub(crate) fn snapshot(cmd: &str, cause: &str) -> Result<TakeRecord, Outcome> {
    shellbridge::with_stage_lock(|| snapshot_unlocked(cmd, cause))
}

/// The unlocked drift-check core: mint a take only when the routed draft's
/// CURRENT content differs from the head take's own payload — comparing
/// parsed [`Value`]s, never raw bytes, so a document that merely
/// re-serialized (different key order, different whitespace) never reads as
/// drift. An absent head — an empty store, or a stale `head.json`
/// `aoide_storage::takes::load_head` couldn't resolve at all — has no
/// existing take to compare against, so it counts as drift unconditionally:
/// there is nothing on record yet, and the first content a store ever sees
/// is always worth capturing. `Ok(None)` is the no-op case; `Ok(Some(_))` is
/// the minted take; `Err` is any of [`snapshot_unlocked`]'s own failures
/// (not routed, nothing staged, a write failure). `cmd` threads through the
/// same way as [`snapshot_unlocked`]'s own — see the module doc.
pub(crate) fn snapshot_if_drifted_unlocked(cmd: &str, cause: &str) -> Result<Option<TakeRecord>, Outcome> {
    let (song, draft) = resolve_draft(cmd)?;

    let head_take = takes::load_head(&song, &draft).and_then(|n| takes::load_take(&song, &draft, n));
    if let Some(head_take) = &head_take {
        let (livery, cover) = read_staged_content(cmd)?;
        if livery == head_take.livery && cover == head_take.cover {
            return Ok(None);
        }
    }

    snapshot_unlocked(cmd, cause).map(Some)
}

/// `rice take` — the explicit snapshot verb (cause `"explicit"`). A bare
/// mint of whatever is currently staged in the routed draft; no selection,
/// no comparison, no revert — `rice back` (a later step) is where reverting
/// and branching actually happen. This handler's own write is not folded
/// into anything else, so [`snapshot`]'s single lock is exactly right.
fn handle_rice_take(_inv: &Invocation) -> Outcome {
    let (song, draft) = match resolve_draft("rice.take") {
        Ok(v) => v,
        Err(o) => return o,
    };

    match snapshot("rice.take", "explicit") {
        Ok(record) => {
            let take_file = takes::take_path(&song, &draft, record.take);
            let head_file = takes::head_path(&song, &draft);
            let message = match record.parent {
                Some(parent) => format!("take {:04} minted — from take {parent:04}", record.take),
                None => format!("take {:04} minted — the draft's first take", record.take),
            };
            Outcome::ok("rice.take", message)
                .changed(vec![
                    take_file.to_string_lossy().into_owned(),
                    head_file.to_string_lossy().into_owned(),
                ])
                .with_data(json!({
                    "take": record.take,
                    "parent": record.parent,
                    "at": record.at,
                    "cause": record.cause,
                    "sessionId": record.session_id,
                }))
        }
        Err(o) => o,
    }
}

// ── Tests (the snapshot cores + `rice take`) ────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Status;
    use aoide_storage::mode::{save_mode_marker, ModeMarker};
    use aoide_test_support::*;

    /// Route `AOIDE_STAGE_DIR` at a fresh tmp stage and mark `mode.json` as
    /// `Draft` for `sonata`/`neon-night` — every snapshot-core test needs
    /// this before it can pass [`resolve_draft`]. Callers still write
    /// `stage/livery.json` themselves (content varies per test) and own
    /// `remove_dir_all(&root)` at the end, matching every other command
    /// module's test rig in this crate.
    fn routed_draft(tag: &str) -> (std::path::PathBuf, String, String) {
        let root = unique_tmp(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let song = "sonata".to_string();
        let draft = "neon-night".to_string();
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some(song.clone()),
            draft: Some(draft.clone()),
            ..Default::default()
        })
        .unwrap();
        (root, song, draft)
    }

    // ── snapshot: numbering + parent chain ──────────────────────────────

    #[test]
    fn first_snapshot_in_a_routed_draft_is_0001_with_no_parent() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("take-first");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();

        let record = snapshot("rice.take", "explicit").unwrap();
        assert_eq!(record.take, 1);
        assert_eq!(record.parent, None, "the very first take has no parent");
        assert_eq!(record.cause, "explicit");
        assert_eq!(takes::load_head(&song, &draft), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn second_snapshot_parents_off_the_first() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("take-second");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();

        let first = snapshot("rice.take", "stage").unwrap();
        assert_eq!(first.take, 1);

        std::fs::write(
            shellbridge::stage_dir().join("livery.json"),
            r##"{"schemaVersion":"0","palette":{"bg":"#111111"}}"##,
        )
        .unwrap();
        let second = snapshot("rice.take", "stage").unwrap();
        assert_eq!(second.take, 2);
        assert_eq!(second.parent, Some(1), "hangs off the head at the time of the mint");
        assert_eq!(takes::load_head(&song, &draft), Some(2));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_outside_draft_mode_refuses() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("take-not-draft");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // No marker at all IS declarative (the safe default) — refused, same
        // as an explicit non-Draft mode below.
        let err = snapshot("rice.take", "explicit").unwrap_err();
        assert_eq!(err.status, Status::Error);
        assert_eq!(err.data.clone().unwrap()["reason"], "not-in-draft-mode");

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Staging,
            song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();
        let err = snapshot("rice.take", "explicit").unwrap_err();
        assert_eq!(err.data.unwrap()["reason"], "not-in-draft-mode", "Staging mode is refused too");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── command-name threading: a refusal reports the ACTUAL caller ─────
    //
    // The known issue A3 exists to fix: before this, every refusal built
    // inside these cores hardcoded `"rice.take"`, harmless while `rice
    // take` was the only caller. `rice stage`/`cover set`'s auto-take hooks
    // are a second caller — a refusal bubbling out of THEIR snapshot must
    // name `"rice.stage"`/`"cover.set"`, not `"rice.take"`, or an agent
    // reading the error would think the wrong command failed.

    #[test]
    fn snapshot_unlocked_refusal_reports_the_invoking_command_not_rice_take() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("take-cmd-thread-snapshot");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // No marker at all IS declarative — refused before this even reaches
        // the take store, so the refusal must name the REAL caller.
        let err = snapshot_unlocked("rice.stage", "stage").unwrap_err();
        assert_eq!(err.command, "rice.stage", "not the hardcoded rice.take");
        assert_eq!(err.data.unwrap()["reason"], "not-in-draft-mode");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn snapshot_if_drifted_unlocked_refusal_reports_the_invoking_command_not_rice_take() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("take-cmd-thread-drift");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let err = snapshot_if_drifted_unlocked("cover.set", "cover-set").unwrap_err();
        assert_eq!(err.command, "cover.set", "not the hardcoded rice.take");
        assert_eq!(err.data.unwrap()["reason"], "not-in-draft-mode");
        let _ = std::fs::remove_dir_all(&stage);
    }

    // ── snapshot_if_drifted_unlocked: no-op vs. mint ────────────────────
    //
    // Exercised directly against the unlocked core — it has no locked
    // wrapper (its only planned caller, `rice back`, folds the drift check
    // into its own single `with_stage_lock` acquisition alongside the
    // revert write and the head-cursor save, so a standalone locked wrapper
    // here would have no caller — YAGNI).

    #[test]
    fn snapshot_if_drifted_unlocked_is_a_noop_when_unchanged_and_mints_when_changed() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("take-drift");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();

        let first = snapshot("rice.take", "stage").unwrap();
        assert_eq!(first.take, 1);

        // Re-serialized but VALUE-identical content must not read as drift.
        let reparsed: Value = serde_json::from_str(VALID_NOTES).unwrap();
        let reserialized = serde_json::to_string_pretty(&reparsed).unwrap();
        std::fs::write(shellbridge::stage_dir().join("livery.json"), reserialized).unwrap();
        let noop = snapshot_if_drifted_unlocked("rice.take", "drift").unwrap();
        assert!(noop.is_none(), "byte-different, value-identical content is not drift");
        assert_eq!(takes::list_takes(&song, &draft).len(), 1, "no new take minted");

        // A genuine change mints a take, parented off the head it drifted from.
        std::fs::write(
            shellbridge::stage_dir().join("livery.json"),
            r##"{"schemaVersion":"0","palette":{"bg":"#222222"}}"##,
        )
        .unwrap();
        let drifted = snapshot_if_drifted_unlocked("rice.take", "drift").unwrap();
        let drifted = drifted.expect("a real content change is drift");
        assert_eq!(drifted.take, 2);
        assert_eq!(drifted.parent, Some(1));
        assert_eq!(drifted.cause, "drift");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_if_drifted_unlocked_mints_unconditionally_on_an_empty_store() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, _song, _draft) = routed_draft("take-drift-empty");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();

        // No head exists yet — there is nothing to compare against, so the
        // very first content is always worth capturing.
        let minted = snapshot_if_drifted_unlocked("rice.take", "drift").unwrap();
        let minted = minted.expect("an empty store has nothing to be identical to");
        assert_eq!(minted.take, 1);
        assert_eq!(minted.parent, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── sessionId: carried when set, omitted when not ──────────────────

    #[test]
    fn take_carries_session_id_when_set_and_omits_when_not() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        let (root, _song, _draft) = routed_draft("take-session");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();

        std::env::remove_var("AOIDE_SESSION_ID");
        let no_session = snapshot("rice.take", "explicit").unwrap();
        assert_eq!(no_session.session_id, None);

        std::env::set_var("AOIDE_SESSION_ID", "sess-123");
        let with_session = snapshot("rice.take", "explicit").unwrap();
        assert_eq!(with_session.session_id, Some("sess-123".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `rice take` — the registry entrypoint ───────────────────────────

    #[test]
    fn rice_take_handler_mints_and_reports_the_take_and_head_files_changed() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("take-handler-ok");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();

        let out = handle_rice_take(&inv(&["rice", "take"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let data = out.data.unwrap();
        assert_eq!(data["take"], 1);
        assert!(data["parent"].is_null());
        assert_eq!(data["cause"], "explicit");
        assert!(out.changed.iter().any(|c| c.ends_with("takes/0001.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("takes/head.json")));
        assert_eq!(takes::load_head(&song, &draft), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rice_take_handler_refuses_outside_draft_mode() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("take-handler-not-draft");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_take(&inv(&["rice", "take"], &[]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "not-in-draft-mode");
        let _ = std::fs::remove_dir_all(&stage);
    }
}
