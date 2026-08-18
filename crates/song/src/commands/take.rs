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
use aoide_protocol::registry::{arg, cmd, flag, Registry};
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
    r.insert(cmd!(
        path: ["rice", "take", "mark"],
        summary: "Stamp a rehearsal-style letter (A-Z) on a take via one atomic write of takes/marks.json — never a take-record rewrite. A letter already in use MOVES to the new take (a normal correction, not an error). Defaults to the current head when --take is omitted.",
        args: [arg!("letter", "string", true, "A single letter A-Z to stamp.")],
        flags: [flag!("take", "int", "Take number to mark; defaults to the current head.")],
        gated: false,
        implemented: true,
        handler: handle_rice_take_mark,
    ));
    r.insert(cmd!(
        path: ["rice", "back"],
        summary: "Revert the routed draft's live stage to an earlier take (--take N or --mark <letter>) and move the head cursor there — the NEXT write hangs off it, branching implicitly with no branch verb. Un-taken drift on the stage is snapshotted first so nothing is destroyed. Draft mode only. A bare `rice back` (neither flag) always refuses in this build — the interactive picker is a later step, not built here.",
        args: [],
        flags: [
            flag!("take", "int", "Take number to revert to."),
            flag!("mark", "string", "Mark letter to revert to (resolved through takes/marks.json)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_rice_back,
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

/// A single letter `A`-`Z` — [`handle_rice_take_mark`]'s whole validation of
/// its positional arg. Upper-case-only and single-character, on purpose:
/// rehearsal marks in an actual score are always capitals, and the plan's
/// own vocabulary never speaks of a "lowercase mark" or a multi-letter one.
/// Rejected outright rather than silently normalized (`.to_uppercase()`)
/// so a typo (`rice take mark a`) surfaces as an error instead of quietly
/// landing on the letter the caller didn't mean to type.
fn valid_mark_letter(s: &str) -> bool {
    let mut chars = s.chars();
    matches!((chars.next(), chars.next()), (Some(c), None) if c.is_ascii_uppercase())
}

/// The unlocked mark core (locking discipline: see the module doc's
/// "Locking discipline" section — this is this file's OTHER
/// read-modify-write besides the snapshot cores, and gets the identical
/// treatment). Stamping a mark is `takes::load_marks` → mutate one entry →
/// `takes::save_marks`: a read-then-write of `takes/marks.json`, racy the
/// same way take-number allocation is if two `rice take mark` calls (or a
/// mark racing a prune) interleave unlocked — so it never locks itself,
/// and [`mark`] below is the one locked entrypoint.
///
/// `target` is already resolved by the caller (`--take N`, parsed, or the
/// current head) — this function's own job is only to confirm `target`
/// names a take that actually exists (`take-not-found` if not), stamp the
/// letter, and report whether it moved. Returns `(target, moved, previous)`
/// where `previous` is whatever take the letter named before this call, if
/// any — `None` for a fresh stamp, `Some(old)` for a move (`moved` is false
/// when `previous == Some(target)`: re-stamping a letter onto the take it
/// already names is a no-op affirmation, not a move).
///
/// Take files are **never** rewritten here — the whole reason marks live in
/// `takes/marks.json` rather than a field on `TakeRecord` (advisor verdict,
/// fork 4 / D6, recorded in the module doc): a mark stamp or move is this
/// ONE `save_marks` call, full stop.
pub(crate) fn mark_unlocked(cmd: &str, letter: &str, target: u32) -> Result<(u32, bool, Option<u32>), Outcome> {
    let (song, draft) = resolve_draft(cmd)?;

    if takes::load_take(&song, &draft, target).is_none() {
        return Err(Outcome::error(cmd, format!("take {target:04} does not exist — nothing to mark"))
            .with_data(json!({ "reason": "take-not-found", "take": target })));
    }

    let mut marks = takes::load_marks(&song, &draft);
    let previous = marks.get(letter).copied();
    let moved = previous.is_some_and(|p| p != target);
    marks.insert(letter.to_string(), target);
    takes::save_marks(&song, &draft, &marks).map_err(|e| {
        Outcome::error(cmd, format!("failed to write marks.json: {e}"))
            .with_data(json!({ "reason": "write-failed" }))
    })?;

    Ok((target, moved, previous))
}

/// `rice take mark`'s locked entrypoint: exactly ONE `with_stage_lock`
/// around [`mark_unlocked`]'s whole read-mutate-write. `cmd`/`letter`/
/// `target` pass straight through.
pub(crate) fn mark(cmd: &str, letter: &str, target: u32) -> Result<(u32, bool, Option<u32>), Outcome> {
    shellbridge::with_stage_lock(|| mark_unlocked(cmd, letter, target))
}

/// `rice take mark <letter> [--take N]` — the phase-A standalone verb
/// (`references/fleshing-out-aoide-ricing.md` §5.2/§10: phase B's `rice
/// score` `mark` step CALLS this later; it does not reimplement it, and
/// this handler is not itself part of that state machine).
///
/// `--take N` names the target explicitly; omitted, it defaults to the
/// CURRENT HEAD (`aoide_storage::takes::load_head`) — "mark where I am
/// right now" is the common case. An empty store (no head at all, nothing
/// ever taken) reports `take-not-found`: from the caller's point of view
/// "no head to default to" and "the named take doesn't exist" are the same
/// fact, so they share the one reason string rather than inventing a
/// second for what is really the same failure.
///
/// Dual-entrance per the project's rule: flags/`--json` only, no prompting,
/// no stdin read ever — the interactive picker belongs to a later step
/// (A8, `rice back`'s bare-tty branch), never to this explicit verb.
fn handle_rice_take_mark(inv: &Invocation) -> Outcome {
    let letter = match inv.args.first() {
        Some(l) => l.clone(),
        None => {
            return Outcome::usage(
                "rice.take.mark",
                "usage: aoide rice take mark <letter A-Z> [--take N] [--json]",
            )
            .with_data(json!({ "reason": "missing-mark" }));
        }
    };
    if !valid_mark_letter(&letter) {
        return Outcome::error(
            "rice.take.mark",
            format!("`{letter}` is not a valid mark: must be a single letter A-Z"),
        )
        .with_data(json!({ "reason": "invalid-mark", "mark": letter }));
    }

    let (song, draft) = match resolve_draft("rice.take.mark") {
        Ok(v) => v,
        Err(o) => return o,
    };

    let target = match inv.flags.get("take") {
        Some(raw) => match raw.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                return Outcome::usage(
                    "rice.take.mark",
                    format!("`--take {raw}` is not a valid take number"),
                )
                .with_data(json!({ "reason": "invalid-take", "take": raw }));
            }
        },
        None => match takes::load_head(&song, &draft) {
            Some(h) => h,
            None => {
                return Outcome::error(
                    "rice.take.mark",
                    "no takes exist yet for this draft — nothing to mark (`aoide rice take` first)",
                )
                .with_data(json!({ "reason": "take-not-found" }));
            }
        },
    };

    match mark("rice.take.mark", &letter, target) {
        Ok((take, moved, previous)) => {
            let marks_file = takes::marks_path(&song, &draft).to_string_lossy().into_owned();
            let message = if moved {
                format!(
                    "mark {letter} moved from take {:04} to take {take:04}",
                    previous.expect("moved implies a previous take")
                )
            } else {
                format!("mark {letter} stamped on take {take:04}")
            };
            Outcome::ok("rice.take.mark", message)
                .changed(vec![marks_file])
                .with_data(json!({
                    "mark": letter,
                    "take": take,
                    "moved": moved,
                    "from": previous,
                }))
        }
        Err(o) => o,
    }
}

// ── `rice back` — the revert that lands the branch-from-any-mark ask ───────
//
// Everything below is ONE mutator: [`back_unlocked`] does drift-snapshot →
// livery/cover write-back → compositor apply → registry re-sync → head
// advance as a single `with_stage_lock` body (advisor verdict D2 — see the
// module doc's "Locking discipline" section, which this function is the
// concrete case that section was written for). It calls ONLY the `_unlocked`
// cores above, never [`snapshot`]/[`mark`] — those re-acquire the lock and
// `with_stage_lock` is documented not re-entrant (`aoide-storage/src/fs.rs`).

/// Everything [`handle_rice_back`] needs to build its `Outcome`, assembled
/// INSIDE the lock so nothing here re-reads state the write already changed
/// underneath it.
struct BackResult {
    /// The head cursor's value BEFORE this call touched anything — captured
    /// before the drift snapshot runs, so it names where the caller was
    /// actually standing, not an intermediate value the drift mint produced.
    from: Option<u32>,
    to: u32,
    /// The mark letter used to select the target, if `--mark` was given —
    /// `None` for a `--take` selection, even if that take happens to carry a
    /// letter (the report says how the caller ASKED, not what the take owns).
    mark: Option<String>,
    /// The take the pre-overwrite drift snapshot minted, if content on the
    /// stage differed from the head take it was about to clobber.
    drifted: Option<u32>,
    changed: Vec<String>,
    registry_note: String,
    hyprctl_status: &'static str,
}

/// The unlocked revert core — see the section banner above for the shape.
/// `cmd` threads through to every `Outcome` built here (module doc's
/// command-name-threading note); `take_flag`/`mark_flag` are already
/// syntax-validated by [`handle_rice_back`] (a parse/letter-shape failure is
/// a usage error surfaced before this ever runs, and before the lock is even
/// taken) — this function's job is resolving WHICH one names a real take and
/// then acting on it.
fn back_unlocked(cmd: &str, take_flag: Option<u32>, mark_flag: Option<String>) -> Result<BackResult, Outcome> {
    let (song, draft) = resolve_draft(cmd)?;

    // D7: refuse before touching anything if the draft's routing symlink is
    // gone, dangling, or was ever replaced by a plain file. `atomic_write`'s
    // symlink transparency (`aoide-storage/src/fs.rs`) is the ENTIRE
    // mechanism a revert rides on — the write-back below carries zero
    // symlink-awareness of its own, exactly like `rice stage`'s. Without
    // this check, a broken routing symlink would make the write below land
    // in a plain `stage/livery.json` instead of the draft file: the draft
    // itself untouched, the take store and the live stage silently
    // disagreeing about which draft is "current". `symlink_metadata` never
    // follows the link, so this answers "is `stage/livery.json` ITSELF a
    // symlink" without caring whether its target exists.
    let stage = shellbridge::stage_dir();
    let livery_path = stage.join("livery.json");
    let routed = std::fs::symlink_metadata(&livery_path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if !routed {
        return Err(Outcome::error(
            cmd,
            format!(
                "draft routing is broken: {} is not a symlink — refusing to revert rather than \
                 silently writing a plain stage file that leaves the draft untouched \
                 (`aoide rice mode draft {draft}` re-routes it)",
                livery_path.display()
            ),
        )
        .with_data(json!({ "reason": "routing-broken", "expected": livery_path.to_string_lossy() })));
    }

    // Resolve the target: `--take N` names it directly; `--mark X` resolves
    // through `takes/marks.json`. A map entry naming a take that no longer
    // exists (a hand-edited marks file, or — once pruning lands — a take
    // pruned without also rewriting the map) reads exactly like an
    // unstamped letter from here: both are "that mark doesn't name anything
    // real", so they share `mark-not-found` rather than inventing a second
    // reason for the same practical failure (mirrors `mark_unlocked`'s own
    // take-not-found/no-head collapse just above).
    let (target, mark_used) = if let Some(n) = take_flag {
        if takes::load_take(&song, &draft, n).is_none() {
            return Err(Outcome::error(cmd, format!("take {n:04} does not exist — nothing to revert to"))
                .with_data(json!({ "reason": "take-not-found", "take": n })));
        }
        (n, None)
    } else {
        let letter = mark_flag.expect("handle_rice_back guarantees take_flag or mark_flag is Some");
        let marks = takes::load_marks(&song, &draft);
        match marks.get(&letter).copied() {
            Some(n) if takes::load_take(&song, &draft, n).is_some() => (n, Some(letter)),
            _ => {
                return Err(
                    Outcome::error(cmd, format!("mark `{letter}` is not stamped on any take"))
                        .with_data(json!({ "reason": "mark-not-found", "mark": letter })),
                );
            }
        }
    };
    let target_record =
        takes::load_take(&song, &draft, target).expect("existence just confirmed above");

    let head_before = takes::load_head(&song, &draft);

    // The rail that makes "nothing is destroyed" literally true even for
    // un-taken hand-edits: preserve whatever is CURRENTLY on the stage
    // before the write below overwrites it, if it differs from the head
    // take it's about to clobber. Folded into THIS lock, not a second
    // acquisition — see the module doc; this is `snapshot_if_drifted_unlocked`'s
    // one sanctioned caller.
    let drifted = snapshot_if_drifted_unlocked(cmd, "drift")?;

    let mut changed = Vec::new();
    if let Some(rec) = &drifted {
        changed.push(takes::take_path(&song, &draft, rec.take).to_string_lossy().into_owned());
        changed.push(takes::head_path(&song, &draft).to_string_lossy().into_owned());
    }

    // The write-back IS the routing (plan §5.2): the identical `atomic_write`
    // seam `rice stage` writes (`commands/rice.rs::handle_rice_stage`),
    // symlink-transparent, so this lands in the draft file the same way
    // every other stage writer does. No new apply path — this reuses the
    // one that already exists.
    let livery_body = serde_json::to_string_pretty(&target_record.livery)
        .map_err(|e| {
            Outcome::error(cmd, format!("failed to serialize take {target:04}'s livery: {e}"))
                .with_data(json!({ "reason": "write-failed" }))
        })?
        + "\n";
    shellbridge::atomic_write(&livery_path, &livery_body).map_err(|e| {
        Outcome::error(cmd, format!("failed to write {}: {e}", livery_path.display()))
            .with_data(json!({ "reason": "write-failed", "target": livery_path.to_string_lossy() }))
    })?;
    changed.push(livery_path.to_string_lossy().into_owned());

    // Best-effort compositor live-apply — the exact sequencing
    // `handle_rice_stage` uses (geometry/border keywords derived from the
    // SAME livery just written), never fatal: the stage-file write above is
    // already the source of truth for the hot-reload half.
    let hyprctl_status = crate::live::apply_live(&crate::live::geometry_keywords(&target_record.livery));

    // Cover restore is narrowed to the STAGE ONLY (advisor verdict D4):
    // `stage/cover.json` is not symlink-routed the way `livery.json` is
    // (`storage/src/mode.rs`'s `handle_mode_draft` symlinks exactly one
    // file), so this writes the same seam `cover set` writes
    // (`commands/cover.rs::handle_cover_set`), never the draft directory's
    // own `cover.json` — that file is a `draft save`-time archive copy no
    // write path maintains and no read path consumes (draft verbs are
    // save/list/drop only). A take minted with NO cover must not leave the
    // previous wallpaper lying on the stage — mirror `draft.rs`'s own
    // fork-time stale-cover removal (`rice.draft.save`'s `cover_src.is_file()`
    // else-branch) rather than leaving a cover the target take never had.
    let cover_path = stage.join("cover.json");
    match &target_record.cover {
        Some(cover_value) => {
            let cover_body = serde_json::to_string_pretty(cover_value).unwrap_or_default() + "\n";
            shellbridge::atomic_write(&cover_path, &cover_body).map_err(|e| {
                Outcome::error(cmd, format!("failed to write {}: {e}", cover_path.display()))
                    .with_data(json!({ "reason": "write-failed", "target": cover_path.to_string_lossy() }))
            })?;
            changed.push(cover_path.to_string_lossy().into_owned());
        }
        None => {
            if cover_path.exists() {
                let _ = std::fs::remove_file(&cover_path);
                changed.push(cover_path.to_string_lossy().into_owned());
            }
        }
    }

    // Registry re-sync, no IPC reload (advisor verdict D1). `registry.json`
    // is derived from the livery's `.widgets` key, so a reverted livery with
    // a different widget set would leave it stale without this — but every
    // file this whole function writes (livery, cover, registry) is
    // FileView-watched by Quickshell exactly like `rice stage`'s own palette
    // tier, so there is nothing for a Quickshell IPC reload to do. The ONE
    // reload lane that exists anywhere in this codebase
    // (`ipc::quickshell_ipc_reload`, gated in `handle_rice_stage`) exists
    // ONLY for dynamically `Qt.createComponent`-loaded widget BODIES, which
    // a revert never touches by design (widget bodies are git's substrate,
    // §5.2) — so that call is never reached from here, deliberately, not by
    // omission.
    let registry_sync = crate::widgets::sync_song_registry(&song).map_err(|e| {
        Outcome::error(cmd, format!("failed to sync widget-type registry: {}", e.error))
            .with_data(json!({ "reason": "registry-sync-failed", "target": e.target }))
    })?;
    changed.extend(registry_sync.changed.clone());

    // A revert is NOT a take (advisor verdict, fork 8) — only the cursor
    // moves. This is the step where branching actually happens: the NEXT
    // snapshot parents off whatever `save_head` names here, not off
    // whatever the head happened to be a moment ago.
    takes::save_head(&song, &draft, target).map_err(|e| {
        Outcome::error(cmd, format!("failed to advance the head cursor: {e}"))
            .with_data(json!({ "reason": "write-failed" }))
    })?;
    changed.push(takes::head_path(&song, &draft).to_string_lossy().into_owned());

    Ok(BackResult {
        from: head_before,
        to: target,
        mark: mark_used,
        drifted: drifted.map(|r| r.take),
        changed,
        registry_note: registry_sync.note,
        hyprctl_status,
    })
}

/// `rice back [--take N | --mark <letter>]` — the verb the branch-from-any-
/// mark ask lands on. Syntax-validates its flags BEFORE taking the lock (a
/// malformed `--take`/`--mark` is a usage error regardless of draft state,
/// so there is no reason to acquire anything to report it), then wraps
/// [`back_unlocked`]'s whole read-drift-write-advance body in exactly ONE
/// `with_stage_lock` — see that function's own doc and the module doc's
/// locking-discipline section.
fn handle_rice_back(inv: &Invocation) -> Outcome {
    let take_flag = match inv.flags.get("take") {
        Some(raw) => match raw.parse::<u32>() {
            Ok(n) => Some(n),
            Err(_) => {
                return Outcome::usage("rice.back", format!("`--take {raw}` is not a valid take number"))
                    .with_data(json!({ "reason": "invalid-take", "take": raw }));
            }
        },
        None => None,
    };
    let mark_flag = match inv.flags.get("mark") {
        Some(letter) => {
            if !valid_mark_letter(letter) {
                return Outcome::error(
                    "rice.back",
                    format!("`{letter}` is not a valid mark: must be a single letter A-Z"),
                )
                .with_data(json!({ "reason": "invalid-mark", "mark": letter }));
            }
            Some(letter.clone())
        }
        None => None,
    };

    // Dual entrance (§7): a bare `rice back` on a tty is EVENTUALLY meant to
    // open a numbered picker defaulting to the head's parent (one Enter is
    // §5.2's one-step undo) — but that picker is a later step (A8), not this
    // one, and half-building tty-detection with no picker on the other end
    // of it would be worse than not building it at all. So THIS build
    // refuses unconditionally whenever neither flag is given, tty or not,
    // and never reads stdin either way: an agent (never a tty) and a User on
    // a bare terminal get the IDENTICAL message pointing at the two flags
    // that work today.
    if take_flag.is_none() && mark_flag.is_none() {
        return Outcome::usage(
            "rice.back",
            "usage: aoide rice back --take N | --mark <letter> [--json] \
             (a bare `rice back` will open a picker on a tty in a later step; \
             not built yet — pass --take or --mark)",
        )
        .with_data(json!({ "reason": "no-selection" }));
    }

    match shellbridge::with_stage_lock(|| back_unlocked("rice.back", take_flag, mark_flag)) {
        Ok(result) => {
            let drift_note = result
                .drifted
                .map(|d| format!("; take {d:04} preserved the un-taken edit that was about to be overwritten"))
                .unwrap_or_default();
            let mark_note = result
                .mark
                .as_ref()
                .map(|m| format!(" (mark {m})"))
                .unwrap_or_default();
            let message = format!(
                "reverted to take {:04}{mark_note} — head now {:04}{drift_note}",
                result.to, result.to
            );
            Outcome::ok("rice.back", message)
                .changed(result.changed)
                .with_data(json!({
                    "from": result.from,
                    "to": result.to,
                    "mark": result.mark,
                    "drifted": result.drifted,
                    "hyprctl": result.hyprctl_status,
                    "registry": result.registry_note,
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

    // ── `rice take mark` — the mark verb (phase A4) ─────────────────────
    //
    // `inv()` (aoide_test_support) has no flags support, so a `--take N`
    // invocation is built by hand, same pattern `graph/permit.rs`'s and
    // `rice.rs`'s own tests use for a hand-populated `Invocation`.

    fn inv_with_take(letter: &str, take: u32) -> Invocation {
        Invocation {
            path: vec!["rice".to_string(), "take".to_string(), "mark".to_string()],
            args: vec![letter.to_string()],
            flags: std::collections::BTreeMap::from([("take".to_string(), take.to_string())]),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn mark_stamps_the_current_head_by_default() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("mark-head-default");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();
        let first = snapshot("rice.take", "explicit").unwrap();
        assert_eq!(first.take, 1);

        let out = handle_rice_take_mark(&inv(&["rice", "take", "mark"], &["A"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let data = out.data.unwrap();
        assert_eq!(data["mark"], "A");
        assert_eq!(data["take"], 1, "no --take given, defaults to the head");
        assert_eq!(data["moved"], false, "a fresh letter is a stamp, not a move");
        assert!(data["from"].is_null());
        assert!(out.changed.iter().any(|c| c.ends_with("takes/marks.json")));
        assert_eq!(takes::load_marks(&song, &draft).get("A"), Some(&1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_take_flag_targets_a_specific_take_not_the_head() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("mark-take-flag");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();
        snapshot("rice.take", "explicit").unwrap(); // take 1
        std::fs::write(
            shellbridge::stage_dir().join("livery.json"),
            r##"{"schemaVersion":"0","palette":{"bg":"#222222"}}"##,
        )
        .unwrap();
        let second = snapshot("rice.take", "explicit").unwrap(); // take 2, now head
        assert_eq!(second.take, 2);
        assert_eq!(takes::load_head(&song, &draft), Some(2));

        // Explicitly mark take 1, even though the head has since moved to 2.
        let out = handle_rice_take_mark(&inv_with_take("A", 1));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(out.data.unwrap()["take"], 1);
        assert_eq!(takes::load_marks(&song, &draft).get("A"), Some(&1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_restamping_a_letter_moves_it_take_files_stay_untouched_one_map_entry() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft) = routed_draft("mark-move");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();
        let first = snapshot("rice.take", "explicit").unwrap();
        std::fs::write(
            shellbridge::stage_dir().join("livery.json"),
            r##"{"schemaVersion":"0","palette":{"bg":"#222222"}}"##,
        )
        .unwrap();
        let second = snapshot("rice.take", "explicit").unwrap();
        assert_eq!((first.take, second.take), (1, 2));
        let take_1_raw_before = std::fs::read_to_string(takes::take_path(&song, &draft, 1)).unwrap();
        let take_2_raw_before = std::fs::read_to_string(takes::take_path(&song, &draft, 2)).unwrap();

        let stamped = handle_rice_take_mark(&inv_with_take("A", 1));
        assert_eq!(stamped.status, Status::Ok, "{:?}", stamped.data);

        let moved = handle_rice_take_mark(&inv_with_take("A", 2));
        assert_eq!(moved.status, Status::Ok, "{:?}", moved.data);
        let data = moved.data.unwrap();
        assert_eq!(data["moved"], true, "the letter already named take 1 — this is a move");
        assert_eq!(data["from"], 1);
        assert_eq!(data["take"], 2);

        // Old take loses the letter, new take has it — as one map, not a
        // per-take field: exactly one entry, naming the new take.
        let marks = takes::load_marks(&song, &draft);
        assert_eq!(marks.len(), 1, "moving overwrote the entry, it did not duplicate it");
        assert_eq!(marks.get("A"), Some(&2));

        // D6/fork 4: marks live OUTSIDE the take record — stamping or moving
        // a letter must never rewrite an NNNN.json.
        assert_eq!(
            std::fs::read_to_string(takes::take_path(&song, &draft, 1)).unwrap(),
            take_1_raw_before,
            "take 1's own file is untouched by the mark ever moving off it"
        );
        assert_eq!(
            std::fs::read_to_string(takes::take_path(&song, &draft, 2)).unwrap(),
            take_2_raw_before,
            "take 2's own file is untouched by the mark landing on it"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_rejects_lowercase_multichar_and_non_letter_marks() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, _song, _draft) = routed_draft("mark-invalid");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();
        snapshot("rice.take", "explicit").unwrap();

        for bad in ["a", "AB", "1", "", "Å"] {
            let out = handle_rice_take_mark(&inv(&["rice", "take", "mark"], &[bad]));
            assert_eq!(out.status, Status::Error, "`{bad}` should be rejected: {:?}", out.data);
            assert_eq!(out.data.unwrap()["reason"], "invalid-mark", "for input `{bad}`");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_missing_letter_arg_is_a_usage_error() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, _song, _draft) = routed_draft("mark-missing-arg");

        let out = handle_rice_take_mark(&inv(&["rice", "take", "mark"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.data.unwrap()["reason"], "missing-mark");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_refuses_outside_draft_mode() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mark-not-draft");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_take_mark(&inv(&["rice", "take", "mark"], &["A"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "not-in-draft-mode");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn mark_on_a_nonexistent_take_errors_take_not_found() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, _song, _draft) = routed_draft("mark-take-missing");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();
        snapshot("rice.take", "explicit").unwrap(); // only take 1 exists

        let out = handle_rice_take_mark(&inv_with_take("A", 99));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "take-not-found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_with_no_takes_at_all_and_no_take_flag_errors_take_not_found() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, _song, _draft) = routed_draft("mark-empty-store");

        // Draft mode, but nothing has ever been taken — no head to default
        // to, which reads the same as "that take doesn't exist".
        let out = handle_rice_take_mark(&inv(&["rice", "take", "mark"], &["A"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "take-not-found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mark_invalid_take_flag_is_a_usage_error() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, _song, _draft) = routed_draft("mark-take-flag-invalid");
        std::fs::write(shellbridge::stage_dir().join("livery.json"), VALID_NOTES).unwrap();
        snapshot("rice.take", "explicit").unwrap();

        let out = handle_rice_take_mark(&Invocation {
            path: vec!["rice".to_string(), "take".to_string(), "mark".to_string()],
            args: vec!["A".to_string()],
            flags: std::collections::BTreeMap::from([("take".to_string(), "not-a-number".to_string())]),
            door: aoide_protocol::Door::Cli,
        });
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.data.unwrap()["reason"], "invalid-take");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `rice back` — the revert that lands the branch-from-any-mark ask ───
    //
    // Unlike `routed_draft` above (a bare Draft-mode marker over a PLAIN
    // stage/livery.json — fine for the snapshot/mark cores, which never
    // check routing), every `rice back` test needs stage/livery.json to be a
    // REAL symlink into the draft file, because `back_unlocked`'s
    // routing-broken rail (D7) checks exactly that before writing anything.

    fn routed_draft_symlinked(tag: &str) -> (std::path::PathBuf, String, String, std::path::PathBuf) {
        let root = unique_tmp(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let song = "sonata".to_string();
        let draft = "neon-night".to_string();
        let draft_dir = shellbridge::draft_dir(&song, &draft);
        std::fs::create_dir_all(&draft_dir).unwrap();
        let draft_livery = draft_dir.join("livery.json");
        std::fs::write(&draft_livery, "{}").unwrap();
        std::os::unix::fs::symlink(&draft_livery, stage.join("livery.json")).unwrap();
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some(song.clone()),
            draft: Some(draft.clone()),
            ..Default::default()
        })
        .unwrap();
        (root, song, draft, draft_livery)
    }

    /// Writes new content THROUGH the routing symlink — plain `std::fs::write`
    /// (unlike `atomic_write`'s rename) follows a symlink transparently, so
    /// this lands in the draft file while leaving the symlink itself intact,
    /// exactly the property every test below relies on to keep re-editing
    /// "the draft" across multiple snapshots.
    fn write_livery(stage: &std::path::Path, bg: &str) {
        std::fs::write(
            stage.join("livery.json"),
            format!(r##"{{"schemaVersion":"0","palette":{{"bg":"{bg}"}}}}"##),
        )
        .unwrap();
    }

    fn inv_back(mark: Option<&str>, take: Option<u32>) -> Invocation {
        let mut flags = std::collections::BTreeMap::new();
        if let Some(m) = mark {
            flags.insert("mark".to_string(), m.to_string());
        }
        if let Some(t) = take {
            flags.insert("take".to_string(), t.to_string());
        }
        Invocation {
            path: vec!["rice".to_string(), "back".to_string()],
            args: vec![],
            flags,
            door: aoide_protocol::Door::Cli,
        }
    }

    /// The acceptance test for the whole ask: revert to a mark, keep
    /// editing, and the takes after the mark survive as siblings of the new
    /// branch rather than being destroyed or renumbered.
    #[test]
    fn revert_to_a_mark_branches_and_leaves_the_old_line_intact() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, draft_livery) = routed_draft_symlinked("back-branch-acceptance");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        let take1 = snapshot("rice.take", "stage").unwrap();
        assert_eq!((take1.take, take1.parent), (1, None));

        write_livery(&stage, "#222222");
        let take2 = snapshot("rice.take", "stage").unwrap();
        assert_eq!((take2.take, take2.parent), (2, Some(1)));

        mark("rice.take.mark", "A", 2).unwrap();

        write_livery(&stage, "#333333");
        let take3 = snapshot("rice.take", "stage").unwrap();
        assert_eq!((take3.take, take3.parent), (3, Some(2)));
        assert_eq!(takes::load_head(&song, &draft), Some(3));

        // `rice back --mark A` — the stage exactly matches the head (take 3)
        // it's about to overwrite, so nothing drifts.
        let out = handle_rice_back(&inv_back(Some("A"), None));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let data = out.data.clone().unwrap();
        assert_eq!(data["from"], 3, "head before the revert");
        assert_eq!(data["to"], 2);
        assert_eq!(data["mark"], "A");
        assert!(data["drifted"].is_null(), "stage matched the head exactly — nothing to preserve");
        assert!(
            data.get("reload").is_none(),
            "a revert never touches Quickshell IPC (D1) — no reload field at all, unlike `rice stage`'s outcome"
        );
        assert_eq!(takes::load_head(&song, &draft), Some(2), "head moved to the mark's take");

        let restored: Value = serde_json::from_str(&std::fs::read_to_string(&draft_livery).unwrap()).unwrap();
        assert_eq!(restored, take2.livery, "the draft file (through the symlink) now holds take 2's content");

        // Takes 3 is completely untouched — nothing destroyed, nothing
        // renumbered.
        let take3_after = takes::load_take(&song, &draft, 3).unwrap();
        assert_eq!(take3_after, take3);

        // Branch out again: the next write hangs off the REVERTED head (2),
        // not off take 3 — this is where branching actually happens.
        write_livery(&stage, "#444444");
        let take4 = snapshot("rice.take", "stage").unwrap();
        assert_eq!((take4.take, take4.parent), (4, Some(2)), "branches off the reverted head, not off take 3");

        // Take 3 is STILL there, still parented on 2 — a sibling of take 4,
        // not overwritten and not renumbered.
        let take3_final = takes::load_take(&song, &draft, 3).unwrap();
        assert_eq!(take3_final.parent, Some(2));
        assert_eq!(takes::children(&takes::list_takes(&song, &draft), 2), vec![3, 4], "two branches off the same mark");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn revert_by_take_number_moves_head_and_restores_content() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, draft_livery) = routed_draft_symlinked("back-by-take");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#aaaaaa");
        let take1 = snapshot("rice.take", "stage").unwrap();
        write_livery(&stage, "#bbbbbb");
        snapshot("rice.take", "stage").unwrap(); // take 2, now head

        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let data = out.data.unwrap();
        assert_eq!(data["to"], 1);
        assert!(data["mark"].is_null(), "a --take selection reports no mark");
        assert_eq!(takes::load_head(&song, &draft), Some(1));

        let restored: Value = serde_json::from_str(&std::fs::read_to_string(&draft_livery).unwrap()).unwrap();
        assert_eq!(restored, take1.livery);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_by_take_reports_null_mark_even_when_the_target_take_carries_one() {
        // Pins the "how was I asked" semantics [`BackResult::mark`]'s own
        // doc comment claims: the report reflects the SELECTOR the caller
        // used, not whatever the resolved take happens to own. Both of this
        // file's other `--take` tests target unmarked takes, so this was
        // otherwise asserted nowhere.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, _draft_livery) = routed_draft_symlinked("back-take-target-has-mark");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap(); // take 1
        write_livery(&stage, "#222222");
        snapshot("rice.take", "stage").unwrap(); // take 2, head
        mark("rice.take.mark", "A", 1).unwrap(); // take 1 — the REVERT TARGET — carries a mark

        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            out.data.unwrap()["mark"].is_null(),
            "selected via --take, not --mark — the report says null even though take 1 owns mark A"
        );
        assert_eq!(takes::load_head(&song, &draft), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_snapshots_an_untaken_hand_edit_before_overwriting_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, draft_livery) = routed_draft_symlinked("back-drift-preserved");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap(); // take 1, head

        // An un-taken hand edit — nothing ever called `rice take`/`rice
        // stage` on this content, so it exists nowhere but the live stage.
        write_livery(&stage, "#hand-edited");

        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let data = out.data.unwrap();
        let drifted_take = data["drifted"].as_u64().expect("the hand edit must have minted a take");
        assert_eq!(drifted_take, 2, "the drift take hangs off the head it preserved");

        // The un-taken edit is recoverable: it is exactly what take 2 holds.
        let preserved = takes::load_take(&song, &draft, 2).unwrap();
        assert_eq!(preserved.cause, "drift");
        assert_eq!(preserved.parent, Some(1));
        assert_eq!(preserved.livery["palette"]["bg"], "#hand-edited");

        // And the revert itself still landed — take 1's content is now live.
        let restored: Value = serde_json::from_str(&std::fs::read_to_string(&draft_livery).unwrap()).unwrap();
        assert_eq!(restored["palette"]["bg"], "#111111");
        assert_eq!(takes::load_head(&song, &draft), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_mints_no_drift_take_when_the_stage_already_matches_the_head() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, _draft_livery) = routed_draft_symlinked("back-no-drift");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap(); // take 1, head — stage matches it exactly

        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(out.data.unwrap()["drifted"].is_null(), "nothing differed from the head — nothing to preserve");
        assert_eq!(
            takes::list_takes(&song, &draft).len(),
            1,
            "no phantom take minted when there was nothing to drift-capture"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_to_the_same_target_twice_in_a_row_mints_no_new_takes_between_calls() {
        // Fork 8 ("a revert is not a take") proven against the state a
        // REVERT ITSELF produces, not just against a stage nobody has
        // touched yet. `back_mints_no_drift_take_when_the_stage_already_
        // matches_the_head` above only exercises the latter (nothing ever
        // ran `rice back` before the assertion); this calls `rice back`
        // twice at the SAME target and checks the take count never grows
        // between the two calls — the second call's drift comparison is
        // against exactly what the first call's own write just produced.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, _draft_livery) = routed_draft_symlinked("back-repeat-same-target");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap(); // take 1
        write_livery(&stage, "#222222");
        snapshot("rice.take", "stage").unwrap(); // take 2, head

        let first = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(first.status, Status::Ok, "{:?}", first.data);
        let count_after_first = takes::list_takes(&song, &draft).len();

        let second = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(second.status, Status::Ok, "{:?}", second.data);
        assert!(
            second.data.as_ref().unwrap()["drifted"].is_null(),
            "the second revert to the same target drifts nothing — the stage already IS take 1"
        );
        assert_eq!(
            takes::list_takes(&song, &draft).len(),
            count_after_first,
            "two consecutive reverts to the same target mint zero takes between them"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_clears_a_stale_stage_cover_when_the_target_take_has_none() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, _draft_livery) = routed_draft_symlinked("back-cover-clear");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        let take1 = snapshot("rice.take", "stage").unwrap();
        assert!(take1.cover.is_none());

        // A cover-set lands on top and gets taken — take 2 carries a cover.
        std::fs::write(stage.join("cover.json"), r#"{"path":"/tmp/x.png"}"#).unwrap();
        let take2 = snapshot("rice.take", "stage").unwrap();
        assert!(take2.cover.is_some());
        assert!(stage.join("cover.json").is_file());

        // Revert to take 1, which has no cover — the stale stage cover
        // (still sitting there from take 2) must be cleared, not left
        // pointing at a wallpaper take 1 never had.
        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(out.data.unwrap()["drifted"].is_null(), "stage matched head (take 2) exactly before the call");
        assert!(!stage.join("cover.json").exists(), "target take had no cover — the stale stage cover is cleared");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_refuses_when_the_routing_symlink_is_missing() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let root = unique_tmp("back-routing-broken");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let song = "sonata".to_string();
        let draft = "neon-night".to_string();
        // Draft mode claimed, but stage/livery.json is a PLAIN file, never
        // routed through `rice mode draft`'s symlink.
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some(song.clone()),
            draft: Some(draft.clone()),
            ..Default::default()
        })
        .unwrap();
        // TWO takes, so target (1) and the pre-existing head (falls back to
        // the max, 2) differ — this is what makes the closing head
        // assertion discriminate. With only one take (both = 1), the
        // fallback in `load_head` lands on 1 whether or not `save_head` ever
        // ran, so that assertion would hold even if the routing-broken
        // refusal secretly still moved the cursor.
        std::fs::create_dir_all(shellbridge::draft_dir(&song, &draft).join("takes")).unwrap();
        let seed = |n: u32, parent: Option<u32>| TakeRecord {
            take: n,
            parent,
            at: "2026-08-18T00:00:00Z".to_string(),
            session_id: None,
            cause: "explicit".to_string(),
            livery: serde_json::json!({ "schemaVersion": "0" }),
            cover: None,
        };
        takes::save_take(&song, &draft, &seed(1, None)).unwrap();
        takes::save_take(&song, &draft, &seed(2, Some(1))).unwrap();

        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "routing-broken");
        // Nothing written: the plain stage file is untouched and the head
        // cursor is exactly what it was before this call (the fallback max,
        // 2) — NOT moved to the target (1), which is what a bug that let
        // `save_head` run despite the refusal would produce.
        assert_eq!(
            std::fs::read_to_string(stage.join("livery.json")).unwrap(),
            VALID_NOTES,
            "a routing-broken refusal writes nothing"
        );
        assert_eq!(
            takes::load_head(&song, &draft),
            Some(2),
            "head stays at the pre-existing fallback (2), never claimed down to the target (1) by this call"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_with_both_take_and_mark_given_take_wins() {
        // No sibling verb has two co-present selectors, so the reviewer
        // ruled a silent `--take`-wins priority defensible but unpinned —
        // this test is the pin.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, _draft_livery) = routed_draft_symlinked("back-both-flags-take-wins");
        let stage = shellbridge::stage_dir();

        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap(); // take 1
        write_livery(&stage, "#222222");
        snapshot("rice.take", "stage").unwrap(); // take 2, head
        mark("rice.take.mark", "A", 2).unwrap(); // A names take 2 — the OTHER selection

        let out = handle_rice_back(&inv_back(Some("A"), Some(1)));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let data = out.data.unwrap();
        assert_eq!(data["to"], 1, "--take wins over a co-present --mark naming a different take");
        assert!(data["mark"].is_null(), "the winning selector was --take, so mark reports null");
        assert_eq!(takes::load_head(&song, &draft), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_take_not_found_and_mark_not_found() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, _song, _draft, _draft_livery) = routed_draft_symlinked("back-not-found");
        let stage = shellbridge::stage_dir();
        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap(); // only take 1 exists, no marks

        let missing_take = handle_rice_back(&inv_back(None, Some(99)));
        assert_eq!(missing_take.status, Status::Error);
        assert_eq!(missing_take.data.unwrap()["reason"], "take-not-found");

        let missing_mark = handle_rice_back(&inv_back(Some("Z"), None));
        assert_eq!(missing_mark.status, Status::Error);
        assert_eq!(missing_mark.data.unwrap()["reason"], "mark-not-found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_invalid_take_and_mark_flags_are_rejected_before_anything_else() {
        // Malformed-flag shape — the bare (neither flag) form is covered by
        // `back_bare_invocation_refuses_without_reading_stdin_or_writing_anything`.
        let bad_take = handle_rice_back(&Invocation {
            path: vec!["rice".to_string(), "back".to_string()],
            args: vec![],
            flags: std::collections::BTreeMap::from([("take".to_string(), "nope".to_string())]),
            door: aoide_protocol::Door::Cli,
        });
        assert_eq!(bad_take.status, Status::Usage);
        assert_eq!(bad_take.data.unwrap()["reason"], "invalid-take");

        let bad_mark = handle_rice_back(&inv_back(Some("ab"), None));
        assert_eq!(bad_mark.status, Status::Error);
        assert_eq!(bad_mark.data.unwrap()["reason"], "invalid-mark");
    }

    #[test]
    fn back_bare_invocation_refuses_without_reading_stdin_or_writing_anything() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let (root, song, draft, _draft_livery) = routed_draft_symlinked("back-bare-refuses");
        let stage = shellbridge::stage_dir();
        write_livery(&stage, "#111111");
        snapshot("rice.take", "stage").unwrap();

        // Neither --take nor --mark: the test harness is never a tty either
        // way, so this exercises both "non-tty" and "this build's tty
        // refusal" at once — the two paths are identical in this step.
        let out = handle_rice_back(&inv_back(None, None));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.data.unwrap()["reason"], "no-selection");
        assert_eq!(takes::load_head(&song, &draft), Some(1), "the bare refusal moved nothing");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn back_refuses_outside_draft_mode() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("back-not-draft");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_back(&inv_back(None, Some(1)));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "not-in-draft-mode");
        let _ = std::fs::remove_dir_all(&stage);
    }
}
