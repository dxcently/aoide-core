//! `rice draft {save,list,drop}` — durable scratch snapshots of the live
//! stage (concepts/Self-Ricing's draft extension, the User 2026-08-14; symlink
//! routing + `rice mode draft`, the User 2026-08-14).
//!
//! A draft is a saved snapshot living at
//! `song/songbook/<song>/drafts/<name>/livery.json` (+ `cover.json` when the
//! stage had one) — nested under the song it varies, not a flat top-level
//! dir: a draft is fundamentally a variation of an ALREADY COMPOSED song, so
//! it belongs inside that song's own directory, not a separate global
//! namespace. Gitignored, outside `stage/`, and never committed/declared
//! truth (that distinction from `song/songbook/<name>/`'s own committed
//! files is the entire point of this feature; `lib/checks.nix`'s
//! `noSongRead` bans the nested `drafts/` path at nix-eval time, same
//! treatment as `stage/`).
//!
//! **Reaching a draft is `rice mode draft <name>`'s job now**
//! (`commands/mode.rs::handle_mode_draft`), not this module's — it points
//! `stage/livery.json` at a SYMLINK into the draft's own file, so every
//! future writer (`rice stage`, `cover set`, a hand-edit, Quickshell's own
//! FileView reload) transparently lands in the draft with zero
//! draft-awareness anywhere, because [`aoide_storage::fs::atomic_write`] is
//! symlink-transparent. This module owns only the drafts THEMSELVES:
//!
//! - **`rice draft save <name>`** — fork whatever's currently live into a
//!   NEW or updated draft snapshot, independent of switching modes (e.g.
//!   preserving a moment as a second draft while still working in a first
//!   one, or saving a snapshot while in plain `Staging` without ever
//!   entering `Draft` mode). Upserts. Never touches `mode.json` — it doesn't
//!   change what's currently routed/active, only what's saved.
//!   [`fork_stage_into`] is the reusable core; `rice mode draft <name>`'s own
//!   "create the draft if it doesn't exist yet" step calls the SAME
//!   function rather than reimplementing the read/write.
//! - **`rice draft list [<song>]`** — enumerate saved drafts.
//! - **`rice draft drop <name>`** — delete a draft outright. Refuses if it's
//!   the draft the CURRENT `Draft` mode is routed to (rather than silently
//!   also tearing down the symlink and falling back to `Staging` — a `drop`
//!   that quietly also changes your mode would be the more surprising
//!   choice; `rice mode stage`/`rice mode declarative` are how you leave
//!   `Draft` mode, explicitly, same as always).
//!
//! There used to be a fourth command, `rice draft stage <name>` (copy-based:
//! read the draft, atomic-write it into the stage as a one-shot snapshot).
//! It's gone — fully superseded by `rice mode draft`'s symlink routing, and
//! keeping both would be two spellings of "go live with this draft" (the
//! no-internal-aliases rule).
//!
//! `mode.json`'s `draft` field is `Some(name)` **if and only if**
//! `mode == Draft` — see `crates/storage/src/mode.rs` for the marker shape
//! and `commands/mode.rs` for how `handle_mode_draft`/`handle_mode_stage`/
//! `handle_mode_declarative` together keep that invariant true across every
//! mode transition.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, Registry};
use aoide_storage::fs as shellbridge;
use aoide_storage::mode::{load_mode_marker, RiceMode};
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "draft", "save"],
        summary: "Fork the current stage (stage/livery.json, required; stage/cover.json if present) into songbook/<song>/drafts/<name>/ — <song> is the currently staged song. Upserts; independent of mode (never switches modes).",
        args: [arg!("name", "string", true, "Draft name to save under the current song's drafts/.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_draft_save,
    ));
    r.insert(cmd!(
        path: ["rice", "draft", "list"],
        summary: "List saved drafts: name, song, saved-at, and whether it's the currently-loaded draft (mode.json is in Draft mode, routed to it). No arg walks every song's drafts/; <song> scopes to just that song.",
        args: [arg!("song", "string", false, "Scope the listing to one song's drafts; omit to list every song's.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_draft_list,
    ));
    r.insert(cmd!(
        path: ["rice", "draft", "drop"],
        summary: "Delete a saved draft of the currently staged song. Errors if the name doesn't exist (not idempotent), or if it's the draft `rice mode draft` currently has the stage routed to (switch modes first).",
        args: [arg!("name", "string", true, "Draft name to delete, from the current song's drafts/.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_draft_drop,
    ));
}

/// The shared "no song is currently staged, nothing to resolve a draft
/// directory under" error — [`handle_draft_drop`] has no other reason to
/// touch `stage/livery.json`, so it resolves the song purely through
/// [`super::mode::current_staged_song`] and reports this single reason on
/// failure (a fresh box, or a stage file with no `"song"` breadcrumb, are
/// the only ways to hit it).
fn no_resolvable_song(cmd: &str) -> Outcome {
    Outcome::error(
        cmd,
        "no song is currently staged — nothing to resolve a draft directory under \
         (stage a song first: `aoide rice stage <name>` or `aoide rice mode stage <name>`)",
    )
    .with_data(json!({ "reason": "no-resolvable-song" }))
}

/// `rice draft save <name>` — fork the current stage into
/// `songbook/<song>/drafts/<name>/`, where `<song>` is whatever
/// `stage/livery.json`'s own `"song"` field names right now. `stage/livery.json`
/// is required (error if absent/unparseable/song-less — there is nothing to
/// snapshot, or nowhere to nest it, without one).
///
/// Reads + validates the stage itself (rather than delegating to
/// [`fork_stage_into`] for that part) so a missing file, invalid JSON, and a
/// valid-but-song-less file each keep their own distinct, specific error
/// reason; the actual write is [`fork_stage_into`], shared with `rice mode
/// draft`'s fork-on-first-entry step.
///
/// Not gated by `rice mode declarative`, and never touches `mode.json` —
/// it only reads the stage (transparently through a `Draft`-mode symlink if
/// one is currently routed there) and writes outside it
/// (`songbook/<song>/drafts/`, never `stage/`), so it works in any mode
/// without changing what's currently active.
fn handle_draft_save(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage(
                "rice.draft.save",
                "usage: aoide rice draft save <name> [--json]",
            )
            .with_data(json!({ "reason": "missing-name" }));
        }
    };
    if !crate::compose::valid_song_name(&name) {
        return Outcome::error(
            "rice.draft.save",
            format!(
                "`{name}` is not a valid draft name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }

    let livery_src = shellbridge::stage_dir().join("livery.json");
    let raw = match std::fs::read_to_string(&livery_src) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(
                "rice.draft.save",
                format!("nothing staged to save: cannot read {} ({e})", livery_src.display()),
            )
            .with_data(json!({
                "reason": "no-staged-livery",
                "expected": livery_src.to_string_lossy(),
            }));
        }
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(
                "rice.draft.save",
                format!("staged livery.json is not valid JSON: {e}"),
            )
            .with_data(json!({ "reason": "invalid-json", "livery": livery_src.to_string_lossy() }));
        }
    };
    let song = match parsed.get("song").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => {
            return Outcome::error(
                "rice.draft.save",
                "staged livery.json carries no `song` field — nothing to nest this draft under \
                 (stage a named song first: `aoide rice stage <name>`)",
            )
            .with_data(json!({ "reason": "no-resolvable-song" }));
        }
    };

    fork_stage_into(&song, &name)
}

/// The reusable core of a draft snapshot: atomic-write the CURRENT
/// `stage/livery.json` into `songbook/<song>/drafts/<name>/livery.json`
/// (reading it fresh — transparently through a `Draft`-mode symlink if one
/// is currently routed there, same as any other reader), mirroring
/// `stage/cover.json` in if present, or removing a stale draft cover if the
/// current stage no longer has one (a draft always mirrors the stage
/// exactly at save/fork time, never a merge of old + new).
///
/// `pub(crate)`, not private: [`handle_draft_save`] (above) and `rice mode
/// draft <name>`'s "create the draft if it doesn't exist yet" step
/// (`commands/mode.rs::handle_mode_draft`) both call this for the identical
/// read/write, rather than each reimplementing it. Takes `song`/`name`
/// already resolved — callers own how they got there (`handle_draft_save`
/// derives it from the stage's own `"song"` field with distinct error
/// reasons; `handle_mode_draft` already has it via
/// [`super::mode::current_staged_song`]).
pub(crate) fn fork_stage_into(song: &str, name: &str) -> Outcome {
    let stage = shellbridge::stage_dir();
    let livery_src = stage.join("livery.json");
    let raw = match std::fs::read_to_string(&livery_src) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(
                "rice.draft.save",
                format!("nothing staged to fork: cannot read {} ({e})", livery_src.display()),
            )
            .with_data(json!({
                "reason": "no-staged-livery",
                "expected": livery_src.to_string_lossy(),
            }));
        }
    };
    if let Err(e) = serde_json::from_str::<Value>(&raw) {
        return Outcome::error(
            "rice.draft.save",
            format!("staged livery.json is not valid JSON: {e}"),
        )
        .with_data(json!({ "reason": "invalid-json", "livery": livery_src.to_string_lossy() }));
    }

    let dir = shellbridge::draft_dir(song, name);
    let livery_dst = dir.join("livery.json");
    if let Err(e) = shellbridge::atomic_write(&livery_dst, &raw) {
        return Outcome::error(
            "rice.draft.save",
            format!("failed to write {}: {e}", livery_dst.display()),
        )
        .with_data(json!({ "reason": "write-failed", "target": livery_dst.to_string_lossy() }));
    }
    let mut changed: Vec<String> = vec![livery_dst.to_string_lossy().into_owned()];

    let cover_src = stage.join("cover.json");
    let cover_dst = dir.join("cover.json");
    let cover_path = if cover_src.is_file() {
        match std::fs::read_to_string(&cover_src) {
            Ok(cover_raw) => {
                if let Err(e) = shellbridge::atomic_write(&cover_dst, &cover_raw) {
                    return Outcome::error(
                        "rice.draft.save",
                        format!("failed to write {}: {e}", cover_dst.display()),
                    )
                    .changed(changed)
                    .with_data(json!({ "reason": "write-failed", "target": cover_dst.to_string_lossy() }));
                }
                changed.push(cover_dst.to_string_lossy().into_owned());
                Some(cover_dst.to_string_lossy().into_owned())
            }
            Err(e) => {
                return Outcome::error(
                    "rice.draft.save",
                    format!("failed to read staged cover.json: {e}"),
                )
                .changed(changed)
                .with_data(json!({ "reason": "cover-read-failed" }));
            }
        }
    } else {
        if cover_dst.exists() {
            let _ = std::fs::remove_file(&cover_dst);
        }
        None
    };

    Outcome::ok(
        "rice.draft.save",
        format!(
            "saved draft `{name}` for `{song}` — {} file(s) snapshotted under {}",
            changed.len(),
            dir.display()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "name": name,
        "song": song,
        "livery": livery_dst.to_string_lossy(),
        "cover": cover_path,
    }))
}

/// `rice draft list [<song>]` — enumerate saved drafts. With `<song>`, scans
/// only `songbook/<song>/drafts/*/livery.json`; with no arg, walks every
/// song under `songbook/` and reports drafts from all of them. Each entry
/// carries its song (structural — the songbook dir it was found under),
/// name, saved-at (the livery.json file's mtime), and whether it is the
/// currently-loaded draft — `mode.json`'s `song`+`draft` pair, which is only
/// ever set together (`draft` is non-null iff `mode == Draft`). A directory
/// with no `livery.json` is not a draft and is silently skipped. An
/// absent/empty scope is `ok` with an empty list — never an error.
fn handle_draft_list(inv: &Invocation) -> Outcome {
    let scope = inv.args.first().cloned();
    let marker = load_mode_marker();

    let songs: Vec<String> = match &scope {
        Some(s) => vec![s.clone()],
        None => {
            let root = shellbridge::song_dir().join("songbook");
            std::fs::read_dir(&root)
                .map(|read| {
                    let mut names: Vec<String> = read
                        .flatten()
                        .filter(|e| e.path().is_dir())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    names
                })
                .unwrap_or_default()
        }
    };

    let mut entries: Vec<((String, String), Value)> = Vec::new();
    for song in &songs {
        let dir = shellbridge::song_drafts_dir(song);
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let livery = path.join("livery.json");
            if !livery.is_file() {
                continue; // no livery.json — not a draft, silently skipped
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let saved_at = std::fs::metadata(&livery)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| aoide_storage::time::iso_utc_from_epoch(d.as_secs() as i64));
            let is_current =
                marker.song.as_deref() == Some(song.as_str()) && marker.draft.as_deref() == Some(name.as_str());
            entries.push((
                (song.clone(), name.clone()),
                json!({
                    "song": song,
                    "name": name,
                    "savedAt": saved_at,
                    "current": is_current,
                }),
            ));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let drafts: Vec<Value> = entries.into_iter().map(|(_, v)| v).collect();

    Outcome::ok("rice.draft.list", format!("{} draft(s)", drafts.len()))
        .with_data(json!({ "drafts": drafts, "scope": scope }))
}

/// `rice draft drop <name>` — delete the CURRENTLY staged song's
/// `songbook/<song>/drafts/<name>/` outright. Missing draft → error
/// `draft-not-found` (NOT idempotent-silent, unlike this codebase's usual
/// tolerate-missing marker discipline — a named drop of nothing is almost
/// certainly a typo the caller should see).
///
/// Refuses (`draft-is-live`) if it's the draft `rice mode draft` currently
/// has `stage/livery.json` symlinked into — chosen over the alternative
/// (drop it AND fall back to plain `Staging`) because a `drop` that also
/// silently changes your mode and re-pins the stage is the more surprising
/// behavior; `rice mode stage`/`rice mode declarative` are the explicit,
/// already-documented way to leave `Draft` mode first.
fn handle_draft_drop(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage(
                "rice.draft.drop",
                "usage: aoide rice draft drop <name> [--json]",
            )
            .with_data(json!({ "reason": "missing-name" }));
        }
    };
    if !crate::compose::valid_song_name(&name) {
        return Outcome::error(
            "rice.draft.drop",
            format!(
                "`{name}` is not a valid draft name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }
    let song = match super::mode::current_staged_song() {
        Some(s) => s,
        None => return no_resolvable_song("rice.draft.drop"),
    };

    let existing = load_mode_marker();
    if existing.mode == RiceMode::Draft
        && existing.song.as_deref() == Some(song.as_str())
        && existing.draft.as_deref() == Some(name.as_str())
    {
        return Outcome::error(
            "rice.draft.drop",
            format!(
                "cannot drop `{name}` — it's the live draft for `{song}` \
                 (stage/livery.json is routed to it); switch modes first \
                 (`aoide rice mode stage` or `aoide rice mode declarative`), then drop it"
            ),
        )
        .with_data(json!({ "reason": "draft-is-live", "name": name, "song": song }));
    }

    let dir = shellbridge::draft_dir(&song, &name);
    if !dir.is_dir() {
        return Outcome::error(
            "rice.draft.drop",
            format!("no draft `{name}` for `{song}` at {}", dir.display()),
        )
        .with_data(json!({
            "reason": "draft-not-found",
            "name": name,
            "song": song,
            "expected": dir.to_string_lossy(),
        }));
    }
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        return Outcome::error(
            "rice.draft.drop",
            format!("failed to remove {}: {e}", dir.display()),
        )
        .with_data(json!({ "reason": "remove-failed", "target": dir.to_string_lossy() }));
    }

    Outcome::ok("rice.draft.drop", format!("dropped draft `{name}` for `{song}`"))
        .changed(vec![dir.to_string_lossy().into_owned()])
        .with_data(json!({ "name": name, "song": song }))
}

// ── Tests (rice draft save/list/drop) ────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::output::Status;
    use aoide_storage::mode::{save_mode_marker, ModeMarker};
    use aoide_test_support::*;

    /// Every test's stage carries a `"song"` breadcrumb — `save`/`drop` both
    /// resolve their target song off it now, so a bare `VALID_NOTES` (which
    /// has no `"song"` field) needs this written first.
    fn stage_with_song(stage: &std::path::Path, song: &str) {
        std::fs::write(
            stage.join("livery.json"),
            format!(
                r##"{{"schemaVersion":"0","song":"{song}","palette":{{"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"}}}}"##
            ),
        )
        .unwrap();
    }

    // ── rice draft save ──────────────────────────────────────────────────

    #[test]
    fn save_creates_the_draft_dir_nested_under_its_song_and_files() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-save-ok");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::fs::write(stage.join("cover.json"), r#"{"path":"x.png"}"#).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let dir = root.join("songbook").join("sonata").join("drafts").join("neon-night");
        let staged = std::fs::read_to_string(stage.join("livery.json")).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("livery.json")).unwrap(), staged);
        assert_eq!(
            std::fs::read_to_string(dir.join("cover.json")).unwrap(),
            r#"{"path":"x.png"}"#
        );
        assert!(out
            .changed
            .iter()
            .any(|c| c.ends_with("songbook/sonata/drafts/neon-night/livery.json")));
        assert!(out
            .changed
            .iter()
            .any(|c| c.ends_with("songbook/sonata/drafts/neon-night/cover.json")));
        let data = out.data.unwrap();
        assert_eq!(data["name"], "neon-night");
        assert_eq!(data["song"], "sonata");
        assert!(data["cover"].as_str().unwrap().ends_with("cover.json"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_without_a_staged_livery_errors() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("draft-save-nostage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "no-staged-livery");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn save_with_a_songless_staged_livery_errors_no_resolvable_song() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("draft-save-nosong");
        std::fs::create_dir_all(&stage).unwrap();
        // VALID_NOTES parses fine but carries no "song" field.
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "no-resolvable-song");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn save_upserts_an_existing_draft() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-save-upsert");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));

        let updated = r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#111111"}}"##;
        std::fs::write(stage.join("livery.json"), updated).unwrap();
        let out = handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let dir = root.join("songbook").join("sonata").join("drafts").join("neon-night");
        assert_eq!(
            std::fs::read_to_string(dir.join("livery.json")).unwrap(),
            updated,
            "re-saving overwrites, not appends/merges"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_clears_a_stale_cover_when_the_current_stage_has_none() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-save-stale-cover");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::fs::write(stage.join("cover.json"), r#"{"path":"x.png"}"#).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        let dir = root.join("songbook").join("sonata").join("drafts").join("neon-night");
        assert!(dir.join("cover.json").is_file());

        std::fs::remove_file(stage.join("cover.json")).unwrap();
        let out = handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(!dir.join("cover.json").exists(), "stale cover removed on re-save");
        assert!(out.data.unwrap()["cover"].is_null());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn saving_one_draft_never_touches_another() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-save-independent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["amber-dusk"]));
        let updated = r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#222222"}}"##;
        std::fs::write(stage.join("livery.json"), updated).unwrap();
        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));

        let drafts = root.join("songbook").join("sonata").join("drafts");
        assert!(
            std::fs::read_to_string(drafts.join("amber-dusk").join("livery.json"))
                .unwrap()
                .contains("#0b1021"),
            "amber-dusk is untouched by saving neon-night"
        );
        assert_eq!(
            std::fs::read_to_string(drafts.join("neon-night").join("livery.json")).unwrap(),
            updated
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drafts_of_two_different_songs_never_collide_even_with_the_same_name() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-save-cross-song");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));

        stage_with_song(&stage, "moonlight");
        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));

        assert!(root
            .join("songbook")
            .join("sonata")
            .join("drafts")
            .join("neon-night")
            .join("livery.json")
            .is_file());
        assert!(root
            .join("songbook")
            .join("moonlight")
            .join("drafts")
            .join("neon-night")
            .join("livery.json")
            .is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_reads_transparently_through_a_symlinked_stage() {
        // The "preserve a moment as a second draft while still working in a
        // first one" scenario `rice mode draft` enables: if `stage/livery.json`
        // is CURRENTLY a symlink (Draft mode routed into some other draft),
        // `rice draft save <new-name>` still reads the live content fine —
        // std::fs::read_to_string follows symlinks transparently, same as
        // any other reader — and forks it into a brand-new draft.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-save-through-symlink");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let existing_dir = root.join("songbook").join("sonata").join("drafts").join("neon-night");
        std::fs::create_dir_all(&existing_dir).unwrap();
        let routed_notes = r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#routed"}}"##;
        std::fs::write(existing_dir.join("livery.json"), routed_notes).unwrap();
        std::os::unix::fs::symlink(&existing_dir.join("livery.json"), stage.join("livery.json")).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_save(&inv(&["rice", "draft", "save"], &["amber-dusk"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let forked = root.join("songbook").join("sonata").join("drafts").join("amber-dusk");
        assert_eq!(std::fs::read_to_string(forked.join("livery.json")).unwrap(), routed_notes);
        // The symlink itself, and what it routes to, are both untouched.
        assert!(std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(existing_dir.join("livery.json")).unwrap(), routed_notes);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice draft list ──────────────────────────────────────────────────

    #[test]
    fn list_with_no_songbook_at_all_is_ok_with_an_empty_list() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("draft-list-absent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_list(&inv(&["rice", "draft", "list"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(out.data.unwrap()["drafts"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn list_scoped_to_a_song_with_no_drafts_is_ok_with_an_empty_list() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-list-scoped-empty");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(root.join("songbook").join("sonata")).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_list(&inv(&["rice", "draft", "list"], &["sonata"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(out.data.unwrap()["drafts"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_surfaces_multiple_drafts_of_one_song_with_the_current_one_flagged() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-list-multi");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["amber-dusk"]));
        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some("sonata".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_draft_list(&inv(&["rice", "draft", "list"], &["sonata"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let drafts = out.data.unwrap()["drafts"].as_array().unwrap().clone();
        assert_eq!(drafts.len(), 2);
        let neon = drafts.iter().find(|d| d["name"] == "neon-night").unwrap();
        assert_eq!(neon["current"], true);
        assert_eq!(neon["song"], "sonata");
        assert!(neon["savedAt"].is_string());
        let amber = drafts.iter().find(|d| d["name"] == "amber-dusk").unwrap();
        assert_eq!(amber["current"], false);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_with_no_arg_walks_every_song_and_scoping_by_name_narrows_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-list-allsongs");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));

        stage_with_song(&stage, "moonlight");
        handle_draft_save(&inv(&["rice", "draft", "save"], &["amber-dusk"]));

        let out_all = handle_draft_list(&inv(&["rice", "draft", "list"], &[]));
        assert_eq!(out_all.status, Status::Ok, "{:?}", out_all.data);
        let all = out_all.data.unwrap()["drafts"].as_array().unwrap().clone();
        assert_eq!(all.len(), 2, "both songs' drafts surface with no scope");
        assert!(all.iter().any(|d| d["song"] == "sonata" && d["name"] == "neon-night"));
        assert!(all.iter().any(|d| d["song"] == "moonlight" && d["name"] == "amber-dusk"));

        let out_scoped = handle_draft_list(&inv(&["rice", "draft", "list"], &["sonata"]));
        let scoped = out_scoped.data.unwrap()["drafts"].as_array().unwrap().clone();
        assert_eq!(scoped.len(), 1, "scoping to sonata excludes moonlight's draft");
        assert_eq!(scoped[0]["name"], "neon-night");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice draft drop ──────────────────────────────────────────────────

    #[test]
    fn drop_removes_a_draft() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-drop-ok");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        let dir = root.join("songbook").join("sonata").join("drafts").join("neon-night");
        assert!(dir.is_dir());

        let out = handle_draft_drop(&inv(&["rice", "draft", "drop"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drop_rejects_a_path_traversal_name_before_touching_the_filesystem() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-drop-traversal");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // `draft_dir(song, name)` joins `name` straight into a path — a
        // traversal name must be rejected before it ever reaches
        // `remove_dir_all`, same guard `handle_draft_save` already applies.
        let out = handle_draft_drop(&inv(&["rice", "draft", "drop"], &["../../evil"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "invalid-name");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drop_on_a_missing_draft_errors() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("draft-drop-missing");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_drop(&inv(&["rice", "draft", "drop"], &["nope"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "draft-not-found");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn drop_with_no_resolvable_song_errors() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("draft-drop-nosong");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_draft_drop(&inv(&["rice", "draft", "drop"], &["neon-night"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "no-resolvable-song");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn drop_of_the_live_draft_is_refused_not_silently_torn_down() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-drop-live");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some("sonata".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_draft_drop(&inv(&["rice", "draft", "drop"], &["neon-night"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "draft-is-live");
        // Nothing was removed, and the marker is untouched.
        assert!(root
            .join("songbook")
            .join("sonata")
            .join("drafts")
            .join("neon-night")
            .is_dir());
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Draft);
        assert_eq!(marker.draft, Some("neon-night".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn drop_of_a_different_draft_succeeds_while_another_is_live() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("draft-drop-other");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        stage_with_song(&stage, "sonata");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_draft_save(&inv(&["rice", "draft", "save"], &["amber-dusk"]));
        handle_draft_save(&inv(&["rice", "draft", "save"], &["neon-night"]));
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some("sonata".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_draft_drop(&inv(&["rice", "draft", "drop"], &["amber-dusk"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        // The live draft's marker is completely untouched by dropping a
        // DIFFERENT one.
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Draft);
        assert_eq!(marker.draft, Some("neon-night".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }
}
