//! `rice mode {status,stage,declarative}` — the staging/declarative mode
//! toggle around `stage/mode.json` (concepts/Self-Ricing's mode-toggle
//! extension, khoa 2026-08-14).
//!
//! `declarative` is the safe default (no marker file at all reads as
//! declarative — [`aoide_storage::mode::load_mode_marker`]). While
//! declarative, the direct CLI entrypoints for `rice stage` and `cover set`
//! refuse (their own `handle_rice_stage_entry`/`handle_cover_set_entry`
//! guards, `commands/rice.rs` and `commands/cover.rs`) — nothing else in
//! this codebase writes `stage/livery.json`/`stage/cover.json`, so refusing
//! those two entrypoints is sufficient to guarantee nothing drifts while
//! locked; no background reconciler process exists (`aoided` is still a
//! one-shot skeleton, `crates/server/src/daemon.rs`) and none is needed for
//! that guarantee to hold.
//!
//! `stage`/`declarative` both reuse [`super::rice::handle_rice_stage`]
//! directly (guard-free, `pub(crate)`) when a song name is given — the SAME
//! side effects a bare `rice stage <name>` has — so `declarative <name>` can
//! re-pin `stage/livery.json` to that song's committed notes and lock it in
//! one step, even from the default (unmarked) declarative state, without
//! tripping its own guard (the marker isn't flipped until AFTER the write
//! succeeds).
//!
//! Whether `rice design enter` should also require/imply staging mode is an
//! open question (not decided here) — it keeps calling `handle_rice_stage`
//! guard-free exactly as before, unaffected by this feature.

use aoide_protocol::Invocation;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::registry::{arg, cmd, Registry};
use aoide_storage::mode::{load_mode_marker, mode_marker_path, save_mode_marker, ModeMarker, RiceMode};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "mode", "status"],
        summary: "Report the current rice mode (staging or declarative) and, in staging, which song it's pointed at.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_status,
    ));
    r.insert(cmd!(
        path: ["rice", "mode", "stage"],
        summary: "Unlock staging: `rice stage`/`cover set` write live again. Optional <name> also stages that song immediately.",
        args: [arg!("name", "string", false, "Song to stage immediately on entering staging mode.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_stage,
    ));
    r.insert(cmd!(
        path: ["rice", "mode", "declarative"],
        summary: "Lock staging: `rice stage`/`cover set` refuse until unlocked again. Optional <name> re-pins stage/livery.json to that song's committed notes first.",
        args: [arg!("name", "string", false, "Song to pin stage/livery.json to before locking; omit to lock as-is.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_declarative,
    ));
}

fn mode_word(m: RiceMode) -> &'static str {
    match m {
        RiceMode::Staging => "staging",
        RiceMode::Declarative => "declarative",
    }
}

/// `rice mode status` — read `stage/mode.json` via `aoide-storage` and
/// report it verbatim (absent file reports the `declarative` default, same
/// tolerate-missing discipline `rice design status` follows for its marker).
fn handle_mode_status(_inv: &Invocation) -> Outcome {
    let m = load_mode_marker();
    Outcome::ok("rice.mode.status", format!("rice mode: {}", mode_word(m.mode))).with_data(json!({
        "mode": mode_word(m.mode),
        "song": m.song,
        "draft": m.draft,
        "since": if m.since.is_empty() { None } else { Some(m.since) },
    }))
}

/// `rice mode stage [<name>]` — unlock staging writers. With `<name>`, also
/// stages that song immediately (delegates straight to
/// [`super::rice::handle_rice_stage`] with the SAME `inv`, no reimplementation
/// — mirrors `rice design enter`'s reuse of the same function).
fn handle_mode_stage(inv: &Invocation) -> Outcome {
    let name = inv.args.first().cloned();
    let mut changed: Vec<String> = Vec::new();

    if name.is_some() {
        let mut staged = super::rice::handle_rice_stage(inv);
        if staged.status != Status::Ok {
            staged.command = "rice.mode.stage".to_string();
            return staged;
        }
        changed = staged.changed;
    }

    let existing = load_mode_marker();
    let marker = ModeMarker {
        mode: RiceMode::Staging,
        song: name.clone().or(existing.song),
        draft: existing.draft,
        since: aoide_storage::time::now_iso_utc(),
    };
    if let Err(e) = save_mode_marker(&marker) {
        return Outcome::error("rice.mode.stage", format!("failed to write mode marker: {e}"))
            .changed(changed)
            .with_data(json!({ "reason": "marker-write-failed" }));
    }
    changed.push(mode_marker_path().to_string_lossy().into_owned());

    Outcome::ok(
        "rice.mode.stage",
        match &name {
            Some(n) => format!("staging mode unlocked — staged `{n}` live"),
            None => "staging mode unlocked".to_string(),
        },
    )
    .changed(changed)
    .with_data(json!({ "mode": "staging", "song": marker.song }))
}

/// `rice mode declarative [<name>]` — lock staging writers. With `<name>`,
/// re-pins `stage/livery.json` to that song's committed notes FIRST (again
/// via `handle_rice_stage`, guard-free), then writes the marker; without a
/// name, locks whatever is already staged as-is (a freeze, not a re-pin —
/// the caller is asserting "this is already correct", not asking us to
/// derive truth from nowhere).
fn handle_mode_declarative(inv: &Invocation) -> Outcome {
    let name = inv.args.first().cloned();
    let mut changed: Vec<String> = Vec::new();

    if name.is_some() {
        let mut staged = super::rice::handle_rice_stage(inv);
        if staged.status != Status::Ok {
            staged.command = "rice.mode.declarative".to_string();
            return staged;
        }
        changed = staged.changed;
    }

    let existing = load_mode_marker();
    let marker = ModeMarker {
        mode: RiceMode::Declarative,
        song: name.clone().or(existing.song),
        draft: None,
        since: aoide_storage::time::now_iso_utc(),
    };
    if let Err(e) = save_mode_marker(&marker) {
        return Outcome::error("rice.mode.declarative", format!("failed to write mode marker: {e}"))
            .changed(changed)
            .with_data(json!({ "reason": "marker-write-failed" }));
    }
    changed.push(mode_marker_path().to_string_lossy().into_owned());

    Outcome::ok(
        "rice.mode.declarative",
        match &marker.song {
            Some(n) => {
                format!("declarative mode locked — pinned to `{n}`; rice stage/cover set refuse until unlocked")
            }
            None => "declarative mode locked — rice stage/cover set refuse until unlocked".to_string(),
        },
    )
    .changed(changed)
    .with_data(json!({ "mode": "declarative", "song": marker.song }))
}

// ── Tests (rice mode status/stage/declarative) ───────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::*;

    #[test]
    fn status_reports_the_declarative_default_with_no_marker_file() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-status-default");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_status(&inv(&["rice", "mode", "status"], &[]));
        assert_eq!(out.status, Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["mode"], "declarative");
        assert!(data["song"].is_null());
        assert!(data["since"].is_null());
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn stage_with_no_name_just_unlocks() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-stage-bare").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Staging);
        assert_eq!(marker.song, None);
        assert!(out.changed.iter().any(|c| c.ends_with("stage/mode.json")));
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn stage_with_a_name_stages_it_and_unlocks() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-stage-named");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Staging);
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert!(out.changed.iter().any(|c| c.ends_with("stage/livery.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("stage/mode.json")));
        assert!(stage.join("livery.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_with_an_unknown_song_name_fails_and_never_unlocks() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-stage-badname").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &["nope"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.command, "rice.mode.stage");
        // The mode marker must never flip on a failed stage — still the
        // default declarative, not left half-unlocked.
        assert_eq!(load_mode_marker().mode, RiceMode::Declarative);
    }

    #[test]
    fn declarative_with_no_name_locks_whatever_is_already_staged() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-declarative-bare");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(load_mode_marker().mode, RiceMode::Declarative);
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn declarative_with_a_name_repins_then_locks_even_from_the_default_state() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-declarative-named");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Starting from the unmarked (default-declarative) state — the
        // re-pin write must NOT trip its own not-yet-written lock.
        assert_eq!(load_mode_marker().mode, RiceMode::Declarative);

        let out = handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Declarative);
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert!(stage.join("livery.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_then_declarative_round_trip_toggles_cleanly() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-roundtrip");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        handle_mode_stage(&inv(&["rice", "mode", "stage"], &[]));
        assert_eq!(load_mode_marker().mode, RiceMode::Staging);

        handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &[]));
        assert_eq!(load_mode_marker().mode, RiceMode::Declarative);

        let _ = std::fs::remove_dir_all(&stage);
    }
}
