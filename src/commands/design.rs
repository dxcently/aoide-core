//! `rice design status`/`enter`/`exit` — the design-mode lifecycle around
//! `stage/design.json` (concepts/Self-Ricing's design-mode extension).
//!
//! Phase A shipped `status` (read-only). Phase B (this file, now) adds the
//! write side: `enter` reuses `rice preview`'s live-apply side effects
//! (`handle_rice_preview` in `commands/rice.rs`, made `pub(crate)` for this)
//! and then records a [`aoide_storage::design::DesignMarker`]; `exit` clears
//! it. `rice design sync` (Phase D) and widget live-carry into
//! `run/qml/songs/` (Phase C, the only thing that would ever populate
//! `carriedSlots`) are still later-phase work — see CONTRACTS.md §4's
//! `design.json` entry for the honest state of the lifecycle today.

use super::rice::handle_rice_preview;
use crate::dispatch::Invocation;
use crate::output::{Outcome, Status};
use crate::registry::{arg, cmd, flag, Registry};
use aoide_storage::design::{delete_design_marker, design_marker_path, save_design_marker, DesignMarker};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "design", "status"],
        summary: "Report the active design session (song, intent doc, sources) or that none is active.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_design_status,
    ));
    r.insert(cmd!(
        path: ["rice", "design", "enter"],
        summary: "Enter design mode for a song: preview it live (drachma + hyprctl) and record that it's being actively iterated on.",
        args: [arg!("name", "string", true, "Song to open for live design (from song/songbook/).")],
        flags: [
            flag!("by", "string", "Optional owner/agent id recorded in the design marker."),
        ],
        gated: false,
        implemented: true,
        handler: handle_design_enter,
    ));
    r.insert(cmd!(
        path: ["rice", "design", "exit"],
        summary: "Leave design mode: clear stage/design.json (run/qml sketches untouched).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_design_exit,
    ));
}

/// `rice design status` — read `stage/design.json` via `aoide-storage` and
/// report it verbatim, or `{"active": false}` when no marker exists.
fn handle_design_status(_inv: &Invocation) -> Outcome {
    match aoide_storage::design::load_design_marker() {
        None => Outcome::ok("rice.design.status", "no design session active")
            .with_data(json!({ "active": false })),
        Some(marker) => Outcome::ok(
            "rice.design.status",
            format!("design session active for `{}`", marker.song),
        )
        .with_data(json!({
            "active": true,
            "song": marker.song,
            "enteredAt": marker.entered_at,
            "by": marker.by,
            "intent": marker.intent,
            "intentPresent": marker.intent_present,
            "sources": marker.sources,
            "carriedSlots": marker.carried_slots,
        })),
    }
}

/// `rice design enter <name> [--by <id>]` — open a song for live design
/// iteration: reuse `rice preview <name>`'s live-apply (drachma.json +
/// best-effort hyprctl geometry/border) so `enter` has the EXACT same
/// side effects a bare `rice preview` has (no reimplementation), then record
/// a [`DesignMarker`] so other tooling (`status`, and later `sync`) knows a
/// session is active.
///
/// Song-not-found / missing-name validation is `handle_rice_preview`'s own
/// check, reused as-is: `enter` and `preview` both take the song name as
/// their first positional arg and nothing else off the `Invocation`, so the
/// SAME `inv` this handler was given is handed straight to `handle_rice_preview`
/// — no adapter needed. Its `Outcome` is relabelled to `rice.design.enter`
/// (keeping its `message`/`data`/`changed`) and returned as-is on anything
/// other than success; only on success do we go on to write the marker.
fn handle_design_enter(inv: &Invocation) -> Outcome {
    if inv.args.first().is_none() {
        return Outcome::usage(
            "rice.design.enter",
            "usage: aoide rice design enter <name> [--by <id>] [--json]",
        )
        .with_data(json!({ "reason": "missing-name" }));
    }

    let mut preview = handle_rice_preview(inv);
    if preview.status != Status::Ok {
        preview.command = "rice.design.enter".to_string();
        return preview;
    }

    // Re-validated by handle_rice_preview above; args.first() is Some.
    let name = inv.args.first().cloned().unwrap_or_default();
    let by = inv.flags.get("by").cloned();
    let intent_path = crate::shellbridge::songbook_dir(&name)
        .join("design")
        .join("intent.md");
    let intent_present = intent_path.is_file();

    let marker = DesignMarker {
        song: name.clone(),
        entered_at: aoide_storage::time::now_iso_utc(),
        by,
        intent: intent_path.to_string_lossy().into_owned(),
        intent_present,
        sources: vec![
            "stage/drachma.json".to_string(),
            format!("song/songbook/{name}/widgets"),
        ],
        carried_slots: vec![],
    };

    if let Err(e) = save_design_marker(&marker) {
        return Outcome::error(
            "rice.design.enter",
            format!("previewed `{name}` live but failed to write the design marker: {e}"),
        )
        .changed(preview.changed)
        .with_data(json!({ "reason": "marker-write-failed", "song": name }));
    }

    let mut changed = preview.changed;
    changed.push(design_marker_path().to_string_lossy().into_owned());

    Outcome::ok(
        "rice.design.enter",
        format!("design mode active for `{name}` — {} file(s) live", changed.len()),
    )
    .changed(changed)
    .with_data(json!({
        "song": name,
        "intent": marker.intent,
        "intentPresent": marker.intent_present,
        "preview": preview.data,
        "nextSteps": [
            "edit run/qml or song widgets",
            format!("aoide rice design sync {name} to push shared-tree edits [not yet built]"),
            "aoide rice design exit when done",
        ],
    }))
}

/// `rice design exit` — leave design mode: clear `stage/design.json` only.
/// Idempotent (no marker present is `ok`, not an error) and deliberately
/// narrow: it never touches `run/qml/` or any song file — the live sketch a
/// design session leaves behind stays exactly as it was until the next
/// `rice preview`/`rice design enter` resets it (an explicit invariant of
/// this feature, not an oversight).
fn handle_design_exit(_inv: &Invocation) -> Outcome {
    match aoide_storage::design::load_design_marker() {
        None => Outcome::ok("rice.design.exit", "not in design mode")
            .with_data(json!({ "wasActive": false })),
        Some(marker) => match delete_design_marker() {
            Ok(()) => Outcome::ok(
                "rice.design.exit",
                format!("left design mode for `{}`", marker.song),
            )
            .changed(vec![design_marker_path().to_string_lossy().into_owned()])
            .with_data(json!({ "wasActive": true, "song": marker.song })),
            Err(e) => Outcome::error(
                "rice.design.exit",
                format!("failed to clear the design marker: {e}"),
            )
            .with_data(json!({ "reason": "marker-remove-failed" })),
        },
    }
}

// ── Tests (rice design status) ───────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::*;

    #[test]
    fn status_reports_inactive_when_no_marker_exists() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-status-none");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_design_status(&inv(&["rice", "design", "status"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.data.unwrap()["active"], false);
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn status_reports_the_marker_fields_when_one_exists() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-status-active");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let marker = DesignMarker {
            song: "moonlight".to_string(),
            entered_at: "2026-08-02T00:00:00Z".to_string(),
            by: Some("khoa".to_string()),
            intent: "/home/khoa/Aoide/song/songbook/moonlight/design/intent.md".to_string(),
            intent_present: true,
            sources: vec!["stage/drachma.json".to_string()],
            carried_slots: vec![],
        };
        save_design_marker(&marker).unwrap();

        let out = handle_design_status(&inv(&["rice", "design", "status"], &[]));
        assert_eq!(out.status, Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["active"], true);
        assert_eq!(data["song"], "moonlight");
        assert_eq!(data["enteredAt"], "2026-08-02T00:00:00Z");
        assert_eq!(data["by"], "khoa");
        assert_eq!(
            data["intent"],
            "/home/khoa/Aoide/song/songbook/moonlight/design/intent.md"
        );
        assert_eq!(data["intentPresent"], true);
        assert_eq!(data["sources"][0], "stage/drachma.json");
        assert!(data["carriedSlots"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&stage);
    }

    // ── rice design enter ────────────────────────────────────────────────

    #[test]
    fn enter_on_an_existing_song_writes_a_marker_and_is_reenterable() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("design-enter-ok");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(song.join("design")).unwrap();
        std::fs::write(song.join("drachma.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("design").join("intent.md"), "# intent\n").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_design_enter(&inv(&["rice", "design", "enter"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{out:?}");
        let data = out.data.clone().unwrap();
        assert_eq!(data["song"], "moonlight");
        assert_eq!(data["intentPresent"], true);
        assert!(data["intent"].as_str().unwrap().ends_with("moonlight/design/intent.md"));
        assert!(data["nextSteps"].is_array());
        // Both the preview's stage write and the marker itself are reported.
        assert!(out.changed.iter().any(|c| c.ends_with("stage/drachma.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("stage/design.json")));

        // The marker actually landed on disk with the right shape.
        let marker = aoide_storage::design::load_design_marker().unwrap();
        assert_eq!(marker.song, "moonlight");
        assert_eq!(marker.by, None);
        assert!(marker.intent_present);
        assert_eq!(marker.sources[0], "stage/drachma.json");
        assert_eq!(marker.sources[1], "song/songbook/moonlight/widgets");
        assert!(marker.carried_slots.is_empty());

        // Re-entering the same song is not an error — it just refreshes the
        // marker (idempotent).
        let out2 = handle_design_enter(&inv(&["rice", "design", "enter"], &["moonlight"]));
        assert_eq!(out2.status, Status::Ok);
        let marker2 = aoide_storage::design::load_design_marker().unwrap();
        assert_eq!(marker2.song, "moonlight");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn enter_records_the_optional_by_flag() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("design-enter-by");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("drachma.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let mut flags = std::collections::BTreeMap::new();
        flags.insert("by".to_string(), "khoa".to_string());
        let invocation = Invocation {
            path: vec!["rice".to_string(), "design".to_string(), "enter".to_string()],
            args: vec!["moonlight".to_string()],
            flags,
            door: crate::daemon::Door::Cli,
        };
        let out = handle_design_enter(&invocation);
        assert_eq!(out.status, Status::Ok);
        let marker = aoide_storage::design::load_design_marker().unwrap();
        assert_eq!(marker.by, Some("khoa".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn enter_missing_name_is_usage_exit_2() {
        let out = handle_design_enter(&inv(&["rice", "design", "enter"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
        assert_eq!(out.data.unwrap()["reason"], "missing-name");
    }

    #[test]
    fn enter_nonexistent_song_reports_the_same_song_not_found_reason_preview_uses() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-enter-missing").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_design_enter(&inv(&["rice", "design", "enter"], &["nope"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "song-not-found");
        // A failed preview must never leave a marker behind.
        assert!(aoide_storage::design::load_design_marker().is_none());
        let _ = std::fs::remove_dir_all(&stage);
    }

    // ── rice design exit ─────────────────────────────────────────────────

    #[test]
    fn exit_with_no_marker_is_ok_not_an_error() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-exit-none");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_design_exit(&inv(&["rice", "design", "exit"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.render(false).1, crate::output::exit::OK);
        assert_eq!(out.data.unwrap()["wasActive"], false);
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn exit_with_an_active_marker_removes_it_and_reports_was_active() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-exit-active");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let marker = DesignMarker {
            song: "moonlight".to_string(),
            entered_at: "2026-08-02T00:00:00Z".to_string(),
            by: None,
            intent: "/x/intent.md".to_string(),
            intent_present: false,
            sources: vec!["stage/drachma.json".to_string()],
            carried_slots: vec![],
        };
        save_design_marker(&marker).unwrap();

        let out = handle_design_exit(&inv(&["rice", "design", "exit"], &[]));
        assert_eq!(out.status, Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["wasActive"], true);
        assert_eq!(data["song"], "moonlight");
        assert!(out.changed.iter().any(|c| c.ends_with("design.json")));
        assert!(aoide_storage::design::load_design_marker().is_none());
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn exit_only_removes_the_marker_and_leaves_every_other_stage_file_untouched() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-exit-scoped");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let marker = DesignMarker {
            song: "moonlight".to_string(),
            entered_at: "2026-08-02T00:00:00Z".to_string(),
            by: None,
            intent: "/x/intent.md".to_string(),
            intent_present: false,
            sources: vec![],
            carried_slots: vec![],
        };
        save_design_marker(&marker).unwrap();
        std::fs::write(stage.join("drachma.json"), VALID_NOTES).unwrap();
        std::fs::write(stage.join("cover.json"), "{\"path\":\"x\"}").unwrap();

        let out = handle_design_exit(&inv(&["rice", "design", "exit"], &[]));
        assert_eq!(out.status, Status::Ok);

        // Exactly the marker is gone; every sibling stage file is byte-for-byte
        // untouched (`exit` never reaches into `run/qml/` or song files).
        assert!(!aoide_storage::design::design_marker_path().exists());
        assert_eq!(
            std::fs::read_to_string(stage.join("drachma.json")).unwrap(),
            VALID_NOTES
        );
        assert_eq!(
            std::fs::read_to_string(stage.join("cover.json")).unwrap(),
            "{\"path\":\"x\"}"
        );
        let _ = std::fs::remove_dir_all(&stage);
    }
}
