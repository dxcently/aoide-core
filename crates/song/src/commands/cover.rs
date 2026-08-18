//! `cover set` — the live wallpaper write-path (song/covers/).

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, Registry};
use aoide_storage::fs as shellbridge;
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["cover", "set"],
        summary: "Set the live wallpaper: stage stage/cover.json (hot-swap) from a cover path or a bare name in song/covers/. Refuses while `rice mode declarative` is locked.",
        args: [arg!("path", "string", true, "Absolute cover path, or a bare filename resolved against song/covers/.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_cover_set_entry,
    ));
}

/// `cover set` registry entrypoint — refuses while `rice mode declarative`
/// is locked, same guard as `rice stage`'s own entrypoint
/// (`commands/rice.rs::handle_rice_stage_entry`, khoa 2026-08-14). The pure
/// write logic stays in [`handle_cover_set`] guard-free.
fn handle_cover_set_entry(inv: &Invocation) -> Outcome {
    let mode_marker = aoide_storage::mode::load_mode_marker();
    if mode_marker.mode == aoide_storage::mode::RiceMode::Declarative {
        return Outcome::error(
            "cover.set",
            "declarative mode is locked — run `aoide rice mode stage` to unlock hot-loading first",
        )
        .with_data(json!({ "reason": "declarative-mode-locked" }));
    }
    let mut out = handle_cover_set(inv);

    // Auto-take (phase A3) — same hook, same posture, same rationale as
    // `rice stage`'s own in `commands/rice.rs::handle_rice_stage_entry`; see
    // that function's doc comment for the full write-up (Draft-mode-only
    // gate off `mode_marker` read before the write; unconditional
    // `snapshot` — not the drift-checking core — because a take records
    // every write and the resulting noise is pruning's problem, not
    // write-time suppression's; the non-fatal `"take"/"takeError"`
    // reporting posture). `cause` is `"cover-set"` and `cmd` is
    // `"cover.set"` — its own dotted name, not `rice.stage`'s, so a
    // refusal names the command that actually ran.
    if out.status == aoide_protocol::output::Status::Ok
        && mode_marker.mode == aoide_storage::mode::RiceMode::Draft
    {
        match super::take::snapshot("cover.set", "cover-set") {
            Ok(record) => {
                if let (Some(song), Some(draft)) = (&mode_marker.song, &mode_marker.draft) {
                    out.changed.push(
                        aoide_storage::takes::take_path(song, draft, record.take)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    out.changed.push(
                        aoide_storage::takes::head_path(song, draft)
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                if let Some(Value::Object(map)) = &mut out.data {
                    map.insert("take".to_string(), json!(record.take));
                }
            }
            Err(err) => {
                if let Some(Value::Object(map)) = &mut out.data {
                    map.insert("take".to_string(), Value::Null);
                    map.insert("takeError".to_string(), json!(err.message));
                }
            }
        }
    }
    out
}

/// `cover set <path>` — switch the live wallpaper by staging a new cover.
///
/// This is the WRITE path the Quickshell wallpaper picker shells out to (QML has
/// no file-write primitive). It resolves `<path>` to an absolute cover file, then
/// atomic-writes `{ "path": "<abs>" }` to `<stage>/cover.json` — exactly the seam
/// `rice stage` uses, which `AoideWallpaper.qml`'s FileView watches and
/// hot-swaps live. Nothing is committed; the baked `AOIDE_WALLPAPER` remains the
/// boot/rebuild fallback.
///
/// Resolution: an absolute `<path>` is taken literally; a bare filename resolves
/// against the shared cover library `song/covers/`. A path that names no existing
/// file is a clear error (exit 1) — we never stage a wallpaper that can't render.
fn handle_cover_set(inv: &Invocation) -> Outcome {
    let arg = match inv.args.first() {
        Some(a) => a.clone(),
        None => {
            return Outcome::usage(
                "cover.set",
                "usage: aoide cover set <path|name> [--json]",
            )
            .with_data(json!({ "reason": "missing-path" }));
        }
    };

    // Absolute path → literal; anything else → the shared covers/ library.
    let resolved = crate::cover::resolve_cover_arg(&arg);

    if !resolved.is_file() {
        return Outcome::error(
            "cover.set",
            format!("no cover at {}: not a file", resolved.display()),
        )
        .with_data(json!({
            "reason": "cover-not-found",
            "arg": arg,
            "resolved": resolved.to_string_lossy(),
        }));
    }

    // Stage cover.json exactly like `rice stage`: pretty `{ "path": … }`
    // with a trailing newline, atomic write into the stage dir.
    let stage = shellbridge::stage_dir();
    let cover_dst = stage.join("cover.json");
    let body = serde_json::to_string_pretty(&json!({ "path": resolved.to_string_lossy() }))
        .unwrap_or_default()
        + "\n";
    if let Err(e) = shellbridge::atomic_write(&cover_dst, &body) {
        return Outcome::error("cover.set", format!("failed to stage cover.json: {e}"))
            .with_data(json!({
                "reason": "stage-write-failed",
                "target": cover_dst.to_string_lossy(),
            }));
    }

    Outcome::ok(
        "cover.set",
        format!("wallpaper set to {} — stage/cover.json live for hot-swap", resolved.display()),
    )
    .changed(vec![cover_dst.to_string_lossy().into_owned()])
    .with_data(json!({
        "cover": resolved.to_string_lossy(),
        "coverJson": cover_dst.to_string_lossy(),
        "seam": "AoideWallpaper.qml FileView-watches stage/cover.json and hot-swaps live",
    }))
}

// ── Tests (cover set) ────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::*;
    use aoide_protocol::output::Status;

    #[test]
    fn cover_set_stages_an_absolute_path() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-abs");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let img = root.join("elsewhere.png");
        std::fs::write(&img, b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(out.status, Status::Ok);
        // cover.json landed in the stage and points at the absolute path.
        let cover = std::fs::read_to_string(stage.join("cover.json")).unwrap();
        assert!(cover.contains("elsewhere.png"), "cover.json points at the file: {cover}");
        assert!(cover.ends_with("\n"), "trailing newline mirrors rice stage");
        assert!(out.changed.iter().any(|c| c.ends_with("cover.json")));
        assert_eq!(
            out.data.unwrap()["cover"].as_str().unwrap(),
            img.to_string_lossy()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_resolves_a_bare_name_against_the_covers_library() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-name");
        let stage = root.join("stage");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(covers.join("sonata.webp"), b"RIFF stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &["sonata.webp"]));
        assert_eq!(out.status, Status::Ok);
        let staged = out.data.unwrap()["cover"].as_str().unwrap().to_string();
        assert!(
            staged.ends_with("covers/sonata.webp"),
            "bare name resolved under the shared covers library: {staged}"
        );
        let cover = std::fs::read_to_string(stage.join("cover.json")).unwrap();
        assert!(cover.contains("covers/sonata.webp"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_missing_file_is_error_exit_1() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-missing");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &["nope.png"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "cover-not-found");
        // Nothing was staged for a missing file.
        assert!(!stage.join("cover.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_missing_arg_is_usage_exit_2() {
        let out = handle_cover_set(&inv(&["cover", "set"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
    }

    // ── cover set: the declarative-mode write guard (khoa 2026-08-14) ────────

    #[test]
    fn cover_set_entry_refuses_while_declarative_mode_is_locked() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-entry-locked");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let img = root.join("elsewhere.png");
        std::fs::write(&img, b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set_entry(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "declarative-mode-locked");
        assert!(!stage.join("cover.json").exists(), "nothing staged while locked");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_entry_allows_writes_once_staging_mode_is_unlocked() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-entry-unlocked");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let img = root.join("elsewhere.png");
        std::fs::write(&img, b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Staging,
            ..Default::default()
        })
        .unwrap();

        let out = handle_cover_set_entry(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(stage.join("cover.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── cover set: the auto-take hook (phase A3) ─────────────────────────

    #[test]
    fn cover_set_entry_in_draft_mode_mints_an_auto_take_on_a_real_change() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-autotake-fires");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();
        let img = root.join("elsewhere.png");
        std::fs::write(&img, b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Draft,
            song: Some("moonlight".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_cover_set_entry(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(out.data.as_ref().unwrap()["take"], 1);
        assert!(out.changed.iter().any(|c| c.ends_with("takes/0001.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("takes/head.json")));

        let record = aoide_storage::takes::load_take("moonlight", "neon-night", 1).unwrap();
        assert_eq!(record.cause, "cover-set");
        assert!(record.cover.is_some(), "the cover that was just set is carried on the take");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_entry_in_draft_mode_mints_again_on_a_content_identical_reset() {
        // The pinned invariant (orchestrator correction over this step's own
        // earlier draft): a take records EVERY write, not just the ones that
        // changed something. Setting the SAME cover twice in a row produces
        // byte-identical content to what take 1 already holds — it must
        // STILL mint a second take. Suppressing on no drift would make the
        // take tree an incomplete record of write events; the resulting
        // duplicate-take noise is `rice take prune`'s problem (phase A9),
        // not this hook's.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-autotake-repeat");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();
        let img = root.join("elsewhere.png");
        std::fs::write(&img, b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Draft,
            song: Some("moonlight".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let first = handle_cover_set_entry(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(first.status, Status::Ok, "{:?}", first.data);
        assert_eq!(first.data.unwrap()["take"], 1);

        let second = handle_cover_set_entry(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(second.status, Status::Ok, "{:?}", second.data);
        assert_eq!(
            second.data.unwrap()["take"], 2,
            "a content-identical cover reset still mints its own take"
        );
        assert!(second.changed.iter().any(|c| c.ends_with("takes/0002.json")));

        let record = aoide_storage::takes::load_take("moonlight", "neon-night", 2).unwrap();
        assert_eq!(record.parent, Some(1), "the second take hangs off the first");
        assert_eq!(
            aoide_storage::takes::list_takes("moonlight", "neon-night").len(),
            2,
            "both writes are on record, even though their content is identical"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
