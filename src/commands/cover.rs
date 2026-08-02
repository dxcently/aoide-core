//! `cover set` — the live wallpaper write-path (song/covers/).

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, Registry};
use crate::shellbridge;
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["cover", "set"],
        summary: "Set the live wallpaper: stage stage/cover.json (hot-swap) from a cover path or a bare name in song/covers/.",
        args: [arg!("path", "string", true, "Absolute cover path, or a bare filename resolved against song/covers/.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_cover_set,
    ));
}

/// `cover set <path>` — switch the live wallpaper by staging a new cover.
///
/// This is the WRITE path the Quickshell wallpaper picker shells out to (QML has
/// no file-write primitive). It resolves `<path>` to an absolute cover file, then
/// atomic-writes `{ "path": "<abs>" }` to `<stage>/cover.json` — exactly the seam
/// `rice preview` uses, which `AoideWallpaper.qml`'s FileView watches and
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
    let resolved = aoide_song::cover::resolve_cover_arg(&arg);

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

    // Stage cover.json exactly like `rice preview`: pretty `{ "path": … }`
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
    use crate::commands::test_support::*;
    use crate::output::Status;

    #[test]
    fn cover_set_stages_an_absolute_path() {
        let _g = crate::env_lock().lock().unwrap();
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
        assert!(cover.ends_with("\n"), "trailing newline mirrors rice preview");
        assert!(out.changed.iter().any(|c| c.ends_with("cover.json")));
        assert_eq!(
            out.data.unwrap()["cover"].as_str().unwrap(),
            img.to_string_lossy()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_resolves_a_bare_name_against_the_covers_library() {
        let _g = crate::env_lock().lock().unwrap();
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
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-missing");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &["nope.png"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "cover-not-found");
        // Nothing was staged for a missing file.
        assert!(!stage.join("cover.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_missing_arg_is_usage_exit_2() {
        let out = handle_cover_set(&inv(&["cover", "set"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
    }
}
