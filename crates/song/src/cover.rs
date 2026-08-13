//! Cover-art derivation + resolution — the shared logic `cover set` and
//! `rice preview` both need to turn a name/arg into a physical cover file
//! under the shared library `song/covers/`.
//!
//! Moved out of `pkgs/aoide/src/commands/rice.rs` and
//! `pkgs/aoide/src/commands/cover.rs` (Phase 5b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md). Both functions are pure aside from
//! reading `aoide_storage::fs::song_dir()` (env-derived path resolution) and
//! stat-ing candidate files — no writes, no `Outcome`/`Invocation`.

use std::path::PathBuf;

/// Extensions we recognise as cover art, in preference order.
pub const COVER_EXTS: &[&str] = &["webp", "png", "jpg", "jpeg"];

/// Derive a physical cover-art file for a song, or `None` when none exists.
///
/// v0 notes carry no runtime cover field (the schema is palette-closed; the
/// build-time `aoide.livery.wallpaper` is a nix path, not a song/ runtime read),
/// so a cover is only ever staged when one is physically present. Covers live
/// in the shared library `song/covers/` — one dir any song (or other consumer)
/// draws from — so the derivable name is `<name>.<ext>` there (a bare
/// `cover.<ext>` would be ambiguous in a shared dir).
pub fn derive_cover(name: &str) -> Option<PathBuf> {
    let covers = aoide_storage::fs::song_dir().join("covers");
    for ext in COVER_EXTS {
        let p = covers.join(format!("{name}.{ext}"));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Resolve a `cover set <path|name>` argument to an absolute cover path.
///
/// An absolute `arg` is taken literally; anything else resolves against the
/// shared cover library `song/covers/`. Does NOT check existence — the caller
/// (`handle_cover_set`) does that so it can render its own "no such file"
/// error with the resolved path in it.
pub fn resolve_cover_arg(arg: &str) -> PathBuf {
    let literal = PathBuf::from(arg);
    if literal.is_absolute() {
        literal
    } else {
        aoide_storage::fs::song_dir().join("covers").join(arg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cover_arg_takes_an_absolute_path_literally() {
        let resolved = resolve_cover_arg("/tmp/somewhere/cover.png");
        assert_eq!(resolved, PathBuf::from("/tmp/somewhere/cover.png"));
    }

    #[test]
    fn resolve_cover_arg_resolves_a_bare_name_against_the_covers_library() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        std::env::set_var("AOIDE_STAGE_DIR", "/tmp/aoide-cover-test/stage");

        let resolved = resolve_cover_arg("sonata.webp");
        assert_eq!(
            resolved,
            PathBuf::from("/tmp/aoide-cover-test/covers/sonata.webp")
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn derive_cover_finds_the_first_matching_extension_or_none() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let root =
            std::env::temp_dir().join(format!("aoide-song-derive-cover-{}", std::process::id()));
        let stage = root.join("stage");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(covers.join("dusk.png"), b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        assert_eq!(derive_cover("dusk"), Some(covers.join("dusk.png")));
        assert_eq!(derive_cover("nope"), None);

        let _ = std::fs::remove_dir_all(&root);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }
}
