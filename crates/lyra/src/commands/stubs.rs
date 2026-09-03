//! Metadata-only registration for lyra's one remaining walking-skeleton stub
//! command, `rice transpose`, plus `rice declare`'s real handler — the two
//! sat together as `register_rice_late` (P-A4 plan, same relative position
//! core's `commands/mod.rs::all()` gave them) before `declare` graduated
//! (L-C2, task #107): its arg parsing/schema were already real, only the
//! live-system action was missing, and that action is now just the
//! composed-song copy step below. `dispatch()` still short-circuits any
//! `implemented == false` command before reaching a handler, so
//! `rice transpose` alone still shares the placeholder.
//!
//! Only `rice declare`/`rice transpose` sit in lyra (P-A4 plan) — the
//! `content`/`make`/`update`/`onboard` stub groups in `aoide-cli`'s own
//! `commands/stubs.rs` are core identity and stay there untouched.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, Registry};
use serde_json::json;

/// Never invoked — `dispatch()` returns the not-implemented envelope itself
/// for any command with `implemented: false`, without calling `handler`.
fn unimplemented(_inv: &Invocation) -> Outcome {
    unreachable!("dispatch() never calls the handler of a not-implemented command")
}

/// `rice declare` / `rice transpose` — sit after `cover set`/`livery` in the
/// historical order (same relative position core's `commands/mod.rs::all()`
/// gives them).
pub fn register_rice_late(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "declare"],
        summary: "Copy a composed song from $AOIDE_ROOT/songbook/<name> into the checkout's song/songbook/<name>, so it can be committed. The gated rebuild itself is the user's own git commit + nix switch, never this command.",
        args: [arg!("name", "string", true, "Rice/song name to declare.")],
        flags: [],
        gated: true,
        implemented: true,
        handler: handle_rice_declare,
        examples: ["rice declare moonlight"],
    ));
    r.insert(cmd!(
        path: ["rice", "transpose"],
        summary: "Replay a song in another key (palette) from the song's songbook/<song>/palette/.",
        args: [
            arg!("rice", "string", true, "Source song name."),
            arg!("palette", "string", true, "Key/palette name to transpose into."),
        ],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
}

/// `rice declare <name>` — the copy half of the stage-vs-commit split (house
/// rule 2: the user gates the rebuild, never this command). Copies the
/// composed song `$AOIDE_ROOT/songbook/<name>/` into the checkout's
/// `song/songbook/<name>/` (`aoide_storage::fs::flake_root()`,
/// `$AOIDE_FLAKE_ROOT` override, default `<home>/Aoide`) — composing lives
/// in the runtime root, committing lives in the checkout git tracks, and
/// this is the seam between them. Nothing beyond the copy: no `git add`, no
/// rebuild proposal, no `nix eval` — those stay the user's own
/// git/rebuild-gate steps. Overwrites only files whose bytes actually
/// differ (never touches a byte-identical destination file), so a repeat
/// declare with nothing new is a true no-op.
fn handle_rice_declare(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage("rice.declare", "usage: aoide rice declare <name> [--json]")
                .with_data(json!({ "reason": "missing-name" }));
        }
    };

    // Review fix (different-Sonnet pass on 07a42a0): `name` is joined
    // unsanitized into both `songbook_dir` (the runtime root) and the
    // checkout's `song/songbook/` below — without this check a `..`-shaped
    // name escapes both roots (arbitrary read from `src`, arbitrary write
    // to `dst`). Same validator `rice compose`/`rice mode` already gate on
    // (`aoide_song::compose::valid_song_name`,
    // `^[a-z0-9][a-z0-9-]*$` — rejects `..`/`/` by construction), checked
    // BEFORE either path is built, not after.
    if !aoide_song::compose::valid_song_name(&name) {
        return Outcome::error(
            "rice.declare",
            format!(
                "`{name}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }

    let src = aoide_storage::fs::songbook_dir(&name);
    if !src.is_dir() {
        return Outcome::error(
            "rice.declare",
            format!(
                "no composed song named `{name}` at {} — run `lyra rice compose {name}` first",
                src.display()
            ),
        )
        .with_data(json!({ "reason": "no-composed-song", "name": name, "expected": src.to_string_lossy() }));
    }

    let checkout = aoide_storage::fs::flake_root();
    if !checkout.is_dir() {
        return Outcome::error(
            "rice.declare",
            format!(
                "no Aoide checkout at {} ($AOIDE_FLAKE_ROOT override, default `<home>/Aoide`) — \
                 `rice declare` commits into the checkout's `song/songbook/`, so a checkout must exist first",
                checkout.display()
            ),
        )
        .with_data(json!({ "reason": "no-checkout", "expected": checkout.to_string_lossy() }));
    }

    let dst = checkout.join("song").join("songbook").join(&name);
    let mut changed = Vec::new();
    if let Err(e) = copy_song_tree(&src, &dst, &mut changed) {
        return Outcome::error(
            "rice.declare",
            format!("copying {} into {} failed: {e}", src.display(), dst.display()),
        )
        .with_data(json!({ "reason": "copy-failed", "name": name }));
    }

    let message = if changed.is_empty() {
        format!("`{name}` already matches {} — nothing to copy", dst.display())
    } else {
        format!("copied {} file(s) into {}", changed.len(), dst.display())
    };
    Outcome::ok("rice.declare", message)
        .gated(true)
        .changed(changed)
        .with_data(json!({ "name": name, "checkout": dst.to_string_lossy() }))
}

/// Recursively copy `src` into `dst`, unfiltered — mirrors `aoide-song`'s
/// own `widgets.rs::copy_tree_atomic` shape (a destination file whose bytes
/// already match the source is left untouched, and not counted as changed);
/// a separate, dozen-line copy rather than a shared helper since that
/// function is private to its own module and this crate does not otherwise
/// depend on it.
fn copy_song_tree(
    src: &std::path::Path,
    dst: &std::path::Path,
    changed: &mut Vec<String>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_song_tree(&entry.path(), &dst_path, changed)?;
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        if std::fs::read(&dst_path).map(|existing| existing == bytes).unwrap_or(false) {
            continue;
        }
        aoide_storage::fs::atomic_write_bytes(&dst_path, &bytes)?;
        changed.push(dst_path.to_string_lossy().into_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::{env_lock, unique_tmp, EnvSaver};

    fn inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["rice".into(), "declare".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        }
    }

    #[test]
    fn missing_name_is_usage() {
        let out = handle_rice_declare(&inv(&[]));
        assert_eq!(out.status, crate::output::Status::Usage);
    }

    /// Review fix (different-Sonnet pass on 07a42a0): a traversal-shaped
    /// name must be refused BEFORE it ever reaches `songbook_dir`/the
    /// checkout join — same pattern `song/src/commands/mode.rs`'s
    /// `current_staged_song_rejects_a_hand_edited_path_traversal_song_field`
    /// pins for the sibling stage-file case. No env override needed: the
    /// name check runs before any path is even built.
    #[test]
    fn path_traversal_shaped_name_is_refused_before_any_path_is_built() {
        let out = handle_rice_declare(&inv(&["../../evil"]));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "invalid-name");
    }

    #[test]
    fn no_composed_song_is_a_taught_error() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_FLAKE_ROOT"]);
        let stage_root = unique_tmp("declare-nosong");
        std::env::set_var("AOIDE_STAGE_DIR", stage_root.join("song").join("stage"));
        std::env::set_var("AOIDE_FLAKE_ROOT", unique_tmp("declare-nosong-checkout"));

        let out = handle_rice_declare(&inv(&["nope"]));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "no-composed-song");

        let _ = std::fs::remove_dir_all(&stage_root);
    }

    #[test]
    fn no_checkout_is_a_taught_error() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_FLAKE_ROOT"]);
        let stage_root = unique_tmp("declare-nocheckout");
        std::env::set_var("AOIDE_STAGE_DIR", stage_root.join("song").join("stage"));
        let songbook = stage_root.join("song").join("songbook").join("dusk");
        std::fs::create_dir_all(&songbook).unwrap();
        std::fs::write(songbook.join("livery.json"), "{}").unwrap();
        let missing_checkout = unique_tmp("declare-nocheckout-missing");
        std::fs::remove_dir_all(&missing_checkout).unwrap(); // unique_tmp creates it; this test wants it ABSENT
        std::env::set_var("AOIDE_FLAKE_ROOT", &missing_checkout);

        let out = handle_rice_declare(&inv(&["dusk"]));
        assert_eq!(out.status, crate::output::Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "no-checkout");

        let _ = std::fs::remove_dir_all(&stage_root);
    }

    #[test]
    fn copies_the_composed_song_into_the_checkout_and_is_idempotent() {
        let _g = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_FLAKE_ROOT"]);
        let stage_root = unique_tmp("declare-copy");
        std::env::set_var("AOIDE_STAGE_DIR", stage_root.join("song").join("stage"));
        let songbook = stage_root.join("song").join("songbook").join("dusk");
        std::fs::create_dir_all(songbook.join("widgets")).unwrap();
        std::fs::write(songbook.join("livery.json"), "{\"a\":1}").unwrap();
        std::fs::write(songbook.join("widgets").join(".gitkeep"), "").unwrap();

        let checkout = unique_tmp("declare-copy-checkout");
        std::env::set_var("AOIDE_FLAKE_ROOT", &checkout);

        let out = handle_rice_declare(&inv(&["dusk"]));
        assert_eq!(out.status, crate::output::Status::Ok, "{out:?}");
        assert!(out.gated, "rice.declare stays gated metadata");
        let dst = checkout.join("song").join("songbook").join("dusk");
        assert_eq!(std::fs::read_to_string(dst.join("livery.json")).unwrap(), "{\"a\":1}");
        assert!(dst.join("widgets").join(".gitkeep").exists());
        assert_eq!(out.changed.len(), 2);

        // Re-declaring with nothing new copies nothing — byte-identical
        // files are left untouched.
        let out2 = handle_rice_declare(&inv(&["dusk"]));
        assert_eq!(out2.status, crate::output::Status::Ok);
        assert!(out2.changed.is_empty(), "byte-identical re-declare copies nothing");

        let _ = std::fs::remove_dir_all(&stage_root);
        let _ = std::fs::remove_dir_all(&checkout);
    }
}
