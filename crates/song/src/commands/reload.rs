//! `lyra reload` — the one mode-aware iteration command of the agent rice
//! loop (design settled by the User, 2026-08-31: edit → `lyra reload` →
//! look, no separate save, no separate sync, no tree-direction trap). Reads
//! `stage/mode.json` (the authority) and dispatches:
//!
//! - **declarative** — SHELL RELOAD ONLY, byte-for-byte the old `quickshell
//!   reload` command ([`shell_reload_only`]), which this command absorbs
//!   outright — hard cutover, no alias, the `node invite` precedent. Nothing
//!   is unlocked, so there is nothing to snapshot or sync.
//! - **staging** — 1. sync via [`super::rice::handle_rice_stage`]'s own body
//!   (the existing seam, never a copy: re-derives `stage/livery.json` from
//!   the committed songbook, syncs widget bodies + the widget-type registry
//!   into `run/qml`, best-effort hyprctl); 2. snapshot the now-synced stage
//!   + widget bodies as a take, deduped against the head
//!   (`commands/take.rs`'s `snapshot_if_identical_to_head`, hanging off
//!   `songbook/<song>/takes/`); 3. shell reload.
//! - **draft** — the same shape, but [`sync_draft_in_place`] stands in for
//!   `handle_rice_stage`: `stage/livery.json` is ALREADY the draft's own
//!   live content via its routing symlink (`commands/mode.rs`'s own doc —
//!   every writer, including a hand-edit, lands straight in the draft), so
//!   re-deriving it from the COMMITTED songbook the way `handle_rice_stage`
//!   does would silently clobber the very edits draft mode exists to hold,
//!   on every single reload. Draft's sync instead applies the SAME
//!   live-apply + widget/registry-sync tail (`crate::live`/`crate::widgets`,
//!   the identical primitives `handle_rice_stage` itself calls) against the
//!   CURRENT staged content, touching `stage/livery.json` not at all. The
//!   take hangs off the routed draft (`songbook/<song>/drafts/<name>/takes/`,
//!   where takes already live). Widget bodies are SONG-scoped, not
//!   draft-scoped (a draft forks the dress — livery+cover — never the
//!   widgets), so a widget edit under draft mode mutates every draft's view
//!   alike.
//!
//! **Sync runs BEFORE snapshot in both arms** — not the order the beats are
//! numbered in casual description, but load-bearing for dedupe-against-head:
//! `handle_rice_stage`'s own write is a pure, deterministic function of the
//! committed songbook (same input, same "song"-field-injected output, every
//! call), so a snapshot taken AFTER it settles into a STABLE value across
//! repeated no-op reloads — a snapshot taken BEFORE it would instead capture
//! that injection itself as "drift" on every single call, defeating dedupe
//! entirely for Staging. Still strictly before the shell reload (beat 3),
//! which is all `rice back`'s reversibility promise ever needed.
//!
//! Snapshot-before-reload makes every iteration reversible via `rice back`
//! for free — the agent loop's undo comes with the verb the agent already
//! runs.

use aoide_protocol::Invocation;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::registry::{cmd, Registry};
use aoide_storage::mode::{self, RiceMode};
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["reload"],
        summary: "The one mode-aware iteration command: reads the rice mode and reloads accordingly. Declarative shell-reloads only (byte for byte the old `quickshell reload`, which this absorbed). Staging/draft snapshot the current rice — deduped against the head take, so an unchanged reload mints nothing — sync it (`rice stage`'s own body), then shell-reload. Snapshot-before-reload makes every dress iteration revertible via `rice back` for free (widget bodies are captured in the take but revert via git, their own substrate).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_reload,
    ));
}

fn handle_reload(inv: &Invocation) -> Outcome {
    let marker = mode::load_mode_marker();
    match marker.mode {
        RiceMode::Declarative => shell_reload_only(),
        RiceMode::Staging | RiceMode::Draft => reload_staging_or_draft(inv, marker),
    }
}

/// The declarative arm — byte-for-byte [`crate::commands::quickshell`]'s old
/// `handle_quickshell_reload`: best-effort, always `Outcome::ok` regardless
/// of whether the IPC call actually reached a live instance. Nothing is
/// unlocked to save in this mode, so this is the WHOLE arm — no sync, no
/// snapshot (the measure is closed).
fn shell_reload_only() -> Outcome {
    let status = crate::ipc::quickshell_ipc_reload();
    Outcome::ok("reload", status.message()).with_data(json!({ "status": status.tag() }))
}

/// The staging/draft arm: sync → snapshot (deduped) → shell reload — see
/// the module doc for why sync runs FIRST. Resolves "the current rice" off
/// the mode marker's own `song` field — populated in both `Staging` and
/// `Draft` (`aoide_storage::mode::ModeMarker`'s own doc) — never re-guesses
/// it a second way.
fn reload_staging_or_draft(inv: &Invocation, marker: mode::ModeMarker) -> Outcome {
    let Some(song) = marker.song.clone() else {
        return Outcome::error(
            "reload",
            "no rice currently staged or drafted — nothing to reload \
             (`aoide rice mode stage` or `aoide rice mode draft <name>` first)",
        )
        .with_data(json!({ "reason": "not-staged-or-drafted" }));
    };
    let draft = marker.draft.as_deref();

    // Beat "sync": Staging re-derives declared content from the committed
    // songbook via `handle_rice_stage`'s own body (the existing seam, never
    // a copy). Draft applies the same live-apply + widget/registry-sync
    // tail WITHOUT touching `stage/livery.json` — see the module doc for why
    // that split is load-bearing, not cosmetic.
    let mut synced = match draft {
        None => super::rice::handle_rice_stage(&Invocation {
            path: vec!["rice".to_string(), "stage".to_string()],
            args: vec![song.clone()],
            flags: inv.flags.clone(),
            door: inv.door,
        }),
        Some(_) => sync_draft_in_place(&song),
    };
    if synced.status != Status::Ok {
        synced.command = "reload".to_string();
        return synced;
    }
    let mut changed = synced.changed.clone();

    // Beat "snapshot": the now-synced stage + widget bodies, deduped against
    // the head — `commands/take.rs`'s own dedupe core (the User's own
    // settled rule, 2026-08-31), reused verbatim rather than reimplemented
    // here.
    let take_data = match super::take::snapshot_if_identical_to_head("reload", "reload") {
        Ok(Some(record)) => {
            changed.push(
                aoide_storage::takes::take_path(&song, draft, record.take)
                    .to_string_lossy()
                    .into_owned(),
            );
            changed.push(
                aoide_storage::takes::head_path(&song, draft)
                    .to_string_lossy()
                    .into_owned(),
            );
            json!({ "take": record.take, "deduped": false })
        }
        Ok(None) => json!({ "take": Value::Null, "deduped": true }),
        Err(err) => json!({ "take": Value::Null, "takeError": err.message }),
    };

    // Beat "reload": shell reload — unconditional, the same call the
    // declarative arm makes. Staging's own `handle_rice_stage` call above
    // already fires its OWN IPC reload internally, but only when widget
    // bodies changed (its bandwidth-saving optimization for its OTHER
    // callers, `rice stage <name>` run standalone — `commands/rice.rs`'s own
    // doc). `lyra reload` means "show me the current state now", so this
    // beat always runs regardless of what that internal call already
    // attempted — a second IPC reload is a harmless no-op, never a
    // correctness problem (`quickshell_ipc_reload` is idempotent by
    // construction, `ipc.rs`'s own doc).
    let status = crate::ipc::quickshell_ipc_reload();

    Outcome::ok(
        "reload",
        format!(
            "reloaded `{song}` ({}) — {}",
            super::mode::mode_word(marker.mode),
            status.message()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "mode": super::mode::mode_word(marker.mode),
        "song": song,
        "draft": marker.draft,
        "take": take_data,
        "sync": synced.data,
        "reload": { "status": status.tag(), "message": status.message() },
    }))
}

/// Draft mode's own "sync" beat: apply hyprctl geometry/border keywords
/// (derived from the CURRENT staged livery — already the draft's own
/// content via its routing symlink) and sync widget bodies + the
/// widget-type registry into `run/qml` — the SAME primitives
/// [`super::rice::handle_rice_stage`] itself calls (`crate::live`/
/// `crate::widgets`), minus the "read the committed songbook and (re)write
/// `stage/livery.json`" step that function opens with. That step is
/// Staging-only: see this module's own doc for why reusing it here would
/// clobber the draft.
fn sync_draft_in_place(song: &str) -> Outcome {
    let stage = aoide_storage::fs::stage_dir();
    let livery_path = stage.join("livery.json");
    let raw = match std::fs::read_to_string(&livery_path) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(
                "reload",
                format!("nothing staged to reload: cannot read {} ({e})", livery_path.display()),
            )
            .with_data(json!({ "reason": "no-staged-livery", "expected": livery_path.to_string_lossy() }));
        }
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error("reload", format!("staged livery.json is not valid JSON: {e}"))
                .with_data(json!({ "reason": "invalid-json", "livery": livery_path.to_string_lossy() }));
        }
    };

    let hyprctl_status = crate::live::apply_live(&crate::live::geometry_keywords(&parsed));

    let widget_sync = match crate::widgets::sync_song_widgets(song) {
        Ok(sync) => sync,
        Err(e) => {
            return Outcome::error("reload", format!("failed to sync widget bodies: {}", e.error))
                .with_data(json!({ "reason": "widget-sync-failed", "target": e.target }));
        }
    };
    let registry_sync = match crate::widgets::sync_song_registry(song) {
        Ok(sync) => sync,
        Err(e) => {
            return Outcome::error("reload", format!("failed to sync widget-type registry: {}", e.error))
                .with_data(json!({ "reason": "registry-sync-failed", "target": e.target }));
        }
    };

    let mut changed = widget_sync.changed.clone();
    changed.extend(registry_sync.changed.clone());

    Outcome::ok("reload", format!("synced `{song}`'s draft in place — {}", widget_sync.note))
        .changed(changed)
        .with_data(json!({
            "hyprctl": hyprctl_status,
            "widgets": widget_sync.note,
            "registry": registry_sync.note,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_storage::fs as shellbridge;
    use aoide_storage::mode::{save_mode_marker, ModeMarker};
    use aoide_test_support::*;

    const VALID_NOTES: &str = r##"{"schemaVersion":"0","palette":{"bg":"#000000"}}"##;

    fn reload_inv() -> Invocation {
        aoide_test_support::inv(&["reload"], &[])
    }

    /// Declarative is the safe default (no marker file at all IS
    /// declarative) — always `Ok`, whatever the live IPC attempt actually
    /// resolved to (`not-running`/`failed`/`reloaded` are reported facts,
    /// same posture the old `quickshell reload` command had). Deliberately
    /// doesn't assert WHICH tag: that depends on whether
    /// `aoide-quickshell.service` happens to be live on the machine running
    /// this test.
    #[test]
    fn declarative_mode_is_shell_reload_only_and_always_ok() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("reload-declarative");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_reload(&reload_inv());
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.command, "reload");
        let data = out.data.unwrap();
        assert!(data["status"].is_string(), "{data:?}");
        assert!(data.get("mode").is_none(), "declarative arm carries no mode/song/take payload");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Mode dispatch is pure off `mode.json` — this is the "declarative
    /// refuses to snapshot/sync" half of that dispatch made concrete: no
    /// `songbook/<song>/takes/` directory is ever created for a declarative
    /// reload, because the declarative arm never calls the snapshot core at
    /// all.
    #[test]
    fn declarative_mode_never_mints_a_take() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("reload-declarative-no-take");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Declarative,
            song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();

        handle_reload(&reload_inv());
        assert!(
            !aoide_storage::takes::takes_dir("sonata", None).is_dir(),
            "declarative reload must never create a takes/ directory"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Staging routing: a reload while staged mints its take under
    /// `songbook/<song>/takes/` — the sibling-of-`drafts/` root, never
    /// nested under a draft that doesn't exist in this mode — and syncs +
    /// reloads successfully.
    #[test]
    fn staging_mode_reload_takes_off_the_song_and_succeeds() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let root = unique_tmp("reload-staging-routing");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let songbook = shellbridge::songbook_dir("sonata");
        std::fs::create_dir_all(&songbook).unwrap();
        std::fs::write(songbook.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Staging,
            song: Some("sonata".to_string()),
            staging_song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_reload(&reload_inv());
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(out.data.as_ref().unwrap()["take"]["deduped"], false);
        assert_eq!(out.data.as_ref().unwrap()["take"]["take"], 1);

        let record = aoide_storage::takes::load_take("sonata", None, 1)
            .expect("take 1 lives under songbook/sonata/takes/, not a draft");
        assert_eq!(record.cause, "reload");
        assert!(
            !shellbridge::song_drafts_dir("sonata").join("takes").is_dir(),
            "a staging-mode take must never be nested under drafts/"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Dedupe against head: a second reload with no intervening edit mints
    /// nothing, reusing `take diff`'s own key-wise machinery
    /// (`snapshot_if_identical_to_head`) rather than a text comparison — the
    /// User's own settled rule, 2026-08-31.
    #[test]
    fn staging_mode_reload_dedupes_against_an_unchanged_head() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let root = unique_tmp("reload-staging-dedupe");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let songbook = shellbridge::songbook_dir("sonata");
        std::fs::create_dir_all(&songbook).unwrap();
        std::fs::write(songbook.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Staging,
            song: Some("sonata".to_string()),
            staging_song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();

        let first = handle_reload(&reload_inv());
        assert_eq!(first.status, Status::Ok, "{:?}", first.data);
        assert_eq!(first.data.as_ref().unwrap()["take"]["take"], 1);

        let second = handle_reload(&reload_inv());
        assert_eq!(second.status, Status::Ok, "{:?}", second.data);
        assert_eq!(second.data.as_ref().unwrap()["take"]["deduped"], true, "{:?}", second.data);
        assert_eq!(
            aoide_storage::takes::list_takes("sonata", None).len(),
            1,
            "an unchanged second reload must not mint a second take"
        );

        // Changing the SONGBOOK (the real staging-mode edit target — sync
        // re-derives `stage/livery.json` from it every call, so editing the
        // stage directly would just be clobbered straight back by the next
        // sync) is real drift — the third reload must mint again, proving
        // the dedupe compares content, not "reload was called before".
        std::fs::write(
            songbook.join("livery.json"),
            r##"{"schemaVersion":"0","palette":{"bg":"#111111"}}"##,
        )
        .unwrap();
        let third = handle_reload(&reload_inv());
        assert_eq!(third.status, Status::Ok, "{:?}", third.data);
        assert_eq!(third.data.as_ref().unwrap()["take"]["deduped"], false, "{:?}", third.data);
        assert_eq!(aoide_storage::takes::list_takes("sonata", None).len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Draft routing: a reload while drafted mints its take off the DRAFT,
    /// not the song root — the two scopes never collide.
    ///
    /// The regression this guards: an earlier version of this command's
    /// draft-mode sync called `handle_rice_stage` directly — the SAME
    /// function the staging arm uses, which reads the COMMITTED songbook
    /// and writes it into `stage/livery.json`. While routed into a draft,
    /// that path is a SYMLINK into the draft file (`commands/mode.rs`'s own
    /// doc), so `atomic_write`'s symlink transparency means that write would
    /// land straight in the draft — silently clobbering it back to plain
    /// declared content on every single reload. This test routes a REAL
    /// symlink (mirroring `rice mode draft`'s own mechanism) and gives the
    /// committed songbook DIFFERENT content from the draft, so a clobber
    /// would be caught immediately: the draft's own content must survive.
    #[test]
    fn draft_mode_reload_takes_off_the_draft_and_never_clobbers_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        let root = unique_tmp("reload-draft-routing");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let songbook = shellbridge::songbook_dir("sonata");
        std::fs::create_dir_all(&songbook).unwrap();
        // Deliberately DIFFERENT from the draft's own content below — the
        // committed truth a clobber would silently overwrite the draft with.
        std::fs::write(songbook.join("livery.json"), VALID_NOTES).unwrap();

        let draft_dir = shellbridge::draft_dir("sonata", "neon-night");
        std::fs::create_dir_all(&draft_dir).unwrap();
        const DRAFT_NOTES: &str = r##"{"schemaVersion":"0","palette":{"bg":"#abcdef"}}"##;
        std::fs::write(draft_dir.join("livery.json"), DRAFT_NOTES).unwrap();

        let stage_livery = stage.join("livery.json");
        let _ = std::fs::remove_file(&stage_livery);
        std::os::unix::fs::symlink(draft_dir.join("livery.json"), &stage_livery).unwrap();

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Draft,
            song: Some("sonata".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_reload(&reload_inv());
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(out.data.as_ref().unwrap()["take"]["take"], 1);

        let record = aoide_storage::takes::load_take("sonata", Some("neon-night"), 1)
            .expect("the take lives under the draft");
        assert_eq!(
            record.livery,
            serde_json::from_str::<serde_json::Value>(DRAFT_NOTES).unwrap(),
            "the captured take is the DRAFT's content, not the songbook's"
        );
        assert!(
            aoide_storage::takes::list_takes("sonata", None).is_empty(),
            "and NOT under the song's own staging-mode takes/ root"
        );

        let after = std::fs::read_to_string(&stage_livery).unwrap();
        assert_eq!(
            after, DRAFT_NOTES,
            "reload must never overwrite the draft's own live content with the committed songbook"
        );
        assert!(
            std::fs::symlink_metadata(&stage_livery).unwrap().file_type().is_symlink(),
            "the routing symlink itself must survive a reload untouched"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
