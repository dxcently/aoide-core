//! `rice mode {status,stage,declarative,draft}` — the staging/declarative/
//! draft mode toggle around `stage/mode.json` (concepts/Self-Ricing's
//! mode-toggle extension, khoa 2026-08-14; three-way `RiceMode` + symlink
//! draft routing, khoa 2026-08-14).
//!
//! Three modes, not two:
//!
//! - **`declarative`** — the safe default (no marker file at all reads as
//!   declarative — [`aoide_storage::mode::load_mode_marker`]). The direct
//!   CLI entrypoints for `rice stage` and `cover set` refuse (their own
//!   `handle_rice_stage_entry`/`handle_cover_set_entry` guards,
//!   `commands/rice.rs` and `commands/cover.rs`) — nothing else in this
//!   codebase writes `stage/livery.json`/`stage/cover.json`, so refusing
//!   those two entrypoints is sufficient to guarantee nothing drifts while
//!   locked; no background reconciler process exists (`aoided` is still a
//!   one-shot skeleton, `crates/server/src/daemon.rs`) and none is needed
//!   for that guarantee to hold.
//! - **`staging`** — `rice stage`/`cover set` write live, always meaning
//!   plain declared content.
//! - **`draft`** — `stage/livery.json` is a SYMLINK into a saved
//!   `songbook/<song>/drafts/<name>/livery.json` ([`handle_mode_draft`]).
//!   Every writer of the stage file — `rice stage`, a hand-edit,
//!   Quickshell's own FileView reload — transparently lands in the draft,
//!   because [`aoide_storage::fs::atomic_write`] resolves and writes through
//!   a symlink at its destination rather than replacing it. This is
//!   ROUTING, not guessing: `rice stage`/`rice mode stage` carry ZERO
//!   draft-awareness and never auto-prefer or auto-detect one — reaching a
//!   draft at all only ever happens through `rice mode draft <name>`.
//!
//! `stage`/`declarative` both reuse [`super::rice::handle_rice_stage`]
//! directly (guard-free, `pub(crate)`) when a song name is given — the SAME
//! side effects a bare `rice stage <name>` has — so `declarative <name>` can
//! re-pin `stage/livery.json` to that song's committed notes and lock it in
//! one step, even from the default (unmarked) declarative state, without
//! tripping its own guard (the marker isn't flipped until AFTER the write
//! succeeds).
//!
//! `rice mode stage` never leaves a bare flag-flip: with no name it resolves
//! "the current rice" off the existing `stage/livery.json`'s own `"song"`
//! field ([`current_staged_song`]) and stages that, so unlocking staging
//! always ALSO enables hot loading of whatever is presently active — only a
//! genuinely fresh box with no stage file yet falls back to a no-op unlock.
//!
//! **Leaving `Draft` mode:** both [`handle_mode_stage`] and
//! [`handle_mode_declarative`] call [`teardown_draft_symlink`] — removing
//! any routing symlink currently at `stage/livery.json` — BEFORE they write
//! plain declared content, so that write lands in a real file rather than
//! transparently through into whatever draft the symlink still pointed at.
//! Neither leaves a dangling symlink behind when transitioning out of
//! `Draft`.

use aoide_protocol::Invocation;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::registry::{arg, cmd, Registry};
use aoide_storage::fs as shellbridge;
use aoide_storage::mode::{load_mode_marker, mode_marker_path, save_mode_marker, ModeMarker, RiceMode};
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "mode", "status"],
        summary: "Report the current rice mode (staging, declarative, or draft) and, in staging/draft, which song (and draft) it's pointed at.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_status,
    ));
    r.insert(cmd!(
        path: ["rice", "mode", "stage"],
        summary: "Unlock staging and enable hot loading now — ALWAYS plain declared content: stages <name> if given, else re-stages whatever rice is currently live. Leaves `Draft` mode (tearing down its routing symlink) if currently in it. `rice stage`/`cover set` write live again.",
        args: [arg!("name", "string", false, "Song to stage immediately; defaults to the currently staged rice.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_stage,
        examples: [
            "rice mode stage moonlight",
            "rice mode stage",
        ],
    ));
    r.insert(cmd!(
        path: ["rice", "mode", "declarative"],
        summary: "Lock staging: `rice stage`/`cover set` refuse until unlocked again. Optional <name> re-pins stage/livery.json to that song's committed notes first. Leaves `Draft` mode (tearing down its routing symlink) if currently in it.",
        args: [arg!("name", "string", false, "Song to pin stage/livery.json to before locking; omit to lock as-is.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_declarative,
    ));
    r.insert(cmd!(
        path: ["rice", "mode", "draft"],
        summary: "Route stage/livery.json into songbook/<song>/drafts/<name>/livery.json via a symlink — every future write (rice stage, a hand-edit) lands directly in the draft. Forks the draft from the current stage first if it doesn't exist yet. Refuses while `rice mode declarative` is locked.",
        args: [arg!("name", "string", true, "Draft name to route the stage into (forked from the current stage if new).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mode_draft,
        examples: ["rice mode draft neon-night"],
    ));
}

/// `pub(crate)`, not private: `commands/reload.rs` reuses this SAME mapping
/// to report which arm `lyra reload`'s dispatch took, rather than growing a
/// second `RiceMode -> &str` match elsewhere.
pub(crate) fn mode_word(m: RiceMode) -> &'static str {
    match m {
        RiceMode::Staging => "staging",
        RiceMode::Declarative => "declarative",
        RiceMode::Draft => "draft",
    }
}

/// `rice mode status` — read `stage/mode.json` via `aoide-storage` and
/// report it verbatim (absent file reports the `declarative` default, the
/// same tolerate-missing discipline every stage-file marker in this
/// codebase follows — [`aoide_storage::mode::load_mode_marker`]).
fn handle_mode_status(_inv: &Invocation) -> Outcome {
    let m = load_mode_marker();
    Outcome::ok("rice.mode.status", format!("rice mode: {}", mode_word(m.mode))).with_data(json!({
        "mode": mode_word(m.mode),
        "song": m.song,
        "draft": m.draft,
        "since": if m.since.is_empty() { None } else { Some(m.since) },
    }))
}

/// Read the song `stage/livery.json` is CURRENTLY carrying, straight off its
/// own `"song"` field — the same field both `rice stage` (below) and the nix
/// activation's `home.activation.aoideSeedStage` reseed script
/// (`modules/facets/quickshell/default.nix`) write on every stage/every
/// activation. This is how "the current rice" is knowable at all: the Rust
/// side has no nix evaluation access, so the stage file's own breadcrumb is
/// the only source of truth for "what is this host actually performing right
/// now" — reused here rather than re-deriving it some other way. Reads
/// transparently through a `Draft`-mode symlink too (`std::fs::read_to_string`
/// always follows symlinks), same as any other reader.
///
/// `pub(crate)`, not private: `commands/draft.rs` reuses this SAME resolution
/// to know which song's `songbook/<song>/drafts/` `rice draft drop <name>`
/// should nest under, and [`handle_mode_draft`] (below) uses it to know which
/// song to fork a new draft from — no adapter, no second implementation of
/// "what is the current rice".
pub(crate) fn current_staged_song() -> Option<String> {
    let path = shellbridge::stage_dir().join("livery.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    let song = parsed.get("song")?.as_str()?.to_string();
    // The stage file is writable outside this CLI (a hand-edit, a rogue
    // writer) and every caller of this function joins the result straight
    // into a path (`draft_dir(song, name)` in `draft.rs`/`mode.rs`) — same
    // traversal class `rice compose`/`rice stage` guard on the WRITE side;
    // this is the same guard on the READ side, so a poisoned `"song"` field
    // can never resolve to anything at all rather than resolving to
    // something unsafe.
    crate::compose::valid_song_name(&song).then_some(song)
}

/// Remove any `Draft`-mode routing symlink currently at `stage/livery.json`,
/// so a caller about to write plain declared content there
/// ([`super::rice::handle_rice_stage`], via `atomic_write`) creates a REAL
/// file rather than writing straight through into whatever draft the
/// symlink still points at. A no-op when `stage/livery.json` is absent or
/// already a plain file.
///
/// [`handle_mode_stage`] and [`handle_mode_declarative`] both call this
/// AFTER resolving which song is currently active (that resolution itself
/// reads through the symlink via [`current_staged_song`], so tearing it down
/// first would blind a bare no-`<name>` call) but BEFORE writing anything —
/// leaving `Draft` mode must never leave a dangling symlink behind.
fn teardown_draft_symlink() -> std::io::Result<()> {
    let stage_livery = shellbridge::stage_dir().join("livery.json");
    match std::fs::symlink_metadata(&stage_livery) {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::remove_file(&stage_livery),
        _ => Ok(()),
    }
}

/// `rice mode stage [<name>]` — unlock staging writers AND enable hot
/// loading immediately, never a bare flag-flip. With `<name>`, stages that
/// song; with no name, resolves "the current rice" off the existing
/// `stage/livery.json`'s own `"song"` field ([`current_staged_song`]) and
/// stages THAT — so entering staging mode always leaves a live, hot-loadable
/// rice behind it, not just an unlocked marker with a stale/absent stage
/// file. Only when no song can be resolved at all (a genuinely fresh box
/// that has never activated or staged) does this fall back to a bare unlock.
///
/// ALWAYS means plain declared content — zero draft-awareness. If currently
/// in `Draft` mode, this doubles as how you LEAVE it:
/// [`teardown_draft_symlink`] removes the routing symlink before the
/// declared-content write below, so that write lands in a real file rather
/// than transparently through into whatever draft the symlink still pointed
/// at.
///
/// Also sweeps stray processes first ([`crate::reap::reap_stray_processes`])
/// — a leftover `qs -p *Preview.qml` harness, a duplicate `shell.qml`
/// process outside `aoide-quickshell.service`, or a stale `hyprlock` — so
/// unlocking staging always starts from a known-clean slate. Best-effort and
/// never fatal to this command: a sweep that reaps nothing, or fails to
/// enumerate `/proc` at all, still proceeds to stage/unlock normally.
fn handle_mode_stage(inv: &Invocation) -> Outcome {
    let reaped = crate::reap::reap_stray_processes();

    let explicit_name = inv.args.first().cloned();
    let existing = load_mode_marker();
    // Resolution order for a bare (no-arg) call: an explicit name always
    // wins; otherwise prefer the remembered `staging_song` — the durable
    // "what was I staging" memory that a declarative lock leaves untouched —
    // over `current_staged_song()`'s file-read fallback, which reflects
    // whatever's CURRENTLY active and is unreliable here once a declarative
    // round-trip has overwritten it. `current_staged_song()` remains the
    // final fallback only for the cold-start case where `staging_song` has
    // never been set (a fresh `mode.json`, or one predating this field).
    let resolved_name = explicit_name
        .clone()
        .or_else(|| existing.staging_song.clone())
        .or_else(current_staged_song);

    if let Err(e) = teardown_draft_symlink() {
        return Outcome::error("rice.mode.stage", format!("failed to clear draft routing: {e}"))
            .with_data(json!({ "reason": "symlink-teardown-failed" }));
    }

    let mut changed: Vec<String> = Vec::new();
    if let Some(name) = &resolved_name {
        let stage_inv = Invocation {
            path: vec!["rice".to_string(), "stage".to_string()],
            args: vec![name.clone()],
            flags: inv.flags.clone(),
            door: inv.door,
        };
        let mut staged = super::rice::handle_rice_stage(&stage_inv);
        if staged.status != Status::Ok {
            staged.command = "rice.mode.stage".to_string();
            return staged;
        }
        changed = staged.changed;
    }

    // `handle_rice_stage` above (the guard-free, marker-blind sibling of
    // `handle_rice_stage_entry`) never touches `stage/mode.json` itself, so
    // `existing` — loaded before that write, above — is still current; no
    // need to re-read it.
    let marker = ModeMarker {
        mode: RiceMode::Staging,
        song: resolved_name.clone().or(existing.song.clone()),
        draft: None,
        // Remember whatever song staging mode is now on, carrying the old
        // value forward in the (normally unreachable) case this call somehow
        // resolves to nothing at all — same defensive `.or(existing...)`
        // pattern `song` above already follows.
        staging_song: resolved_name.clone().or(existing.staging_song.clone()),
        since: aoide_storage::time::now_iso_utc(),
    };
    if let Err(e) = save_mode_marker(&marker) {
        return Outcome::error("rice.mode.stage", format!("failed to write mode marker: {e}"))
            .changed(changed)
            .with_data(json!({ "reason": "marker-write-failed" }));
    }
    changed.push(mode_marker_path().to_string_lossy().into_owned());

    let reap_note = if reaped.is_empty() {
        String::new()
    } else {
        format!(" — reaped {} stray process(es)", reaped.len())
    };

    Outcome::ok(
        "rice.mode.stage",
        match &resolved_name {
            Some(n) if explicit_name.is_some() => format!("staging mode unlocked — staged `{n}` live{reap_note}"),
            Some(n) => format!("staging mode unlocked — re-staged the current rice `{n}` live{reap_note}"),
            None => format!("staging mode unlocked — no current rice to stage (no stage/livery.json yet){reap_note}"),
        },
    )
    .changed(changed)
    .with_data(json!({
        "mode": "staging",
        "song": marker.song,
        "reaped": reaped.iter().map(|p| json!({
            "pid": p.pid, "reason": p.reason, "cmdline": p.cmdline,
        })).collect::<Vec<_>>(),
    }))
}

/// `rice mode declarative [<name>]` — lock staging writers. With `<name>`,
/// re-pins `stage/livery.json` to that song's committed notes FIRST (via
/// `handle_rice_stage`, guard-free), then writes the marker.
///
/// With NO name, this mirrors [`handle_mode_stage`]'s own no-arg auto-resolve
/// pattern rather than freezing the stage as-is: it resolves "the current
/// rice" off `stage/livery.json`'s own `"song"` field ([`current_staged_song`]),
/// re-pins from THAT song's committed notes, then locks — so `rice mode
/// declarative` with no name discards whatever unsaved live edits sat in the
/// stage, same as the `<name>` path always has (`rice draft save` first to
/// keep them, hence the success message below). Only when no song can be
/// resolved at all (a genuinely fresh box with no stage file yet) does this
/// fall back to a bare lock with nothing to re-pin — the one case where
/// nothing is discarded, because there was nothing live to discard.
///
/// If currently in `Draft` mode, this is also how you leave it: the SAME
/// [`teardown_draft_symlink`] call [`handle_mode_stage`] makes, so the
/// re-pin write below lands in a real file, never through a stale symlink.
///
/// A resolvable song whose re-pin fails returns that error and does NOT flip
/// the marker — same failure handling the `<name>` path already had.
fn handle_mode_declarative(inv: &Invocation) -> Outcome {
    let explicit_name = inv.args.first().cloned();
    let resolved_name = explicit_name.or_else(current_staged_song);

    if let Err(e) = teardown_draft_symlink() {
        return Outcome::error("rice.mode.declarative", format!("failed to clear draft routing: {e}"))
            .with_data(json!({ "reason": "symlink-teardown-failed" }));
    }

    let mut changed: Vec<String> = Vec::new();
    if let Some(name) = &resolved_name {
        let stage_inv = Invocation {
            path: vec!["rice".to_string(), "stage".to_string()],
            args: vec![name.clone()],
            flags: inv.flags.clone(),
            door: inv.door,
        };
        let mut staged = super::rice::handle_rice_stage(&stage_inv);
        if staged.status != Status::Ok {
            staged.command = "rice.mode.declarative".to_string();
            return staged;
        }
        changed = staged.changed;
    }

    let existing = load_mode_marker();
    let marker = ModeMarker {
        mode: RiceMode::Declarative,
        song: resolved_name.clone().or(existing.song),
        draft: None,
        // Carried forward UNCHANGED, never cleared or overwritten here — this
        // is the crux of the staging-memory fix: `song` above legitimately
        // gets overwritten to reflect what's now actually active, but
        // `staging_song` must survive a declarative lock so a later bare
        // `rice mode stage` can still find its way back to it.
        staging_song: existing.staging_song,
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
        match &resolved_name {
            Some(n) => format!(
                "declarative mode locked — re-pinned to `{n}`'s committed notes \
                 (unsaved live edits discarded — `rice draft save` first to keep them); \
                 rice stage/cover set refuse until unlocked"
            ),
            None => "declarative mode locked — rice stage/cover set refuse until unlocked".to_string(),
        },
    )
    .changed(changed)
    .with_data(json!({ "mode": "declarative", "song": marker.song }))
}

/// `rice mode draft <name>` — enter DRAFT mode: point `stage/livery.json`
/// at a symlink into `songbook/<song>/drafts/<name>/livery.json`, where
/// `song` is resolved the same way `rice mode stage`'s no-arg form does
/// ([`current_staged_song`] — no separate `<song>` arg). Forks the draft
/// from whatever's CURRENTLY in the stage first if it doesn't exist yet,
/// reusing [`super::draft::fork_stage_into`] (the SAME write `rice draft
/// save`'s own handler performs, not a reimplementation) — so entering a
/// brand-new draft name is also how you create one.
///
/// Every future writer of `stage/livery.json` — `rice stage`, a hand-edit,
/// Quickshell's own FileView reload — transparently lands in the draft file
/// from here on, because [`aoide_storage::fs::atomic_write`] resolves and
/// writes through a symlink at its destination rather than replacing it.
/// Zero draft-awareness anywhere else is what makes this simple. (`cover
/// set`/`stage/cover.json` are NOT part of this routing — only
/// `livery.json` is symlinked.)
///
/// Removes whatever currently sits at `stage/livery.json` (a real declared
/// file, or an old symlink routed to a DIFFERENT draft) before creating the
/// new symlink. Refuses with the same `declarative-mode-locked` shape every
/// other write path uses.
fn handle_mode_draft(inv: &Invocation) -> Outcome {
    let existing = load_mode_marker();
    if existing.mode == RiceMode::Declarative {
        return Outcome::error(
            "rice.mode.draft",
            "declarative mode is locked — run `aoide rice mode stage` to unlock hot-loading first",
        )
        .with_data(json!({ "reason": "declarative-mode-locked" }));
    }

    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage(
                "rice.mode.draft",
                "usage: aoide rice mode draft <name> [--json]",
            )
            .with_data(json!({ "reason": "missing-name" }));
        }
    };
    if !crate::compose::valid_song_name(&name) {
        return Outcome::error(
            "rice.mode.draft",
            format!(
                "`{name}` is not a valid draft name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }

    let song = match current_staged_song() {
        Some(s) => s,
        None => {
            return Outcome::error(
                "rice.mode.draft",
                "no song is currently staged — nothing to fork a draft from \
                 (stage a song first: `aoide rice stage <name>` or `aoide rice mode stage <name>`)",
            )
            .with_data(json!({ "reason": "no-resolvable-song" }));
        }
    };

    let mut changed: Vec<String> = Vec::new();
    let draft_livery = shellbridge::draft_dir(&song, &name).join("livery.json");
    if !draft_livery.is_file() {
        let mut forked = super::draft::fork_stage_into(&song, &name);
        if forked.status != Status::Ok {
            forked.command = "rice.mode.draft".to_string();
            return forked;
        }
        changed.append(&mut forked.changed);
    }

    let stage_livery = shellbridge::stage_dir().join("livery.json");
    if std::fs::symlink_metadata(&stage_livery).is_ok() {
        if let Err(e) = std::fs::remove_file(&stage_livery) {
            return Outcome::error(
                "rice.mode.draft",
                format!("failed to clear stage/livery.json before routing: {e}"),
            )
            .changed(changed)
            .with_data(json!({ "reason": "symlink-setup-failed" }));
        }
    }
    if let Some(parent) = stage_livery.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Outcome::error("rice.mode.draft", format!("failed to prepare the stage dir: {e}"))
                .changed(changed)
                .with_data(json!({ "reason": "symlink-setup-failed" }));
        }
    }
    if let Err(e) = std::os::unix::fs::symlink(&draft_livery, &stage_livery) {
        return Outcome::error(
            "rice.mode.draft",
            format!("failed to route stage/livery.json to the draft: {e}"),
        )
        .changed(changed)
        .with_data(json!({ "reason": "symlink-setup-failed" }));
    }
    changed.push(stage_livery.to_string_lossy().into_owned());

    let marker = ModeMarker {
        mode: RiceMode::Draft,
        song: Some(song.clone()),
        draft: Some(name.clone()),
        // Out of scope for this command (entering `Draft`, not `Staging`) —
        // carry the existing "what was I staging" memory forward unchanged.
        staging_song: existing.staging_song,
        since: aoide_storage::time::now_iso_utc(),
    };
    if let Err(e) = save_mode_marker(&marker) {
        return Outcome::error("rice.mode.draft", format!("failed to write mode marker: {e}"))
            .changed(changed)
            .with_data(json!({ "reason": "marker-write-failed" }));
    }
    changed.push(mode_marker_path().to_string_lossy().into_owned());

    Outcome::ok(
        "rice.mode.draft",
        format!("draft mode routed — stage/livery.json now points at `{song}`'s draft `{name}`"),
    )
    .changed(changed)
    .with_data(json!({ "mode": "draft", "song": song, "draft": name }))
}

// ── Tests (rice mode status/stage/declarative/draft) ──────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::*;

    #[test]
    fn current_staged_song_rejects_a_hand_edited_path_traversal_song_field() {
        // `current_staged_song()`'s result is joined straight into
        // `draft_dir(song, name)` by both `draft.rs` and `handle_mode_draft`
        // below — a stage/livery.json hand-edited (or written by some other
        // process) with a traversal `"song"` must resolve to nothing at all,
        // same as a missing/absent one, rather than resolving to something
        // a caller then treats as a safe directory component.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("current-staged-song-traversal");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"../../evil","palette":{"bg":"#000"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        assert_eq!(current_staged_song(), None);
        let _ = std::fs::remove_dir_all(&stage);
    }

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
    fn stage_with_no_name_resolves_and_restages_the_current_song() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-stage-resolve-current");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        // The stage file ALREADY carries a "song" breadcrumb — written by a
        // prior `rice stage`/`rice mode stage` call or the nix activation's
        // reseed script — even though the caller passes no name this time.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"moonlight","palette":{"bg":"#000"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            out.message.contains("re-staged the current rice"),
            "message names the auto-resolve path: {}",
            out.message
        );
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Staging);
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert!(out.changed.iter().any(|c| c.ends_with("stage/livery.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("stage/mode.json")));
        // The re-stage pulled FRESH content from songbook/moonlight (which
        // has an "accent" the seeded stage stub lacked) — proves it actually
        // re-derived, not just reused the breadcrumb as a no-op.
        let restaged = std::fs::read_to_string(stage.join("livery.json")).unwrap();
        assert!(restaged.contains("\"accent\""));
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
    fn declarative_with_no_name_but_a_resolvable_current_song_repins_then_locks() {
        // The behavior change (khoa 2026-08-14): bare `rice mode declarative`
        // no longer freezes the stage as-is — it mirrors `rice mode stage`'s
        // own no-arg auto-resolve and re-pins from the COMMITTED songbook
        // notes before locking.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-declarative-autoresolve");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        // The stage already carries a "song" breadcrumb but STALE content (no
        // "accent" field, which VALID_NOTES has) — proves the lock actually
        // RE-PINS from the committed songbook rather than freezing the stale
        // stage in place.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"moonlight","palette":{"bg":"#000"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            out.message.contains("unsaved live edits discarded"),
            "the behavior change is self-documented in the CLI output: {}",
            out.message
        );
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Declarative);
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert_eq!(marker.draft, None);
        let repinned = std::fs::read_to_string(stage.join("livery.json")).unwrap();
        assert!(
            repinned.contains("\"accent\""),
            "re-pinned from the committed songbook, not frozen as-is: {repinned}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn declarative_with_no_name_and_no_resolvable_song_is_still_a_bare_lock() {
        // The unchanged fallback: a genuinely fresh box with no stage file
        // yet has nothing to resolve, so this is still a no-op freeze, not an
        // error and not a fabricated re-pin.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-declarative-bare");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            !out.message.contains("discarded"),
            "nothing was live to discard: {}",
            out.message
        );
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Declarative);
        assert_eq!(marker.song, None);
        assert!(!stage.join("livery.json").exists(), "nothing staged out of nowhere");
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

    // ── `staging_song` survives a declarative lock (khoa 2026-08-17) ──────
    //
    // The regression this whole field exists to fix: `current_staged_song()`
    // reads `stage/livery.json`'s own `"song"` field, which `handle_rice_stage`
    // overwrites on EVERY stage — including the re-pin a declarative lock
    // performs. So staging `etude`, then locking declarative on `sonata`,
    // used to permanently lose the memory that `etude` was ever staged: a
    // later bare `rice mode stage` (no name — exactly what the bar toggle
    // sends) would resolve back to `sonata`, never `etude`. `staging_song` is
    // a separate, declarative-immune memory of "what was I staging" that a
    // bare `rice mode stage` now prefers over the unreliable file-read.

    #[test]
    fn staging_song_survives_a_declarative_lock_and_a_bare_stage_resolves_back_to_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-staging-song-survives-lock");
        let stage = root.join("stage");
        let sonata = root.join("songbook").join("sonata");
        let etude = root.join("songbook").join("etude");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&sonata).unwrap();
        std::fs::create_dir_all(&etude).unwrap();
        std::fs::write(sonata.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(etude.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // Stage `etude` explicitly.
        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &["etude"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.song, Some("etude".to_string()));
        assert_eq!(marker.staging_song, Some("etude".to_string()));

        // Lock declarative on `sonata` — `song` flips, `staging_song` must
        // NOT: this is the actual regression, asserted explicitly.
        let out = handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &["sonata"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Declarative);
        assert_eq!(marker.song, Some("sonata".to_string()));
        assert_eq!(
            marker.staging_song,
            Some("etude".to_string()),
            "declarative locking must not erase the staging memory"
        );

        // A bare `rice mode stage` (no name — exactly what the bar toggle
        // sends) must resolve back to `etude`, NOT `sonata` and NOT whatever
        // `current_staged_song()`/`stage/livery.json` currently says.
        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            out.message.contains("etude"),
            "bare stage resolved to the remembered staging_song, not the just-locked song: {}",
            out.message
        );
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Staging);
        assert_eq!(marker.song, Some("etude".to_string()));
        assert_eq!(marker.staging_song, Some("etude".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bare_stage_on_a_fresh_mode_json_still_falls_back_to_current_staged_song() {
        // Cold-start case: a `mode.json` that has never carried a
        // `staging_song` (a fresh box, or one predating this field) must
        // still resolve a bare `rice mode stage` off `current_staged_song()`
        // — the old behavior — rather than failing to resolve at all.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-staging-song-cold-start");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        // The stage file already carries a "song" breadcrumb, as if seeded by
        // the nix activation reseed script — but no mode.json exists yet, so
        // `staging_song` has never been set.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"moonlight","palette":{"bg":"#000"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        assert_eq!(load_mode_marker(), ModeMarker::default(), "no mode.json written yet");

        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert_eq!(marker.staging_song, Some("moonlight".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice mode draft ───────────────────────────────────────────────────

    #[test]
    fn mode_draft_forks_a_new_draft_and_routes_the_symlink() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-draft-fork");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let live_notes = r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#live"}}"##;
        std::fs::write(stage.join("livery.json"), live_notes).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Staging,
            song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);

        let draft_livery = root.join("songbook").join("sonata").join("drafts").join("neon-night").join("livery.json");
        assert_eq!(std::fs::read_to_string(&draft_livery).unwrap(), live_notes, "forked from the live stage");
        assert!(
            std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink(),
            "stage/livery.json is now a symlink"
        );
        assert_eq!(std::fs::read_link(stage.join("livery.json")).unwrap(), draft_livery);
        assert_eq!(std::fs::read_to_string(stage.join("livery.json")).unwrap(), live_notes, "reads through fine");

        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Draft);
        assert_eq!(marker.song, Some("sonata".to_string()));
        assert_eq!(marker.draft, Some("neon-night".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mode_draft_routes_to_an_existing_draft_without_reforking() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-draft-existing");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#live"}}"##,
        )
        .unwrap();
        let existing_dir = root.join("songbook").join("sonata").join("drafts").join("neon-night");
        std::fs::create_dir_all(&existing_dir).unwrap();
        let existing_notes = r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#already-saved"}}"##;
        std::fs::write(existing_dir.join("livery.json"), existing_notes).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        save_mode_marker(&ModeMarker {
            mode: RiceMode::Staging,
            song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        // The EXISTING draft content is untouched (not overwritten by the
        // live stage's own content) — routing, not re-forking.
        assert_eq!(std::fs::read_to_string(&existing_dir.join("livery.json")).unwrap(), existing_notes);
        assert_eq!(std::fs::read_to_string(stage.join("livery.json")).unwrap(), existing_notes);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mode_draft_replaces_a_symlink_routed_to_a_different_draft() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-draft-reroute");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#seed"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        save_mode_marker(&ModeMarker {
            mode: RiceMode::Staging,
            song: Some("sonata".to_string()),
            ..Default::default()
        })
        .unwrap();

        handle_mode_draft(&inv(&["rice", "mode", "draft"], &["amber-dusk"]));
        assert_eq!(load_mode_marker().draft, Some("amber-dusk".to_string()));

        let out = handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let marker = load_mode_marker();
        assert_eq!(marker.draft, Some("neon-night".to_string()));
        let neon_livery = root.join("songbook").join("sonata").join("drafts").join("neon-night").join("livery.json");
        assert_eq!(std::fs::read_link(stage.join("livery.json")).unwrap(), neon_livery);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mode_draft_refuses_while_declarative_locked() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-draft-locked");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // No marker file at all IS declarative (the safe default).
        let out = handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "declarative-mode-locked");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn mode_draft_missing_name_is_usage() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-draft-noname");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        save_mode_marker(&ModeMarker { mode: RiceMode::Staging, ..Default::default() }).unwrap();

        let out = handle_mode_draft(&inv(&["rice", "mode", "draft"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.data.unwrap()["reason"], "missing-name");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn mode_draft_with_no_resolvable_song_errors() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("mode-draft-nosong").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        save_mode_marker(&ModeMarker { mode: RiceMode::Staging, ..Default::default() }).unwrap();

        let out = handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "no-resolvable-song");
    }

    // ── leaving Draft mode tears the symlink down ─────────────────────────

    #[test]
    fn mode_stage_tears_down_an_active_draft_symlink() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-stage-teardown");
        let stage = root.join("stage");
        let song = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        // current_staged_song() reads THIS file's own "song" field, not the
        // marker's — handle_mode_draft needs it to resolve what to fork from.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#seed"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        save_mode_marker(&ModeMarker { mode: RiceMode::Staging, song: Some("sonata".to_string()), ..Default::default() }).unwrap();

        handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert!(std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink());

        let out = handle_mode_stage(&inv(&["rice", "mode", "stage"], &["sonata"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            !std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink(),
            "the routing symlink must be gone — a real file now"
        );
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Staging);
        assert_eq!(marker.draft, None);
        // The draft file itself is untouched — only the routing is torn down.
        let draft_livery = root.join("songbook").join("sonata").join("drafts").join("neon-night").join("livery.json");
        assert!(draft_livery.is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mode_declarative_tears_down_an_active_draft_symlink() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mode-declarative-teardown");
        let stage = root.join("stage");
        let song = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        // current_staged_song() reads THIS file's own "song" field, not the
        // marker's — handle_mode_draft needs it to resolve what to fork from.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"sonata","palette":{"bg":"#seed"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        save_mode_marker(&ModeMarker { mode: RiceMode::Staging, song: Some("sonata".to_string()), ..Default::default() }).unwrap();

        handle_mode_draft(&inv(&["rice", "mode", "draft"], &["neon-night"]));
        assert!(std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink());

        let out = handle_mode_declarative(&inv(&["rice", "mode", "declarative"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            !std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink(),
            "the routing symlink must be gone — a real file now"
        );
        let marker = load_mode_marker();
        assert_eq!(marker.mode, RiceMode::Declarative);
        assert_eq!(marker.song, Some("sonata".to_string()));
        assert_eq!(marker.draft, None);
        let staged = std::fs::read_to_string(stage.join("livery.json")).unwrap();
        assert!(staged.contains("\"accent\""), "re-pinned from the committed songbook: {staged}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
