//! Per-song widget QML sync — the runtime-tree half of `rice stage`
//! (concepts/song/Self-Ricing.md "Staging vs Declarative Mode"). `rice
//! stage` already hot-reloads a song's palette/notes via
//! `song/stage/livery.json`; this module carries a song's widget QML
//! BODIES (`song/songbook/<song>/widgets/*.qml`) into the live runtime tree
//! (`run/qml/songs/<song>/`) too, so Quickshell's own file-watcher picks up
//! an edit to an EXISTING widget file live, no rebuild needed. A brand-new
//! widget file still needs a service restart to be discovered
//! (`manifest.json` is read once at startup) — a known, unchanged
//! limitation this module does not attempt to fix.
//!
//! Mirrors the nix build's own per-song widget carry
//! (`modules/facets/quickshell/default.nix`'s `quickshellConfig`
//! derivation) as closely as possible: the WHOLE `widgets/` tree is copied
//! unfiltered (helper components, asset subdirs, `.gitkeep`, everything),
//! while the manifest only ever lists top-level lowercase-kebab `.qml`
//! files as slots.

use std::path::Path;

/// A successful widget sync — including the clean no-op "nothing to do"
/// cases (no `widgets/` dir, no deployed runtime tree).
pub struct WidgetSyncOk {
    /// `run/qml`-rooted files actually (re)written, absolute paths.
    pub changed: Vec<String>,
    /// This song's manifested slot names, sorted.
    pub slots: Vec<String>,
    /// Human summary for the caller's `Outcome` message/data.
    pub note: String,
}

/// A widget sync failure — an IO error partway through the copy or the
/// manifest rewrite. Fatal to the caller: a torn widgets/manifest write is
/// worse than refusing the whole `rice stage` call.
pub struct WidgetSyncErr {
    pub error: String,
    pub target: String,
}

/// Sync `<song>/songbook/<name>/widgets/` into `run/qml/songs/<name>/` and
/// regenerate that song's `manifest.json` entry — the live-desktop half of
/// `rice stage`.
///
/// Clean-skips (`Ok`, empty `changed`) when the song has no `widgets/` dir,
/// or when no `run/qml` runtime tree is deployed at all (no
/// `nixos-rebuild switch` yet) — neither is an error, just nothing to sync.
pub fn sync_song_widgets(name: &str) -> Result<WidgetSyncOk, WidgetSyncErr> {
    let src = aoide_storage::fs::songbook_dir(name).join("widgets");
    if !src.is_dir() {
        return Ok(WidgetSyncOk {
            changed: vec![],
            slots: vec![],
            note: format!("no widgets/ dir for `{name}`; runtime widgets left untouched"),
        });
    }

    let run_qml = aoide_storage::fs::run_qml_dir();
    if !run_qml.is_dir() {
        return Ok(WidgetSyncOk {
            changed: vec![],
            slots: vec![],
            note: "no run/qml runtime tree deployed; widgets not synced".into(),
        });
    }

    let dst = run_qml.join("songs").join(name);
    let mut changed: Vec<String> = Vec::new();
    copy_tree_atomic(&src, &dst, &mut changed)?;
    let slots = sync_manifest_entry(name, &src, &run_qml, &mut changed)?;

    let note = if changed.is_empty() {
        "widget bodies already current".to_string()
    } else {
        format!("synced {} widget file(s) into run/qml/songs/{name}", changed.len())
    };
    Ok(WidgetSyncOk { changed, slots, note })
}

/// Recursively copy `src` into `dst`, unfiltered — every file and subdir,
/// including `.gitkeep` and uppercase helper components — matching the nix
/// build's `cp -r "$d/widgets/."`. A destination file whose bytes already
/// match the source is left untouched (not written, not counted in
/// `changed`): Quickshell would otherwise reload/reinstantiate every widget
/// on every palette-only `rice stage` call, causing visible flicker/lost
/// widget state.
fn copy_tree_atomic(
    src: &Path,
    dst: &Path,
    changed: &mut Vec<String>,
) -> Result<(), WidgetSyncErr> {
    std::fs::create_dir_all(dst).map_err(|e| WidgetSyncErr {
        error: e.to_string(),
        target: dst.to_string_lossy().into_owned(),
    })?;
    let entries = std::fs::read_dir(src).map_err(|e| WidgetSyncErr {
        error: e.to_string(),
        target: src.to_string_lossy().into_owned(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: src.to_string_lossy().into_owned(),
        })?;
        let file_type = entry.file_type().map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: entry.path().to_string_lossy().into_owned(),
        })?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree_atomic(&entry.path(), &dst_path, changed)?;
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: entry.path().to_string_lossy().into_owned(),
        })?;
        if std::fs::read(&dst_path).map(|existing| existing == bytes).unwrap_or(false) {
            continue; // byte-identical — skip, deliberately not counted as changed.
        }
        aoide_storage::fs::atomic_write_bytes(&dst_path, &bytes).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: dst_path.to_string_lossy().into_owned(),
        })?;
        changed.push(dst_path.to_string_lossy().into_owned());
    }
    Ok(())
}

/// Recompute `name`'s slot list from `src`'s top-level entries and rewrite
/// `run_qml/songs/manifest.json`'s entry for it, preserving every other
/// song's entry untouched. Returns the computed slot list.
///
/// A file qualifies as a slot iff it is a FILE (not a dir), its name is not
/// `.gitkeep`, it ends with `.qml`, and its first byte is ascii-lowercase or
/// an ascii digit — the same lowercase-kebab-vs-uppercase-helper rule
/// `modules/facets/quickshell/default.nix`'s manifest generation uses.
fn sync_manifest_entry(
    name: &str,
    src: &Path,
    run_qml: &Path,
    changed: &mut Vec<String>,
) -> Result<Vec<String>, WidgetSyncErr> {
    let entries = std::fs::read_dir(src).map_err(|e| WidgetSyncErr {
        error: e.to_string(),
        target: src.to_string_lossy().into_owned(),
    })?;
    let mut slots: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: src.to_string_lossy().into_owned(),
        })?;
        let file_type = entry.file_type().map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: entry.path().to_string_lossy().into_owned(),
        })?;
        if !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(base) = file_name.to_str() else {
            continue;
        };
        if base == ".gitkeep" {
            continue;
        }
        let Some(stem) = base.strip_suffix(".qml") else {
            continue;
        };
        let Some(&first) = base.as_bytes().first() else {
            continue;
        };
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            continue;
        }
        slots.push(stem.to_string());
    }
    slots.sort();
    slots.dedup();

    let manifest_path = run_qml.join("songs").join("manifest.json");
    let existing = std::fs::read_to_string(&manifest_path).ok();
    let mut manifest: serde_json::Value = existing
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    manifest
        .as_object_mut()
        .expect("normalized to an object above")
        .insert(name.to_string(), serde_json::json!(slots));

    let body = serde_json::to_string_pretty(&manifest).unwrap_or_default() + "\n";
    let differs = existing.as_deref() != Some(body.as_str());
    if differs {
        aoide_storage::fs::atomic_write(&manifest_path, &body).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: manifest_path.to_string_lossy().into_owned(),
        })?;
        changed.push(manifest_path.to_string_lossy().into_owned());
    }

    Ok(slots)
}
