//! Per-song widget QML sync — the runtime-tree half of `rice stage`
//! (concepts/song/Self-Ricing.md "Staging vs Declarative Mode"). `rice
//! stage` already hot-reloads a song's palette/notes via
//! `song/stage/livery.json`; this module carries a song's widget QML
//! BODIES (`song/songbook/<song>/widgets/*.qml`) into the live runtime tree
//! (`run/qml/songs/<song>/`) too, so Quickshell's own file-watcher picks up
//! an edit to an EXISTING widget file live, no rebuild needed. `manifest.json`
//! is a hot-reloaded `FileView` on the QML side (`StagingEngine.qml`), not
//! read once at startup — a brand-new slot still needs THIS module's own
//! manifest regeneration (below) to appear in it, but no service restart.
//!
//! **C4/W3 (the manifest/registry generator, unified):** `manifest.json` and
//! `registry.json` are no longer derived by scanning THIS song's own
//! `widgets/` directory and patching one entry. A scan cannot answer "who
//! owns this slot" once a composition borrows another song's widget body —
//! only `composeSong` (`lib/song.nix`, run inside `lib/songbook.nix`)
//! resolves ownership, and it runs in the nix evaluator, nowhere else. So
//! both files are regenerated WHOLE, for every committed song at once, by
//! shelling out to `nix eval --json` against the `songbookManifest` flake
//! output (`flake.nix`) — the exact same generator
//! `modules/facets/quickshell/default.nix`'s `quickshellConfig` derivation
//! calls at build time. One generator, two callers: [`eval_songbook`] is
//! that shell-out, invoked once from the manifest path
//! ([`sync_song_widgets`]) and once from the registry path
//! ([`sync_song_registry`]) — see each function's own doc.
//!
//! This also fixes a real, silent hazard the old per-entry writer left
//! behind: it preserved every OTHER song's entry verbatim on each write, so
//! a manifest.json written by nix (owner-map shape) that this module then
//! patched would leave every UNTOUCHED song's entry in owner-map shape but
//! silently rewrite the STAGED song's own entry back to the old bare-list
//! shape — a shape `StagingEngine.qml`'s `has()` cannot look up, so every
//! widget for that one song would render nothing, no error anywhere.
//! Whole-file regeneration from nix can't reproduce that failure mode: every
//! song's entry, staged or not, comes from the same eval every time.
//!
//! Mirrors the nix build's own per-song widget carry
//! (`modules/facets/quickshell/default.nix`'s `quickshellConfig`
//! derivation) as closely as possible for the BODY copy: the WHOLE
//! `widgets/` tree is copied unfiltered (helper components, asset subdirs,
//! `.gitkeep`, everything), while the manifest only ever lists top-level
//! lowercase-kebab `.qml` files as slots.

use std::path::Path;

/// A successful widget sync — including the clean no-op "nothing to do"
/// cases (no `widgets/` dir, no deployed runtime tree).
pub struct WidgetSyncOk {
    /// `run/qml`-rooted files actually (re)written, absolute paths.
    pub changed: Vec<String>,
    /// This song's LOCAL slot names, sorted — a scan of the widgets/ dir
    /// just copied (never the just-regenerated manifest.json): informational
    /// only, for the `Outcome`'s own `data.slots`/message, independent of
    /// what nix's committed-tree eval says this song owns. A song being
    /// staged from an uncommitted/relocated songbook (tests; a brand-new
    /// song not yet `git add`ed) can carry local widget files nix's eval of
    /// the real committed tree has never seen — this field still reports
    /// them; `manifest.json` itself does not until nix does.
    pub slots: Vec<String>,
    /// Whether any widget BODY file (not `manifest.json`) was (re)written —
    /// the trigger `rice stage`'s caller uses to decide whether a
    /// Quickshell IPC reload is worth it (dynamically
    /// `Qt.createComponent`-loaded widget bodies have no file watcher;
    /// `manifest.json` does, via `StagingEngine.qml`'s own `FileView`, so a
    /// manifest-only regeneration needs no IPC nudge).
    pub bodies_changed: bool,
    /// Human summary for the caller's `Outcome` message/data.
    pub note: String,
}

/// A widget sync failure — an IO error partway through the copy, or the
/// `nix eval` shell-out failing/producing something unusable. Fatal to the
/// caller in both cases: a torn widgets copy is worse than refusing the
/// call, and a manifest/registry write built on a NIX EVAL FAILURE is
/// exactly the silently-wrong-file class this module exists to prevent —
/// better to leave the last-good file in place and surface nix's own
/// message than guess.
pub struct WidgetSyncErr {
    pub error: String,
    pub target: String,
}

/// A successful widget-TYPE registry sync — including the clean no-op
/// "nothing to do" case (no deployed `run/qml` runtime tree).
pub struct RegistrySyncOk {
    /// `run/qml`-rooted files actually (re)written, absolute paths — 0 or 1
    /// entries (`registry.json`'s own path), same shape as
    /// [`WidgetSyncOk::changed`].
    pub changed: Vec<String>,
    /// This song's freshly-regenerated registry entry (`{}` when the
    /// committed tree declares nothing for it), straight from
    /// [`eval_songbook`]'s output — never the pre-regeneration file.
    pub widgets: serde_json::Value,
    /// Human summary for the caller's `Outcome` message/data.
    pub note: String,
}

/// Test-only input seam: when set, [`eval_songbook`] reads its `{
/// manifest, registry }` payload from the JSON FILE at this path instead of
/// shelling out to `nix eval`. Exists so the widgets-sync-MECHANICS tests
/// (body copy, manifest whole-regen/shape-healing, registry idempotency —
/// `commands/rice.rs`'s `mod tests`) can run inside the `aoide` package
/// derivation's sandboxed `checkPhase`, which has `HOME=/homeless-shelter`,
/// no flake checkout, no network, and no usable `nix` binary. Those tests
/// exercise THIS crate's regeneration/write logic, not the real
/// `lib/songbook.nix` generator's output shape, so a fixture is a strictly
/// better input for them: hermetic, and no longer coupled to the committed
/// songbook's current slot counts. Tests that deliberately assert the REAL
/// generator's field shapes for the real committed songs still call a real
/// `nix eval` and stay `#[ignore]`d for the sandbox (matching
/// `crates/cli/tests/peer_connectivity.rs`'s precedent for the same
/// sandbox constraint).
///
/// Opt-in only, read once per call, and validated exactly like the real `nix
/// eval` payload below (never a default/empty value on missing/malformed
/// input) — this is an alternate SOURCE for the same validated shape, not a
/// fallback that lets a broken/missing `nix` proceed quietly. A deployed
/// system that never sets this variable is byte-for-byte the pre-existing
/// code path.
pub(crate) const SONGBOOK_EVAL_FIXTURE_VAR: &str = "AOIDE_SONGBOOK_EVAL_FIXTURE";

/// One `nix eval --json` shell-out against the `songbookManifest` flake
/// output (`flake.nix`), which wraps `lib/songbook.nix` — the SAME function
/// `modules/facets/quickshell/default.nix`'s `quickshellConfig` derivation
/// calls at build time. Evaluates against
/// [`aoide_storage::fs::flake_root`] (the git checkout, not the relocatable
/// stage/runtime trees — see that function's doc), so the result reflects
/// the COMMITTED songbook (an untracked file needs `git add` before nix's
/// git-tree source sees it at all; an already-tracked file's uncommitted
/// edit is visible without a commit).
///
/// `--no-eval-cache`: this runs in `rice stage`'s hot path, where a widget
/// edit made moments ago must be reflected immediately — never served from
/// a cache keyed on a state that's since changed.
///
/// Returns the WHOLE `{ manifest, registry }` payload; callers pick the
/// half they need. On any failure (nix missing, eval error, unparseable or
/// incomplete output) returns `Err` with nix's own message where available
/// — never a default/empty value, which a caller could mistake for "the
/// songbook is genuinely empty" and write out.
///
/// [`SONGBOOK_EVAL_FIXTURE_VAR`] short-circuits this whole shell-out for
/// tests — see that constant's own doc.
fn eval_songbook() -> Result<SongbookEval, WidgetSyncErr> {
    if let Ok(path) = std::env::var(SONGBOOK_EVAL_FIXTURE_VAR) {
        let bytes = std::fs::read(&path).map_err(|e| WidgetSyncErr {
            error: format!(
                "failed to read {SONGBOOK_EVAL_FIXTURE_VAR} fixture at {path}: {e}"
            ),
            target: path.clone(),
        })?;
        return parse_songbook_eval(&bytes, &path);
    }

    let flake_root = aoide_storage::fs::flake_root();
    let flake_ref = format!("{}#songbookManifest", flake_root.to_string_lossy());

    let output = std::process::Command::new("nix")
        .args(["eval", "--json", "--no-eval-cache", &flake_ref])
        .output()
        .map_err(|e| WidgetSyncErr {
            error: format!(
                "failed to run `nix eval` (is `nix` on PATH?): {e}"
            ),
            target: flake_ref.clone(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WidgetSyncErr {
            error: format!(
                "nix eval failed regenerating the songbook manifest/registry — \
                 manifest.json/registry.json left untouched:\n{}",
                stderr.trim()
            ),
            target: flake_ref,
        });
    }

    parse_songbook_eval(&output.stdout, &flake_ref)
}

/// Shared validation for [`eval_songbook`]'s payload, whichever of the two
/// sources above produced it: must be `{ manifest, registry }` with both
/// fields objects — never a default/empty value on partial/garbled input,
/// which a caller could mistake for "the songbook is genuinely empty" and
/// write out.
fn parse_songbook_eval(bytes: &[u8], target: &str) -> Result<SongbookEval, WidgetSyncErr> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| WidgetSyncErr {
        error: format!("songbook eval output isn't valid JSON: {e}"),
        target: target.to_string(),
    })?;

    let manifest = parsed
        .get("manifest")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| WidgetSyncErr {
            error: "songbook eval output has no `manifest` object — refusing to write a malformed manifest.json"
                .to_string(),
            target: target.to_string(),
        })?;
    let registry = parsed
        .get("registry")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| WidgetSyncErr {
            error: "songbook eval output has no `registry` object — refusing to write a malformed registry.json"
                .to_string(),
            target: target.to_string(),
        })?;

    Ok(SongbookEval { manifest, registry })
}

/// [`eval_songbook`]'s parsed result — the whole committed songbook's
/// manifest and registry, keyed by song name.
struct SongbookEval {
    manifest: serde_json::Value,
    registry: serde_json::Value,
}

/// Sync `<song>/songbook/<name>/widgets/` into `run/qml/songs/<name>/` and
/// regenerate `manifest.json` WHOLE (every committed song, via
/// [`eval_songbook`]) — the live-desktop half of `rice stage`.
///
/// Clean-skips (`Ok`, empty `changed`) only when no `run/qml` runtime tree
/// is deployed at all (no `nixos-rebuild switch` yet) — there is nowhere to
/// write. Unlike the pre-C4 version, a MISSING `widgets/` dir for `name`
/// does NOT skip the manifest regeneration: the manifest is a whole-songbook
/// artifact, not a per-song one, so it stays current (and self-heals any
/// other song's stale/malformed entry) on every `rice stage` call once a
/// runtime tree exists, regardless of whether the ACTIVE song has bodies to
/// carry.
///
/// Pre-existing scope limit, not introduced here: the BODY copy is still
/// per-STAGED-song only, `name`'s own `widgets/` tree. Once a borrow exists
/// (W5+), editing the OWNING song's widget body and running `rice stage` on
/// the BORROWING song does not carry that edit into
/// `run/qml/songs/<owner>/` — only staging the owner directly does.
/// manifest.json/registry.json stay correct regardless (whole regen, every
/// call), so this is a live-preview body-freshness papercut, not a
/// correctness bug, and it self-resolves on the owner's own next stage or on
/// a rebuild. Whoever lands the first borrow should re-check whether this is
/// still an acceptable seam or worth widening to "sync every song the
/// active one's manifest entries resolve through."
pub fn sync_song_widgets(name: &str) -> Result<WidgetSyncOk, WidgetSyncErr> {
    let run_qml = aoide_storage::fs::run_qml_dir();
    if !run_qml.is_dir() {
        return Ok(WidgetSyncOk {
            changed: vec![],
            slots: vec![],
            bodies_changed: false,
            note: "no run/qml runtime tree deployed; widgets not synced".into(),
        });
    }

    let src = aoide_storage::fs::songbook_dir(name).join("widgets");
    let mut changed: Vec<String> = Vec::new();
    let local_slots = if src.is_dir() {
        let dst = run_qml.join("songs").join(name);
        copy_tree_atomic(&src, &dst, &mut changed)?;
        scan_slot_names(&src)?
    } else {
        Vec::new()
    };
    let body_file_count = changed.len();
    let bodies_changed = body_file_count > 0;

    regenerate_manifest(&run_qml, &mut changed)?;

    let note = if !bodies_changed {
        "widget bodies already current".to_string()
    } else {
        format!("synced {body_file_count} widget file(s) into run/qml/songs/{name}")
    };
    Ok(WidgetSyncOk { changed, slots: local_slots, bodies_changed, note })
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

/// `name`'s top-level slot files in `src` — informational only (see
/// [`WidgetSyncOk::slots`]'s doc), same rule
/// `modules/facets/quickshell/default.nix`'s manifest generation uses: a
/// FILE (not a dir), not `.gitkeep`, ending `.qml`, first byte
/// ascii-lowercase or an ascii digit.
fn scan_slot_names(src: &Path) -> Result<Vec<String>, WidgetSyncErr> {
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
    Ok(slots)
}

/// Regenerate `run_qml/songs/manifest.json` WHOLE from [`eval_songbook`] —
/// every committed song's owner-map entry, replacing the file outright
/// (preserve-nothing: the eval is total, so a stale or malformed entry for
/// ANY song, not just the one being staged, self-heals on every call).
fn regenerate_manifest(run_qml: &Path, changed: &mut Vec<String>) -> Result<(), WidgetSyncErr> {
    let eval = eval_songbook()?;
    let manifest_path = run_qml.join("songs").join("manifest.json");
    let body = serde_json::to_string_pretty(&eval.manifest).unwrap_or_default() + "\n";
    let existing = std::fs::read_to_string(&manifest_path).ok();
    if existing.as_deref() != Some(body.as_str()) {
        aoide_storage::fs::atomic_write(&manifest_path, &body).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: manifest_path.to_string_lossy().into_owned(),
        })?;
        changed.push(manifest_path.to_string_lossy().into_owned());
    }
    Ok(())
}

/// Regenerate `run/qml/songs/registry.json` WHOLE from [`eval_songbook`] —
/// the second call site of the one generator (see the module doc's "one
/// generator, invoked twice"). Same preserve-nothing posture as
/// [`regenerate_manifest`]: every committed song's registry entry comes
/// from THIS eval, every time, so a stale entry for any song self-heals
/// regardless of which song is being staged.
///
/// Clean-skips (`Ok`, empty `changed`) when no `run/qml` runtime tree is
/// deployed at all — mirrors [`sync_song_widgets`]'s own not-yet-switched
/// early return (`registry.json` lives under the same tree).
pub fn sync_song_registry(name: &str) -> Result<RegistrySyncOk, WidgetSyncErr> {
    let run_qml = aoide_storage::fs::run_qml_dir();
    if !run_qml.is_dir() {
        return Ok(RegistrySyncOk {
            changed: vec![],
            widgets: serde_json::json!({}),
            note: "no run/qml runtime tree deployed; registry not synced".into(),
        });
    }

    let eval = eval_songbook()?;
    let registry_path = run_qml.join("songs").join("registry.json");
    let body = serde_json::to_string_pretty(&eval.registry).unwrap_or_default() + "\n";
    let existing = std::fs::read_to_string(&registry_path).ok();
    let differs = existing.as_deref() != Some(body.as_str());
    let mut changed: Vec<String> = Vec::new();
    if differs {
        aoide_storage::fs::atomic_write(&registry_path, &body).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: registry_path.to_string_lossy().into_owned(),
        })?;
        changed.push(registry_path.to_string_lossy().into_owned());
    }

    let widgets = eval.registry.get(name).cloned().unwrap_or_else(|| serde_json::json!({}));

    let note = if differs {
        format!("synced `{name}`'s widget-type registry entry")
    } else {
        "widget-type registry entry already current".to_string()
    };
    Ok(RegistrySyncOk { changed, widgets, note })
}
