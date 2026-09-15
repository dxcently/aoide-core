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
//! song's entry, staged or not, comes from the same eval every time (a
//! CHECKOUT host's committed songbook is stable across calls, so "every
//! song" and "every committed song nix can see" are the same set).
//!
//! Mirrors the nix build's own per-song widget carry
//! (`modules/facets/quickshell/default.nix`'s `quickshellConfig`
//! derivation) as closely as possible for the BODY copy: the WHOLE
//! `widgets/` tree is copied unfiltered (helper components, asset subdirs,
//! `.gitkeep`, everything), while the manifest only ever lists top-level
//! lowercase-kebab `.qml` files as slots.
//!
//! **L-C3 (repo-less hosts, lyra-carrier lane, task #107):** the `nix eval`
//! shell-out above needs a real flake checkout at `flake_root()` — a host
//! with no `~/Aoide` clone has none. [`eval_songbook`] checks for
//! `flake_root()/flake.nix` first and, when absent, never shells to `nix` at
//! all: it reads the SHIPPED, prebaked `manifest.json`/`registry.json` from
//! [`aoide_storage::fs::song_templates_dir`] (`pkgs/lyra-songbook`, baked at
//! nix build time by the SAME `lib/songbook.nix` generator) as the BASELINE.
//! Unlike a checkout host, a repo-less host's OTHER composed songs are not
//! inside that baseline at all (they live only in the runtime songbook, and
//! the baked templates freeze whatever the package build saw) — a bare
//! baseline-plus-current-song write would silently drop every OTHER
//! previously-staged song's entry on the very next `rice stage` call. So
//! [`eval_songbook_from_templates`] OVERLAYS the EXISTING on-disk manifest/
//! registry's entries for any song that still has a directory in the host
//! songbook (a composed song survives a regen it isn't part of; a song
//! whose directory was removed is pruned — never an immortal stale key) on
//! top of the baked baseline, THEN patches in the CURRENTLY-staged song's
//! own entry from a direct, nix-free directory scan ([`scan_own_entry`]) —
//! the only shape `rice compose` can ever produce (it never writes a
//! `_widgets/` shelf, so there is no borrowed-ownership case to resolve
//! without nix). This self-heals the staged song on every call and
//! preserves every other still-live song's entry in between — not the
//! checkout path's "every song, every call" (there is no whole-songbook
//! eval to lean on here).

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
/// `crates/cli/tests/node_connectivity.rs`'s precedent for the same
/// sandbox constraint).
///
/// Opt-in only, read once per call, and validated exactly like the real `nix
/// eval` payload below (never a default/empty value on missing/malformed
/// input) — this is an alternate SOURCE for the same validated shape, not a
/// fallback that lets a broken/missing `nix` proceed quietly. `#[cfg(test)]`
/// on both this constant and its read in [`eval_songbook`] compiles the seam
/// out of every non-test build: a deployed binary contains no read of this
/// variable, so its eval can never be redirected through the environment.
/// All setters live in this crate's own `mod tests` (`commands/rice.rs`),
/// the same compilation unit, so the plain `cfg(test)` gate reaches them.
#[cfg(test)]
pub(crate) const SONGBOOK_EVAL_FIXTURE_VAR: &str = "AOIDE_SONGBOOK_EVAL_FIXTURE";

/// On a CHECKOUT host (`flake_root()` names a real flake): one `nix eval
/// --json` shell-out against the `songbookManifest` flake output
/// (`flake.nix`), which wraps `lib/songbook.nix` — the SAME function
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
/// On a REPO-LESS host (no `flake.nix` at `flake_root()`, L-C3,
/// lyra-carrier lane, task #107): `nix` is never invoked at all — routes to
/// [`eval_songbook_from_templates`] instead, which merges the shipped/env
/// templates dir's prebaked baseline, the EXISTING on-disk file's entries
/// for every still-live song, and `name`'s own freshly-scanned entry (see
/// that function's own doc for the merge order).
///
/// Returns the WHOLE `{ manifest, registry }` payload; callers pick the
/// half they need. On any failure (nix missing, eval error, unparseable or
/// incomplete output, or the templates-path equivalents) returns `Err` with
/// the underlying message where available — never a default/empty value,
/// which a caller could mistake for "the songbook is genuinely empty" and
/// write out.
///
/// `run_qml` is threaded through only for the templates path (it reads the
/// CURRENT `run_qml/songs/{manifest,registry}.json` there to preserve other
/// songs' entries) — the checkout-host `nix eval` path below ignores it
/// entirely, since a fresh whole-songbook eval needs no prior on-disk state.
///
/// [`SONGBOOK_EVAL_FIXTURE_VAR`] short-circuits BOTH paths above for tests —
/// see that constant's own doc.
fn eval_songbook(name: &str, run_qml: &Path) -> Result<SongbookEval, WidgetSyncErr> {
    #[cfg(test)]
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

    // L-C3 (lyra-carrier lane, task #107): a repo-less host has no flake at
    // `flake_root()` at all — shelling `nix eval` there would just fail
    // loudly (or hang on a missing `nix` binary) for no benefit. Route
    // straight to the shipped/env templates fallback instead of attempting
    // the shell-out first and catching the failure after the fact; the
    // nix-eval path below stays exactly as it was for a real checkout host.
    if !flake_root.join("flake.nix").is_file() {
        return eval_songbook_from_templates(name, &flake_root, run_qml);
    }

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

/// The offline fallback for [`eval_songbook`] on a repo-less host (no flake
/// at `flake_root()`, just checked by the caller). Three layers, in order,
/// each overwriting the last:
///
///   1. **Baseline**: the SHIPPED, prebaked `manifest.json`/`registry.json`
///      from [`aoide_storage::fs::song_templates_dir`] — nix build time
///      already computed them via the SAME `lib/songbook.nix` generator the
///      checkout-host `nix eval` path calls at runtime
///      (`pkgs/lyra-songbook/default.nix`). Authoritative for every shipped,
///      read-only song; frozen at package-build time, so it never reflects a
///      song composed at RUNTIME.
///   2. **Overlay**: [`overlay_surviving_entries`] copies every entry from
///      the EXISTING on-disk `run_qml/songs/{manifest,registry}.json` whose
///      song still has a directory in the host songbook on top of the
///      baseline. This is the fix for the hazard a bare
///      baseline-plus-current-song write would otherwise reproduce: without
///      it, staging song B after having staged song A would silently drop
///      A's entry (A is in neither the frozen baseline nor B's own scan) —
///      `StagingEngine.qml` would then fall back to resolving A's widgets
///      against a DIFFERENT song's slot, no error anywhere. A song whose
///      songbook directory was since removed is NOT overlaid — its entry is
///      pruned rather than kept immortal.
///   3. **Patch**: `name`'s own entry, from a fresh, nix-free scan of its
///      ACTUAL committed songbook directory ([`scan_own_entry`]) — always
///      wins over both the baseline and the overlay, so THIS call's song is
///      never served stale. A template song staged again picks up a local
///      edit this way too. Skipped when `name` has NO directory in the host
///      songbook (a shipped song staged from the declared twin before any
///      seed): there is nothing to scan, and the baked baseline entry is
///      the truth — an empty patch would delete it.
///
/// Net effect: this self-heals the CURRENTLY-staged song on every call and
/// preserves every other still-live song's entry in between — not the
/// checkout path's "every song, every call" (there is no whole-songbook eval
/// to lean on here; see the module doc).
///
/// `flake_root` is threaded through only for error messages (naming both
/// locations checked), never read from here otherwise. `run_qml` is where
/// the overlay step's EXISTING on-disk files live (`run_qml/songs/
/// {manifest,registry}.json`) — the same tree [`regenerate_manifest`]/
/// [`sync_song_registry`] write the merged result back into.
fn eval_songbook_from_templates(
    name: &str,
    flake_root: &Path,
    run_qml: &Path,
) -> Result<SongbookEval, WidgetSyncErr> {
    let Some(templates) = aoide_storage::fs::song_templates_dir() else {
        return Err(WidgetSyncErr {
            error: format!(
                "no flake checkout at {} (no `flake.nix`) and no shipped song templates dir \
                 found either ($AOIDE_SONG_TEMPLATES is unset, and no `share/lyra/songbook` \
                 sits beside this binary) — regenerating manifest.json/registry.json needs \
                 one of the two",
                flake_root.display()
            ),
            target: flake_root.to_string_lossy().into_owned(),
        });
    };

    let manifest_path = templates.join("manifest.json");
    let registry_path = templates.join("registry.json");
    if !manifest_path.is_file() || !registry_path.is_file() {
        return Err(WidgetSyncErr {
            error: format!(
                "no flake checkout at {} (no `flake.nix`) and the templates dir at {} has no \
                 baked manifest.json/registry.json — set $AOIDE_FLAKE_ROOT to a real checkout, \
                 or $AOIDE_SONG_TEMPLATES to a directory shipping both",
                flake_root.display(),
                templates.display()
            ),
            target: templates.to_string_lossy().into_owned(),
        });
    }

    // A `_widgets/` shelf (borrowed/composed widget ownership) can only be
    // resolved by `composeSong` in the nix evaluator (module doc, "only
    // `composeSong`... resolves ownership") — `rice compose` never writes
    // one, so this is an honest gap, not a silently-wrong guess.
    let shelf_dir = aoide_storage::fs::songbook_dir(name).join("_widgets");
    if shelf_dir.is_dir() {
        return Err(WidgetSyncErr {
            error: format!(
                "`{name}` has a `_widgets/` shelf (borrowed/composed widget ownership) — \
                 resolving that requires `nix eval` against a real flake checkout, which this \
                 repo-less host doesn't have (checked {}); set $AOIDE_FLAKE_ROOT to a checkout",
                flake_root.display()
            ),
            target: shelf_dir.to_string_lossy().into_owned(),
        });
    }

    let manifest_bytes = std::fs::read(&manifest_path).map_err(|e| WidgetSyncErr {
        error: format!(
            "failed to read shipped templates manifest.json at {}: {e}",
            manifest_path.display()
        ),
        target: manifest_path.to_string_lossy().into_owned(),
    })?;
    let registry_bytes = std::fs::read(&registry_path).map_err(|e| WidgetSyncErr {
        error: format!(
            "failed to read shipped templates registry.json at {}: {e}",
            registry_path.display()
        ),
        target: registry_path.to_string_lossy().into_owned(),
    })?;

    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|e| WidgetSyncErr {
            error: format!("shipped templates manifest.json is not valid JSON: {e}"),
            target: manifest_path.to_string_lossy().into_owned(),
        })?;
    let mut registry: serde_json::Value =
        serde_json::from_slice(&registry_bytes).map_err(|e| WidgetSyncErr {
            error: format!("shipped templates registry.json is not valid JSON: {e}"),
            target: registry_path.to_string_lossy().into_owned(),
        })?;
    if !manifest.is_object() || !registry.is_object() {
        return Err(WidgetSyncErr {
            error: "shipped templates manifest.json/registry.json must both be JSON objects \
                    keyed by song name — refusing to write a malformed manifest.json/\
                    registry.json"
                .to_string(),
            target: templates.to_string_lossy().into_owned(),
        });
    }

    // Layer 2: overlay the EXISTING on-disk entries for every song that
    // still has a directory in the host songbook — see this function's own
    // doc for why (composed songs live outside the frozen baseline).
    overlay_surviving_entries(&mut manifest, &run_qml.join("songs").join("manifest.json"));
    overlay_surviving_entries(&mut registry, &run_qml.join("songs").join("registry.json"));

    // Layer 3: patch — `name`'s own entry always wins over both the
    // baseline and the overlay — but only when there IS a songbook directory
    // to scan. A shipped song staged straight from the declared twin
    // (`song/declared/livery.json`) on a host whose runtime songbook never
    // seeded it has nothing local to scan, and its baked baseline entry is
    // the truth; an empty patch here deleted sonata from osaka's manifest
    // and blanked every surface.
    if aoide_storage::fs::songbook_dir(name).is_dir() {
        let (own_manifest, own_registry) = scan_own_entry(name)?;
        let manifest_obj = manifest.as_object_mut().expect("checked is_object above");
        // Only songs with at least one slot appear in manifest.json (the same
        // asymmetry `lib/songbook.nix`'s own comment documents) — an empty
        // scan removes any stale entry for `name` rather than writing `{}`.
        match own_manifest.as_object() {
            Some(m) if !m.is_empty() => {
                manifest_obj.insert(name.to_string(), own_manifest);
            }
            _ => {
                manifest_obj.remove(name);
            }
        }
        let registry_obj = registry.as_object_mut().expect("checked is_object above");
        // registry.json keeps EVERY committed song, `{}` when it declares
        // nothing — always inserted, never conditionally removed.
        registry_obj.insert(name.to_string(), own_registry);
    }

    Ok(SongbookEval { manifest, registry })
}

/// Layer 2 of [`eval_songbook_from_templates`]'s merge: copy every entry
/// from the EXISTING on-disk file at `existing_path` into `target` (already
/// validated as a JSON object by the caller) — but ONLY for a song that
/// still has a directory under [`aoide_storage::fs::songbook_dir`] in the
/// host songbook. A song whose directory was since removed is silently
/// skipped, which is the prune: its entry has nowhere to survive from (not
/// in the frozen baseline, not in the on-disk overlay), so it simply isn't
/// present in the merged result — never an immortal stale key.
///
/// A missing or corrupt `existing_path` is treated as "nothing to overlay"
/// (the same "tolerate as empty" posture `undying::load_undying`/
/// `node_store`'s own loaders hold for their files) — this is a best-effort
/// preservation layer over what's already on disk, not a durable store of
/// its own; the baseline and the layer-3 patch are what makes every call
/// correct regardless of what this step finds.
fn overlay_surviving_entries(target: &mut serde_json::Value, existing_path: &Path) {
    let Ok(raw) = std::fs::read_to_string(existing_path) else {
        return;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let Some(existing_obj) = parsed.as_object() else {
        return;
    };
    let target_obj = target
        .as_object_mut()
        .expect("eval_songbook_from_templates already validated `target` is an object");
    for (song, entry) in existing_obj {
        if aoide_storage::fs::songbook_dir(song).is_dir() {
            target_obj.insert(song.clone(), entry.clone());
        }
    }
}

/// `name`'s own manifest/registry entry, computed directly from its
/// committed songbook directory with no nix involved — the same "no
/// `_widgets/` shelf" formula `lib/songbook.nix`'s `songMeta` uses per song
/// (owner is always the song itself, `file` is always `<slot>.qml`; the
/// registry falls back to `livery.json`'s `.widgets // {}`). `rice compose`
/// never writes a `_widgets/` shelf, so this is the ONLY shape a freshly
/// composed song can ever have — [`eval_songbook_from_templates`] checks for
/// a shelf and refuses before ever calling this.
fn scan_own_entry(name: &str) -> Result<(serde_json::Value, serde_json::Value), WidgetSyncErr> {
    let song_dir = aoide_storage::fs::songbook_dir(name);

    let widgets_dir = song_dir.join("widgets");
    let manifest_entry = if widgets_dir.is_dir() {
        let slots = scan_slot_names(&widgets_dir)?;
        let mut m = serde_json::Map::new();
        for slot in slots {
            m.insert(
                slot.clone(),
                serde_json::json!({ "owner": name, "file": format!("{slot}.qml") }),
            );
        }
        serde_json::Value::Object(m)
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    let livery_path = song_dir.join("livery.json");
    let registry_entry = if livery_path.is_file() {
        let raw = std::fs::read_to_string(&livery_path).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: livery_path.to_string_lossy().into_owned(),
        })?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|e| WidgetSyncErr {
            error: format!("{}'s livery.json is not valid JSON: {e}", song_dir.display()),
            target: livery_path.to_string_lossy().into_owned(),
        })?;
        parsed
            .get("widgets")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()))
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    Ok((manifest_entry, registry_entry))
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

/// Capture `<song>/songbook/<name>/widgets/` as `{ "<relative path>":
/// "<utf-8 content>" }` — the take store's own widget-body payload (`lyra
/// reload` design, settled 2026-08-31: "Takes gain WIDGET BODIES in both
/// modes", closing the gap that widget QML was never snapshotted). Reads
/// the SONGBOOK tree, the same source [`sync_song_widgets`] itself copies
/// from — not the deployed `run/qml` copy — because widget bodies are
/// song-scoped git substrate (this module's own header), the same source of
/// truth a take is meant to remember. An absent `widgets/` dir captures as
/// `{}` (no widgets), the same clean-skip [`sync_song_widgets`] uses for a
/// missing local tree. Unfiltered, recursive, matching
/// [`copy_tree_atomic`]'s own walk (helper components, asset subdirs,
/// `.gitkeep`, everything) — a take is a full-content snapshot, not a
/// filtered one. A non-UTF-8 file is a hard error: QML source is always
/// text, so an unreadable file here means something is already wrong, not
/// something to silently skip.
pub fn snapshot_widget_bodies(song: &str) -> Result<serde_json::Value, WidgetSyncErr> {
    let src = aoide_storage::fs::songbook_dir(song).join("widgets");
    let mut map = serde_json::Map::new();
    if src.is_dir() {
        capture_tree(&src, &src, &mut map)?;
    }
    Ok(serde_json::Value::Object(map))
}

/// [`snapshot_widget_bodies`]'s own recursive walk: `root` stays fixed
/// across the recursion (every captured key is relative to it), `dir` is
/// the directory currently being read.
fn capture_tree(
    root: &Path,
    dir: &Path,
    out: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), WidgetSyncErr> {
    let entries = std::fs::read_dir(dir).map_err(|e| WidgetSyncErr {
        error: e.to_string(),
        target: dir.to_string_lossy().into_owned(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: dir.to_string_lossy().into_owned(),
        })?;
        let file_type = entry.file_type().map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: entry.path().to_string_lossy().into_owned(),
        })?;
        let path = entry.path();
        if file_type.is_dir() {
            capture_tree(root, &path, out)?;
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| WidgetSyncErr {
            error: e.to_string(),
            target: path.to_string_lossy().into_owned(),
        })?;
        let text = String::from_utf8(bytes).map_err(|e| WidgetSyncErr {
            error: format!("{} is not valid UTF-8, cannot snapshot: {e}", path.display()),
            target: path.to_string_lossy().into_owned(),
        })?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        out.insert(rel, serde_json::Value::String(text));
    }
    Ok(())
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

    regenerate_manifest(name, &run_qml, &mut changed)?;

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
/// every committed song's owner-map entry, replacing the file outright. On
/// a checkout host the eval is total: a stale or malformed entry for ANY
/// song, not just the one being staged, self-heals on every call. On a
/// repo-less host [`eval_songbook_from_templates`]'s three-layer merge
/// self-heals the STAGED song's own entry on every call and preserves every
/// other still-live song's entry from the file this write is about to
/// replace (see that function's own doc).
fn regenerate_manifest(name: &str, run_qml: &Path, changed: &mut Vec<String>) -> Result<(), WidgetSyncErr> {
    let eval = eval_songbook(name, run_qml)?;
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
/// generator, invoked twice"). Same posture as [`regenerate_manifest`]: a
/// checkout host's eval is total (every committed song's registry entry
/// comes from THIS eval, every time); a repo-less host's merge self-heals
/// the staged song and preserves every other still-live song's entry from
/// the file this write is about to replace.
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

    let eval = eval_songbook(name, &run_qml)?;
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
