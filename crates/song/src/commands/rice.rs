//! `rice lint` / `rice stage` / `rice compose` — the self-ricing loop
//! (concepts/Self-Ricing). `rice declare`/`rice transpose` are still
//! walking-skeleton stubs; their metadata lives in `commands/stubs.rs`.
//! `rice gen` (a speculative prompt/wallpaper generator) was cut outright
//! (khoa 2026-08-14) — never built, no design for it existed; `rice compose`
//! is the real scaffolding entry point.

use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use crate::notes;
use aoide_storage::fs as shellbridge;
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "lint"],
        summary: "Validate a rice against the note schema (native livery engine).",
        args: [arg!("name", "string", false, "Rice/song name to lint; defaults to the staged rice.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_rice_lint,
    ));
    r.insert(cmd!(
        path: ["rice", "stage"],
        summary: "Hot-load a rice live — ALWAYS the declared committed content, ignoring any saved draft (stage/livery.json hot-reload + best-effort hyprctl geometry/border apply); nothing committed. No <name>: re-stages the currently active song's declared content, overriding whatever draft `rice mode stage` may have auto-loaded. Refuses while `rice mode declarative` is locked.",
        args: [arg!("name", "string", false, "Rice/song name to stage; defaults to the currently active song's declared content.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_rice_stage_entry,
    ));
    r.insert(cmd!(
        path: ["rice", "compose"],
        summary: "Scaffold a new song under song/songbook/<name>/ by copying --from's notes (rice.nix, livery.json, design/intent.md, widgets/).",
        args: [arg!("name", "string", true, "New song name: ^[a-z0-9][a-z0-9-]*$ (lowercase, digits, hyphens).")],
        flags: [
            flag!("from", "string", "Source song to copy notes from (default \"sonata\")."),
            flag!("force", "bool", "Overwrite the song's scaffolded files if it already exists."),
        ],
        gated: false,
        implemented: true,
        handler: handle_rice_compose,
        examples: ["rice compose moonlight --from sonata"],
    ));
}

/// Resolve the `livery.json` a `rice` verb should act on:
///
/// * **no arg** — the staged notes (`<stage>/livery.json`) if present, else
///   a usage error (exit 2). We never lint with no file.
/// * **an arg that names an existing file** — taken as a literal path.
/// * **otherwise the arg is a committed-song NAME** →
///   `<song>/songbook/<name>/livery.json` (resolved through the same stage-dir
///   seam as `graph emit`, so an `AOIDE_STAGE_DIR` override relocates it too).
///
/// The `livery` verb group (`commands/livery.rs`) re-implements this SAME rule
/// as its own `resolve_notes` with a `skip` offset (its `emit` takes the target
/// first) — two implementations, one rule. Kept `pub(crate)` so that seam stays
/// reachable crate-internally.
pub(crate) fn resolve_rice_notes(inv: &Invocation, cmd: &str) -> Result<PathBuf, Outcome> {
    match inv.args.first() {
        None => {
            let staged = shellbridge::stage_dir().join("livery.json");
            if staged.is_file() {
                Ok(staged)
            } else {
                Err(Outcome::usage(
                    cmd,
                    format!(
                        "no rice named and no staged notes at {}; \
                         usage: aoide rice lint [<name>|<path>] [--json]",
                        staged.display()
                    ),
                )
                .with_data(json!({
                    "reason": "no-staged-notes",
                    "expected": staged.to_string_lossy(),
                })))
            }
        }
        Some(arg) => {
            // An existing path wins as a literal; otherwise treat it as a name.
            let literal = PathBuf::from(arg);
            if literal.is_file() {
                Ok(literal)
            } else {
                Ok(shellbridge::songbook_notes(arg))
            }
        }
    }
}

/// `rice lint [<name>|<path>]` — validate a rice against the note schema.
///
/// Runs the NATIVE `livery::lint` engine in-process — no external binary, no
/// PATH lookup. The no-arg form lints
/// the staged rice; a bare `<name>` resolves to the committed song's notes
/// (never treated as a literal path). An error envelope always carries a
/// non-zero exit (schema failure → exit 1).
fn handle_rice_lint(inv: &Invocation) -> Outcome {
    let target = match resolve_rice_notes(inv, "rice.lint") {
        Ok(p) => p,
        Err(o) => return o,
    };
    let run = notes::run_lint(&target);
    if run.ok {
        Outcome::ok("rice.lint", "note schema validation passed").with_data(json!({
            "notes": target.to_string_lossy(),
            "schemaVersion": crate::livery::SCHEMA_VERSION,
            "engine": "livery",
        }))
    } else {
        // Error status → exit 1 (never a status:error with exit 0).
        Outcome::error("rice.lint", "note schema validation reported problems")
            .with_data(json!({
                "notes": target.to_string_lossy(),
                "errors": run.errors,
            }))
    }
}

/// `rice stage` registry entrypoint — refuses while `rice mode declarative`
/// is locked (`aoide_storage::mode`, khoa 2026-08-14): `rice mode stage`
/// unlocks it first. The pure staging logic stays in [`handle_rice_stage`]
/// itself (`pub(crate)`, kept guard-free) so `rice mode`'s own writes can
/// reuse it directly — including `rice mode declarative <name>`'s re-pin,
/// which legitimately writes WHILE the mode marker is still whatever it was
/// before this call (the marker only flips to `declarative` after that
/// write succeeds).
///
/// No `<name>`: resolves the current song the same way `rice mode stage`'s
/// own no-arg form does ([`super::mode::current_staged_song`], off
/// `stage/livery.json`'s own `"song"` field) and stages its committed
/// content — so "restage the declared truth for whatever's active" never
/// requires retyping the song name. No resolvable song → the same
/// `missing-name` usage error a truly bare call always had.
///
/// **Marker bookkeeping while in `Staging` mode:** on success, updates
/// `mode.json`'s `song` to the name just staged (`draft` stays/becomes
/// `None` — this handler always writes plain declared content, never a
/// draft). **While in `Draft` mode, the marker is left completely
/// untouched.** This is deliberate, not an oversight: `stage/livery.json`
/// may currently be a symlink into `songbook/<song>/drafts/<name>/livery.json`
/// (`rice mode draft`, `commands/mode.rs`), and `handle_rice_stage`'s write
/// below carries zero symlink-awareness — it transparently lands wherever
/// the symlink points (`aoide_storage::fs::atomic_write` is
/// symlink-transparent), so the routing itself is unaffected and the
/// `mode`/`song`/`draft` triple the marker already carries stays accurate.
/// Mutating `song`/`draft` here while `mode` stays `Draft` would violate the
/// "`draft` is `Some` iff `mode == Draft`" invariant if this handler ever
/// diverged from the song the draft actually belongs to — leaving the
/// marker alone sidesteps that entirely. Only `rice mode stage`/`rice mode
/// declarative` ever transition OUT of `Draft` (tearing the symlink down
/// first); this entrypoint is not one of those.
fn handle_rice_stage_entry(inv: &Invocation) -> Outcome {
    let mode_marker = aoide_storage::mode::load_mode_marker();
    if mode_marker.mode == aoide_storage::mode::RiceMode::Declarative {
        return Outcome::error(
            "rice.stage",
            "declarative mode is locked — run `aoide rice mode stage` to unlock hot-loading first",
        )
        .with_data(json!({ "reason": "declarative-mode-locked" }));
    }

    let resolved_inv: Invocation;
    let inv: &Invocation = if inv.args.first().is_some() {
        inv
    } else if let Some(name) = super::mode::current_staged_song() {
        resolved_inv = Invocation {
            path: inv.path.clone(),
            args: vec![name],
            flags: inv.flags.clone(),
            door: inv.door,
        };
        &resolved_inv
    } else {
        inv
    };

    let mut out = handle_rice_stage(inv);

    // Auto-take (phase A3, `references/fleshing-out-aoide-ricing.md` §5.2 —
    // the whole point of the feature: an agent's edits get snapshotted
    // without it having to remember `rice take`, so the take tree reflects
    // what actually happened, not what someone remembered to record). Gated
    // on `mode_marker` — the marker as READ AT THE TOP of this function,
    // before `handle_rice_stage` ran — because this entrypoint deliberately
    // leaves `mode.json` untouched for a Draft-mode write (see this
    // function's own doc comment above); it cannot have changed underneath
    // us. Outside Draft mode there is no draft directory to nest a `takes/`
    // under at all, so nothing fires — `take::resolve_draft` would refuse it
    // anyway, this just skips the call.
    //
    // Unconditional `snapshot`, not the drift-checking core: a take records
    // every write, not just the ones that changed something —
    // `aoide_storage::takes`' own module doc says it plainly ("minted on
    // every rehearsal write"). A content-identical restage still mints. The
    // resulting noise is pruning's problem (`rice take prune`, phase A9,
    // §7.1), not write-time suppression's — suppressing here would make the
    // take tree an incomplete record of what happened, which is a bigger
    // cost than a few prunable duplicates. (The drift-checking core exists
    // for a genuinely different job: `rice back`, a later step, must
    // preserve un-taken edits that are ABOUT TO BE DESTROYED by an
    // overwrite. This hook runs after a write has already landed — nothing
    // is about to be destroyed, so that rationale does not transfer here.)
    // `snapshot` (the locked wrapper) is correct: `handle_rice_stage` just
    // above holds no stage lock of its own for this to nest inside.
    //
    // Non-fatal, same tier as the hyprctl/widget-registry calls inside
    // `handle_rice_stage` itself: a bookkeeping failure must never turn a
    // successful live write into an error, so a failed snapshot is reported
    // in `data` (`"take": null, "takeError": "…"`) rather than flipping
    // `out.status`. The command name passed is `"rice.stage"` (not
    // `"rice.take"`) so a refusal — however unlikely once we're already
    // known to be routed in Draft mode — names the command that actually
    // asked (advisor-flagged known issue, see `commands/take.rs`).
    if out.status == aoide_protocol::output::Status::Ok
        && mode_marker.mode == aoide_storage::mode::RiceMode::Draft
    {
        match super::take::snapshot("rice.stage", "stage") {
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

    if out.status == aoide_protocol::output::Status::Ok
        && mode_marker.mode != aoide_storage::mode::RiceMode::Draft
    {
        if let Some(name) = inv.args.first() {
            let updated = aoide_storage::mode::ModeMarker {
                mode: mode_marker.mode,
                song: Some(name.clone()),
                draft: None,
                // Out of scope for this entrypoint (the direct, guard-checked
                // `rice stage <name>` CLI, not `rice mode stage`) — carry the
                // existing "what was I staging" memory forward unchanged
                // rather than deriving a new opinion about it here.
                staging_song: mode_marker.staging_song,
                since: mode_marker.since,
            };
            if aoide_storage::mode::save_mode_marker(&updated).is_ok() {
                out.changed
                    .push(aoide_storage::mode::mode_marker_path().to_string_lossy().into_owned());
            }
        }
    }
    out
}

/// `rice stage <name>` — hot-load a committed song live: stage its
/// `livery.json` (plus a derivable cover) into `<stage>/` so the Quickshell
/// surfaces hot-reload it, AND best-effort live-apply its geometry + border
/// colours to the running compositor via `hyprctl --batch keyword …`
/// (guarded on `$HYPRLAND_INSTANCE_SIGNATURE`; see hypr.rs). ALSO syncs the
/// song's widget QML bodies (`song/songbook/<name>/widgets/*.qml`) into the
/// live runtime tree (`run/qml/songs/<name>/`, `crate::widgets`) so
/// Quickshell's own file-watcher hot-reloads an edited EXISTING widget file
/// too — no rebuild for that either (a brand-new widget file still needs a
/// service restart to be discovered). Nothing is committed; the hyprctl
/// call is keyword-only (never `reload`) and never fatal — a failed/absent
/// hyprctl still leaves the stage file updated.
///
/// This is the honest form of the hand-copy agents had been doing: drive the
/// songbook notes into the stage so the shell has a palette to render.
///
/// `pub(crate)`, not private: `rice mode`'s `stage`/`declarative` handlers
/// (`commands/mode.rs`) call this directly to get the SAME live-apply side
/// effects a bare `rice stage <name>` has, rather than reimplementing them
/// — it hands this the identical `Invocation` it was given (both commands
/// take the song name as their first positional arg, and this function reads
/// nothing else off `inv`), so no adapter/duplication is needed. Writes
/// through `aoide_storage::fs::atomic_write`, which is symlink-transparent —
/// while `stage/livery.json` is routed into a draft (`rice mode draft`,
/// `Draft` mode), this function's write lands straight in the draft file
/// with zero symlink-awareness needed here, which is the entire mechanism.
pub(crate) fn handle_rice_stage(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage("rice.stage", "usage: aoide rice stage <name> [--json]")
                .with_data(json!({ "reason": "missing-name" }));
        }
    };
    // Same guard `rice compose` applies to its own `<name>`: this string is
    // joined straight into `songbook_notes(&name)` below (a read path — an
    // unvalidated `../../x` would let `rice stage` read any JSON-parseable
    // file on the box) AND gets written verbatim into the staged notes'
    // `"song"` field, which `current_staged_song()` later trusts for
    // `draft`/`mode` verbs' own path-building. Reject it here, once, at the
    // source.
    if !crate::compose::valid_song_name(&name) {
        return Outcome::error(
            "rice.stage",
            format!(
                "`{name}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }

    let notes_src = shellbridge::songbook_notes(&name);
    let raw = match std::fs::read_to_string(&notes_src) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(
                "rice.stage",
                format!("no song `{name}`: cannot read {} ({e})", notes_src.display()),
            )
            .with_data(json!({
                "reason": "song-not-found",
                "name": name,
                "expected": notes_src.to_string_lossy(),
            }));
        }
    };
    // Never stage a torn palette: require the notes to at least parse as JSON
    // (full schema validation is `rice lint`'s job — the livery engine).
    let parsed: Value = match serde_json::from_str::<Value>(&raw) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(
                "rice.stage",
                format!("notes for `{name}` are not valid JSON: {e}"),
            )
            .with_data(json!({
                "reason": "invalid-json",
                "name": name,
                "notes": notes_src.to_string_lossy(),
            }));
        }
    };

    // Compute the compositor keyword batch BEFORE `parsed` is consumed below
    // (geometry + border colours only — see hypr.rs for why an absent/null
    // geometry field is skipped rather than defaulted).
    let hypr_keywords = crate::live::geometry_keywords(&parsed);

    // Inject the song name into the staged notes: LiveryState.qml's
    // `songName` property reads this to resolve per-song flavor widgets
    // (StagingEngine.qml / WidgetSlot.qml) — CONTRACTS.md §4's "additive"
    // precedent (mirrors `parentSessionId` on session records). When the
    // notes don't parse as an object (shouldn't happen for a valid notes
    // file, but defends against a malformed one), fall back to writing `raw`
    // unchanged rather than fabricating a shape.
    let staged = match parsed {
        Value::Object(mut obj) => {
            obj.insert("song".to_string(), json!(name));
            serde_json::to_string_pretty(&Value::Object(obj)).unwrap_or(raw.clone()) + "\n"
        }
        _ => raw.clone(),
    };

    let stage = shellbridge::stage_dir();
    let notes_dst = stage.join("livery.json");
    if let Err(e) = shellbridge::atomic_write(&notes_dst, &staged) {
        return Outcome::error("rice.stage", format!("failed to stage livery.json: {e}"))
            .with_data(json!({ "reason": "stage-write-failed", "target": notes_dst.to_string_lossy() }));
    }
    let mut changed: Vec<String> = vec![notes_dst.to_string_lossy().into_owned()];

    // Live-apply geometry + border colours on the compositor side (best-effort,
    // guarded, non-fatal). The stage-file write above is already the source of
    // truth for the hot-reload half (Quickshell's FileView); this hyprctl call
    // is on top of it, never a precondition for it — a failed/absent hyprctl
    // never turns this preview into an error. No `hyprctl reload`: see hypr.rs.
    let hyprctl_status = crate::live::apply_live(&hypr_keywords);

    // Cover: staged only when physically derivable; otherwise left untouched.
    let cover = crate::cover::derive_cover(&name);
    let cover_note = match &cover {
        Some(path) => {
            let cover_dst = stage.join("cover.json");
            let body = serde_json::to_string_pretty(&json!({ "path": path.to_string_lossy() }))
                .unwrap_or_default()
                + "\n";
            if let Err(e) = shellbridge::atomic_write(&cover_dst, &body) {
                return Outcome::error(
                    "rice.stage",
                    format!("failed to stage cover.json: {e}"),
                )
                .with_data(json!({ "reason": "stage-write-failed", "target": cover_dst.to_string_lossy() }));
            }
            changed.push(cover_dst.to_string_lossy().into_owned());
            format!("staged cover {}", path.display())
        }
        None => "no derivable cover; cover.json left untouched".to_string(),
    };

    // Captured BEFORE the widget sync below so the outcome message's "N
    // stage file(s) live for hot-reload" clause keeps meaning "stage-dir
    // files" — widget bodies get their own clause, not folded into this count.
    let stage_file_count = changed.len();

    // Widget bodies: the runtime-tree half of `rice stage` — carries
    // song/songbook/<name>/widgets/*.qml into run/qml/songs/<name>/ so
    // Quickshell's own file-watcher hot-reloads an edited EXISTING widget
    // file too, no rebuild. Fatal on failure, mirroring the cover-write
    // IO-failure path above: a torn widget copy/manifest write is worse
    // than refusing the whole call.
    let widget_sync = match crate::widgets::sync_song_widgets(&name) {
        Ok(sync) => sync,
        Err(e) => {
            return Outcome::error(
                "rice.stage",
                format!("failed to sync widget bodies: {}", e.error),
            )
            .with_data(json!({ "reason": "widget-sync-failed", "target": e.target }));
        }
    };
    let widget_sync_changed = !widget_sync.changed.is_empty();
    changed.extend(widget_sync.changed);

    // Widget-TYPE registry (Phase 3): the runtime hot-sync counterpart to
    // Phase 2's build-time registry.json walk — rewrites this song's entry
    // from its current livery.json `.widgets` key. Same call site, same
    // trigger (unconditional on `rice stage`/`preview`), same fatal-on-IO
    // posture as the widget-body sync just above.
    let registry_sync = match crate::widgets::sync_song_registry(&name) {
        Ok(sync) => sync,
        Err(e) => {
            return Outcome::error(
                "rice.stage",
                format!("failed to sync widget-type registry: {}", e.error),
            )
            .with_data(json!({ "reason": "registry-sync-failed", "target": e.target }));
        }
    };
    changed.extend(registry_sync.changed);

    // Quickshell IPC hot-reload (best-effort, non-fatal — same tier as
    // hyprctl_status above). The palette/notes tier written above is
    // already covered by LiveryState's own FileView watch — a full-scene
    // rebuild is only worth it when the widget-body sync (dynamically
    // `Qt.createComponent`-loaded QML, which no file watcher tracks) wrote
    // something. A total widget-sync no-op re-stage never reloads.
    let reload_data = if widget_sync_changed {
        let status = crate::ipc::quickshell_ipc_reload();
        json!({ "status": status.tag(), "message": status.message() })
    } else {
        json!({
            "status": "skipped",
            "message": "no widget bodies changed; nothing to reload",
        })
    };

    Outcome::ok(
        "rice.stage",
        format!(
            "staged `{name}` — {stage_file_count} stage file(s) live for hot-reload; \
             {cover_note}; {}",
            widget_sync.note
        ),
    )
    .changed(changed)
    .with_data(json!({
        "name": name,
        "notes": notes_dst.to_string_lossy(),
        "cover": cover.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "hyprctl": hyprctl_status,
        "widgets": widget_sync.note,
        "slots": widget_sync.slots,
        "registry": registry_sync.note,
        "reload": reload_data,
        "seam": "Quickshell hot-reloads stage/livery.json (palette + component tiers); \
                 geometry + border colours are ALSO applied \
                 live via best-effort, guarded `hyprctl --batch keyword …` (see hypr.rs) \
                 — keyword-only, never `hyprctl reload`",
    }))
}

/// `rice compose <name> [--from <song>] [--force]` — scaffold a new
/// committed song under `song/songbook/<name>/` by copying an existing
/// song's notes.
///
/// Writes ONLY inside `song/songbook/<name>/` (house rule 1): `rice.nix` (a
/// self-gating skeleton — the sole `.nix` file, satisfying `checks.song-shape`),
/// `livery.json` (a mirror of `--from`'s, INCLUDING any geometry block, so
/// `aoide rice stage <name>` renders + live-applies immediately),
/// `design/intent.md` (honest-empty — no fabricated rationale), and
/// `widgets/.gitkeep` (no per-song widgets yet). No `hypr/` dir: geometry
/// lives in the livery tier, not a build fragment.
fn handle_rice_compose(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage(
                "rice.compose",
                "usage: aoide rice compose <name> [--from <song>] [--force] [--json]",
            )
            .with_data(json!({ "reason": "missing-name" }));
        }
    };

    if !crate::compose::valid_song_name(&name) {
        return Outcome::error(
            "rice.compose",
            format!(
                "`{name}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-name", "name": name }));
    }

    let from = inv
        .flags
        .get("from")
        .cloned()
        .unwrap_or_else(|| "sonata".to_string());

    if !crate::compose::valid_song_name(&from) {
        return Outcome::error(
            "rice.compose",
            format!(
                "`--from {from}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-from", "from": from }));
    }
    if from == name {
        return Outcome::error(
            "rice.compose",
            format!("`--from` cannot be `{name}` itself — nothing to copy from"),
        )
        .with_data(json!({ "reason": "from-equals-name", "name": name }));
    }

    let force = inv.flag_present("force");

    let target = shellbridge::songbook_dir(&name);
    if target.exists() && !force {
        return Outcome::error(
            "rice.compose",
            format!(
                "song `{name}` already exists at {} (pass --force to overwrite)",
                target.display()
            ),
        )
        .with_data(json!({
            "reason": "already-exists",
            "name": name,
            "path": target.to_string_lossy(),
        }));
    }

    let from_notes_path = shellbridge::songbook_notes(&from);
    let raw_notes = match std::fs::read_to_string(&from_notes_path) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(
                "rice.compose",
                format!(
                    "--from song `{from}` not found: cannot read {} ({e})",
                    from_notes_path.display()
                ),
            )
            .with_data(json!({
                "reason": "from-song-not-found",
                "from": from,
                "expected": from_notes_path.to_string_lossy(),
            }));
        }
    };
    let from_parsed: Value = match serde_json::from_str(&raw_notes) {
        Ok(v) => v,
        Err(e) => {
            return Outcome::error(
                "rice.compose",
                format!("--from song `{from}`'s notes are not valid JSON: {e}"),
            )
            .with_data(json!({
                "reason": "invalid-json",
                "from": from,
                "notes": from_notes_path.to_string_lossy(),
            }));
        }
    };

    let rice_nix = crate::compose::render_rice_nix(&name, &from, &from_parsed);
    let intent_md = crate::compose::render_intent_md(&name, &from);

    let writes: [(PathBuf, String); 4] = [
        (target.join("rice.nix"), rice_nix),
        (target.join("livery.json"), raw_notes.clone()),
        (target.join("design").join("intent.md"), intent_md),
        (target.join("widgets").join(".gitkeep"), String::new()),
    ];
    let mut changed: Vec<String> = Vec::new();
    for (path, contents) in &writes {
        if let Err(e) = shellbridge::atomic_write(path, contents) {
            return Outcome::error(
                "rice.compose",
                format!("failed to write {}: {e}", path.display()),
            )
            .with_data(json!({ "reason": "write-failed", "target": path.to_string_lossy() }));
        }
        changed.push(path.to_string_lossy().into_owned());
    }

    Outcome::ok(
        "rice.compose",
        format!(
            "composed song `{name}` from `{from}` — {} file(s) written under {}",
            changed.len(),
            target.display()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "name": name,
        "from": from,
        "nextSteps": [
            format!("truth: set aoide.song = \"{name}\" in the host's default.nix and rebuild"),
            format!("sketch: `aoide rice stage {name}` to hot-load it live, no rebuild"),
        ],
    }))
}

// ── Tests (rice lint resolution + rice stage staging + rice compose) ────────
#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::*;
    use aoide_protocol::output::Status;

    #[test]
    fn lint_no_arg_without_staged_notes_is_usage_exit_2() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("lint-nostage"); // exists, but no livery.json
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[]));
        assert_eq!(out.status, Status::Usage, "no-arg + no staged notes → usage");
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn lint_no_arg_resolves_staged_default_and_passes_natively() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("lint-staged");
        std::fs::write(stage.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[]));
        // Resolved the STAGED default (else this would be a Usage error), and
        // the native engine validates it in-process — Ok, exit 0, no binary.
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::OK);
        let data = out.data.unwrap();
        let notes = data["notes"].as_str().unwrap().to_string();
        assert!(notes.ends_with("livery.json"), "lint targeted the staged notes: {notes}");
        assert!(notes.starts_with(stage.to_str().unwrap()));
        assert_eq!(data["schemaVersion"], "0");
        assert_eq!(data["engine"], "livery");
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn lint_bare_name_resolves_to_songbook_notes_not_a_literal_path() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("lint-name");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // `moonlight` is a NAME, not a path — it must resolve under songbook/.
        let out = handle_rice_lint(&inv(&["rice", "lint"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "songbook notes lint natively");
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert!(
            notes.ends_with("songbook/moonlight/livery.json"),
            "bare name resolved to the songbook song: {notes}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lint_existing_path_arg_is_taken_literally() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("lint-path");
        let file = root.join("elsewhere.json");
        std::fs::write(&file, VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[file.to_str().unwrap()]));
        assert_eq!(out.status, Status::Ok, "an existing path lints literally");
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert_eq!(notes, file.to_string_lossy(), "an existing path is literal");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lint_invalid_notes_report_the_schema_errors_natively() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("lint-invalid");
        let file = root.join("bad.json");
        std::fs::write(&file, r##"{ "palette": { "bg": "#nope" } }"##).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[file.to_str().unwrap()]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        let errors = out.data.unwrap()["errors"].as_array().unwrap().clone();
        assert!(
            errors.iter().any(|e| e.as_str().unwrap().contains("palette.bg")),
            "schema errors surface natively: {errors:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_writes_notes_and_reports_no_derivable_cover() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-ok");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        // livery.json landed in the stage with the song name injected, its
        // original fields (e.g. the palette) survived the round-trip, and no
        // legacy mirror is written any more (Phase 4 dropped it).
        let staged = std::fs::read_to_string(stage.join("livery.json")).unwrap();
        let parsed: Value = serde_json::from_str(&staged).unwrap();
        assert_eq!(parsed["song"], "moonlight");
        assert_eq!(parsed["palette"]["bg"], "#0b1021");
        assert_eq!(
            out.changed.len(),
            1,
            "only livery.json is staged — no legacy mirror (Phase 4)"
        );
        assert!(out
            .changed
            .iter()
            .any(|c| c.ends_with("stage/livery.json")));
        // No cover exists for moonlight → cover.json is left untouched.
        assert!(!stage.join("cover.json").exists());
        assert!(out.data.unwrap()["cover"].is_null());
        assert!(out.message.contains("cover.json left untouched"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_writes_a_derivable_cover_from_the_covers_library() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-cover");
        let stage = root.join("stage");
        let song = root.join("songbook").join("dusk");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(covers.join("dusk.png"), b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["dusk"]));
        assert_eq!(out.status, Status::Ok);
        let cover = std::fs::read_to_string(stage.join("cover.json")).unwrap();
        assert!(cover.contains("dusk.png"), "cover.json points at the derived file");
        assert!(out.changed.iter().any(|c| c.ends_with("cover.json")));
        let data = out.data.unwrap();
        assert!(data["cover"].as_str().unwrap().ends_with("covers/dusk.png"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_missing_song_is_error_exit_1() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("stage-missing").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["nope"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "song-not-found");
    }

    #[test]
    fn stage_missing_name_is_usage_exit_2() {
        let out = handle_rice_stage(&inv(&["rice", "stage"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
    }

    #[test]
    fn stage_rejects_a_path_traversal_name_before_reading_or_writing_anything() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-traversal");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        // A file OUTSIDE songbook/ that a `../../` traversal could reach if
        // the name were joined unvalidated into `songbook_notes(&name)`.
        std::fs::write(root.join("secret.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["../secret"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "invalid-name");
        assert!(!stage.join("livery.json").exists(), "nothing staged from a rejected name");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice stage: the declarative-mode write guard (khoa 2026-08-14) ───────

    #[test]
    fn stage_entry_refuses_while_declarative_mode_is_locked() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-entry-locked");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // No marker file at all IS declarative (the safe default) — the
        // entry must refuse, not silently write.
        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "declarative-mode-locked");
        assert!(!stage.join("livery.json").exists(), "nothing staged while locked");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_entry_allows_writes_once_staging_mode_is_unlocked() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-entry-unlocked");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Staging,
            ..Default::default()
        })
        .unwrap();

        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(stage.join("livery.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice stage: bare form auto-resolves the current song (khoa
    // ── 2026-08-14) — same "no name = current song" convenience `rice mode
    // ── stage` already documents its own no-arg form with ─────────────────

    #[test]
    fn stage_entry_with_no_name_resolves_the_current_song() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-entry-bare-resolve");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        // The stage already carries the "song" breadcrumb `current_staged_song`
        // reads, as if a prior `rice mode stage moonlight` had run.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"moonlight",
                "palette":{"bg":"#111111","fg":"#000000","accent":"#000000","urgent":"#000000"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Staging,
            ..Default::default()
        })
        .unwrap();

        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let restaged = std::fs::read_to_string(stage.join("livery.json")).unwrap();
        assert!(restaged.contains("#82aaff"), "VALID_NOTES's declared accent landed: {restaged}");
        let marker = aoide_storage::mode::load_mode_marker();
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert_eq!(marker.draft, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_entry_while_in_draft_mode_writes_through_the_symlink_and_leaves_the_marker_untouched() {
        // The new mechanism (khoa 2026-08-14): `rice stage` carries zero
        // symlink-awareness. If `stage/livery.json` is CURRENTLY routed into
        // a draft (`rice mode draft`, `Draft` mode), a plain `rice stage
        // <name>` call still writes its declared content — but that write
        // transparently lands in the draft file (atomic_write is
        // symlink-transparent), and this entrypoint deliberately leaves
        // `mode.json` completely alone: the routing (mode/song/draft) is
        // unaffected by this write, so touching the marker here would be
        // both unnecessary and risk contradicting it.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("stage-entry-draft-mode-symlink");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        let draft_dir = song.join("drafts").join("neon-night");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::create_dir_all(&draft_dir).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        let draft_livery = draft_dir.join("livery.json");
        std::fs::write(&draft_livery, "stale draft content").unwrap();
        std::os::unix::fs::symlink(&draft_livery, stage.join("livery.json")).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Draft,
            song: Some("moonlight".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();

        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        // The symlink itself survives, and the declared content landed in
        // the draft file it points at, not a fresh plain file.
        assert!(std::fs::symlink_metadata(stage.join("livery.json")).unwrap().file_type().is_symlink());
        let draft_now = std::fs::read_to_string(&draft_livery).unwrap();
        assert!(draft_now.contains("#82aaff"), "declared content landed in the draft file: {draft_now}");
        // The marker is completely untouched — still Draft, still neon-night.
        let marker = aoide_storage::mode::load_mode_marker();
        assert_eq!(marker.mode, aoide_storage::mode::RiceMode::Draft);
        assert_eq!(marker.song, Some("moonlight".to_string()));
        assert_eq!(marker.draft, Some("neon-night".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice stage: the auto-take hook (phase A3) ────────────────────────

    /// Shared rig for the auto-take tests below: routes `stage/livery.json`
    /// into `songbook/moonlight/drafts/neon-night/livery.json` through a
    /// symlink (the same layout `stage_entry_while_in_draft_mode_…` above
    /// uses) and marks `mode.json` `Draft`. Returns
    /// `(root, stage, song_dir)` — callers write `song_dir/livery.json`
    /// themselves before each `handle_rice_stage_entry` call, matching how
    /// `rice stage <name>` actually gets its content (the COMMITTED
    /// songbook notes, never the previous stage content).
    fn draft_routed_for_auto_take(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = unique_tmp(tag);
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        let draft_dir = song.join("drafts").join("neon-night");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::create_dir_all(&draft_dir).unwrap();
        let draft_livery = draft_dir.join("livery.json");
        std::fs::write(&draft_livery, "{}").unwrap();
        std::os::unix::fs::symlink(&draft_livery, stage.join("livery.json")).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Draft,
            song: Some("moonlight".to_string()),
            draft: Some("neon-night".to_string()),
            ..Default::default()
        })
        .unwrap();
        (root, stage, song)
    }

    #[test]
    fn stage_entry_in_draft_mode_mints_an_auto_take_on_a_real_change() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, _stage, song) = draft_routed_for_auto_take("stage-autotake-fires");
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();

        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        // A successful write never turns into an error over take bookkeeping,
        // and here the take succeeded too: reported in `data`, and both the
        // take file and the head cursor are in `changed`.
        assert_eq!(out.data.as_ref().unwrap()["take"], 1);
        assert!(out.changed.iter().any(|c| c.ends_with("takes/0001.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("takes/head.json")));

        let record = aoide_storage::takes::load_take("moonlight", "neon-night", 1).unwrap();
        assert_eq!(record.cause, "stage", "auto-take from rice stage carries cause \"stage\"");
        assert_eq!(record.parent, None, "first take in an empty store has no parent");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_entry_in_draft_mode_mints_again_on_a_content_identical_restage() {
        // The pinned invariant (orchestrator correction over this step's own
        // earlier draft): a take records EVERY write, not just the ones that
        // changed something. A `rice stage` re-run with unchanged committed
        // notes produces byte-identical content to what take 1 already
        // holds — it must STILL mint. Suppressing on no drift would make the
        // take tree an incomplete record of write events; the resulting
        // duplicate-take noise is `rice take prune`'s problem (phase A9),
        // not this hook's.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, _stage, song) = draft_routed_for_auto_take("stage-autotake-repeat");
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();

        let first = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(first.status, Status::Ok, "{:?}", first.data);
        assert_eq!(first.data.unwrap()["take"], 1);

        let second = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(second.status, Status::Ok, "{:?}", second.data);
        assert_eq!(
            second.data.unwrap()["take"], 2,
            "a content-identical restage still mints its own take"
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

    #[test]
    fn stage_entry_with_no_name_and_nothing_resolvable_is_usage_exit_2() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("stage-entry-bare-unresolvable").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Staging,
            ..Default::default()
        })
        .unwrap();

        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
        let _ = std::fs::remove_dir_all(&stage);
    }

    // ── rice stage: the hyprctl live-apply guard (Phase F) ───────────────────

    #[test]
    fn stage_off_hyprland_skips_hyprctl_without_panicking() {
        // The common test path: no compositor, `hyprctl` may not even exist on
        // PATH — the guard must trip on the env var alone, never touching the
        // process spawn.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let root = unique_tmp("stage-hypr-off");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), NOTES_WITH_WINDOW).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(
            out.data.unwrap()["hyprctl"],
            "skipped (HYPRLAND_INSTANCE_SIGNATURE unset)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_with_no_window_or_geometry_reports_an_empty_batch() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let root = unique_tmp("stage-hypr-empty");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(
            out.data.unwrap()["hyprctl"],
            "skipped (no geometry/border keywords resolved)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice stage: widget-body runtime sync (the widgets.rs module) ─────────
    //
    // `run_qml_dir()` resolves ONE LEVEL ABOVE `song_dir()`
    // (aoide_storage::fs::run_qml_dir): `song_dir()` is `stage_dir()`'s
    // parent, and `run_qml_dir()` is `song_dir()`'s parent joined with
    // `run/qml`. Every OTHER test in this file uses a 2-level layout
    // (`<root>/stage`, `<root>/songbook/<name>`), under which `run/qml`
    // would resolve OUTSIDE the test's own tmp root (a sibling of `<root>`
    // itself) — fine for tests that never touch it, but wrong for these.
    // `widget_sync_tmp` adds one more level (`<root>/aoide/…`) so
    // `run_qml_dir()` lands under the SAME per-test root as `song/stage`/
    // `song/songbook`, keeping these tests isolated from each other and
    // from any stray `/tmp/run` a prior run might have left behind.

    /// Builds the 3-level tmp layout the widget-sync tests need. Returns
    /// `(root, stage, run_qml)`; callers still
    /// `std::env::set_var("AOIDE_STAGE_DIR", &stage)` themselves (matching
    /// every other test here) and own `remove_dir_all(&root)` at the end.
    fn widget_sync_tmp(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = unique_tmp(tag);
        let aoide_root = root.join("aoide");
        let stage = aoide_root.join("song").join("stage");
        let run_qml = aoide_root.join("run").join("qml");
        std::fs::create_dir_all(&stage).unwrap();
        (root, stage, run_qml)
    }

    #[test]
    fn stage_syncs_an_edited_widget_body_into_the_runtime_tree() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-widget-edit");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("widgets").join("bar.qml"), "// new bar body\n").unwrap();
        let runtime_song_dir = run_qml.join("songs").join("moonlight");
        std::fs::create_dir_all(&runtime_song_dir).unwrap();
        std::fs::write(runtime_song_dir.join("bar.qml"), "// stale bar body\n").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(
            std::fs::read_to_string(runtime_song_dir.join("bar.qml")).unwrap(),
            "// new bar body\n"
        );
        assert!(
            out.changed.iter().any(|c| c.ends_with("run/qml/songs/moonlight/bar.qml")),
            "the synced runtime widget is reported changed: {:?}",
            out.changed
        );
        let data = out.data.unwrap();
        assert_eq!(data["slots"], json!(["bar"]));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_leaves_an_unchanged_widget_body_untouched() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-widget-unchanged");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        let body = "// stable bar body\n";
        std::fs::write(song.join("widgets").join("bar.qml"), body).unwrap();
        let runtime_song_dir = run_qml.join("songs").join("moonlight");
        std::fs::create_dir_all(&runtime_song_dir).unwrap();
        std::fs::write(runtime_song_dir.join("bar.qml"), body).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            !out.changed.iter().any(|c| c.ends_with("run/qml/songs/moonlight/bar.qml")),
            "a byte-identical widget body must not be reported as changed: {:?}",
            out.changed
        );
        assert_eq!(std::fs::read_to_string(runtime_song_dir.join("bar.qml")).unwrap(), body);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_regenerates_the_manifest_for_a_newly_present_slot() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-widget-manifest");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("widgets").join("bar.qml"), "// bar\n").unwrap();
        std::fs::write(song.join("widgets").join("calendar.qml"), "// calendar\n").unwrap();
        let songs_dir = run_qml.join("songs");
        std::fs::create_dir_all(&songs_dir).unwrap();
        std::fs::write(
            songs_dir.join("manifest.json"),
            r#"{"moonlight":["bar"],"dusk":["clock"]}"#,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(songs_dir.join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["moonlight"], json!(["bar", "calendar"]));
        assert_eq!(
            manifest["dusk"],
            json!(["clock"]),
            "another song's manifest entry survives the rewrite untouched"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_skips_widget_sync_when_no_runtime_tree_exists() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, _run_qml) = widget_sync_tmp("stage-widget-no-runtime");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("widgets").join("bar.qml"), "// bar\n").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            !out.changed.iter().any(|c| c.contains("/run/qml")),
            "no runtime tree deployed → nothing widget-synced: {:?}",
            out.changed
        );
        assert!(!root.join("aoide").join("run").exists(), "no run/ dir was created");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_skips_widget_sync_when_song_has_no_widgets_dir() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-widget-no-widgets-dir");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::create_dir_all(&run_qml).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        // livery.json is staged and registry.json is (re)synced — a widget
        // TYPE declaration lives in livery.json, not the widgets/ dir, so
        // the registry sync runs independently of it (Phase 3). No widget
        // BODIES are copied though: no widgets/ dir → no per-song run/qml
        // songs/moonlight/ dir.
        assert_eq!(
            out.changed.len(),
            2,
            "no widgets/ dir → no bodies synced, but registry.json still is: {:?}",
            out.changed
        );
        assert!(out.changed.iter().any(|c| c.ends_with("stage/livery.json")));
        assert!(out.changed.iter().any(|c| c.ends_with("run/qml/songs/registry.json")));
        assert!(!run_qml.join("songs").join("moonlight").exists());
        let registry: Value = serde_json::from_str(
            &std::fs::read_to_string(run_qml.join("songs").join("registry.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            registry["moonlight"],
            json!({}),
            "VALID_NOTES carries no .widgets key → registry entry is {{}}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_syncs_a_widget_type_declaration_into_the_registry() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-registry-declare");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        let notes = r##"{ "schemaVersion":"0",
            "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
            "widgets": { "grimoire": { "kind": "surface", "layer": "top" } } }"##;
        std::fs::write(song.join("livery.json"), notes).unwrap();
        std::fs::write(song.join("widgets").join("grimoire.qml"), "// grimoire\n").unwrap();
        std::fs::create_dir_all(&run_qml).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let registry: Value = serde_json::from_str(
            &std::fs::read_to_string(run_qml.join("songs").join("registry.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            registry["moonlight"],
            json!({ "grimoire": { "kind": "surface", "layer": "top" } })
        );
        assert!(
            out.changed.iter().any(|c| c.ends_with("run/qml/songs/registry.json")),
            "registry.json write is reported changed: {:?}",
            out.changed
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_syncs_a_dock_kind_widget_declaration_with_order_into_the_registry() {
        // Phase 9 v2 expansion: `sync_song_registry` passes `.widgets`
        // through verbatim with no per-field inspection, so a `dock`-kind
        // entry carrying an `order` field should round-trip unchanged —
        // same as any other widgets shape (confirms no code change needed
        // here for the new kind).
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-registry-dock-order");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        let notes = r##"{ "schemaVersion":"0",
            "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
            "widgets": { "usage": { "kind": "dock", "order": 2 } } }"##;
        std::fs::write(song.join("livery.json"), notes).unwrap();
        std::fs::write(song.join("widgets").join("usage.qml"), "// usage\n").unwrap();
        std::fs::create_dir_all(&run_qml).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let registry: Value = serde_json::from_str(
            &std::fs::read_to_string(run_qml.join("songs").join("registry.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            registry["moonlight"],
            json!({ "usage": { "kind": "dock", "order": 2 } }),
            "a dock-kind entry with `order` round-trips through sync_song_registry unchanged"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_regenerates_the_registry_preserving_other_songs() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-registry-preserve");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        let songs_dir = run_qml.join("songs");
        std::fs::create_dir_all(&songs_dir).unwrap();
        std::fs::write(
            songs_dir.join("registry.json"),
            r#"{"dusk":{"clock":{"kind":"surface"}}}"#,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let registry: Value =
            serde_json::from_str(&std::fs::read_to_string(songs_dir.join("registry.json")).unwrap())
                .unwrap();
        assert_eq!(registry["moonlight"], json!({}), "no .widgets key → {{}}");
        assert_eq!(
            registry["dusk"],
            json!({"clock":{"kind":"surface"}}),
            "another song's registry entry survives the rewrite untouched"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_leaves_the_registry_untouched_when_already_current() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-registry-unchanged");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        let songs_dir = run_qml.join("songs");
        std::fs::create_dir_all(&songs_dir).unwrap();
        // Already current — byte-identical to what the sync would write.
        let body = serde_json::to_string_pretty(&json!({"moonlight": {}})).unwrap() + "\n";
        std::fs::write(songs_dir.join("registry.json"), &body).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert!(
            !out.changed.iter().any(|c| c.ends_with("run/qml/songs/registry.json")),
            "a byte-identical registry entry must not be reported as changed: {:?}",
            out.changed
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_entry_refuses_and_syncs_nothing_while_declarative_locked() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-entry-widget-locked");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("widgets").join("bar.qml"), "// new bar body\n").unwrap();
        let runtime_song_dir = run_qml.join("songs").join("moonlight");
        std::fs::create_dir_all(&runtime_song_dir).unwrap();
        std::fs::write(runtime_song_dir.join("bar.qml"), "// stale bar body\n").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // No marker file at all IS declarative (the safe default).
        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.data.unwrap()["reason"], "declarative-mode-locked");
        assert_eq!(
            std::fs::read_to_string(runtime_song_dir.join("bar.qml")).unwrap(),
            "// stale bar body\n",
            "the declarative-mode lock covers widget bodies too, not just livery.json"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_entry_with_no_name_syncs_the_current_songs_widgets() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-entry-widget-bare");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("widgets").join("bar.qml"), "// new bar body\n").unwrap();
        let runtime_song_dir = run_qml.join("songs").join("moonlight");
        std::fs::create_dir_all(&runtime_song_dir).unwrap();
        std::fs::write(runtime_song_dir.join("bar.qml"), "// stale bar body\n").unwrap();
        // The stage already carries the "song" breadcrumb `current_staged_song`
        // reads, as if a prior `rice mode stage moonlight` had run.
        std::fs::write(
            stage.join("livery.json"),
            r##"{"schemaVersion":"0","song":"moonlight",
                "palette":{"bg":"#111111","fg":"#000000","accent":"#000000","urgent":"#000000"}}"##,
        )
        .unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        aoide_storage::mode::save_mode_marker(&aoide_storage::mode::ModeMarker {
            mode: aoide_storage::mode::RiceMode::Staging,
            ..Default::default()
        })
        .unwrap();

        let out = handle_rice_stage_entry(&inv(&["rice", "stage"], &[]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(
            std::fs::read_to_string(runtime_song_dir.join("bar.qml")).unwrap(),
            "// new bar body\n",
            "the no-arg path syncs widgets the same as the named-song path"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stage_copies_helper_and_asset_files_not_just_slots() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let (root, stage, run_qml) = widget_sync_tmp("stage-widget-helpers");
        let song = root.join("aoide").join("song").join("songbook").join("moonlight");
        std::fs::create_dir_all(song.join("widgets").join("assets")).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(song.join("widgets").join("bar.qml"), "// bar\n").unwrap();
        std::fs::write(
            song.join("widgets").join("WorkspaceRow.qml"),
            "// helper component\n",
        )
        .unwrap();
        std::fs::write(song.join("widgets").join("assets").join("logo.txt"), "logo data").unwrap();
        std::fs::create_dir_all(&run_qml).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_stage(&inv(&["rice", "stage"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        let runtime_song_dir = run_qml.join("songs").join("moonlight");
        assert_eq!(
            std::fs::read_to_string(runtime_song_dir.join("bar.qml")).unwrap(),
            "// bar\n"
        );
        assert_eq!(
            std::fs::read_to_string(runtime_song_dir.join("WorkspaceRow.qml")).unwrap(),
            "// helper component\n"
        );
        assert_eq!(
            std::fs::read_to_string(runtime_song_dir.join("assets").join("logo.txt")).unwrap(),
            "logo data"
        );
        let data = out.data.unwrap();
        assert_eq!(
            data["slots"],
            json!(["bar"]),
            "the helper component and asset file are carried but excluded from the manifest"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice compose (Phase E) ────────────────────────────────────────────────
    //
    // The PURE `nix_scalar`/`valid_song_name` unit tests moved to
    // `crate::compose`'s own test module (Phase 5b restructure) alongside
    // the functions they exercise. Everything below is handler-level: it
    // drives `handle_rice_compose` through `Invocation`/`Outcome`.

    #[test]
    fn compose_neutralizes_nix_interpolation_in_notes() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-interpolation");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("livery.json"), NOTES_WITH_INTERPOLATION).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_compose(&inv(&["rice", "compose"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);

        let target = root.join("songbook").join("moonlight");
        let rice_nix = std::fs::read_to_string(target.join("rice.nix")).unwrap();
        // The hostile value must land as an inert literal (`\${`), never a
        // live interpolation site (`"${` unescaped).
        assert!(
            rice_nix.contains(r#""bg" = "\${builtins.currentTime}";"#),
            "expected inert literal, got: {rice_nix}"
        );
        assert!(
            !rice_nix.contains(r#""${builtins.currentTime}"#),
            "must not contain a live interpolation site: {rice_nix}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compose_rejects_invalid_names() {
        for bad in ["Dusk", "dusk_two", "-dusk", "dusk/two", "../etc", "", "dusk.two"] {
            let out = handle_rice_compose(&inv(&["rice", "compose"], &[bad]));
            assert_eq!(out.status, Status::Error, "`{bad}` should be rejected");
            assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
            assert_eq!(out.data.unwrap()["reason"], "invalid-name", "for `{bad}`");
        }
    }

    #[test]
    fn compose_rejects_invalid_from() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-badfrom");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        for bad in ["../../etc", "../etc/passwd", "de/fault", "De Fault", ""] {
            let target = root.join("songbook").join("moonlight");
            let out = handle_rice_compose(&{
                let mut i = inv(&["rice", "compose"], &["moonlight"]);
                i.flags.insert("from".into(), bad.into());
                i
            });
            assert_eq!(out.status, Status::Error, "`--from {bad}` should be rejected");
            assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
            assert_eq!(out.data.unwrap()["reason"], "invalid-from", "for `--from {bad}`");
            assert!(!target.exists(), "nothing written for `--from {bad}`");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compose_rejects_from_equal_to_name() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-fromeqname");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let target = root.join("songbook").join("moonlight");
        let out = handle_rice_compose(&{
            let mut i = inv(&["rice", "compose"], &["moonlight"]);
            i.flags.insert("from".into(), "moonlight".into());
            i
        });
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "from-equals-name");
        assert!(!target.exists(), "nothing written when --from == name");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compose_missing_name_is_usage_exit_2() {
        let out = handle_rice_compose(&inv(&["rice", "compose"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
    }

    #[test]
    fn compose_missing_from_song_is_error() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-nofrom");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_compose(&inv(&["rice", "compose"], &["moonlight"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "from-song-not-found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compose_scaffolds_every_file_from_a_from_song_with_no_window_or_geometry() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-ok");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_compose(&inv(&["rice", "compose"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(out.changed.len(), 4);

        let target = root.join("songbook").join("moonlight");
        assert!(target.join("rice.nix").is_file());
        assert!(target.join("livery.json").is_file());
        assert!(target.join("design").join("intent.md").is_file());
        assert!(target.join("widgets").join(".gitkeep").is_file());
        // No stray .nix files (checks.song-shape requires rice.nix to be the
        // ONLY .nix under a songbook entry).
        assert!(!target.join("hypr").exists());

        let rice_nix = std::fs::read_to_string(target.join("rice.nix")).unwrap();
        assert!(rice_nix.contains("config.aoide.song == \"moonlight\""));
        assert!(rice_nix.contains("\"#0b1021\""), "palette bg copied: {rice_nix}");
        assert!(rice_nix.contains("border = null;"), "no window in `from` → null template");
        assert!(rice_nix.contains("gapsOut = null;"), "no geometry in `from` → null template");
        assert!(rice_nix.contains("carries no geometry tier"));

        let mirrored = std::fs::read_to_string(target.join("livery.json")).unwrap();
        assert_eq!(mirrored, VALID_NOTES, "livery.json mirrors --from exactly");

        let intent = std::fs::read_to_string(target.join("design").join("intent.md")).unwrap();
        assert!(intent.contains("inherited from `sonata` — retune"));
        assert!(intent.contains("slots.md"));
        assert!(intent.contains("update-playbook.md"));
        assert_eq!(
            std::fs::read_to_string(target.join("widgets").join(".gitkeep")).unwrap(),
            ""
        );

        let data = out.data.unwrap();
        assert_eq!(data["name"], "moonlight");
        assert_eq!(data["from"], "sonata");
        assert_eq!(data["nextSteps"].as_array().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compose_with_geometry_and_window_copies_every_field_including_nulls() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-geo");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("livery.json"), NOTES_WITH_GEOMETRY).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_compose(&{
            let mut i = inv(&["rice", "compose"], &["dusk"]);
            i.flags.insert("from".into(), "sonata".into());
            i
        });
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);

        let target = root.join("songbook").join("dusk");
        let rice_nix = std::fs::read_to_string(target.join("rice.nix")).unwrap();
        assert!(rice_nix.contains("gapsOut = 10;"));
        assert!(rice_nix.contains("gapsIn = 4;"));
        assert!(rice_nix.contains("borderSize = 3;"));
        assert!(rice_nix.contains("rounding = 6;"));
        assert!(rice_nix.contains("blurEnabled = false;"));
        assert!(rice_nix.contains("blurSize = 5;"));
        assert!(rice_nix.contains("blurPasses = 2;"));
        assert!(rice_nix.contains("border = \"#82aaff\";"));
        assert!(rice_nix.contains("borderInactive = \"#0b1021\";"));
        assert!(rice_nix.contains("inherited from song \"sonata\""));

        let mirrored = std::fs::read_to_string(target.join("livery.json")).unwrap();
        assert_eq!(mirrored, NOTES_WITH_GEOMETRY, "geometry block mirrored verbatim");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compose_refuses_to_overwrite_without_force_then_succeeds_with_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("compose-exists");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("sonata");
        let target = root.join("songbook").join("dusk");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(from_dir.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_compose(&inv(&["rice", "compose"], &["dusk"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "already-exists");
        assert!(!target.join("rice.nix").exists(), "nothing written without --force");

        let out2 = handle_rice_compose(&{
            let mut i = inv(&["rice", "compose"], &["dusk"]);
            i.flags.insert("force".into(), "true".into());
            i
        });
        assert_eq!(out2.status, Status::Ok, "{:?}", out2.data);
        assert!(target.join("rice.nix").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }
}
