//! `rice lint` / `rice preview` / `rice mint` — the self-ricing loop
//! (concepts/Self-Ricing). `rice gen`/`rice adopt`/`rice transpose` are still
//! walking-skeleton stubs; their metadata lives in `commands/stubs.rs`.

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
        path: ["rice", "preview"],
        summary: "Rehearse a rice live (stage/livery.json hot-reload + legacy mirror + best-effort hyprctl geometry/border apply); nothing committed.",
        args: [arg!("name", "string", true, "Rice/song name to preview (from song/songbook/).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_rice_preview,
    ));
    r.insert(cmd!(
        path: ["rice", "mint"],
        summary: "Scaffold a new song under song/songbook/<name>/ by copying --from's notes (rice.nix, livery.json, design/intent.md, widgets/); `rice new` is a parse alias for this.",
        args: [arg!("name", "string", true, "New song name: ^[a-z0-9][a-z0-9-]*$ (lowercase, digits, hyphens).")],
        flags: [
            flag!("from", "string", "Source song to copy notes from (default \"default\")."),
            flag!("force", "bool", "Overwrite the song's scaffolded files if it already exists."),
        ],
        gated: false,
        implemented: true,
        handler: handle_rice_mint,
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

/// `rice preview <name>` — rehearse a committed song live: stage its
/// `livery.json` (plus a derivable cover) into `<stage>/` so the Quickshell
/// surfaces hot-reload it, AND best-effort live-apply its geometry + border
/// colours to the running compositor via `hyprctl --batch keyword …`
/// (guarded on `$HYPRLAND_INSTANCE_SIGNATURE`; see hypr.rs). Nothing is
/// committed; the hyprctl call is keyword-only (never `reload`) and never
/// fatal — a failed/absent hyprctl still leaves the stage file updated.
///
/// This is the honest form of the hand-copy agents had been doing: drive the
/// songbook notes into the stage so the shell has a palette to render.
///
/// `pub(crate)`, not private: `rice design enter` (Phase B,
/// `commands/design.rs`) calls this directly to get the SAME live-apply side
/// effects a bare `rice preview <name>` has, rather than reimplementing them
/// — it hands this the identical `Invocation` it was given (both commands
/// take the song name as their first positional arg, and this function reads
/// nothing else off `inv`), so no adapter/duplication is needed.
pub(crate) fn handle_rice_preview(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage("rice.preview", "usage: aoide rice preview <name> [--json]")
                .with_data(json!({ "reason": "missing-name" }));
        }
    };

    let notes_src = shellbridge::songbook_notes(&name);
    let raw = match std::fs::read_to_string(&notes_src) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::error(
                "rice.preview",
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
                "rice.preview",
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
        return Outcome::error("rice.preview", format!("failed to stage livery.json: {e}"))
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
                    "rice.preview",
                    format!("failed to stage cover.json: {e}"),
                )
                .with_data(json!({ "reason": "stage-write-failed", "target": cover_dst.to_string_lossy() }));
            }
            changed.push(cover_dst.to_string_lossy().into_owned());
            format!("staged cover {}", path.display())
        }
        None => "no derivable cover; cover.json left untouched".to_string(),
    };

    Outcome::ok(
        "rice.preview",
        format!(
            "previewing `{name}` — {} stage file(s) live for hot-reload; {cover_note}",
            changed.len()
        ),
    )
    .changed(changed)
    .with_data(json!({
        "name": name,
        "notes": notes_dst.to_string_lossy(),
        "cover": cover.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "hyprctl": hyprctl_status,
        "seam": "Quickshell hot-reloads stage/livery.json (palette + component tiers); \
                 geometry + border colours are ALSO applied \
                 live via best-effort, guarded `hyprctl --batch keyword …` (see hypr.rs) \
                 — keyword-only, never `hyprctl reload`",
    }))
}

/// `rice mint <name> [--from <song>] [--force]` — scaffold a new committed
/// song under `song/songbook/<name>/` by copying an existing song's notes.
/// `aoide rice new` (cli.rs) is a pure parse alias for this same path — there
/// is only ONE registry entry (`rice.mint`).
///
/// Writes ONLY inside `song/songbook/<name>/` (house rule 1): `rice.nix` (a
/// self-gating skeleton — the sole `.nix` file, satisfying `checks.song-shape`),
/// `livery.json` (a mirror of `--from`'s, INCLUDING any geometry block, so
/// `aoide rice preview <name>` renders + live-applies immediately),
/// `design/intent.md` (honest-empty — no fabricated rationale), and
/// `widgets/.gitkeep` (no per-song widgets yet). No `hypr/` dir: geometry
/// lives in the livery tier, not a build fragment.
fn handle_rice_mint(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage(
                "rice.mint",
                "usage: aoide rice mint <name> [--from <song>] [--force] [--json]",
            )
            .with_data(json!({ "reason": "missing-name" }));
        }
    };

    if !crate::mint::valid_song_name(&name) {
        return Outcome::error(
            "rice.mint",
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
        .unwrap_or_else(|| "default".to_string());

    if !crate::mint::valid_song_name(&from) {
        return Outcome::error(
            "rice.mint",
            format!(
                "`--from {from}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$` \
                 (lowercase letters, digits, hyphens; no leading hyphen, no `/`, no `..`)"
            ),
        )
        .with_data(json!({ "reason": "invalid-from", "from": from }));
    }
    if from == name {
        return Outcome::error(
            "rice.mint",
            format!("`--from` cannot be `{name}` itself — nothing to copy from"),
        )
        .with_data(json!({ "reason": "from-equals-name", "name": name }));
    }

    let force = inv.flag_present("force");

    let target = shellbridge::songbook_dir(&name);
    if target.exists() && !force {
        return Outcome::error(
            "rice.mint",
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
                "rice.mint",
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
                "rice.mint",
                format!("--from song `{from}`'s notes are not valid JSON: {e}"),
            )
            .with_data(json!({
                "reason": "invalid-json",
                "from": from,
                "notes": from_notes_path.to_string_lossy(),
            }));
        }
    };

    let rice_nix = crate::mint::render_rice_nix(&name, &from, &from_parsed);
    let intent_md = crate::mint::render_intent_md(&name, &from);

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
                "rice.mint",
                format!("failed to write {}: {e}", path.display()),
            )
            .with_data(json!({ "reason": "write-failed", "target": path.to_string_lossy() }));
        }
        changed.push(path.to_string_lossy().into_owned());
    }

    Outcome::ok(
        "rice.mint",
        format!(
            "minted song `{name}` from `{from}` — {} file(s) written under {}",
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
            format!("sketch: `aoide rice preview {name}` to rehearse it live, no rebuild"),
        ],
    }))
}

// ── Tests (rice lint resolution + rice preview staging + rice mint) ─────────
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
    fn preview_stages_notes_and_reports_no_derivable_cover() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("preview-ok");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["moonlight"]));
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
    fn preview_stages_a_derivable_cover_from_the_covers_library() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("preview-cover");
        let stage = root.join("stage");
        let song = root.join("songbook").join("dusk");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::fs::write(covers.join("dusk.png"), b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["dusk"]));
        assert_eq!(out.status, Status::Ok);
        let cover = std::fs::read_to_string(stage.join("cover.json")).unwrap();
        assert!(cover.contains("dusk.png"), "cover.json points at the derived file");
        assert!(out.changed.iter().any(|c| c.ends_with("cover.json")));
        let data = out.data.unwrap();
        assert!(data["cover"].as_str().unwrap().ends_with("covers/dusk.png"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preview_missing_song_is_error_exit_1() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("preview-missing").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["nope"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "song-not-found");
    }

    #[test]
    fn preview_missing_name_is_usage_exit_2() {
        let out = handle_rice_preview(&inv(&["rice", "preview"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
    }

    // ── rice preview: the hyprctl live-apply guard (Phase F) ─────────────────

    #[test]
    fn preview_off_hyprland_skips_hyprctl_without_panicking() {
        // The common test path: no compositor, `hyprctl` may not even exist on
        // PATH — the guard must trip on the env var alone, never touching the
        // process spawn.
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let root = unique_tmp("preview-hypr-off");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), NOTES_WITH_WINDOW).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(
            out.data.unwrap()["hyprctl"],
            "skipped (HYPRLAND_INSTANCE_SIGNATURE unset)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preview_with_no_window_or_geometry_reports_an_empty_batch() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let root = unique_tmp("preview-hypr-empty");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(
            out.data.unwrap()["hyprctl"],
            "skipped (no geometry/border keywords resolved)"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── rice mint (Phase E) ───────────────────────────────────────────────────
    //
    // The PURE `nix_scalar`/`valid_song_name` unit tests moved to
    // `crate::mint`'s own test module (Phase 5b restructure) alongside
    // the functions they exercise. Everything below is handler-level: it
    // drives `handle_rice_mint` through `Invocation`/`Outcome`.

    #[test]
    fn mint_neutralizes_nix_interpolation_in_notes() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-interpolation");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("default");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("livery.json"), NOTES_WITH_INTERPOLATION).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["moonlight"]));
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
    fn mint_rejects_invalid_names() {
        for bad in ["Dusk", "dusk_two", "-dusk", "dusk/two", "../etc", "", "dusk.two"] {
            let out = handle_rice_mint(&inv(&["rice", "mint"], &[bad]));
            assert_eq!(out.status, Status::Error, "`{bad}` should be rejected");
            assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
            assert_eq!(out.data.unwrap()["reason"], "invalid-name", "for `{bad}`");
        }
    }

    #[test]
    fn mint_rejects_invalid_from() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-badfrom");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        for bad in ["../../etc", "../etc/passwd", "de/fault", "De Fault", ""] {
            let target = root.join("songbook").join("moonlight");
            let out = handle_rice_mint(&{
                let mut i = inv(&["rice", "mint"], &["moonlight"]);
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
    fn mint_rejects_from_equal_to_name() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-fromeqname");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let target = root.join("songbook").join("moonlight");
        let out = handle_rice_mint(&{
            let mut i = inv(&["rice", "mint"], &["moonlight"]);
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
    fn mint_missing_name_is_usage_exit_2() {
        let out = handle_rice_mint(&inv(&["rice", "mint"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::USAGE);
    }

    #[test]
    fn mint_missing_from_song_is_error() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-nofrom");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["moonlight"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "from-song-not-found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mint_scaffolds_every_file_from_a_from_song_with_no_window_or_geometry() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-ok");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("default");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["moonlight"]));
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
        assert!(intent.contains("inherited from `default` — retune"));
        assert!(intent.contains("slots.md"));
        assert!(intent.contains("update-playbook.md"));
        assert_eq!(
            std::fs::read_to_string(target.join("widgets").join(".gitkeep")).unwrap(),
            ""
        );

        let data = out.data.unwrap();
        assert_eq!(data["name"], "moonlight");
        assert_eq!(data["from"], "default");
        assert_eq!(data["nextSteps"].as_array().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mint_with_geometry_and_window_copies_every_field_including_nulls() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-geo");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("livery.json"), NOTES_WITH_GEOMETRY).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&{
            let mut i = inv(&["rice", "mint"], &["dusk"]);
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
    fn mint_refuses_to_overwrite_without_force_then_succeeds_with_it() {
        let _g = aoide_test_support::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-exists");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("default");
        let target = root.join("songbook").join("dusk");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(from_dir.join("livery.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["dusk"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "already-exists");
        assert!(!target.join("rice.nix").exists(), "nothing written without --force");

        let out2 = handle_rice_mint(&{
            let mut i = inv(&["rice", "mint"], &["dusk"]);
            i.flags.insert("force".into(), "true".into());
            i
        });
        assert_eq!(out2.status, Status::Ok, "{:?}", out2.data);
        assert!(target.join("rice.nix").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }
}
