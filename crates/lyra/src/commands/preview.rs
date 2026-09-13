//! `lyra preview` / `lyra preview set` — a throwaway, ISOLATED canvas for
//! iterating on a widget's QML without touching the live desktop at all.
//! `lyra preview [<widget>]` assembles a standalone ROOT (its own song
//! stage, its own fixture state, its own `run/qml/` COPIES of the checkout's
//! QML — never symlinks into it, so a write through the root stays in it) under
//! `$XDG_RUNTIME_DIR/aoide-preview` (never under `$XDG_RUNTIME_DIR/aoide/`
//! — that is the LIVE daemon's socket dir, `aoided.sock`/`session-*.sock`,
//! and the live reaper's own socket globs look there) and spawns a
//! genuinely separate `quickshell -p <root>/run/qml/WidgetPreview.qml`
//! against it, with `AOIDE_ROOT`/`AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR`/
//! `AOIDE_DAEMON_SOCKET` all repointed at that root on the CHILD's env
//! only — `AOIDE_DAEMON_SOCKET` at a path that never exists, so no facet
//! QML can reach the real `aoided` even if a stub bridge were bypassed.
//! `lyra preview set` edits that root's `preview.json` control document
//! (widget, viewport, anchor, zoom, fixture, livery — the schema below)
//! without a canvas needing to be running; the canvas (P2, another QML
//! phase not yet landed — `WidgetPreview.qml` does not exist at this
//! phase) is expected to hot-reload off that same file via `FileView`,
//! the same discipline every other stage file in this codebase uses.
//!
//! **Why a second root instead of reusing `$AOIDE_ROOT`:** the live root
//! is shared with a running `aoided`/desktop session — staging a fixture's
//! `sessions.json`/`projects.json` there would corrupt whatever the real
//! conductor graph is tracking. This command never reads or writes
//! anything under the live root; every path it touches hangs off its own
//! `--root` (or the default above).
//!
//! **The QML is paint only** (root `AGENTS.md` house rule 7's "delete
//! every `.qml`" test) — everything this command does (building the root,
//! staging fixtures/livery, editing `preview.json`) is a plain filesystem
//! operation, reachable and fully testable with no quickshell installed;
//! only the final spawn (skipped entirely by `--no-launch`) needs the
//! binary on `PATH`.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, flag, Registry};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["preview"],
        summary: "Build an isolated preview root (song stage, fixture state, run/qml copies of the checkout's QML) and launch the standalone quickshell canvas against it -- never the live daemon or its socket dir. <widget> is a bare slot (uses --song), `<song>/<slot>`, or an absolute path under a songbook's own widgets/.",
        args: [arg!("widget", "string", false, "Initial widget to preview: a bare slot name, `<song>/<slot>`, or an absolute songbook widgets/ path.")],
        flags: [
            flag!("song", "string", "Song whose default livery/widgets seed the preview (default \"sonata\")."),
            flag!("fixture", "string", "Fixture set name under modules/facets/quickshell/preview/fixtures/, or a directory path (default \"many\")."),
            flag!(
                "livery",
                "string",
                "Palette source, resolved through the livery engine: `live` (the resolved live stage twin, read-only), a song name (that song's own songbook livery.json), a path to a livery file, or a path to a base16 scheme (JSON or flat key:value lines). Default: the preview's own --song."
            ),
            flag!("root", "string", "Preview root directory (default $XDG_RUNTIME_DIR/aoide-preview)."),
            flag!("no-launch", "bool", "Build the root and print it; never spawn quickshell.")
        ],
        gated: false,
        implemented: true,
        handler: handle_preview,
    ));
    r.insert(cmd!(
        path: ["preview", "set"],
        summary: "Read, validate, and merge flags into an existing preview root's preview.json control file -- no canvas needs to be running. Existing keys survive; only the given flags/args are overwritten.",
        args: [],
        flags: [
            flag!("root", "string", "Preview root directory (default $XDG_RUNTIME_DIR/aoide-preview)."),
            flag!("widget", "string", "Widget to preview -- same mapping as `lyra preview`'s positional."),
            flag!("song", "string", "Song context a bare <slot> widget maps under."),
            flag!("width", "string", "Widget width in px, or `auto`."),
            flag!("height", "string", "Widget height in px, or `auto`."),
            flag!("anchor", "string", "One of: tl, t, tr, l, c, r, bl, b, br."),
            flag!("margin", "string", "Anchor margin in px (>= 0)."),
            flag!("viewport", "string", "WxH, or one of: 16:9, 16:10, 4:3, ultrawide, portrait."),
            flag!("zoom", "string", "`fit`, or a positive number."),
            flag!("aspect-lock", "string", "on|off -- lock the viewport's aspect ratio."),
            flag!("widget-aspect-lock", "string", "on|off -- lock the widget's own aspect ratio."),
            flag!("background", "string", "livery|checker"),
            flag!("fixture", "string", "Re-stage state/stage from a different fixture set or directory."),
            flag!(
                "livery",
                "string",
                "Palette source, resolved through the livery engine: `live`, a song name, a livery file path, or a base16 scheme path -- same four forms as `lyra preview --livery`."
            )
        ],
        gated: false,
        implemented: true,
        handler: handle_preview_set,
    ));
    r.insert(cmd!(
        path: ["preview", "declare"],
        summary: "Copy the previewed widget body and/or palette from a preview root into the checkout's song/songbook/<song> -- the canvas's counterpart of `rice declare`. Byte-identical -> no-op; git commit and rebuild stay the user's own.",
        args: [],
        flags: [
            flag!("root", "string", "Preview root directory (default $XDG_RUNTIME_DIR/aoide-preview)."),
            flag!("slot", "string", "Widget slot name under song/songbook/<song>/widgets/ (default: the previewed widget file's own basename).")
        ],
        gated: true,
        implemented: true,
        handler: handle_preview_declare,
    ));
}

/// The window `WidgetPreview.qml` (P2) is expected to title itself —
/// [`best_effort_float`] polls `hyprctl clients -j` for exactly this
/// `class`/`title` pair. A future rename of either needs a matching edit
/// here in the same commit, or the auto-float silently stops finding
/// anything (harmless — see that function's own doc — but confusing).
const WINDOW_CLASS: &str = "org.quickshell";
const WINDOW_TITLE: &str = "aoide-widget-preview";

const SCHEMA_VERSION: &str = "0";

const ANCHORS: &[&str] = &["tl", "t", "tr", "l", "c", "r", "bl", "b", "br"];

/// `(preset name, width, height)` — the fixed viewport presets `--viewport`
/// accepts by name; any other `WxH` shape is `"custom"`.
const VIEWPORT_PRESETS: &[(&str, u32, u32)] = &[
    ("16:9", 1920, 1080),
    ("16:10", 1920, 1200),
    ("4:3", 1600, 1200),
    ("ultrawide", 2560, 1080),
    ("portrait", 1080, 1920),
];

/// Env vars a facet's QML might already carry (a live `lyra` session's own
/// widget-slot overrides) that must never leak into the isolated canvas —
/// the preview always renders the canvas's OWN `preview.json` choices, not
/// whatever the shell happened to export.
const ENV_REMOVE: &[&str] = &[
    "QS_STAGE",
    "CONDUCTOR_WIDGET",
    "TERMINALS_WIDGET",
    "DOCK_WIDGET",
    "POWER_WIDGET",
    "METERS_WIDGET",
    "CAL_WIDGET",
];

// ─────────────────────────── handlers ───────────────────────────

fn handle_preview(inv: &Invocation) -> Outcome {
    let cmd = "preview";

    let checkout = aoide_storage::fs::flake_root();
    if !checkout.join("flake.nix").is_file() {
        return Outcome::error(
            cmd,
            format!(
                "needs an Aoide checkout: no flake.nix under {}",
                checkout.display()
            ),
        );
    }

    let root = match resolve_root(inv.flags.get("root").map(String::as_str)) {
        Ok(r) => r,
        Err(e) => return Outcome::usage(cmd, e),
    };
    // A running canvas only blocks a second LAUNCH on the same root; a
    // `--no-launch` rebuild is the documented way to re-stage its copies
    // (and merge into its control file) while it stays up.
    if !inv.flag_present("no-launch") {
        if let Err(e) = refuse_if_running(&root) {
            return Outcome::error(cmd, e);
        }
    }

    let control_path = root.join("preview.json");
    let existing = read_control(&control_path);

    let song = inv
        .flags
        .get("song")
        .cloned()
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|d| d.get("song"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| "sonata".to_string());
    if !aoide_song::compose::valid_song_name(&song) {
        return Outcome::usage(
            cmd,
            format!("`--song {song}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$`"),
        );
    }

    let fixture_arg = inv
        .flags
        .get("fixture")
        .cloned()
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|d| d.get("fixture"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| "many".to_string());

    let livery_spec = inv
        .flags
        .get("livery")
        .cloned()
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|d| d.get("liverySource"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| song.clone());

    // ── build the root ──────────────────────────────────────────
    let stage_song_dir = root.join("song").join("stage");
    if let Err(e) = std::fs::create_dir_all(&stage_song_dir) {
        return Outcome::error(cmd, format!("creating {}: {e}", stage_song_dir.display()));
    }
    let livery_dst = stage_song_dir.join("livery.json");
    if let Err(e) = stage_livery(&livery_spec, &song, &checkout, &livery_dst) {
        return match e {
            LiveryStageError::Usage(m) => Outcome::usage(cmd, m),
            LiveryStageError::Error(m) => Outcome::error(cmd, m),
        };
    }
    if let Err(e) = write_mode_json(&root, &song) {
        return Outcome::error(cmd, e);
    }
    if let Err(e) = seed_static_stage_files(&root) {
        return Outcome::error(cmd, e);
    }

    let fixture_source = match resolve_fixture_source(&checkout, &fixture_arg) {
        Ok(s) => s,
        Err(e) => return Outcome::error(cmd, e),
    };
    let state_stage_dir = root.join("state").join("stage");
    if let Err(e) = stage_fixture(&fixture_source, &state_stage_dir) {
        return Outcome::error(cmd, e);
    }

    let run_qml_dir = root.join("run").join("qml");
    if let Err(e) = stage_qml_copies(&checkout, &run_qml_dir) {
        return Outcome::error(cmd, e);
    }
    let run_qml_songs = run_qml_dir.join("songs");
    if let Err(e) = stage_song_copies(&checkout, &run_qml_songs) {
        return Outcome::error(cmd, e);
    }
    if let Err(e) = stage_songs_manifest(&run_qml_songs) {
        return Outcome::error(cmd, e);
    }

    // ── control file ────────────────────────────────────────────
    let mut doc = existing.unwrap_or_default();
    if let Some(widget) = inv.args.first() {
        if has_parent_dir_component(widget) {
            return Outcome::usage(
                cmd,
                format!("widget `{widget}` may not contain a `..` component"),
            );
        }
        doc.insert(
            "widget".to_string(),
            json!(map_widget(widget, &song, &checkout)),
        );
    }
    doc.entry("widget".to_string())
        .or_insert_with(|| json!(format!("songs/{song}/conductor.qml")));
    doc.insert("song".to_string(), json!(song));
    doc.entry("widgetWidth".to_string())
        .or_insert_with(|| json!("auto"));
    doc.entry("widgetHeight".to_string())
        .or_insert_with(|| json!("auto"));
    doc.entry("widgetAspectLock".to_string())
        .or_insert_with(|| json!(false));
    doc.entry("viewportWidth".to_string())
        .or_insert_with(|| json!(1920));
    doc.entry("viewportHeight".to_string())
        .or_insert_with(|| json!(1080));
    doc.entry("viewportPreset".to_string())
        .or_insert_with(|| json!("16:9"));
    doc.entry("viewportAspectLock".to_string())
        .or_insert_with(|| json!(true));
    doc.entry("anchor".to_string())
        .or_insert_with(|| json!("tl"));
    doc.entry("margin".to_string()).or_insert_with(|| json!(0));
    doc.entry("zoom".to_string())
        .or_insert_with(|| json!("fit"));
    doc.entry("background".to_string())
        .or_insert_with(|| json!("livery"));
    doc.insert("fixture".to_string(), json!(fixture_arg));
    doc.insert(
        "fixturesDir".to_string(),
        json!(fixtures_registry_dir(&checkout).to_string_lossy()),
    );
    doc.insert(
        "fixtures".to_string(),
        json!(list_available_fixture_sets(&checkout)),
    );
    doc.insert("schemaVersion".to_string(), json!(SCHEMA_VERSION));
    // The launching binary's own absolute path -- a deployed `lyra` on the
    // canvas's PATH may predate `preview set` entirely, so the QML rail
    // spawns THIS path (falling back to bare `lyra` only for a doc written
    // before this field existed) rather than trust PATH inside the canvas.
    if let Ok(exe) = std::env::current_exe() {
        doc.insert("lyra".to_string(), json!(exe.to_string_lossy()));
    }
    // `livery` (the staged file path) is a dead key: the canvas already
    // knows that path as `$AOIDE_ROOT/song/stage/livery.json` and treats
    // `livery` as a legacy alias of `liverySource`, deleting it on every
    // save -- writing it back here would just ping-pong against the
    // canvas. `liverySource` (the spec as given) is the one name.
    doc.remove("livery");
    doc.insert("liverySource".to_string(), json!(livery_spec));
    doc.insert("liveries".to_string(), json!(list_liveries(&checkout)));
    let widget_field = doc
        .get("widget")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let widget_abs = resolve_widget_abs(&checkout, &widget_field);
    let watch = compute_watch_list(&checkout, &song, widget_abs.as_deref());
    doc.insert(
        "stage".to_string(),
        Value::Object(compute_stage_map(&checkout, &root, &watch)),
    );
    doc.insert("watch".to_string(), json!(watch));

    if let Err(e) = write_control(&control_path, &doc) {
        return Outcome::error(cmd, e);
    }

    if inv.flag_present("no-launch") {
        return Outcome::ok(cmd, format!("preview root built at {}", root.display())).with_data(
            json!({
                "root": root.to_string_lossy(),
                "controlFile": control_path.to_string_lossy(),
                "pid": Value::Null,
                "launched": false,
                "exit": Value::Null,
            }),
        );
    }

    let my_pid = std::process::id();
    let pid_path = pid_file(&root);
    if let Err(e) = std::fs::write(&pid_path, my_pid.to_string()) {
        return Outcome::error(cmd, format!("writing {}: {e}", pid_path.display()));
    }

    let widget_qml = run_qml_dir.join("WidgetPreview.qml");
    match spawn_quickshell(&widget_qml, &root) {
        Ok(mut child) => {
            best_effort_float(child.id());
            let status = child.wait();
            let _ = std::fs::remove_file(&pid_path);
            match status {
                Ok(status) => Outcome::ok(cmd, "canvas closed").with_data(json!({
                    "root": root.to_string_lossy(),
                    "controlFile": control_path.to_string_lossy(),
                    "pid": my_pid,
                    "launched": true,
                    "exit": status.code(),
                })),
                Err(e) => Outcome::error(cmd, format!("waiting on quickshell: {e}")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_file(&pid_path);
            Outcome::error(
                cmd,
                "quickshell not found on PATH -- install quickshell, or build with --no-launch",
            )
        }
        Err(e) => {
            let _ = std::fs::remove_file(&pid_path);
            Outcome::error(cmd, format!("spawning quickshell: {e}"))
        }
    }
}

fn handle_preview_set(inv: &Invocation) -> Outcome {
    let cmd = "preview.set";
    let root = match resolve_root(inv.flags.get("root").map(String::as_str)) {
        Ok(r) => r,
        Err(e) => return Outcome::usage(cmd, e),
    };
    let control_path = root.join("preview.json");
    let Some(mut doc) = read_control(&control_path) else {
        return Outcome::error(
            cmd,
            format!(
                "no preview at {} -- run `lyra preview --no-launch` first",
                root.display()
            ),
        );
    };

    let checkout = aoide_storage::fs::flake_root();
    let mut changed: Vec<String> = Vec::new();

    if let Some(song) = inv.flags.get("song") {
        if !aoide_song::compose::valid_song_name(song) {
            return Outcome::usage(
                cmd,
                format!(
                    "`--song {song}` is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$`"
                ),
            );
        }
        doc.insert("song".to_string(), json!(song));
        changed.push("song".to_string());
        if let Err(e) = write_mode_json(&root, song) {
            return Outcome::error(cmd, e);
        }
        changed.push("mode".to_string());
    }

    if let Some(widget) = inv.flags.get("widget") {
        if has_parent_dir_component(widget) {
            return Outcome::usage(
                cmd,
                format!("--widget `{widget}` may not contain a `..` component"),
            );
        }
        let song = doc
            .get("song")
            .and_then(Value::as_str)
            .unwrap_or("sonata")
            .to_string();
        doc.insert(
            "widget".to_string(),
            json!(map_widget(widget, &song, &checkout)),
        );
        changed.push("widget".to_string());
    }

    if inv.flags.get("widget").is_some() || inv.flags.get("song").is_some() {
        let song = doc
            .get("song")
            .and_then(Value::as_str)
            .unwrap_or("sonata")
            .to_string();
        let widget_field = doc
            .get("widget")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let widget_abs = resolve_widget_abs(&checkout, &widget_field);
        let watch = compute_watch_list(&checkout, &song, widget_abs.as_deref());
        doc.insert(
            "stage".to_string(),
            Value::Object(compute_stage_map(&checkout, &root, &watch)),
        );
        doc.insert("watch".to_string(), json!(watch));
        changed.push("watch".to_string());
        changed.push("stage".to_string());
    }

    if let Some(w) = inv.flags.get("width") {
        match parse_dim(w) {
            Ok(v) => {
                doc.insert("widgetWidth".to_string(), v);
                changed.push("widgetWidth".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--width `{w}`: {e}")),
        }
    }
    if let Some(h) = inv.flags.get("height") {
        match parse_dim(h) {
            Ok(v) => {
                doc.insert("widgetHeight".to_string(), v);
                changed.push("widgetHeight".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--height `{h}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("widget-aspect-lock") {
        match parse_bool_on_off(v) {
            Ok(b) => {
                doc.insert("widgetAspectLock".to_string(), json!(b));
                changed.push("widgetAspectLock".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--widget-aspect-lock `{v}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("aspect-lock") {
        match parse_bool_on_off(v) {
            Ok(b) => {
                doc.insert("viewportAspectLock".to_string(), json!(b));
                changed.push("viewportAspectLock".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--aspect-lock `{v}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("viewport") {
        match parse_viewport(v) {
            Ok((w, h, preset)) => {
                doc.insert("viewportWidth".to_string(), json!(w));
                doc.insert("viewportHeight".to_string(), json!(h));
                doc.insert("viewportPreset".to_string(), json!(preset));
                changed.push("viewportWidth".to_string());
                changed.push("viewportHeight".to_string());
                changed.push("viewportPreset".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--viewport `{v}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("anchor") {
        match parse_anchor(v) {
            Ok(a) => {
                doc.insert("anchor".to_string(), json!(a));
                changed.push("anchor".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--anchor `{v}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("margin") {
        match parse_margin(v) {
            Ok(m) => {
                doc.insert("margin".to_string(), json!(m));
                changed.push("margin".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--margin `{v}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("zoom") {
        match parse_zoom(v) {
            Ok(z) => {
                doc.insert("zoom".to_string(), z);
                changed.push("zoom".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--zoom `{v}`: {e}")),
        }
    }
    if let Some(v) = inv.flags.get("background") {
        match parse_background(v) {
            Ok(b) => {
                doc.insert("background".to_string(), json!(b));
                changed.push("background".to_string());
            }
            Err(e) => return Outcome::usage(cmd, format!("--background `{v}`: {e}")),
        }
    }

    if let Some(fixture_arg) = inv.flags.get("fixture") {
        let source = match resolve_fixture_source(&checkout, fixture_arg) {
            Ok(s) => s,
            Err(e) => return Outcome::error(cmd, e),
        };
        let state_stage_dir = root.join("state").join("stage");
        if let Err(e) = stage_fixture(&source, &state_stage_dir) {
            return Outcome::error(cmd, e);
        }
        doc.insert("fixture".to_string(), json!(fixture_arg));
        doc.insert(
            "fixturesDir".to_string(),
            json!(fixtures_registry_dir(&checkout).to_string_lossy()),
        );
        doc.insert(
            "fixtures".to_string(),
            json!(list_available_fixture_sets(&checkout)),
        );
        changed.push("fixture".to_string());
    }

    if let Some(livery_spec) = inv.flags.get("livery") {
        let song = doc
            .get("song")
            .and_then(Value::as_str)
            .unwrap_or("sonata")
            .to_string();
        let dst = root.join("song").join("stage").join("livery.json");
        if let Err(e) = stage_livery(livery_spec, &song, &checkout, &dst) {
            return match e {
                LiveryStageError::Usage(m) => Outcome::usage(cmd, m),
                LiveryStageError::Error(m) => Outcome::error(cmd, m),
            };
        }
        doc.remove("livery"); // legacy alias of `liverySource` -- see the builder's own note
        doc.insert("liverySource".to_string(), json!(livery_spec));
        doc.insert("liveries".to_string(), json!(list_liveries(&checkout)));
        changed.push("liverySource".to_string());
        changed.push("liveries".to_string());
    }

    // A control doc from before this fix-up may still carry the legacy
    // `livery` key even when `--livery` wasn't given this call -- drop it
    // on every write, not just when the flag is present.
    doc.remove("livery");

    if let Err(e) = write_control(&control_path, &doc) {
        return Outcome::error(cmd, e);
    }

    Outcome::ok(cmd, format!("{} key(s) updated", changed.len()))
        .with_data(Value::Object(doc))
        .changed(changed)
}

/// `lyra preview declare` — the canvas's counterpart of `rice declare`
/// (`commands/stubs.rs::handle_rice_declare`, Self-Ricing.md's "the copy
/// half of the stage-vs-commit split"): the previewed body/palette become
/// checkout truth. `git commit`/rebuild stay the user's own — this command
/// never touches git, the live stage, `~/.aoide`, or `run/qml`, only the
/// checkout's `song/songbook/<song>/`.
fn handle_preview_declare(inv: &Invocation) -> Outcome {
    let cmd = "preview.declare";
    let root = match resolve_root(inv.flags.get("root").map(String::as_str)) {
        Ok(r) => r,
        Err(e) => return Outcome::usage(cmd, e),
    };
    let control_path = root.join("preview.json");
    let Some(doc) = read_control(&control_path) else {
        return Outcome::error(
            cmd,
            format!(
                "no preview at {} -- run `lyra preview --no-launch` first",
                root.display()
            ),
        );
    };

    let checkout = aoide_storage::fs::flake_root();
    if !checkout.join("flake.nix").is_file() {
        return Outcome::error(
            cmd,
            format!(
                "needs an Aoide checkout: no flake.nix under {}",
                checkout.display()
            ),
        );
    }

    let song = match doc.get("song").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => {
            return Outcome::error(
                cmd,
                format!(
                    "{}: no `song` key -- run `lyra preview` to build the root first",
                    control_path.display()
                ),
            )
        }
    };
    // A hand-edited or corrupted `preview.json` could carry a `song` with a
    // `/` or `..` in it -- validate before it's ever joined into a path
    // (the checkout's `widgets_dir`/`checkout_livery_path` below both key
    // off it directly).
    if !aoide_song::compose::valid_song_name(&song) {
        return Outcome::usage(
            cmd,
            format!(
                "{}: `song` (`{song}`) is not a valid song name: must match `^[a-z0-9][a-z0-9-]*$`",
                control_path.display()
            ),
        );
    }
    let widget_field = match doc.get("widget").and_then(Value::as_str) {
        Some(w) => w.to_string(),
        None => {
            return Outcome::error(
                cmd,
                format!(
                    "{}: no `widget` key -- run `lyra preview` to build the root first",
                    control_path.display()
                ),
            )
        }
    };

    let mut changed: Vec<String> = Vec::new();

    // ── widget body ─────────────────────────────────────
    // Never declare a facet file or an out-of-songbook path -- only a
    // widget under `run/qml/songs/` (mirrors a real songbook's own
    // `<song>/widgets/`) is something `preview declare` has any business
    // copying back into the checkout. The prefix check alone is a STRING
    // match and nothing more: a `..`-laden field
    // (`songs/demo/../../../../modules/facets/quickshell/qml/ShellBridge`)
    // satisfies it while resolving to a facet file entirely outside any
    // songbook -- so a `..` component is refused outright, and (the
    // structural check underneath the string one) the field's resolved
    // CHECKOUT file is required to land inside the real checkout songbook.
    if has_parent_dir_component(&widget_field) || !widget_field.starts_with("songs/") {
        return Outcome::usage(
            cmd,
            format!(
                "`widget` (`{widget_field}`) is outside run/qml/songs/ -- `preview declare` only declares a song's own widget body, never a facet file"
            ),
        );
    }
    let songbook_real = match checkout.join("song").join("songbook").canonicalize() {
        Ok(p) => p,
        Err(e) => return Outcome::error(cmd, format!("resolving the checkout songbook: {e}")),
    };
    let source = match resolve_widget_abs(&checkout, &widget_field) {
        Some(p) => p,
        None => {
            return Outcome::error(
                cmd,
                format!("resolving widget `{widget_field}`: no such file under the checkout"),
            )
        }
    };
    let source_is_in_a_songbook_widgets_dir =
        source.strip_prefix(&songbook_real).is_ok_and(|rel| {
            let comps: Vec<_> = rel.components().collect();
            comps.len() >= 3 && comps[1].as_os_str() == "widgets"
        });
    if !source_is_in_a_songbook_widgets_dir {
        return Outcome::usage(
            cmd,
            format!("`widget` (`{widget_field}`) resolves to {} which is outside any songbook's widgets/ directory", source.display()),
        );
    }

    let slot = match inv.flags.get("slot") {
        Some(s) => {
            if !aoide_song::compose::valid_song_name(s) {
                return Outcome::usage(
                    cmd,
                    format!(
                        "`--slot {s}` is not a valid slot name: must match `^[a-z0-9][a-z0-9-]*$`"
                    ),
                );
            }
            s.clone()
        }
        None => match source.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => {
                return Outcome::error(
                    cmd,
                    format!(
                        "{}: cannot derive a slot name -- pass --slot",
                        source.display()
                    ),
                )
            }
        },
    };

    let widgets_dir = checkout
        .join("song")
        .join("songbook")
        .join(&song)
        .join("widgets");
    let target = widgets_dir.join(format!("{slot}.qml"));

    let body_status = if target.canonicalize().ok().as_deref() == Some(source.as_path()) {
        // "already" -- the checkout file already IS the previewed body
        // (the previewed widget resolved straight through to its own
        // songbook slot; there is nothing to copy).
        "already"
    } else {
        let src_bytes = match std::fs::read(&source) {
            Ok(b) => b,
            Err(e) => return Outcome::error(cmd, format!("reading {}: {e}", source.display())),
        };
        if std::fs::read(&target).ok().as_deref() == Some(src_bytes.as_slice()) {
            "unchanged"
        } else {
            if let Err(e) = std::fs::create_dir_all(&widgets_dir) {
                return Outcome::error(cmd, format!("creating {}: {e}", widgets_dir.display()));
            }
            if let Err(e) = aoide_storage::fs::atomic_write_bytes(&target, &src_bytes) {
                return Outcome::error(cmd, format!("writing {}: {e}", target.display()));
            }
            changed.push(target.to_string_lossy().into_owned());
            "declared"
        }
    };

    // ── palette ─────────────────────────────────────────
    let livery_source = doc
        .get("liverySource")
        .and_then(Value::as_str)
        .unwrap_or("");
    let palette_status = if livery_source == song {
        "own"
    } else {
        let stage_livery_path = root.join("song").join("stage").join("livery.json");
        let raw = match std::fs::read_to_string(&stage_livery_path) {
            Ok(s) => s,
            Err(e) => {
                return Outcome::error(cmd, format!("reading {}: {e}", stage_livery_path.display()))
            }
        };
        let resolved: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return Outcome::error(cmd, format!("parsing {}: {e}", stage_livery_path.display()))
            }
        };

        let checkout_livery_path = checkout
            .join("song")
            .join("songbook")
            .join(&song)
            .join("livery.json");
        let original_raw = std::fs::read_to_string(&checkout_livery_path).ok();
        let mut checkout_obj: Map<String, Value> = match &original_raw {
            Some(s) => match serde_json::from_str(s) {
                Ok(Value::Object(m)) => m,
                _ => {
                    return Outcome::error(
                        cmd,
                        format!("{}: not a JSON object", checkout_livery_path.display()),
                    )
                }
            },
            None => {
                let mut m = Map::new();
                m.insert("schemaVersion".to_string(), json!(SCHEMA_VERSION));
                m
            }
        };

        for tier in ["palette", "base16", "bar", "notif", "window"] {
            match resolved.get(tier) {
                Some(v) => {
                    checkout_obj.insert(tier.to_string(), v.clone());
                }
                None => {
                    checkout_obj.remove(tier);
                }
            }
        }
        checkout_obj.remove("song");

        let pretty = match serde_json::to_string_pretty(&Value::Object(checkout_obj)) {
            Ok(s) => s + "\n",
            Err(e) => {
                return Outcome::error(
                    cmd,
                    format!("serializing {}: {e}", checkout_livery_path.display()),
                )
            }
        };
        if original_raw.as_deref() == Some(pretty.as_str()) {
            "unchanged"
        } else {
            if let Err(e) = aoide_storage::fs::atomic_write(&checkout_livery_path, &pretty) {
                return Outcome::error(
                    cmd,
                    format!("writing {}: {e}", checkout_livery_path.display()),
                );
            }
            changed.push(checkout_livery_path.to_string_lossy().into_owned());
            "declared"
        }
    };

    let message = if changed.is_empty() {
        format!("`{song}` already matches the preview -- commit and rebuild are yours")
    } else {
        format!(
            "{} file(s) declared into {} -- commit and rebuild are yours",
            changed.len(),
            checkout.join("song").join("songbook").join(&song).display()
        )
    };

    Outcome::ok(cmd, message)
        .gated(true)
        .changed(changed.clone())
        .with_data(json!({
            "body": body_status,
            "palette": palette_status,
            "files": changed,
        }))
}

// ─────────────────────────── root resolution ───────────────────────────

/// `$XDG_RUNTIME_DIR/aoide-preview` when set, else `temp_dir()/aoide-
/// preview-<uid>` — deliberately NEVER `$XDG_RUNTIME_DIR/aoide/…`, the live
/// daemon's own socket dir (`aoided.sock`, `session-*.sock`); the live
/// reaper and socket globs look there, so a preview root under it would be
/// swept or mistaken for a real session.
fn default_root() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("aoide-preview");
        }
    }
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("aoide-preview-{uid}"))
}

/// The daemon's stable runtime dir, `$XDG_RUNTIME_DIR/aoide` -- the SAME
/// value `aoide_storage::attest::daemon_socket_path().parent()` returns
/// when nothing overrides it, but computed here WITHOUT reading
/// `$AOIDE_DAEMON_SOCKET`. That override matters: the canvas's own child
/// env repoints it at `<root>/no-daemon.sock` (`child_env`, below), so a
/// gate that trusted `daemon_socket_path()` would see the preview root
/// itself as "the live dir" from inside its own canvas and refuse every
/// `--root <root>` rail call. This is the live dir as the REAL daemon would
/// resolve it from a plain shell, independent of what a canvas child
/// repoints; duplicated from attest's own unset-fallback (`/run/user/1000`)
/// rather than reaching into that crate's env-reading internals.
fn live_daemon_dir() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/run/user/1000".into());
    PathBuf::from(runtime).join("aoide")
}

/// The root a `--root` names, else [`default_root`]. A relative `--root`
/// is taken against the current directory. Refused, as a usage error: a
/// `..` component, and anything at or under [`live_daemon_dir`] -- the LIVE
/// daemon's socket dir, whose reaper and socket globs would sweep a preview
/// root or mistake it for a real session.
pub(crate) fn resolve_root(root_flag: Option<&str>) -> Result<PathBuf, String> {
    let candidate = match root_flag {
        Some(r) if !r.is_empty() => {
            let p = PathBuf::from(r);
            if p.is_absolute() {
                p
            } else {
                std::env::current_dir()
                    .map_err(|e| format!("resolving --root `{r}`: current dir: {e}"))?
                    .join(p)
            }
        }
        _ => return Ok(default_root()),
    };
    check_root(&candidate, Some(&live_daemon_dir()))
}

/// The checking half of [`resolve_root`]: `candidate` is absolute already,
/// `live_dir` the daemon's runtime dir. Both the path as spelled AND what
/// it resolves to (its deepest existing ancestor canonicalized, the rest
/// appended -- the same shape as `preview declare`'s containment check)
/// are compared against the live dir as spelled and as resolved, so a
/// `--root` that is itself a symlink into the live dir cannot pass on
/// spelling alone. `starts_with` is component-wise, so `.../aoide-preview`
/// is NOT under `.../aoide`.
fn check_root(candidate: &Path, live_dir: Option<&Path>) -> Result<PathBuf, String> {
    if candidate
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "--root `{}` has a `..` component -- name the root directory directly",
            candidate.display()
        ));
    }
    if let Some(live) = live_dir {
        let resolved = resolve_existing_prefix(candidate);
        let live_resolved = resolve_existing_prefix(live);
        let under = [candidate, resolved.as_path()]
            .iter()
            .any(|p| p.starts_with(live) || p.starts_with(&live_resolved));
        if under {
            return Err(format!(
                "--root `{}` is under {} -- the live daemon's own dir, swept by its reaper; use the default $XDG_RUNTIME_DIR/aoide-preview or any directory outside it",
                candidate.display(),
                live.display()
            ));
        }
    }
    Ok(candidate.to_path_buf())
}

/// `p` with its deepest EXISTING ancestor canonicalized (symlinks
/// followed) and the not-yet-existing tail appended verbatim; `p` itself
/// when nothing along it exists.
fn resolve_existing_prefix(p: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        if let Ok(real) = cur.canonicalize() {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.file_name(), cur.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

fn pid_file(root: &Path) -> PathBuf {
    root.join("preview.pid")
}

/// Refuse a second `lyra preview` against the same root while a first one's
/// canvas is still up — `preview.pid` names the FIRST invocation's own pid
/// (the `lyra` process, not quickshell's), so `kill(pid, 0)` is a pure
/// liveness probe with no signal delivered.
fn refuse_if_running(root: &Path) -> Result<(), String> {
    let pf = pid_file(root);
    let Ok(content) = std::fs::read_to_string(&pf) else {
        return Ok(());
    };
    let Ok(pid) = content.trim().parse::<i32>() else {
        return Ok(());
    };
    if pid_is_live(pid) {
        return Err(format!(
            "a canvas is already running on {} (pid {pid}); use --root for a second one",
            root.display()
        ));
    }
    Ok(())
}

fn pid_is_live(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

// ─────────────────────────── control file ───────────────────────────

pub(crate) fn read_control(path: &Path) -> Option<Map<String, Value>> {
    let raw = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<Value>(&raw).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn write_control(path: &Path, doc: &Map<String, Value>) -> Result<(), String> {
    let body = serde_json::to_string_pretty(&Value::Object(doc.clone()))
        .map_err(|e| format!("serializing {}: {e}", path.display()))?
        + "\n";
    aoide_storage::fs::atomic_write(path, &body)
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

// ─────────────────────────── livery staging ───────────────────────────

/// A livery-staging failure, distinguishing a usage error (bad input, worth
/// telling the caller how to fix) from an engine/IO error.
#[derive(Debug)]
enum LiveryStageError {
    Usage(String),
    Error(String),
}

/// Load `--livery <spec>`'s raw container, before it goes through the
/// engine. Four forms, disambiguated by shape:
///   - `"live"` — the resolved LIVE stage twin (`aoide_storage::fs::
///     stage_dir().join("livery.json")`, host overrides included) — read
///     only, never written by this command.
///   - a bare valid song name that has a songbook dir — that song's own
///     `song/songbook/<name>/livery.json`.
///   - anything else — a literal path, either to a livery file or to a
///     base16 scheme file (JSON or the flat line shape); [`parse_livery_or_base16`]
///     tells the two apart.
fn load_livery_container(spec: &str, checkout: &Path) -> Result<Value, LiveryStageError> {
    let src: PathBuf = if spec == "live" {
        aoide_storage::fs::stage_dir().join("livery.json")
    } else if !spec.contains('/')
        && aoide_song::compose::valid_song_name(spec)
        && checkout.join("song").join("songbook").join(spec).is_dir()
    {
        checkout
            .join("song")
            .join("songbook")
            .join(spec)
            .join("livery.json")
    } else {
        PathBuf::from(spec)
    };
    let raw = std::fs::read_to_string(&src)
        .map_err(|e| LiveryStageError::Error(format!("reading {}: {e}", src.display())))?;
    parse_livery_or_base16(&raw, &src)
}

/// A livery FILE parses as a JSON object carrying `palette`/`base16`/… and
/// is returned as-is. A base16 SCHEME is detected by `base00` present and
/// `palette` absent (JSON gallery shape, or the flat `key: value` line
/// shape this workspace has no yaml crate to parse properly) and gets
/// synthesized into a livery container by [`livery_from_base16`].
fn parse_livery_or_base16(raw: &str, src: &Path) -> Result<Value, LiveryStageError> {
    if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(raw) {
        if obj.contains_key("base00") && !obj.contains_key("palette") {
            let scheme = base16_scheme_from_json(&obj);
            return livery_from_base16(&scheme).map_err(|missing| {
                LiveryStageError::Usage(format!(
                    "{}: base16 scheme missing slot(s): {}",
                    src.display(),
                    missing.join(", ")
                ))
            });
        }
        return Ok(Value::Object(obj));
    }
    let scheme = parse_flat_base16_lines(raw);
    if scheme.contains_key("base00") {
        return livery_from_base16(&scheme).map_err(|missing| {
            LiveryStageError::Usage(format!(
                "{}: base16 scheme missing slot(s): {}",
                src.display(),
                missing.join(", ")
            ))
        });
    }
    Err(LiveryStageError::Error(format!(
        "{}: not a livery JSON object or a recognized base16 scheme",
        src.display()
    )))
}

/// Pull the sixteen `base0X` string slots out of an already-parsed JSON
/// object, normalizing each hex value on the way in.
fn base16_scheme_from_json(obj: &Map<String, Value>) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for key in aoide_song::livery::schema::BASE16_KEYS {
        if let Some(v) = obj.get(key).and_then(Value::as_str) {
            out.insert(key.to_string(), normalize_hex(v));
        }
    }
    out
}

/// A tiny hand-rolled line parser for the flat base16 YAML shape
/// (`scheme: "…"` / `base00: "1e1e2e"`, one `key: value` per line, `#`
/// comments, optional quotes) — there is no yaml crate in this workspace
/// and this is the one shape base16 gallery schemes actually ship in, so a
/// real parser would be a dependency for four lines of syntax. Only
/// `base0X` keys are collected; every other line (`scheme:`, `author:`, …)
/// is ignored.
fn parse_flat_base16_lines(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if !aoide_song::livery::schema::BASE16_KEYS.contains(&key) {
            continue;
        }
        let mut value = value.trim();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = &value[1..value.len() - 1];
        }
        out.insert(key.to_string(), normalize_hex(value));
    }
    out
}

/// Hex normalization: `--livery`'s base16 forms may arrive with or without
/// a leading `#`, in any case — every value this command stages is
/// `#rrggbb` lowercase.
fn normalize_hex(s: &str) -> String {
    format!("#{}", s.trim().trim_start_matches('#').to_lowercase())
}

/// Synthesize a v0 livery container from a bare base16 scheme. The palette
/// mapping — `bg=base00, fg=base05, accent=base0D, urgent=base08,
/// hot=base0B` — is CONTRACTS.md §1's base16 column read in reverse, the
/// mirror of `modules/facets/stylix/default.nix`'s `synthesisedScheme`
/// (lines 77-105), which derives base16 FROM the palette in the opposite
/// direction. `hot=base0B` is this reverse seam's own choice: stylix's
/// forward mapping never emits a `hot` slot at all (`hot` is optional and
/// palette-only), so there is no existing round-trip to preserve for it —
/// `base0B` (the ramp's other accent slot, "green" in the standard
/// naming) was picked to keep `hot` visually distinct from `accent`
/// (`base0D`). `bar`/`notif`/`window` all-null so `resolve` applies the
/// palette fallback (CONTRACTS.md §1) instead of a synthesized guess.
fn livery_from_base16(
    scheme: &std::collections::BTreeMap<String, String>,
) -> Result<Value, Vec<String>> {
    let missing: Vec<String> = aoide_song::livery::schema::BASE16_KEYS
        .iter()
        .filter(|k| !scheme.contains_key(**k))
        .map(|k| k.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(missing);
    }
    let get = |k: &str| scheme.get(k).cloned().unwrap_or_default();
    let base16: Map<String, Value> = aoide_song::livery::schema::BASE16_KEYS
        .iter()
        .map(|k| (k.to_string(), json!(get(k))))
        .collect();
    Ok(json!({
        "schemaVersion": SCHEMA_VERSION,
        "palette": {
            "bg": get("base00"),
            "fg": get("base05"),
            "accent": get("base0D"),
            "urgent": get("base08"),
            "hot": get("base0B"),
        },
        "base16": base16,
        "bar": { "bg": Value::Null, "fg": Value::Null, "accent": Value::Null },
        "notif": { "bg": Value::Null, "fg": Value::Null, "urgent": Value::Null },
        "window": { "border": Value::Null, "borderInactive": Value::Null },
    }))
}

/// Every songbook dir under the checkout with a `livery.json` of its own,
/// sorted, `_`-prefixed (shelved) dirs skipped — `preview.json`'s
/// `"liveries"` list, so a future picker UI (or a human reading the
/// control file) can see every `<song>` form `--livery` will accept
/// without having to `ls` the songbook by hand.
fn list_liveries(checkout: &Path) -> Vec<String> {
    let songbook = checkout.join("song").join("songbook");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&songbook) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('_') {
            continue;
        }
        if entry.path().join("livery.json").is_file() {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// Stage `spec` (any of the four `--livery` forms) into `dst`, through the
/// SAME engine every live emit uses: [`load_livery_container`] resolves the
/// form to a raw container, `aoide_song::livery::resolve::resolve` +
/// `to_json_string` fully resolve it (fallbacks applied — the document
/// `lyra livery resolve` itself prints; `LiveryState` on the QML side never
/// sees a null), the string is reparsed, given `"song": <song>`, pretty-
/// printed with a trailing newline, and atomic-written. A resolve failure
/// returns [`LiveryStageError::Error`] and leaves `dst` untouched — the
/// caller must not have already deleted or truncated it.
fn stage_livery(
    spec: &str,
    song: &str,
    checkout: &Path,
    dst: &Path,
) -> Result<(), LiveryStageError> {
    let container = load_livery_container(spec, checkout)?;
    let resolved = aoide_song::livery::resolve::resolve(&container)
        .map_err(|e| LiveryStageError::Error(format!("resolving livery `{spec}`: {e}")))?;
    let staged = aoide_song::livery::resolve::to_json_string(&resolved);
    let mut obj = match serde_json::from_str::<Value>(&staged) {
        Ok(Value::Object(obj)) => obj,
        _ => {
            return Err(LiveryStageError::Error(format!(
                "resolving livery `{spec}`: engine produced non-object output"
            )))
        }
    };
    obj.insert("song".to_string(), json!(song));
    let pretty = serde_json::to_string_pretty(&Value::Object(obj))
        .map_err(|e| LiveryStageError::Error(format!("serializing resolved livery: {e}")))?
        + "\n";
    aoide_storage::fs::atomic_write(dst, &pretty)
        .map_err(|e| LiveryStageError::Error(format!("writing {}: {e}", dst.display())))
}

// ─────────────────────────── other facet stage files ───────────────────────────

/// `ROOT/song/stage/mode.json` -- the facet QML's own rice-mode read
/// (`LiveryState.qml`, lines 216/267, and its callers all expect this file
/// to exist). Rewritten UNCONDITIONALLY on every `lyra preview` build and
/// on `preview set --song`: the canvas's mode is always "staging" of the
/// PREVIEWED song, never whatever the live root's own `rice mode` last
/// set -- there is no live mode to reflect inside an isolated preview.
fn write_mode_json(root: &Path, song: &str) -> Result<(), String> {
    let path = root.join("song").join("stage").join("mode.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let doc = json!({
        "mode": "staging",
        "song": song,
        "stagingSong": song,
        "since": aoide_storage::time::now_iso_utc(),
    });
    let pretty = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
    aoide_storage::fs::atomic_write(&path, &pretty)
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Every OTHER facet-read stage file a preview root needs merely to EXIST
/// so its QML doesn't start with a parse warning on a missing file:
/// `song/stage/cover.json` (`LiveryState.qml`/`AoideWallpaper.qml:32`),
/// `song/stage/grimoire.json` (`GrimoireLedger`), and `state/usage.json`.
/// Seeded once, on the initial build, and never overwritten again by this
/// command -- unlike `mode.json` these aren't part of what a preview
/// iterates on, just present so nothing errors.
fn seed_static_stage_files(root: &Path) -> Result<(), String> {
    seed_if_absent(
        &root.join("song").join("stage").join("cover.json"),
        &json!({ "path": "" }),
    )?;
    // `schemaVersion` is a STRING "0" on every real stage file this
    // workspace writes (`jq .schemaVersion` against the live
    // `grimoire.json`/`usage.json` both print `"0"`, matching
    // `SCHEMA_VERSION`'s own type here) -- a bare number would be a type
    // mismatch against what these facets actually read on a real host.
    // `launches` is an OBJECT keyed by app id on both the live file and
    // `GrimoireLedger.qml:113`, never an array.
    seed_if_absent(
        &root.join("song").join("stage").join("grimoire.json"),
        &json!({ "schemaVersion": SCHEMA_VERSION, "launches": {} }),
    )?;
    seed_if_absent(
        &root.join("state").join("usage.json"),
        &json!({ "schemaVersion": SCHEMA_VERSION, "fetchedAt": "", "live": {}, "local": {} }),
    )
}

/// Write `value` to `path` only when it doesn't already exist -- a rebuild
/// must never clobber whatever's already there.
fn seed_if_absent(path: &Path, value: &Value) -> Result<(), String> {
    if path.is_file() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let pretty = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    aoide_storage::fs::atomic_write(path, &pretty)
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

// ─────────────────────────── fixture staging ───────────────────────────

const FIXTURE_FILES: &[(&str, &str)] = &[
    ("sessions.json", r#"{"schemaVersion":"0","sessions":[]}"#),
    ("projects.json", r#"{"schemaVersion":"0","projects":[]}"#),
    ("hooks.json", "{}"),
    ("herald.json", "{}"),
];

#[derive(Debug)]
enum FixtureSource {
    Dir(PathBuf),
    BuiltinEmpty,
}

fn fixtures_registry_dir(checkout: &Path) -> PathBuf {
    checkout
        .join("modules")
        .join("facets")
        .join("quickshell")
        .join("preview")
        .join("fixtures")
}

fn list_available_fixture_sets(checkout: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(fixtures_registry_dir(checkout)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// `--fixture` resolution (`preview` and `preview set` share this):
/// a value containing `/` is a literal directory; else it names a set
/// under [`fixtures_registry_dir`]. Neither existing yet is only a hard
/// error when at least one OTHER fixture set is on disk (a real typo);
/// with none at all (P2 hasn't landed any yet) this falls back to
/// [`FixtureSource::BuiltinEmpty`] so `lyra preview` still works today.
fn resolve_fixture_source(checkout: &Path, fixture_arg: &str) -> Result<FixtureSource, String> {
    let target = if fixture_arg.contains('/') {
        PathBuf::from(fixture_arg)
    } else {
        fixtures_registry_dir(checkout).join(fixture_arg)
    };
    if target.is_dir() {
        return Ok(FixtureSource::Dir(target));
    }
    let available = list_available_fixture_sets(checkout);
    if available.is_empty() {
        return Ok(FixtureSource::BuiltinEmpty);
    }
    Err(format!(
        "fixture `{fixture_arg}` not found at {} (available: {})",
        target.display(),
        available.join(", ")
    ))
}

/// Materialize the four state/stage fixture files. A [`FixtureSource::Dir`]
/// missing one of the four falls back to that ONE file's own empty default
/// rather than failing the whole build — the fixture set may simply not
/// need to seed every kind of state.
fn stage_fixture(source: &FixtureSource, state_stage_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(state_stage_dir)
        .map_err(|e| format!("creating {}: {e}", state_stage_dir.display()))?;
    for (name, default_body) in FIXTURE_FILES {
        let dst = state_stage_dir.join(name);
        let write_default = || aoide_storage::fs::atomic_write(&dst, &format!("{default_body}\n"));
        match source {
            FixtureSource::Dir(dir) => {
                let src = dir.join(name);
                if src.is_file() {
                    let bytes = std::fs::read(&src)
                        .map_err(|e| format!("reading {}: {e}", src.display()))?;
                    aoide_storage::fs::atomic_write_bytes(&dst, &bytes)
                } else {
                    write_default()
                }
            }
            FixtureSource::BuiltinEmpty => write_default(),
        }
        .map_err(|e| format!("writing {}: {e}", dst.display()))?;
    }
    Ok(())
}

// ─────────────────────────── run/qml staging (copies) ───────────────────────────
//
// `ROOT/run/qml/*` are COPIES of the checkout's files, never symlinks into
// it: a write through `run/qml/` (a worker's `cat >`, an editor's save, a
// misdirected `declare`) must land in the throwaway root and nowhere else.
// The checkout is the ONLY place a widget is edited; the canvas refreshes
// its copies from preview.json's `stage` map before every reload, and a
// `lyra preview --no-launch --root <ROOT>` rebuild re-stages everything.

/// Whatever stands at `dst` (a stale symlink from an older root, a file, a
/// dir) is removed first, so a root built by an earlier symlinking build
/// upgrades to copies on its next rebuild.
fn remove_stale(dst: &Path) -> Result<(), String> {
    let Ok(md) = std::fs::symlink_metadata(dst) else {
        return Ok(());
    };
    let res = if md.is_dir() {
        std::fs::remove_dir_all(dst)
    } else {
        std::fs::remove_file(dst)
    };
    res.map_err(|e| format!("removing stale {}: {e}", dst.display()))
}

fn copy_file_fresh(src: &Path, dst: &Path) -> Result<(), String> {
    remove_stale(dst)?;
    let bytes = std::fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    aoide_storage::fs::atomic_write_bytes(dst, &bytes)
        .map_err(|e| format!("writing {}: {e}", dst.display()))
}

/// Copy every regular file under `src_dir` (recursing into real
/// subdirectories; symlinks inside the checkout are skipped, never
/// followed) into a fresh `dst_dir`.
fn copy_tree_fresh(src_dir: &Path, dst_dir: &Path) -> Result<(), String> {
    remove_stale(dst_dir)?;
    std::fs::create_dir_all(dst_dir).map_err(|e| format!("creating {}: {e}", dst_dir.display()))?;
    let entries =
        std::fs::read_dir(src_dir).map_err(|e| format!("reading {}: {e}", src_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", src_dir.display()))?;
        let ft = entry
            .file_type()
            .map_err(|e| format!("reading {}: {e}", entry.path().display()))?;
        let dst = dst_dir.join(entry.file_name());
        if ft.is_dir() {
            copy_tree_fresh(&entry.path(), &dst)?;
        } else if ft.is_file() {
            copy_file_fresh(&entry.path(), &dst)?;
        }
    }
    Ok(())
}

/// One copy per `*.qml` in `CHECKOUT/modules/facets/quickshell/qml/`,
/// landing at `ROOT/run/qml/<file>.qml`, plus the facet's resolved icon
/// assets (`CHECKOUT/modules/facets/quickshell/icons/` -> `ROOT/run/qml/
/// icons/`, the canvas toolbar's `Qt.resolvedUrl("icons/...")` source) —
/// refreshed on every build, so a rebuild always reflects the checkout's
/// CURRENT files. Icons are `lyra icon resolve` output already in the
/// checkout; nothing is fetched here.
fn stage_qml_copies(checkout: &Path, run_qml_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(run_qml_dir)
        .map_err(|e| format!("creating {}: {e}", run_qml_dir.display()))?;
    let facet = checkout.join("modules").join("facets").join("quickshell");
    let icons = facet.join("icons");
    if icons.is_dir() {
        copy_tree_fresh(&icons, &run_qml_dir.join("icons"))?;
    }
    let src_dir = facet.join("qml");
    let Ok(entries) = std::fs::read_dir(&src_dir) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", src_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("qml") && path.is_file() {
            copy_file_fresh(&path, &run_qml_dir.join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// One copied tree per song dir under `CHECKOUT/song/songbook/` that has a
/// `widgets/` dir, `_`-prefixed (shelved) dirs skipped — `ROOT/run/qml/
/// songs/<song>/` mirrors that song's OWN `widgets/` dir, so `import
/// "../.."`-shaped relative imports inside a widget resolve exactly as
/// they do under the live deployed tree.
fn stage_song_copies(checkout: &Path, run_qml_songs: &Path) -> Result<(), String> {
    std::fs::create_dir_all(run_qml_songs)
        .map_err(|e| format!("creating {}: {e}", run_qml_songs.display()))?;
    let songbook = checkout.join("song").join("songbook");
    let Ok(entries) = std::fs::read_dir(&songbook) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", songbook.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('_') {
            continue;
        }
        let widgets_dir = path.join("widgets");
        if widgets_dir.is_dir() {
            copy_tree_fresh(&widgets_dir, &run_qml_songs.join(&name))?;
        }
    }
    Ok(())
}

/// `src -> dst` for every `watch` entry that has a copy under `ROOT/run/
/// qml/` (a songbook widget file: `CHECKOUT/song/songbook/<s>/widgets/<rest>`
/// -> `ROOT/run/qml/songs/<s>/<rest>`). The canvas rewrites each `dst` from
/// its `src` before a reload; a watched file with no copy (a foreign path
/// the canvas loads verbatim) has no entry.
fn compute_stage_map(checkout: &Path, root: &Path, watch: &[String]) -> Map<String, Value> {
    let songbook = checkout.join("song").join("songbook");
    let mut out = Map::new();
    for src in watch {
        let Ok(rel) = Path::new(src).strip_prefix(&songbook) else {
            continue;
        };
        let comps: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if comps.len() >= 3 && comps[1] == "widgets" {
            let dst = root
                .join("run")
                .join("qml")
                .join("songs")
                .join(&comps[0])
                .join(comps[2..].join("/"));
            out.insert(src.clone(), json!(dst.to_string_lossy()));
        }
    }
    out
}

/// `ROOT/run/qml/songs/{manifest,registry}.json` — copied verbatim from the
/// LIVE deployed tree (`aoide_storage::fs::run_qml_dir()`) when present,
/// else the literal `{}` (a fresh host with no `lyra rice stage` history
/// yet has neither file).
fn stage_songs_manifest(run_qml_songs: &Path) -> Result<(), String> {
    for name in ["manifest.json", "registry.json"] {
        let src = aoide_storage::fs::run_qml_dir().join("songs").join(name);
        let dst = run_qml_songs.join(name);
        match std::fs::read(&src) {
            Ok(bytes) => aoide_storage::fs::atomic_write_bytes(&dst, &bytes),
            Err(_) => aoide_storage::fs::atomic_write(&dst, "{}"),
        }
        .map_err(|e| format!("writing {}: {e}", dst.display()))?;
    }
    Ok(())
}

// ─────────────────────────── widget positional mapping ───────────────────────────

/// True if any component of `s` is a literal `..` -- the structural half of
/// every widget-path guard in this module: a `..`-laden widget spec
/// resolves (`songs/<song>/../../..`) to a file entirely outside the tree
/// a string-prefix check thinks it's confined to. Checked at every site a
/// widget spec enters this module raw -- the positional arg in `preview`,
/// `--widget` in `preview set`, and (as a second, independent guard) the
/// persisted field `preview declare` reads back.
fn has_parent_dir_component(s: &str) -> bool {
    Path::new(s)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Pure: an absolute path under `CHECKOUT/song/songbook/<s>/widgets/<file>`
/// rewrites to `songs/<s>/<file>` (so it resolves inside the isolated
/// root's own run/qml copies); any other absolute path is kept verbatim (the
/// canvas reports the load error live — this never checks existence);
/// `<song>/<slot>` and a bare `<slot>` (against `song`) both map to
/// `songs/<song>/<slot>.qml`.
fn map_widget(widget: &str, song: &str, checkout: &Path) -> String {
    let p = Path::new(widget);
    if p.is_absolute() {
        let songbook = checkout.join("song").join("songbook");
        if let Ok(rel) = p.strip_prefix(&songbook) {
            let comps: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            if comps.len() >= 3 && comps[1] == "widgets" {
                let file = comps[2..].join("/");
                return format!("songs/{}/{file}", comps[0]);
            }
        }
        return widget.to_string();
    }
    if widget.starts_with("songs/") {
        // Already the canvas's own spelling -- and exactly what
        // `preview.json`'s `widget` field itself holds, so `preview set
        // --widget songs/sonata/conductor.qml` (round-tripping a value
        // read back from the control file) must pass through unchanged.
        // Falling into the `split_once` branch below would double-prefix
        // it (`songs/songs/sonata/conductor.qml.qml`).
        return widget.to_string();
    }
    if let Some((s, slot)) = widget.split_once('/') {
        return format!("songs/{s}/{slot}.qml");
    }
    format!("songs/{song}/{widget}.qml")
}

/// Resolve a `preview.json` `widget` field to the CHECKOUT file it names
/// (the file the designer edits -- never the root's own copy of it):
/// absolute already (an out-of-songbook path `map_widget` passed through
/// verbatim) is canonicalized directly; `songs/<s>/<rest>` maps to
/// `CHECKOUT/song/songbook/<s>/widgets/<rest>`; any other relative
/// spelling is a facet file, `CHECKOUT/modules/facets/quickshell/qml/
/// <rest>`. A `..` component is refused (`None`), as is a missing file --
/// best-effort metadata for [`compute_watch_list`], never worth failing
/// the whole build/merge over.
pub(crate) fn resolve_widget_abs(checkout: &Path, widget_field: &str) -> Option<PathBuf> {
    if has_parent_dir_component(widget_field) {
        return None;
    }
    let p = Path::new(widget_field);
    let candidate = if p.is_absolute() {
        p.to_path_buf()
    } else if let Some(rest) = widget_field.strip_prefix("songs/") {
        let (song, file) = rest.split_once('/')?;
        checkout
            .join("song")
            .join("songbook")
            .join(song)
            .join("widgets")
            .join(file)
    } else {
        checkout
            .join("modules")
            .join("facets")
            .join("quickshell")
            .join("qml")
            .join(widget_field)
    };
    candidate.canonicalize().ok()
}

/// The P2 canvas's hot-reload watch set (task: live reload + `preview
/// declare`): every `*.qml` under the CURRENT song's own
/// `checkout/song/songbook/<song>/widgets/` (sorted), plus the previewed
/// widget's own resolved file when it lives somewhere else -- a foreign
/// song's widget, or a facet path passed in verbatim. Pure over an
/// already-resolved absolute widget path so it needs no env, no preview
/// root, and no live filesystem beyond the two directories it's handed.
fn compute_watch_list(checkout: &Path, song: &str, widget_abs: Option<&Path>) -> Vec<String> {
    let widgets_dir = checkout
        .join("song")
        .join("songbook")
        .join(song)
        .join("widgets");
    let mut out: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&widgets_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("qml") {
                out.push(path.to_string_lossy().into_owned());
            }
        }
    }
    if let Some(w) = widget_abs {
        let w = w.to_string_lossy().into_owned();
        if !out.contains(&w) {
            out.push(w);
        }
    }
    out.sort();
    out
}

// ─────────────────────────── preview-set flag parsing (pure) ───────────────────────────

fn parse_bool_on_off(v: &str) -> Result<bool, String> {
    match v {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(format!("`{other}` is not `on` or `off`")),
    }
}

fn parse_dim(v: &str) -> Result<Value, String> {
    if v == "auto" {
        return Ok(json!("auto"));
    }
    match v.parse::<i64>() {
        Ok(n) if n > 0 => Ok(json!(n)),
        _ => Err(format!("`{v}` is not a positive integer or `auto`")),
    }
}

fn parse_zoom(v: &str) -> Result<Value, String> {
    if v == "fit" {
        return Ok(json!("fit"));
    }
    match v.parse::<f64>() {
        Ok(n) if n > 0.0 => Ok(json!(n)),
        _ => Err(format!("`{v}` is not `fit` or a positive number")),
    }
}

fn parse_margin(v: &str) -> Result<i64, String> {
    match v.parse::<i64>() {
        Ok(n) if n >= 0 => Ok(n),
        Ok(_) => Err(format!("`{v}` must be >= 0")),
        Err(_) => Err(format!("`{v}` is not an integer")),
    }
}

fn parse_anchor(v: &str) -> Result<&str, String> {
    ANCHORS
        .iter()
        .find(|a| **a == v)
        .copied()
        .ok_or_else(|| format!("`{v}` is not one of: {}", ANCHORS.join(", ")))
}

fn parse_background(v: &str) -> Result<&str, String> {
    match v {
        "livery" | "checker" => Ok(v),
        other => Err(format!("`{other}` is not `livery` or `checker`")),
    }
}

fn viewport_preset(name: &str) -> Option<(u32, u32)> {
    VIEWPORT_PRESETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, w, h)| (*w, *h))
}

fn parse_viewport(v: &str) -> Result<(u32, u32, String), String> {
    if let Some((w, h)) = viewport_preset(v) {
        return Ok((w, h, v.to_string()));
    }
    if let Some((w, h)) = v.split_once('x').or_else(|| v.split_once('X')) {
        if let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>()) {
            return Ok((w, h, "custom".to_string()));
        }
    }
    let presets = VIEWPORT_PRESETS
        .iter()
        .map(|(n, _, _)| *n)
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!("`{v}` is not a WxH size or one of: {presets}"))
}

// ─────────────────────────── child env (pure) ───────────────────────────

/// The child's env overrides plus the keys stripped from it — a pure
/// function so a test can assert the safety property directly: no value
/// here may ever equal or start with the LIVE daemon's socket dir
/// (`$XDG_RUNTIME_DIR/aoide/`), and `AOIDE_DAEMON_SOCKET` must resolve
/// under `root`. Called by [`spawn_quickshell`] only — kept separate so
/// the pure half is testable with no process spawned.
fn child_env(root: &Path) -> (Vec<(String, String)>, &'static [&'static str]) {
    let sets = vec![
        (
            "AOIDE_ROOT".to_string(),
            root.to_string_lossy().into_owned(),
        ),
        (
            "AOIDE_STATE_DIR".to_string(),
            root.join("state").to_string_lossy().into_owned(),
        ),
        (
            "AOIDE_STAGE_DIR".to_string(),
            root.join("state")
                .join("stage")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "AOIDE_DAEMON_SOCKET".to_string(),
            root.join("no-daemon.sock").to_string_lossy().into_owned(),
        ),
    ];
    (sets, ENV_REMOVE)
}

// ─────────────────────────── spawn ───────────────────────────

/// Spawn `quickshell -p <qml_path>` against `root`'s own env. Arms
/// `PR_SET_PDEATHSIG` on the child exactly like `commands::dialog_qml::
/// spawn_quickshell` (lines 205-229 of that file) — the SAME discipline (a
/// killed `lyra preview` must never orphan its own canvas window), rewritten
/// here rather than imported since that function is private to its module
/// and this crate never reaches across a `commands::*` module boundary for
/// one private fn (`pkgs/aoide/crates/AGENTS.md`'s "no cross-crate
/// copying" holds the same shape within a crate too: reach into a `pub`
/// seam, never fork the logic behind a private one).
fn spawn_quickshell(qml_path: &Path, root: &Path) -> std::io::Result<Child> {
    use std::os::unix::process::CommandExt;

    let parent_pid = unsafe { libc::getpid() };
    let (envs, removes) = child_env(root);

    let mut cmd = Command::new("quickshell");
    cmd.args(["-p", &qml_path.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for k in removes {
        cmd.env_remove(k);
    }
    for (k, v) in &envs {
        cmd.env(k, v);
    }

    // SAFETY: this closure runs in the forked CHILD, strictly between
    // `fork()` and `execve()` — only async-signal-safe calls belong here.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                libc::_exit(1);
            }
            Ok(())
        });
    }

    cmd.spawn()
}

/// Best-effort: poll `hyprctl clients -j` for up to 20s (a first launch
/// compiles the whole canvas before its window maps) for the canvas
/// window (`WINDOW_CLASS`/`WINDOW_TITLE`), float it, size it (1400x900, or
/// `<monitor_w-40>x<monitor_h-80>` when the FOCUSED monitor -- read from
/// `hyprctl monitors -j` -- is narrower than that, e.g. a portrait
/// secondary output where a fixed 1400-wide window would land off-screen
/// at a negative x and get clamped out of any shot), and center it. Every
/// failure (no `hyprctl`, not on Hyprland, the window never appearing, a
/// monitor query that fails) is swallowed silently — `aoide_screen` is not
/// a lyra dependency (root `AGENTS.md`'s core/paint boundary), so this
/// shells `hyprctl` directly, the same pattern `aoide_song::live::
/// apply_live` already uses for its own best-effort geometry keywords.
fn best_effort_float(canvas_pid: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(addr) = find_client_address(Some(canvas_pid)) {
            let _ = Command::new("hyprctl")
                .args(["dispatch", "setfloating", &format!("address:{addr}")])
                .status();
            // Size to the focused monitor, then place by address: `centerwindow`
            // acts on the FOCUSED window, which is the launching terminal.
            let (w, h, at) = match focused_monitor_dims() {
                Some((mx, my, mw, mh)) => {
                    let (w, h) = if mw < 1400 {
                        (mw - 40, mh - 80)
                    } else {
                        (1400, 900)
                    };
                    (w, h, Some((mx + (mw - w) / 2, my + (mh - h) / 2)))
                }
                None => (1400, 900, None),
            };
            let _ = Command::new("hyprctl")
                .args([
                    "dispatch",
                    "resizewindowpixel",
                    &format!("exact {w} {h},address:{addr}"),
                ])
                .status();
            match at {
                Some((x, y)) => {
                    let _ = Command::new("hyprctl")
                        .args([
                            "dispatch",
                            "movewindowpixel",
                            &format!("exact {x} {y},address:{addr}"),
                        ])
                        .status();
                }
                None => {
                    let _ = Command::new("hyprctl")
                        .args(["dispatch", "centerwindow"])
                        .status();
                }
            }
            return;
        }
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// The FOCUSED monitor's `(x, y, width, height)` in layout pixels, from
/// `hyprctl monitors -j` — `width`/`height` are the panel's native size, so
/// an odd `transform` (90°/270°, a portrait monitor) swaps them. `None` on
/// any failure (no `hyprctl`, bad JSON, no monitor marked focused).
fn focused_monitor_dims() -> Option<(i64, i64, i64, i64)> {
    let out = Command::new("hyprctl")
        .args(["monitors", "-j"])
        .output()
        .ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    v.as_array()?.iter().find_map(|m| {
        if m.get("focused").and_then(Value::as_bool) != Some(true) {
            return None;
        }
        let x = m.get("x").and_then(Value::as_i64).unwrap_or(0);
        let y = m.get("y").and_then(Value::as_i64).unwrap_or(0);
        let w = m.get("width").and_then(Value::as_i64)?;
        let h = m.get("height").and_then(Value::as_i64)?;
        let rotated = m.get("transform").and_then(Value::as_i64).unwrap_or(0) % 2 == 1;
        Some(if rotated { (x, y, h, w) } else { (x, y, w, h) })
    })
}

/// The Hyprland address of a canvas window: class + title, and — when
/// `pid` is given — that exact quickshell pid, so two open canvases (two
/// roots) never resolve to each other. `None` without `hyprctl`.
pub(crate) fn find_client_address(pid: Option<u32>) -> Option<String> {
    let out = Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
        .ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    v.as_array()?.iter().find_map(|c| {
        if c.get("class").and_then(Value::as_str) == Some(WINDOW_CLASS)
            && c.get("title").and_then(Value::as_str) == Some(WINDOW_TITLE)
            && pid.is_none_or(|p| c.get("pid").and_then(Value::as_u64) == Some(u64::from(p)))
        {
            c.get("address").and_then(Value::as_str).map(String::from)
        } else {
            None
        }
    })
}

// ─────────────────────────── tests ───────────────────────────

/// The quickshell pid painting `root`'s canvas, from `qs list --all` (one
/// `Process ID:` / `Config path:` block per instance) — the instance whose
/// config path is this root's `run/qml/WidgetPreview.qml`. `None` when `qs`
/// is missing or no instance paints this root.
pub(crate) fn canvas_pid(root: &Path) -> Option<u32> {
    let out = Command::new("qs").args(["list", "--all"]).output().ok()?;
    let qml = root.join("run").join("qml").join("WidgetPreview.qml");
    parse_qs_list(&String::from_utf8_lossy(&out.stdout), &qml)
}

fn parse_qs_list(text: &str, qml: &Path) -> Option<u32> {
    let want = qml.to_string_lossy();
    let mut pid: Option<u32> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Instance ") {
            pid = None;
        } else if let Some(v) = line.strip_prefix("Process ID:") {
            pid = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("Config path:") {
            if v.trim() == want.as_ref() {
                return pid;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_qs_list_picks_the_instance_whose_config_path_is_this_roots_canvas() {
        let text = "Instance a:\n  Process ID: 11\n  Shell ID: x\n  Config path: /home/u/.aoide/run/qml/shell.qml\n\nInstance b:\n  Process ID: 22\n  Config path: /tmp/r/run/qml/WidgetPreview.qml\n";
        assert_eq!(
            parse_qs_list(text, Path::new("/tmp/r/run/qml/WidgetPreview.qml")),
            Some(22)
        );
        assert_eq!(
            parse_qs_list(text, Path::new("/tmp/other/run/qml/WidgetPreview.qml")),
            None
        );
        assert_eq!(
            parse_qs_list("", Path::new("/tmp/r/run/qml/WidgetPreview.qml")),
            None
        );
    }
    use std::collections::BTreeMap;

    /// A fake CHECKOUT: `flake.nix`, a couple of facet qml files, two songs
    /// (one with a `_`-prefixed shelved sibling that must be skipped).
    fn fake_checkout(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("flake.nix"), "{ }\n").unwrap();

        let qml = dir.join("modules/facets/quickshell/qml");
        std::fs::create_dir_all(&qml).unwrap();
        std::fs::write(qml.join("ShellBridge.qml"), "// bridge\n").unwrap();
        std::fs::write(qml.join("LiveryState.qml"), "// livery\n").unwrap();
        std::fs::write(qml.join("not-qml.txt"), "ignore me\n").unwrap();
        let icons = dir.join("modules/facets/quickshell/icons/iconoir");
        std::fs::create_dir_all(&icons).unwrap();
        std::fs::write(icons.join("drag-hand-gesture.svg"), "<svg/>\n").unwrap();

        let songbook = dir.join("song/songbook");
        let sonata_widgets = songbook.join("sonata/widgets");
        std::fs::create_dir_all(&sonata_widgets).unwrap();
        std::fs::write(sonata_widgets.join("conductor.qml"), "// conductor\n").unwrap();
        std::fs::write(
            songbook.join("sonata/livery.json"),
            r##"{"palette": {"bg": "#111111", "fg": "#eeeeee", "accent": "#ff00ff", "urgent": "#ff0000"}}"##,
        )
        .unwrap();

        let etude_widgets = songbook.join("etude/widgets");
        std::fs::create_dir_all(&etude_widgets).unwrap();
        std::fs::write(etude_widgets.join("dock.qml"), "// dock\n").unwrap();
        std::fs::write(
            songbook.join("etude/livery.json"),
            r##"{"palette": {"bg": "#222222", "fg": "#dddddd", "accent": "#00ffff", "urgent": "#ffaa00"}}"##,
        )
        .unwrap();

        // shelved: has a widgets/ dir too, but must never be linked.
        let shelved_widgets = songbook.join("_shelved/widgets");
        std::fs::create_dir_all(&shelved_widgets).unwrap();
        std::fs::write(shelved_widgets.join("x.qml"), "// x\n").unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide_lyra_preview_test_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ── root builder ──────────────────────────────────────────

    #[test]
    fn root_builder_creates_the_exact_tree_with_manifest_fallback() {
        // `stage_songs_manifest` reads `aoide_storage::fs::run_qml_dir()`,
        // which honors `$AOIDE_STAGE_DIR` (process-global,
        // `pkgs/aoide/crates/AGENTS.md`'s "per-crate tests only" note) --
        // pin it at a scratch dir with no deployed manifest so this test
        // never reads the REAL host's `~/.aoide` and never races another
        // test in this binary over the same env var.
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved_stage_dir = std::env::var_os("AOIDE_STAGE_DIR");

        let base = scratch("root_builder");
        let checkout = base.join("checkout");
        let root = base.join("root");
        fake_checkout(&checkout);
        std::env::set_var("AOIDE_STAGE_DIR", base.join("unrelated-live-stage"));

        let stage_song_dir = root.join("song").join("stage");
        std::fs::create_dir_all(&stage_song_dir).unwrap();
        stage_livery(
            "sonata",
            "sonata",
            &checkout,
            &stage_song_dir.join("livery.json"),
        )
        .unwrap();
        write_mode_json(&root, "sonata").unwrap();
        seed_static_stage_files(&root).unwrap();

        let source = resolve_fixture_source(&checkout, "many").unwrap();
        assert!(matches!(source, FixtureSource::BuiltinEmpty));
        let state_stage_dir = root.join("state").join("stage");
        stage_fixture(&source, &state_stage_dir).unwrap();

        let run_qml_dir = root.join("run").join("qml");
        stage_qml_copies(&checkout, &run_qml_dir).unwrap();
        let run_qml_songs = run_qml_dir.join("songs");
        stage_song_copies(&checkout, &run_qml_songs).unwrap();
        stage_songs_manifest(&run_qml_songs).unwrap();

        // qml copies: only *.qml, regular files holding the checkout's bytes.
        let bridge = run_qml_dir.join("ShellBridge.qml");
        assert!(!std::fs::symlink_metadata(&bridge)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&bridge).unwrap(), "// bridge\n");
        assert!(!run_qml_dir.join("not-qml.txt").exists());
        // icon assets: the facet's resolved tree, copied beside the QML.
        let icon = run_qml_dir.join("icons/iconoir/drag-hand-gesture.svg");
        assert!(!std::fs::symlink_metadata(&icon)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&icon).unwrap(), "<svg/>\n");

        // song copies: sonata + etude present as real dirs, _shelved skipped.
        assert!(!std::fs::symlink_metadata(run_qml_songs.join("sonata"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(run_qml_songs.join("sonata/conductor.qml")).unwrap(),
            "// conductor\n"
        );
        assert!(run_qml_songs.join("etude").is_dir());
        assert!(!run_qml_songs.join("_shelved").exists());

        // manifest/registry fallback to `{}` (no deployed run/qml/songs on this host env).
        assert_eq!(
            std::fs::read_to_string(run_qml_songs.join("manifest.json")).unwrap(),
            "{}"
        );
        assert_eq!(
            std::fs::read_to_string(run_qml_songs.join("registry.json")).unwrap(),
            "{}"
        );

        // fixture: no sets exist at all -> builtin empty defaults.
        let sessions: Value = serde_json::from_str(
            &std::fs::read_to_string(state_stage_dir.join("sessions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(sessions, json!({"schemaVersion": "0", "sessions": []}));
        let hooks: Value = serde_json::from_str(
            &std::fs::read_to_string(state_stage_dir.join("hooks.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(hooks, json!({}));

        // the four other facet-read stage files exist -- LiveryState.qml
        // (mode.json/cover.json), AoideWallpaper.qml (cover.json),
        // GrimoireLedger (grimoire.json), and state/usage.json -- so none
        // of those components starts with a parse warning.
        let mode: Value = serde_json::from_str(
            &std::fs::read_to_string(stage_song_dir.join("mode.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(mode["mode"], "staging");
        assert_eq!(mode["song"], "sonata");
        assert_eq!(mode["stagingSong"], "sonata");
        assert!(mode["since"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(stage_song_dir.join("cover.json").is_file());
        assert!(stage_song_dir.join("grimoire.json").is_file());
        assert!(root.join("state").join("usage.json").is_file());

        match saved_stage_dir {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
    }

    #[test]
    fn build_root_writes_the_launching_binarys_absolute_path_as_lyra() {
        // The QML rail spawns `controlDoc.lyra || "lyra"`; a deployed `lyra`
        // on the canvas's PATH may predate `preview set` entirely (owner
        // 586's bug report), so the root builder must name the RUNNING
        // binary in the control doc, not leave the rail to guess from PATH.
        // `with_flake_root` already serializes on `env_lock()` -- taking it
        // again here would self-deadlock the same thread on a non-reentrant
        // mutex, so AOIDE_STAGE_DIR is saved/set/restored INSIDE its
        // closure, under the one lock it holds.
        let base = scratch("lyra_bin_field");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        let mut flags = BTreeMap::new();
        flags.insert("root".to_string(), root.to_str().unwrap().to_string());
        flags.insert("no-launch".to_string(), "true".to_string());
        let outcome = with_flake_root(&checkout, || {
            let saved_stage_dir = std::env::var_os("AOIDE_STAGE_DIR");
            std::env::set_var("AOIDE_STAGE_DIR", base.join("unrelated-live-stage"));
            let outcome = handle_preview(&Invocation {
                path: vec!["preview".to_string()],
                args: vec![],
                flags,
                door: aoide_protocol::Door::Cli,
            });
            match saved_stage_dir {
                Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
                None => std::env::remove_var("AOIDE_STAGE_DIR"),
            }
            outcome
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let doc: Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("preview.json")).unwrap())
                .unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(doc["lyra"], json!(exe.to_string_lossy()));
        assert!(Path::new(doc["lyra"].as_str().unwrap()).is_absolute());
    }

    #[test]
    fn seed_if_absent_never_clobbers_a_file_mutated_after_the_first_seed() {
        let base = scratch("seed_if_absent_idempotent");
        let path = base.join("stage").join("cover.json");
        seed_if_absent(&path, &json!({ "path": "" })).unwrap();
        // the canvas (or a user) mutates the seeded file in place...
        std::fs::write(&path, r#"{"path":"mutated.png"}"#).unwrap();
        // ...a rebuild's seed pass must leave it exactly alone.
        seed_if_absent(&path, &json!({ "path": "" })).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"path":"mutated.png"}"#
        );
    }

    #[test]
    fn fixture_resolution_prefers_a_dir_and_falls_back_to_a_single_missing_file() {
        let base = scratch("fixture_resolution");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);

        let fixtures = fixtures_registry_dir(&checkout);
        let many = fixtures.join("many");
        std::fs::create_dir_all(&many).unwrap();
        std::fs::write(
            many.join("sessions.json"),
            r#"{"schemaVersion":"0","sessions":[{"id":"s1"}]}"#,
        )
        .unwrap();
        // projects.json deliberately absent from this fixture set.

        let source = resolve_fixture_source(&checkout, "many").unwrap();
        let state_stage_dir = base.join("state_stage");
        stage_fixture(&source, &state_stage_dir).unwrap();

        let sessions: Value = serde_json::from_str(
            &std::fs::read_to_string(state_stage_dir.join("sessions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(sessions["sessions"][0]["id"], "s1");
        let projects: Value = serde_json::from_str(
            &std::fs::read_to_string(state_stage_dir.join("projects.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(projects, json!({"schemaVersion": "0", "projects": []}));

        // an unknown name, with `many` now on disk, is a real error naming it.
        let err = resolve_fixture_source(&checkout, "nope").unwrap_err();
        assert!(err.contains("nope"), "{err}");
        assert!(err.contains("many"), "{err}");
    }

    #[test]
    fn fixture_resolution_accepts_a_literal_directory_path() {
        let base = scratch("fixture_literal_dir");
        let dir = base.join("some/fixture/dir");
        std::fs::create_dir_all(&dir).unwrap();
        let source = resolve_fixture_source(&base, &dir.to_string_lossy()).unwrap();
        assert!(matches!(source, FixtureSource::Dir(d) if d == dir));
    }

    // ── livery staging: the four --livery forms ──────────────

    /// A full, valid base16 scheme with distinct values in every slot, so a
    /// missing-slot assertion can reliably name the ONE it drops.
    fn full_base16_pairs() -> Vec<(&'static str, &'static str)> {
        aoide_song::livery::schema::BASE16_KEYS
            .iter()
            .enumerate()
            .map(|(i, k)| (*k, BASE16_HEX[i]))
            .collect()
    }

    const BASE16_HEX: [&str; 16] = [
        "1e1e2e", "2a2a3a", "363646", "424252", "6c6c7c", "d8d8e8", "e4e4f4", "f0f0ff", "e06090",
        "e8905a", "e8c860", "70c860", "60b8d8", "8888e8", "b878d8", "f8b8d8",
    ];

    #[test]
    fn spec_live_reads_the_resolved_live_stage_twin() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved_root = std::env::var_os("AOIDE_ROOT");

        let base = scratch("livery_live");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        std::env::set_var("AOIDE_ROOT", base.join("live-root"));
        let live_stage = aoide_storage::fs::stage_dir();
        std::fs::create_dir_all(&live_stage).unwrap();
        std::fs::write(
            live_stage.join("livery.json"),
            r##"{"palette": {"bg": "#010101", "fg": "#fefefe", "accent": "#ab00ab", "urgent": "#cd0000"}}"##,
        )
        .unwrap();

        let dst = base.join("out-livery.json");
        stage_livery("live", "sonata", &checkout, &dst).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&dst).unwrap()).unwrap();
        assert_eq!(v["song"], "sonata");
        assert_eq!(v["palette"]["bg"], "#010101");
        assert_eq!(v["palette"]["accent"], "#ab00ab");

        match saved_root {
            Some(val) => std::env::set_var("AOIDE_ROOT", val),
            None => std::env::remove_var("AOIDE_ROOT"),
        }
    }

    #[test]
    fn spec_song_name_reads_that_songs_own_songbook_livery() {
        let base = scratch("livery_song");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let dst = base.join("out-livery.json");

        // spec is "etude" while the preview's own --song is "sonata" --
        // the two are independent: --livery names ANY songbook song.
        stage_livery("etude", "sonata", &checkout, &dst).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&dst).unwrap()).unwrap();
        assert_eq!(
            v["song"], "sonata",
            "the CURRENT preview song is inserted, not the livery's source song"
        );
        assert_eq!(v["palette"]["bg"], "#222222");
        assert_eq!(v["palette"]["accent"], "#00ffff");
    }

    #[test]
    fn spec_livery_file_path_resolves_through_the_engine() {
        let base = scratch("livery_file_path");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let src = base.join("custom-livery.json");
        std::fs::write(&src, r##"{"palette": {"bg": "#000000", "fg": "#ffffff", "accent": "#0000ff", "urgent": "#ff0000"}}"##).unwrap();
        let dst = base.join("out-livery.json");

        stage_livery(&src.to_string_lossy(), "sonata", &checkout, &dst).unwrap();
        let body = std::fs::read_to_string(&dst).unwrap();
        assert!(body.ends_with('\n'));
        assert!(!body.ends_with("\n\n"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["song"], "sonata");
        assert_eq!(v["palette"]["bg"], "#000000");
        // resolved output, not a verbatim copy: the null component tiers
        // fall back to concrete palette-derived colours.
        assert_eq!(v["bar"]["accent"], "#0000ff");
    }

    #[test]
    fn spec_base16_json_scheme_synthesizes_a_palette_and_resolves() {
        let base = scratch("livery_base16_json");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let src = base.join("scheme.json");
        let obj: Map<String, Value> = full_base16_pairs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), json!(format!("#{v}"))))
            .collect();
        std::fs::write(&src, serde_json::to_string(&Value::Object(obj)).unwrap()).unwrap();
        let dst = base.join("out-livery.json");

        stage_livery(&src.to_string_lossy(), "sonata", &checkout, &dst).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&dst).unwrap()).unwrap();
        assert_eq!(v["song"], "sonata");
        assert_eq!(v["palette"]["bg"], "#1e1e2e"); // base00
        assert_eq!(v["palette"]["fg"], "#d8d8e8"); // base05
        assert_eq!(v["palette"]["accent"], "#8888e8"); // base0D
        assert_eq!(v["palette"]["urgent"], "#e06090"); // base08
        assert_eq!(v["palette"]["hot"], "#70c860"); // base0B
        assert_eq!(v["base16"]["base0F"], "#f8b8d8");
    }

    #[test]
    fn spec_base16_flat_yaml_lines_scheme_synthesizes_a_palette() {
        let base = scratch("livery_base16_yaml");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let src = base.join("scheme.yaml");

        let mut text = String::from("scheme: \"test scheme\"\nauthor: \"nobody\"\n");
        for (i, (k, v)) in full_base16_pairs().into_iter().enumerate() {
            // mix quoted/unquoted and with/without a leading `#`, since a
            // real base16 gallery file is inconsistent about both.
            if i % 2 == 0 {
                text.push_str(&format!("{k}: \"{v}\"\n"));
            } else {
                text.push_str(&format!("{k}: #{v}\n"));
            }
        }
        std::fs::write(&src, text).unwrap();
        let dst = base.join("out-livery.json");

        stage_livery(&src.to_string_lossy(), "sonata", &checkout, &dst).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&dst).unwrap()).unwrap();
        assert_eq!(v["palette"]["bg"], "#1e1e2e");
        assert_eq!(v["palette"]["accent"], "#8888e8");
        assert_eq!(v["base16"]["base0A"], "#e8c860");
    }

    #[test]
    fn base16_scheme_missing_a_slot_is_a_usage_error_naming_it() {
        let base = scratch("livery_base16_missing");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let src = base.join("scheme.json");
        let mut pairs = full_base16_pairs();
        pairs.retain(|(k, _)| *k != "base05");
        let obj: Map<String, Value> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), json!(format!("#{v}"))))
            .collect();
        std::fs::write(&src, serde_json::to_string(&Value::Object(obj)).unwrap()).unwrap();
        let dst = base.join("out-livery.json");

        let err = stage_livery(&src.to_string_lossy(), "sonata", &checkout, &dst).unwrap_err();
        match err {
            LiveryStageError::Usage(m) => assert!(m.contains("base05"), "{m}"),
            other => panic!("expected a usage error naming base05, got {other:?}"),
        }
        assert!(!dst.exists());
    }

    #[test]
    fn a_livery_that_fails_to_resolve_errors_and_leaves_the_prior_file_intact() {
        let base = scratch("livery_resolve_failure");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let dst = base.join("out-livery.json");
        std::fs::write(&dst, "PRIOR CONTENT\n").unwrap();

        let src = base.join("broken-livery.json");
        std::fs::write(&src, r##"{"palette": {"bg": "{palette.nope}"}}"##).unwrap();

        let err = stage_livery(&src.to_string_lossy(), "sonata", &checkout, &dst).unwrap_err();
        assert!(matches!(err, LiveryStageError::Error(_)));
        assert_eq!(
            std::fs::read_to_string(&dst).unwrap(),
            "PRIOR CONTENT\n",
            "a resolve failure must leave dst untouched"
        );
    }

    #[test]
    fn liveries_list_is_sorted_and_skips_shelved_and_livery_less_songs() {
        let base = scratch("liveries_list");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        // a third song with no livery.json of its own -- must not appear.
        std::fs::create_dir_all(checkout.join("song/songbook/no-livery/widgets")).unwrap();

        let got = list_liveries(&checkout);
        assert_eq!(got, vec!["etude".to_string(), "sonata".to_string()]);
    }

    // ── control merge (via handle_preview_set) ───────────────

    fn inv(flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: vec!["preview".to_string(), "set".to_string()],
            args: vec![],
            flags: flag_map,
            door: aoide_protocol::Door::Cli,
        }
    }

    fn write_seed_control(root: &Path, extra: Value) {
        std::fs::create_dir_all(root).unwrap();
        let mut doc = serde_json::Map::new();
        doc.insert("schemaVersion".to_string(), json!("0"));
        doc.insert("widget".to_string(), json!("songs/sonata/conductor.qml"));
        doc.insert("song".to_string(), json!("sonata"));
        doc.insert("widgetWidth".to_string(), json!("auto"));
        doc.insert("widgetHeight".to_string(), json!("auto"));
        doc.insert("widgetAspectLock".to_string(), json!(false));
        doc.insert("viewportWidth".to_string(), json!(1920));
        doc.insert("viewportHeight".to_string(), json!(1080));
        doc.insert("viewportPreset".to_string(), json!("16:9"));
        doc.insert("viewportAspectLock".to_string(), json!(true));
        doc.insert("anchor".to_string(), json!("tl"));
        doc.insert("margin".to_string(), json!(0));
        doc.insert("zoom".to_string(), json!("fit"));
        doc.insert("background".to_string(), json!("livery"));
        if let Value::Object(extra) = extra {
            for (k, v) in extra {
                doc.insert(k, v);
            }
        }
        write_control(&root.join("preview.json"), &doc).unwrap();
    }

    #[test]
    fn merge_keeps_existing_keys_and_overrides_only_given_flags() {
        let root = scratch("merge_existing");
        write_seed_control(&root, json!({}));

        let outcome =
            handle_preview_set(&inv(&[("root", root.to_str().unwrap()), ("anchor", "br")]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Ok);
        let data = outcome.data.unwrap();
        assert_eq!(data["anchor"], "br");
        // untouched keys survive.
        assert_eq!(data["zoom"], "fit");
        assert_eq!(data["background"], "livery");
        assert_eq!(outcome.changed, vec!["anchor".to_string()]);
    }

    #[test]
    fn merge_expands_presets_and_marks_custom_for_wxh() {
        let root = scratch("merge_preset");
        write_seed_control(&root, json!({}));

        let outcome = handle_preview_set(&inv(&[
            ("root", root.to_str().unwrap()),
            ("viewport", "4:3"),
        ]));
        let data = outcome.data.unwrap();
        assert_eq!(data["viewportWidth"], 1600);
        assert_eq!(data["viewportHeight"], 1200);
        assert_eq!(data["viewportPreset"], "4:3");

        let outcome = handle_preview_set(&inv(&[
            ("root", root.to_str().unwrap()),
            ("viewport", "800x600"),
        ]));
        let data = outcome.data.unwrap();
        assert_eq!(data["viewportWidth"], 800);
        assert_eq!(data["viewportHeight"], 600);
        assert_eq!(data["viewportPreset"], "custom");
    }

    #[test]
    fn merge_rejects_every_bad_value_with_usage() {
        let root = scratch("merge_bad_values");
        write_seed_control(&root, json!({}));
        let bad = [
            ("width", "not-a-number"),
            ("height", "-5"),
            ("anchor", "middle"),
            ("margin", "-1"),
            ("zoom", "0"),
            ("background", "wallpaper"),
            ("viewport", "nonsense"),
            ("aspect-lock", "maybe"),
            ("widget-aspect-lock", "sure"),
            ("song", "Not_Valid"),
        ];
        for (flag, value) in bad {
            let outcome =
                handle_preview_set(&inv(&[("root", root.to_str().unwrap()), (flag, value)]));
            assert_eq!(
                outcome.status,
                aoide_protocol::output::Status::Usage,
                "--{flag} {value} should be a usage error"
            );
        }
    }

    #[test]
    fn preview_set_reaches_an_isolated_root_from_inside_a_canvas_shaped_env() {
        // The Rust-level stand-in for an actual rail click: the canvas
        // child env this root's own quickshell process runs under
        // (`child_env` -- AOIDE_DAEMON_SOCKET repointed into the root,
        // XDG_RUNTIME_DIR elsewhere) must not make `preview set --root
        // <root> --livery <song>` refuse itself, which is exactly the
        // regression owner 588 found (every rail→CLI action dead from
        // inside any canvas). Live computer-use evidence of a real click is
        // the coordinator's job, not this test's.
        // `with_flake_root` already serializes on `env_lock()` -- the
        // XDG_RUNTIME_DIR/AOIDE_DAEMON_SOCKET save/set/restore happens
        // INSIDE its closure, under that one lock, never a second one taken
        // here (a non-reentrant mutex self-deadlocks on a nested lock).
        let base = scratch("rail_click_canvas_env");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let xdg = base.join("xdg");
        std::fs::create_dir_all(&xdg).unwrap();
        let root = base.join("aoide-preview-w2");
        write_seed_control(&root, json!({"liverySource": "sonata"}));
        std::fs::create_dir_all(root.join("song").join("stage")).unwrap();

        let outcome = with_flake_root(&checkout, || {
            let saved_xdg = std::env::var_os("XDG_RUNTIME_DIR");
            let saved_sock = std::env::var_os("AOIDE_DAEMON_SOCKET");
            std::env::set_var("XDG_RUNTIME_DIR", &xdg);
            std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("no-daemon.sock"));
            let outcome = handle_preview_set(&inv(&[
                ("root", root.to_str().unwrap()),
                ("livery", "etude"),
            ]));
            match saved_xdg {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
            match saved_sock {
                Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
                None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
            }
            outcome
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let data = outcome.data.unwrap();
        assert_eq!(data["liverySource"], "etude");
    }

    #[test]
    fn set_refuses_a_widget_with_a_parent_dir_component() {
        // BLOCKER 1 fix-up: `--widget` is embedded verbatim into the
        // persisted `widget` field via `map_widget`'s non-absolute branch
        // with zero validation on the "slot" half -- a `..`-laden value
        // must be refused here, at the flag site, not just downstream.
        let root = scratch("set_widget_traversal");
        write_seed_control(&root, json!({}));
        let outcome = handle_preview_set(&inv(&[
            ("root", root.to_str().unwrap()),
            (
                "widget",
                "demo/../../../../modules/facets/quickshell/qml/ShellBridge",
            ),
        ]));
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
    }

    // ── widget positional mapping ─────────────────────────────

    #[test]
    fn widget_mapping_covers_every_shape() {
        let base = scratch("widget_mapping");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);

        let abs = checkout.join("song/songbook/sonata/widgets/conductor.qml");
        assert_eq!(
            map_widget(&abs.to_string_lossy(), "sonata", &checkout),
            "songs/sonata/conductor.qml"
        );

        assert_eq!(
            map_widget("sonata/conductor", "etude", &checkout),
            "songs/sonata/conductor.qml"
        );
        assert_eq!(
            map_widget("conductor", "etude", &checkout),
            "songs/etude/conductor.qml"
        );

        assert_eq!(
            map_widget("/some/other/place.qml", "sonata", &checkout),
            "/some/other/place.qml"
        );

        // already the canvas's own spelling (round-tripped from
        // `preview.json` itself, e.g. `preview set --widget
        // songs/sonata/conductor.qml`) -- must pass through unchanged,
        // never double-prefixed to `songs/songs/sonata/conductor.qml.qml`.
        assert_eq!(
            map_widget("songs/sonata/conductor.qml", "etude", &checkout),
            "songs/sonata/conductor.qml"
        );
    }

    // ── pid refusal ────────────────────────────────────────────

    #[test]
    fn pid_refusal_names_a_live_process() {
        let root = scratch("pid_refusal");
        std::fs::write(pid_file(&root), std::process::id().to_string()).unwrap();
        let err = refuse_if_running(&root).unwrap_err();
        assert!(err.contains(&std::process::id().to_string()), "{err}");
        assert!(err.contains("already running"));
    }

    #[test]
    fn pid_refusal_ignores_a_dead_pid() {
        let root = scratch("pid_dead");
        // pid 1 belongs to init and is unreachable to signal from an
        // unprivileged test process on most hosts, but a genuinely bogus,
        // never-issued pid is a more portable "definitely dead" choice.
        std::fs::write(pid_file(&root), "999999999").unwrap();
        assert!(refuse_if_running(&root).is_ok());
    }

    // ── child env safety ───────────────────────────────────────

    #[test]
    fn child_env_never_points_at_the_live_daemon_socket_dir() {
        // The realistic default root -- a SIBLING of the live daemon's own
        // `$XDG_RUNTIME_DIR/aoide/` socket dir, not a descendant of it.
        let live_socket_dir = "/run/user/1000/aoide/";
        let root = PathBuf::from("/run/user/1000/aoide-preview");
        let (envs, removed) = child_env(&root);
        for (k, v) in &envs {
            assert!(
                v.starts_with(root.to_str().unwrap()),
                "{k}={v} must live under the isolated root"
            );
            assert!(
                !v.starts_with(live_socket_dir) && v != live_socket_dir.trim_end_matches('/'),
                "{k}={v} must never point at the live daemon's own socket dir"
            );
        }
        let socket = envs
            .iter()
            .find(|(k, _)| k == "AOIDE_DAEMON_SOCKET")
            .unwrap();
        assert!(socket.1.starts_with(root.to_str().unwrap()));
        for key in [
            "QS_STAGE",
            "CONDUCTOR_WIDGET",
            "TERMINALS_WIDGET",
            "DOCK_WIDGET",
            "POWER_WIDGET",
            "METERS_WIDGET",
            "CAL_WIDGET",
        ] {
            assert!(removed.contains(&key));
        }
    }

    #[test]
    fn default_root_is_never_under_the_live_daemon_dir() {
        // `XDG_RUNTIME_DIR` is process-global (crates/AGENTS.md's own
        // "Per-crate tests only" note) -- serialize against any other test
        // in this crate touching it.
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let root = default_root();
        assert_eq!(root, PathBuf::from("/run/user/1000/aoide-preview"));
        assert!(!root.to_string_lossy().contains("/aoide/"));
        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    // ── watch list (pure) ──────────────────────────────────────

    #[test]
    fn compute_watch_list_lists_song_widgets_plus_a_foreign_widget_file() {
        let base = scratch("watch_list");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);

        // sonata's own widgets/ has exactly one qml file (conductor.qml).
        let sonata_conductor = checkout
            .join("song/songbook/sonata/widgets/conductor.qml")
            .to_string_lossy()
            .into_owned();
        let only_song = compute_watch_list(&checkout, "sonata", None);
        assert_eq!(only_song, vec![sonata_conductor.clone()]);

        // a foreign widget (etude's dock.qml) is appended, staying sorted.
        let foreign = checkout.join("song/songbook/etude/widgets/dock.qml");
        let mut expected = vec![
            sonata_conductor.clone(),
            foreign.to_string_lossy().into_owned(),
        ];
        expected.sort();
        assert_eq!(
            compute_watch_list(&checkout, "sonata", Some(&foreign)),
            expected
        );

        // the widget's own file, when it's ALREADY inside the song's own
        // widgets/, is never duplicated.
        let own = checkout.join("song/songbook/sonata/widgets/conductor.qml");
        assert_eq!(
            compute_watch_list(&checkout, "sonata", Some(&own)),
            vec![sonata_conductor]
        );
    }

    // ── preview declare ─────────────────────────────────────────

    fn inv_declare(flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: vec!["preview".to_string(), "declare".to_string()],
            args: vec![],
            flags: flag_map,
            door: aoide_protocol::Door::Cli,
        }
    }

    /// Runs `body` with `$AOIDE_FLAKE_ROOT` pinned at `checkout` -- process-
    /// global (`pkgs/aoide/crates/AGENTS.md`'s "per-crate tests only" note),
    /// serialized via `env_lock()` and restored afterward.
    fn with_flake_root<R>(checkout: &Path, body: impl FnOnce() -> R) -> R {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("AOIDE_FLAKE_ROOT");
        std::env::set_var("AOIDE_FLAKE_ROOT", checkout);
        let r = body();
        match saved {
            Some(v) => std::env::set_var("AOIDE_FLAKE_ROOT", v),
            None => std::env::remove_var("AOIDE_FLAKE_ROOT"),
        }
        r
    }

    #[test]
    fn declare_refuses_a_widget_outside_songs_prefix() {
        let base = scratch("declare_refuse_facet");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");
        write_seed_control(
            &root,
            json!({"widget": "ShellBridge.qml", "song": "sonata"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn declare_copies_body_from_a_foreign_widget_path_and_creates_target() {
        let base = scratch("declare_foreign_body");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        // "songs/etude/dock.qml" resolves to the CHECKOUT's own
        // `song/songbook/etude/widgets/dock.qml` -- never to anything under
        // `root` -- and the containment check requires exactly that file
        // to live inside a real songbook `widgets/` dir. The stale link
        // planted under `root` below must be ignored, not followed.
        let etude_dock = checkout.join("song/songbook/etude/widgets/dock.qml");
        std::fs::write(&etude_dock, "// foreign dock body\n").unwrap();
        let link_dir = root.join("run/qml/songs/etude");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(&etude_dock, link_dir.join("dock.qml")).unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/etude/dock.qml", "song": "sonata", "liverySource": "sonata"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let data = outcome.data.unwrap();
        assert_eq!(data["body"], "declared");
        let target = checkout.join("song/songbook/sonata/widgets/dock.qml");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "// foreign dock body\n"
        );
        assert!(outcome
            .changed
            .iter()
            .any(|c| c == &target.to_string_lossy()));
    }

    #[test]
    fn declare_reports_already_when_widget_resolves_to_its_own_checkout_slot() {
        let base = scratch("declare_already");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        let link_dir = root.join("run/qml/songs/sonata");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(
            checkout.join("song/songbook/sonata/widgets/conductor.qml"),
            link_dir.join("conductor.qml"),
        )
        .unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/sonata/conductor.qml", "song": "sonata", "liverySource": "sonata"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let data = outcome.data.unwrap();
        assert_eq!(data["body"], "already");
        assert!(outcome.changed.is_empty());
    }

    #[test]
    fn declare_reports_unchanged_when_bytes_already_match_a_different_target_file() {
        let base = scratch("declare_unchanged");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        // the foreign source and the EXISTING target already hold identical
        // bytes at genuinely different paths (not the same file via symlink) --
        // the source itself must still be a real symlink into the checkout
        // songbook per the containment check (BLOCKER 1 fix-up).
        let etude_dock = checkout.join("song/songbook/etude/widgets/dock.qml");
        std::fs::write(&etude_dock, "// same body\n").unwrap();
        let link_dir = root.join("run/qml/songs/etude");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(&etude_dock, link_dir.join("dock.qml")).unwrap();

        let target_dir = checkout.join("song/songbook/sonata/widgets");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(target_dir.join("dock.qml"), "// same body\n").unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/etude/dock.qml", "song": "sonata", "liverySource": "sonata"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let data = outcome.data.unwrap();
        assert_eq!(data["body"], "unchanged");
        assert!(outcome.changed.is_empty());
    }

    #[test]
    fn declare_palette_merge_preserves_foreign_keys_and_drops_song() {
        let base = scratch("declare_palette_merge");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        // widget body already matches its own slot -- isolates this test to
        // the palette half.
        let link_dir = root.join("run/qml/songs/sonata");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(
            checkout.join("song/songbook/sonata/widgets/conductor.qml"),
            link_dir.join("conductor.qml"),
        )
        .unwrap();

        let stage_dir = root.join("song/stage");
        std::fs::create_dir_all(&stage_dir).unwrap();
        std::fs::write(
            stage_dir.join("livery.json"),
            r##"{"schemaVersion":"0","palette":{"bg":"#010101","fg":"#fefefe","accent":"#ab00ab","urgent":"#cd0000"},"bar":{"bg":"#010101","fg":"#fefefe","accent":"#ab00ab"},"notif":{"bg":"#010101","fg":"#fefefe","urgent":"#cd0000"},"window":{"border":"#ab00ab","borderInactive":"#010101"},"song":"sonata"}"##,
        )
        .unwrap();

        let checkout_livery = checkout.join("song/songbook/sonata/livery.json");
        std::fs::write(
            &checkout_livery,
            r##"{"schemaVersion":"0","song":"stale","widgets":{"conductor":{"kind":"surface"}},"cover":"cover.png","palette":{"bg":"#111111","fg":"#eeeeee","accent":"#ff00ff","urgent":"#ff0000"}}"##,
        )
        .unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/sonata/conductor.qml", "song": "sonata", "liverySource": "live"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let data = outcome.data.unwrap();
        assert_eq!(data["palette"], "declared");

        let merged: Value =
            serde_json::from_str(&std::fs::read_to_string(&checkout_livery).unwrap()).unwrap();
        assert_eq!(merged["palette"]["bg"], "#010101");
        assert!(
            merged.get("song").is_none(),
            "song key must never be written to the checkout livery.json"
        );
        assert_eq!(
            merged["widgets"]["conductor"]["kind"], "surface",
            "foreign keys survive the merge"
        );
        assert_eq!(merged["cover"], "cover.png");
    }

    #[test]
    fn declare_skips_palette_when_livery_source_is_the_songs_own() {
        let base = scratch("declare_palette_own");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        let link_dir = root.join("run/qml/songs/sonata");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(
            checkout.join("song/songbook/sonata/widgets/conductor.qml"),
            link_dir.join("conductor.qml"),
        )
        .unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/sonata/conductor.qml", "song": "sonata", "liverySource": "sonata"}),
        );

        // no root/song/stage/livery.json at all -- if the palette step tried
        // to read it, this would error; "own" must skip it entirely.
        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Ok,
            "{:?}",
            outcome.message
        );
        let data = outcome.data.unwrap();
        assert_eq!(data["palette"], "own");
    }

    #[test]
    fn declare_refuses_a_widget_field_with_a_parent_dir_component_even_when_it_resolves_through_a_real_symlink(
    ) {
        // BLOCKER 1: `starts_with("songs/")` alone is a string match -- a
        // `..`-laden persisted `widget` field satisfies it while
        // canonicalizing, through a REAL `run/qml/songs/<song>` directory
        // symlink (what an older, symlinking root left behind), straight out
        // to a facet file entirely outside any songbook. Reproduces the
        // coordinator's own review shape (`demo/../../../../modules/facets/
        // quickshell/qml/ShellBridge`; "sonata" stands in for "demo" here).
        let base = scratch("declare_traversal_via_symlink");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        let songs_dir = root.join("run/qml/songs");
        std::fs::create_dir_all(&songs_dir).unwrap();
        std::os::unix::fs::symlink(
            checkout.join("song/songbook/sonata/widgets"),
            songs_dir.join("sonata"),
        )
        .unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/sonata/../../../../modules/facets/quickshell/qml/ShellBridge.qml", "song": "sonata"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[("root", root.to_str().unwrap())]))
        });
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(
            !checkout
                .join("song/songbook/sonata/widgets/ShellBridge.qml")
                .exists(),
            "must never copy a facet file into the songbook"
        );
    }

    #[test]
    fn declare_refuses_an_invalid_slot_name() {
        // BLOCKER 2: `--slot` was joined into `widgets_dir.join(...)`
        // completely unvalidated -- `--slot "../../../pwned/evil"` wrote
        // `song/pwned/evil.qml`, outside the intended `widgets/` dir.
        let base = scratch("declare_bad_slot");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let root = base.join("root");

        let link_dir = root.join("run/qml/songs/sonata");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(
            checkout.join("song/songbook/sonata/widgets/conductor.qml"),
            link_dir.join("conductor.qml"),
        )
        .unwrap();

        write_seed_control(
            &root,
            json!({"widget": "songs/sonata/conductor.qml", "song": "sonata", "liverySource": "sonata"}),
        );

        let outcome = with_flake_root(&checkout, || {
            handle_preview_declare(&inv_declare(&[
                ("root", root.to_str().unwrap()),
                ("slot", "../../../pwned/evil"),
            ]))
        });
        assert_eq!(outcome.status, aoide_protocol::output::Status::Usage);
        assert!(
            !checkout.join("pwned").exists(),
            "must never escape the songbook widgets/ dir"
        );
    }

    #[test]
    fn a_write_through_run_qml_never_reaches_the_checkout() {
        let base = scratch("run_qml_is_copies");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let run_qml_dir = base.join("root/run/qml");
        // A root built by an earlier, symlinking build: the link must be
        // replaced by a copy, never written through.
        std::fs::create_dir_all(run_qml_dir.join("songs")).unwrap();
        std::os::unix::fs::symlink(
            checkout.join("modules/facets/quickshell/qml/ShellBridge.qml"),
            run_qml_dir.join("ShellBridge.qml"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            checkout.join("song/songbook/sonata/widgets"),
            run_qml_dir.join("songs/sonata"),
        )
        .unwrap();

        stage_qml_copies(&checkout, &run_qml_dir).unwrap();
        stage_song_copies(&checkout, &run_qml_dir.join("songs")).unwrap();

        for (copy, original) in [
            (
                run_qml_dir.join("ShellBridge.qml"),
                checkout.join("modules/facets/quickshell/qml/ShellBridge.qml"),
            ),
            (
                run_qml_dir.join("songs/sonata/conductor.qml"),
                checkout.join("song/songbook/sonata/widgets/conductor.qml"),
            ),
        ] {
            assert!(
                !std::fs::symlink_metadata(&copy)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{}",
                copy.display()
            );
            let before = std::fs::read_to_string(&original).unwrap();
            std::fs::write(&copy, "// clobbered through run/qml\n").unwrap();
            assert_eq!(
                std::fs::read_to_string(&original).unwrap(),
                before,
                "{} changed the checkout",
                copy.display()
            );
        }
        assert!(!std::fs::symlink_metadata(run_qml_dir.join("songs/sonata"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn compute_stage_map_pairs_each_songbook_watch_entry_with_its_run_qml_copy() {
        let checkout = Path::new("/c");
        let root = Path::new("/r");
        let watch = vec![
            "/c/song/songbook/sonata/widgets/conductor.qml".to_string(),
            "/c/song/songbook/etude/widgets/parts/Knob.qml".to_string(),
            "/c/modules/facets/quickshell/qml/ShellBridge.qml".to_string(),
            "/elsewhere/foreign.qml".to_string(),
        ];
        let map = compute_stage_map(checkout, root, &watch);
        assert_eq!(
            Value::Object(map),
            json!({
                "/c/song/songbook/sonata/widgets/conductor.qml": "/r/run/qml/songs/sonata/conductor.qml",
                "/c/song/songbook/etude/widgets/parts/Knob.qml": "/r/run/qml/songs/etude/parts/Knob.qml",
            })
        );
    }

    #[test]
    fn resolve_widget_abs_maps_the_field_to_the_checkout_file_and_refuses_parent_components() {
        let base = scratch("resolve_widget_abs");
        let checkout = base.join("checkout");
        fake_checkout(&checkout);
        let real = checkout.canonicalize().unwrap();
        assert_eq!(
            resolve_widget_abs(&checkout, "songs/sonata/conductor.qml"),
            Some(real.join("song/songbook/sonata/widgets/conductor.qml"))
        );
        assert_eq!(
            resolve_widget_abs(&checkout, "ShellBridge.qml"),
            Some(real.join("modules/facets/quickshell/qml/ShellBridge.qml"))
        );
        assert_eq!(
            resolve_widget_abs(
                &checkout,
                "songs/sonata/../../../modules/facets/quickshell/qml/ShellBridge.qml"
            ),
            None
        );
        assert_eq!(
            resolve_widget_abs(&checkout, "songs/sonata/missing.qml"),
            None
        );
        assert_eq!(resolve_widget_abs(&checkout, "songs/sonata"), None);
    }

    #[test]
    fn check_root_refuses_the_live_daemon_dir_and_parent_components() {
        let live = Path::new("/run/user/1000/aoide");
        let err = check_root(Path::new("/run/user/1000/aoide/preview"), Some(live)).unwrap_err();
        assert!(err.contains("live daemon"), "{err}");
        assert!(check_root(Path::new("/run/user/1000/aoide"), Some(live)).is_err());
        let err = check_root(
            Path::new("/run/user/1000/aoide-preview/../aoide/x"),
            Some(live),
        )
        .unwrap_err();
        assert!(err.contains("`..`"), "{err}");
        assert_eq!(
            check_root(Path::new("/run/user/1000/aoide-preview"), Some(live)).unwrap(),
            PathBuf::from("/run/user/1000/aoide-preview")
        );
        assert_eq!(
            check_root(Path::new("/tmp/anywhere"), Some(live)).unwrap(),
            PathBuf::from("/tmp/anywhere")
        );
    }

    #[test]
    fn an_unset_xdg_runtime_dir_still_refuses_the_daemons_default_runtime_dir() {
        // `live_daemon_dir` never reads `AOIDE_DAEMON_SOCKET` (that override
        // is what the canvas child env repoints, see the fn's own doc), so
        // this test only needs XDG_RUNTIME_DIR unset -- the expected dir
        // comes from the same resolver (one spelling), not a literal here.
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved_xdg = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::remove_var("XDG_RUNTIME_DIR");
        let live = live_daemon_dir();
        assert!(live.starts_with("/run/user/"), "{}", live.display());
        let candidate = live.join("x");
        let err = resolve_root(Some(candidate.to_str().unwrap())).unwrap_err();
        let outcome =
            handle_preview_declare(&inv_declare(&[("root", candidate.to_str().unwrap())]));
        if let Some(v) = saved_xdg {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
        assert!(err.contains("live daemon"), "{err}");
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Usage,
            "{:?}",
            outcome.message
        );
    }

    #[test]
    fn resolve_root_accepts_the_preview_root_from_inside_its_own_canvas() {
        // The canvas child env repoints AOIDE_DAEMON_SOCKET at
        // `<root>/no-daemon.sock` (`child_env`) precisely so a canvas
        // process never dials the real daemon; that redirect must not make
        // the rail's own `--root <root>` calls look like they target the
        // live dir from inside that same canvas (owner 588's regression).
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = scratch("canvas_shaped_env_accept");
        let xdg = tmp.join("xdg");
        std::fs::create_dir_all(&xdg).unwrap();
        let root = tmp.join("aoide-preview-w2");
        std::fs::create_dir_all(&root).unwrap();
        let saved_xdg = std::env::var_os("XDG_RUNTIME_DIR");
        let saved_sock = std::env::var_os("AOIDE_DAEMON_SOCKET");
        std::env::set_var("XDG_RUNTIME_DIR", &xdg);
        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("no-daemon.sock"));
        let result = resolve_root(Some(root.to_str().unwrap()));
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        assert_eq!(result.unwrap(), root);
    }

    #[test]
    fn resolve_root_still_refuses_the_real_live_dir_under_canvas_shaped_env() {
        // Same canvas-shaped env (AOIDE_DAEMON_SOCKET repointed) as above,
        // but a `--root` that names the real live dir or a descendant of it
        // must still be refused -- the fix permits the isolated preview
        // root, it does not blanket-accept anything the socket points near.
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = scratch("canvas_shaped_env_refuse");
        let xdg = tmp.join("xdg");
        let live = xdg.join("aoide");
        std::fs::create_dir_all(&live).unwrap();
        let root = tmp.join("aoide-preview-w2");
        std::fs::create_dir_all(&root).unwrap();
        let saved_xdg = std::env::var_os("XDG_RUNTIME_DIR");
        let saved_sock = std::env::var_os("AOIDE_DAEMON_SOCKET");
        std::env::set_var("XDG_RUNTIME_DIR", &xdg);
        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("no-daemon.sock"));
        let err_live = resolve_root(Some(live.to_str().unwrap())).unwrap_err();
        let err_child = resolve_root(Some(live.join("sub").to_str().unwrap())).unwrap_err();
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_sock {
            Some(v) => std::env::set_var("AOIDE_DAEMON_SOCKET", v),
            None => std::env::remove_var("AOIDE_DAEMON_SOCKET"),
        }
        assert!(err_live.contains("live daemon"), "{err_live}");
        assert!(err_child.contains("live daemon"), "{err_child}");
    }

    #[test]
    fn a_symlinked_root_resolving_under_the_live_dir_is_refused() {
        let tmp = scratch("symlinked_root");
        let live = tmp.join("aoide");
        std::fs::create_dir_all(live.join("inside")).unwrap();
        // The link itself resolves into the live dir ...
        let link = tmp.join("looks-harmless");
        std::os::unix::fs::symlink(&live, &link).unwrap();
        let err = check_root(&link, Some(&live)).unwrap_err();
        assert!(err.contains("live daemon"), "{err}");
        // ... and so does a not-yet-existing child beneath it.
        let err = check_root(&link.join("preview"), Some(&live)).unwrap_err();
        assert!(err.contains("live daemon"), "{err}");
        // A sibling that does not resolve there still passes.
        let other = tmp.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let ok = tmp.join("ok-link");
        std::os::unix::fs::symlink(&other, &ok).unwrap();
        assert_eq!(check_root(&ok, Some(&live)).unwrap(), ok);
        // And at the command boundary, with the live dir itself resolved
        // through XDG_RUNTIME_DIR (never the daemon socket override --
        // `live_daemon_dir` deliberately ignores it), the link is a usage
        // error.
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved_xdg = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);
        let outcome = handle_preview_declare(&inv_declare(&[("root", link.to_str().unwrap())]));
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Usage,
            "{:?}",
            outcome.message
        );
    }

    #[test]
    fn a_hostile_root_flag_is_a_usage_error_at_the_command_boundary() {
        // `resolve_root` itself reads XDG_RUNTIME_DIR; the pure check above
        // covers the live dir, so this only needs the env-free refusal.
        let err = resolve_root(Some("/tmp/x/../y")).unwrap_err();
        assert!(err.contains("`..`"), "{err}");
        let inv = inv_declare(&[("root", "/tmp/x/../y")]);
        let outcome = handle_preview_declare(&inv);
        assert_eq!(
            outcome.status,
            aoide_protocol::output::Status::Usage,
            "{:?}",
            outcome.message
        );
    }
}
