//! `lyra preview shot` / `preview tree` / `preview notes` (P6 of the widget-
//! preview canvas workstream, PLAN.md's "Agent tools, screenshots,
//! annotations" section) — the shell-first surface that lets an agent USE
//! P1/P2's isolated canvas (`commands::preview`) without a human: grab a
//! picture of the screen/canvas/widget/one element, dump the widget's live
//! item tree joined against its own QML source (so a node comes back with
//! not just geometry but `id`/`file:line`), and keep a small scaffolding
//! notes list an agent can read as a work list. Every capability here is
//! reachable from a shell — the canvas (P7, `modules/facets/quickshell/
//! qml/WidgetPreview.qml`'s `IpcHandler { target: "preview" }`) only PAINTS
//! the same data, per root `AGENTS.md` house rule 7's "delete every
//! `.qml` — is this still reachable from a terminal?" test.
//!
//! **The one `qs` seam.** [`qs_ipc_call`] is the ONLY place anything in this
//! module shells `quickshell` — every other function here is plain
//! filesystem/parsing logic. Argv shape confirmed LIVE (`qs ipc call
//! --help`, khoa's rig, 2026-09-12), not guessed:
//! ```text
//! quickshell ipc call [target] [function] [arguments...]
//! ```
//! so the full invocation is `qs -p <root>/run/qml/WidgetPreview.qml ipc
//! call preview <function> <args...>` — `preview` is the `IpcHandler`'s own
//! `target` name P7's canvas registers (`shot`/`tree`/`reload` its three
//! functions; `reload` is P7's own QML-side convenience, never wired to a
//! CLI path here). Confirmed live too: `qs`'s own failure text (`"No
//! running instances for …"`, `"Could not open config file …"`) prints to
//! **stdout**, not stderr — [`qs_ipc_call`] reads both and joins them so a
//! caller's error message is never silently empty.
//!
//! **`shot`'s own success/failure file pair** (P7's contract, confirmed
//! against real canvas output): success writes `<out>` (the image) AND
//! `<out>.meta.json`; failure writes `<out>.error` (a plain-text message,
//! e.g. `"element not found: Nope[9]"`) and NO `<out>` at all — this module
//! polls for EITHER within 5s (100ms), surfacing `.error`'s own text as the
//! command's error message on failure ([`poll_for_shot`]). Every one of
//! these sidecar names — `<out>.json` (ours), `<out>.meta.json`, `<out>.
//! error` — is the FULL `--out` value with the suffix LITERALLY APPENDED
//! ([`append_suffix`]), never `PathBuf::with_extension` (which replaces the
//! part after the last dot: `"foo.png".with_extension("meta.json")` drops
//! `.png` entirely, landing at `"foo.meta.json"` instead of the real
//! `"foo.png.meta.json"`).
//!
//! Every test in this file stands a FAKE `qs` shell script on `PATH` rather
//! than shelling the real canvas — the same "shim stands in for a real
//! binary" discipline `pkgs/aoide/crates/AGENTS.md`'s "Per-crate tests
//! only" section documents for `curl`/`qrencode`; unlike those two, `qs`
//! never reads stdin, so no `cat > /dev/null` opener is needed in the shim.
//!
//! **Element path grammar** (shared with P7's own pick-mode, PLAN.md):
//! `Type[i]` (or `Type[i]#objectName`, the suffix purely informational) per
//! level, joined by `/`, walked from the previewed widget's ROOT down
//! through its children in declaration/creation order — `i` is the index
//! among same-TYPE siblings at that level, not the sibling's absolute
//! position. This string is CANVAS-AUTHORITATIVE, not a Rust-side
//! derivation: every node in the live tree ([`RuntimeNode::path`]) already
//! carries its own path verbatim (confirmed against a real 421KB live
//! dump), so [`resolve_element_path`] does a plain recursive string-equality
//! search rather than re-deriving Type[i] indices itself — load-bearing
//! because a `Repeater`'s generated items land as SIBLINGS of the
//! `Repeater` in `children`, a subtlety only the canvas's own numbering is
//! guaranteed to get right. `preview shot --what element`, `preview notes
//! --add --element`/its read-time resolution, and P7's own picker all mean
//! the same string the same way.
//!
//! **Static QML parser** ([`parse_static_qml`]) — a hand-rolled scan, not a
//! real QML parser (this workspace carries no such dependency, same "good
//! enough" posture `commands::preview`'s own base16 line parser documents
//! for YAML): a line matching `^\s*([A-Z][A-Za-z0-9_.]*)\s*\{` opens a node
//! (a dotted type like `MoodFaces.Face` strips to its last segment,
//! `Face`); `id:`/`objectName:` lines attach to whichever node is
//! currently open; braces are counted per line with string literals and
//! `//` comments blanked out first. **Known limits, accepted**: no
//! multi-line `/* */` comments, and a line is checked from its own start
//! only — a `{` opening a node must be the first non-blank thing on its
//! line (the ordinary style every widget in this tree is written in
//! today). A join can only be as good as this parse.
//!
//! **The tree join** ([`join_level`]) is the ONE join implementation —
//! `preview tree`'s own dump, `preview shot --what element`'s `source`/
//! crop enrichment, and `preview notes`'s read-time `element` → `source`
//! resolution ([`build_joined_tree`]) all share it, never a forked second
//! copy (this crate's own `AGENTS.md`, "no cross-crate copying" holds
//! within a crate too). Runtime children are matched against static
//! siblings under an already-matched parent: an exact `objectName` match
//! wins first, then position among remaining same-type static siblings
//! (`"positional"`), else `"none"`.
//!
//! **Cross-file first, unconditionally** (`ComponentMap`,
//! `build_component_map`): before any of the above, every runtime node's
//! own `type` is checked against every `*.qml` file named in
//! `preview.json`'s own `watch` list (the song's `widgets/` directory plus
//! the previewed widget's own file) — a match (`"file"`) switches the
//! static context to THAT file's own root node (`source` points at its own
//! `file:line`) and its runtime children are matched against that file's
//! own top-level parse for the rest of the recursion. This is what lets a
//! widget whose visible body lives below a `Loader` (`conductor.qml`'s
//! `SessionMenu` → `SessionCard` → …) resolve past its OWN file's border —
//! a live end-to-end run against a real multi-file widget found the
//! entire visible body reading back `"none"` before this existed
//! (coordinator review). Because the file check runs FIRST and
//! unconditionally at every node, an ancestor stuck at `"none"` never
//! closes off a basename-typed descendant further down — only a `"none"`
//! node with no basename-typed descendants below it ever actually
//! terminates a subtree.
use crate::dispatch::Invocation;
use crate::output::{Outcome, Status};
use crate::registry::{cmd, flag, Registry};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["preview", "shot"],
        summary: "Capture the full screen, the canvas window, the previewed widget, or one element inside it -- a <out>.json sidecar records widget/element identity, and (for --what element) the source file:line.",
        args: [],
        flags: [
            flag!("root", "string", "Preview root directory (default $XDG_RUNTIME_DIR/aoide-preview)."),
            flag!("what", "string", "screen|canvas|widget|element (default widget)."),
            flag!("element", "string", "Element path (Type[i]/Type[i]#objectName), required for --what element."),
            flag!("annotated", "bool", "Ask the canvas to draw its own note/shape overlay into the capture."),
            flag!("out", "string", "Output PNG path (default ROOT/shots/<what>-<utc-compact>.png).")
        ],
        gated: false,
        implemented: true,
        handler: handle_preview_shot,
    ));
    r.insert(cmd!(
        path: ["preview", "tree"],
        summary: "Dump the previewed widget's live item tree, joined against a static parse of its own QML source -- id, source file:line, and how each node was matched.",
        args: [],
        flags: [
            flag!("root", "string", "Preview root directory (default $XDG_RUNTIME_DIR/aoide-preview)."),
            flag!("at", "string", "x,y widget-local coordinates -- return only the deepest visible node containing this point, with its ancestor path.")
        ],
        gated: false,
        implemented: true,
        handler: handle_preview_tree,
    ));
    r.insert(cmd!(
        path: ["preview", "notes"],
        summary: "List, add, complete, or clear scaffolding notes on the preview canvas -- a work list of what to change and where, resolved to a source line when the canvas is up.",
        args: [],
        flags: [
            flag!("root", "string", "Preview root directory (default $XDG_RUNTIME_DIR/aoide-preview)."),
            flag!("add", "bool", "Add a note -- requires --text."),
            flag!("text", "string", "Note text (with --add)."),
            flag!("rect", "string", "x,y,w,h in widget-local coordinates (with --add; mutually exclusive with --element)."),
            flag!("element", "string", "Element path this note highlights (with --add; mutually exclusive with --rect)."),
            flag!("shape", "string", "rect|ellipse|arrow|line (with --add)."),
            flag!("done", "string", "Mark note #n done."),
            flag!("clear", "bool", "Empty the notes list (keeps the file).")
        ],
        gated: false,
        implemented: true,
        handler: handle_preview_notes,
    ));
}

/// How long/often every ipc-backed poll in this module waits for the canvas
/// to produce a file (`preview shot`'s widget/element kinds, `preview
/// tree`'s dump) — the brief's own "poll ≤5s (100ms)".
const POLL_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

// A JSON NUMBER, not a string -- confirmed against the real canvas's own
// `notes.json` writes (coordinator's live end-to-end run, review item 5):
// unlike `preview.json`'s own `schemaVersion` (a string there), this one
// is `0` the number.
const NOTES_SCHEMA_VERSION: i64 = 0;

// ─────────────────────────── `preview shot` ───────────────────────────

const SHOT_WHATS: &[&str] = &["screen", "canvas", "widget", "element"];

fn parse_shot_what(s: &str) -> Result<&'static str, String> {
    SHOT_WHATS
        .iter()
        .find(|w| **w == s)
        .copied()
        .ok_or_else(|| format!("`{s}` is not one of: {}", SHOT_WHATS.join(", ")))
}

fn handle_preview_shot(inv: &Invocation) -> Outcome {
    let cmd = "preview.shot";

    // Resolved BEFORE any filesystem/root touch (mirrors `aoide_screen::
    // capture::shot`'s own "region/scale source resolved early" discipline)
    // so both usage errors the brief names are reachable with no preview
    // root at all.
    let what = match inv.flags.get("what") {
        None => "widget",
        Some(w) => match parse_shot_what(w) {
            Ok(w) => w,
            Err(e) => return Outcome::usage(cmd, e),
        },
    };
    let element = inv.flags.get("element").map(String::as_str);
    if what == "element" && element.is_none() {
        return Outcome::usage(cmd, "--element is required for --what element");
    }
    if what != "element" && element.is_some() {
        return Outcome::usage(cmd, "--element is only valid with --what element");
    }

    let root = match super::preview::resolve_root(inv.flags.get("root").map(String::as_str)) {
        Ok(r) => r,
        Err(e) => return Outcome::usage(cmd, e),
    };
    let Some(control) = super::preview::read_control(&root.join("preview.json")) else {
        return Outcome::error(
            cmd,
            format!(
                "no preview at {} -- run `lyra preview --no-launch` first",
                root.display()
            ),
        );
    };

    let out = match inv.flags.get("out") {
        Some(p) => PathBuf::from(p),
        None => default_shot_out(
            &root,
            what,
            &utc_compact(),
            std::process::id(),
            next_auto_name_seq(),
        ),
    };
    // No `--out` ending-in-`.json` guard here (unlike `aoide_screen::
    // capture::shot`'s own `sidecar_collides_with_dest`): our sidecar path
    // is `--out`'s FULL value with `.json` LITERALLY APPENDED
    // (`append_suffix`), matching P7's own on-disk convention -- a
    // caller-given `--out foo.json` lands at `foo.json.json`, never
    // colliding with the image itself.
    if let Some(parent) = out.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Outcome::error(cmd, format!("creating {}: {e}", parent.display()));
        }
    }

    let mut sidecar = build_shot_sidecar_base(what, &out, &root, &control);
    if what == "element" {
        sidecar.insert("element".to_string(), json!(element.unwrap()));
    }

    match what {
        "screen" | "canvas" => {
            let mut flags = std::collections::BTreeMap::new();
            flags.insert("out".to_string(), out.to_string_lossy().into_owned());
            if what == "canvas" {
                let Some(addr) =
                    super::preview::find_client_address(super::preview::canvas_pid(&root))
                else {
                    return Outcome::error(cmd, "canvas not running")
                        .with_data(json!({"reason": "canvas-not-running"}));
                };
                flags.insert("window".to_string(), addr);
            }
            let sub = Invocation {
                path: vec!["screen".to_string(), "shot".to_string()],
                args: vec![],
                flags,
                door: inv.door,
            };
            let screen_outcome = aoide_screen::capture::shot(&sub);
            if screen_outcome.status != Status::Ok {
                return Outcome::new(
                    cmd,
                    screen_outcome.status,
                    format!("{what} capture failed: {}", screen_outcome.message),
                )
                .with_data(screen_outcome.data.unwrap_or_else(|| json!({})));
            }
            fold_screen_sidecar(&mut sidecar, &out);
        }
        "widget" | "element" => {
            let annotated = if inv.flag_present("annotated") {
                "on"
            } else {
                "off"
            };
            // The canvas's own element-kind ipc call is now PERMANENTLY
            // broken by design (canvas-side contract update, confirmed
            // after a live element grab came back a fully transparent
            // PNG): `what=element` at the ipc level always writes
            // `<out>.error` and no PNG. `--what element` is therefore a
            // Rust-side CROP of a full widget capture -- always call the
            // canvas with `what="widget"` (never `what`, never a real
            // element arg), and never a second ipc "kind" for elements.
            if let Err(tail) = qs_ipc_call(
                &root,
                "shot",
                &["widget", "-", &out.to_string_lossy(), annotated],
            ) {
                return Outcome::error(cmd, format!("canvas ipc call failed: {tail}"))
                    .with_data(json!({"reason": "ipc-failed"}));
            }
            // The canvas answers with exactly one of two files: `<out>` on
            // success, `<out>.error` (plain text) on failure.
            let error_path = append_suffix(&out, "error");
            if let Err(e) = poll_for_shot(&out, &error_path, POLL_TIMEOUT, POLL_INTERVAL) {
                return Outcome::error(
                    cmd,
                    format!("canvas could not produce {}: {e}", out.display()),
                )
                .with_data(json!({"reason": "shot-failed"}));
            }
            merge_canvas_meta(&mut sidecar, &append_suffix(&out, "meta.json"));

            if what == "element" {
                let elem = element.expect("--what element requires --element, checked above");
                // `source` (file:line) and the crop rect both come from
                // the SAME join `preview tree`/`preview notes` use, never
                // a second forked lookup -- but unlike the old best-effort
                // `source` enrichment, a lookup failure here IS a hard
                // error now: there is no rect to crop to without it, and
                // the alternative (silently shipping the full widget PNG
                // back as an "element" shot) is worse than failing loudly.
                let joined = match build_joined_tree(&root, &control) {
                    Ok(j) => j,
                    Err(e) => {
                        return Outcome::error(cmd, format!("resolving --element {elem}: {e}"))
                            .with_data(json!({"reason": "tree-unavailable"}));
                    }
                };
                let Some(node) = resolve_element_path(&joined, elem) else {
                    return Outcome::error(cmd, format!("element not found: {elem}"))
                        .with_data(json!({"reason": "element-not-found"}));
                };
                if let Some(src) = &node.source {
                    sidecar.insert("source".to_string(), json!(src));
                }

                let scale = sidecar
                    .get("scale")
                    .and_then(Value::as_f64)
                    .filter(|s| *s > 0.0)
                    .unwrap_or(1.0);
                let img = match image::open(&out) {
                    Ok(img) => img,
                    Err(e) => {
                        return Outcome::error(
                            cmd,
                            format!("opening captured {}: {e}", out.display()),
                        )
                        .with_data(json!({"reason": "crop-failed"}))
                    }
                };
                let (img_w, img_h) = (img.width(), img.height());
                let Some((cx, cy, cw, ch)) = clamp_crop(node.rect, scale, img_w, img_h) else {
                    return Outcome::error(cmd, format!("element {elem} has no visible area to crop within the {img_w}x{img_h} capture"))
                        .with_data(json!({"reason": "empty-crop"}));
                };
                if let Err(e) = img.crop_imm(cx, cy, cw, ch).save(&out) {
                    return Outcome::error(cmd, format!("writing cropped {}: {e}", out.display()))
                        .with_data(json!({"reason": "crop-failed"}));
                }
                sidecar.insert(
                    "elementRect".to_string(),
                    json!({"x": cx, "y": cy, "w": cw, "h": ch}),
                );
            }
        }
        _ => unreachable!("parse_shot_what already validated `what`"),
    }

    let notes_doc = read_notes(&root.join("notes.json"));
    sidecar.insert(
        "notes".to_string(),
        notes_doc.get("notes").cloned().unwrap_or_else(|| json!([])),
    );

    let sidecar_path = append_suffix(&out, "json");
    let pretty = match serde_json::to_string_pretty(&Value::Object(sidecar.clone())) {
        Ok(s) => s + "\n",
        Err(e) => {
            return Outcome::error(cmd, format!("serializing sidecar: {e}"))
                .changed(vec![out.to_string_lossy().into_owned()])
        }
    };
    if let Err(e) = aoide_storage::fs::atomic_write(&sidecar_path, &pretty) {
        return Outcome::error(
            cmd,
            format!(
                "captured but failed to write sidecar {}: {e}",
                sidecar_path.display()
            ),
        )
        .changed(vec![out.to_string_lossy().into_owned()]);
    }

    Outcome::ok(
        cmd,
        format!(
            "{what} shot written to {} -- sidecar {}",
            out.display(),
            sidecar_path.display()
        ),
    )
    .changed(vec![
        out.to_string_lossy().into_owned(),
        sidecar_path.to_string_lossy().into_owned(),
    ])
    .with_data(Value::Object(sidecar))
}

/// `ROOT/shots/<what>-<utc-compact>-<pid>-<seq>.png` — the brief's own
/// default naming, with `aoide_screen::capture::auto_name`'s own pid+seq
/// disambiguation shape folded in (review item 4): `<utc-compact>` alone is
/// only 1-second resolution, so two shots inside the same second (a script
/// looping `preview shot`) would otherwise collide and silently overwrite
/// each other. `stamp`/`pid`/`seq` are injected so the naming itself stays
/// pure/testable (the caller supplies [`utc_compact`]'s real output,
/// `std::process::id()`, and [`next_auto_name_seq()`] at the call site) --
/// `next_auto_name_seq` is this module's OWN counter, not a reuse of
/// `aoide_screen`'s (that one is `pub(crate)` to `aoide_screen`, not
/// reachable from this crate).
fn default_shot_out(root: &Path, what: &str, stamp: &str, pid: u32, seq: u64) -> PathBuf {
    root.join("shots")
        .join(format!("{what}-{stamp}-{pid}-{seq}.png"))
}

/// This module's own monotonic disambiguator for [`default_shot_out`],
/// mirroring `aoide_screen::capture`'s `AUTO_NAME_SEQ`/`next_auto_name_seq`
/// shape (same fix for the same class of collision) without reaching into
/// that crate's `pub(crate)` internals.
static AUTO_NAME_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_auto_name_seq() -> u64 {
    AUTO_NAME_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// ISO-8601 UTC with every non-alphanumeric character stripped
/// (`2026-09-12T18:30:45Z` -> `20260912T183045Z`) — a filename-safe,
/// still-sortable timestamp, reusing `aoide_storage::time::now_iso_utc`
/// rather than hand-rolling a second clock read.
fn utc_compact() -> String {
    aoide_storage::time::now_iso_utc()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

/// `<out>` with `.<suffix>` LITERALLY APPENDED onto the full path (never
/// `PathBuf::with_extension`, which REPLACES the part after the last dot —
/// `PathBuf::from("foo.png").with_extension("meta.json")` gives
/// `"foo.meta.json"`, silently dropping `.png`). P7's own on-disk
/// convention, confirmed against real canvas output: `<out>.json` (this
/// module's own sidecar), `<out>.meta.json`, `<out>.error` are all formed
/// this way.
fn append_suffix(out: &Path, suffix: &str) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".");
    s.push(suffix);
    PathBuf::from(s)
}

fn build_shot_sidecar_base(
    what: &str,
    out: &Path,
    root: &Path,
    control: &Map<String, Value>,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("what".to_string(), json!(what));
    m.insert("out".to_string(), json!(out.to_string_lossy()));
    m.insert("root".to_string(), json!(root.to_string_lossy()));
    m.insert(
        "widget".to_string(),
        control.get("widget").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "song".to_string(),
        control.get("song").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "widgetWidth".to_string(),
        control.get("widgetWidth").cloned().unwrap_or(Value::Null),
    );
    m.insert(
        "widgetHeight".to_string(),
        control.get("widgetHeight").cloned().unwrap_or(Value::Null),
    );
    m
}

/// After a successful `aoide_screen::capture::shot` capture at `out`, fold
/// ITS OWN sidecar into `sidecar` and delete the orphan. `aoide_screen::
/// capture::shot` writes its own sidecar at `out.with_extension("json")`
/// (`sidecar_collides_with_dest`'s own convention, `crates/screen/src/
/// capture.rs`) — a DIFFERENT path from ours (`append_suffix`'s literal
/// `<out>.json`), so the two never collide as this module's docs used to
/// (incorrectly) claim; left alone, theirs would simply be an orphan file
/// nobody ever reads back (review item 3). A missing or unparsable sidecar
/// is a silent no-op, same posture as [`merge_canvas_meta`].
fn fold_screen_sidecar(sidecar: &mut Map<String, Value>, out: &Path) {
    let their_sidecar = out.with_extension("json");
    if let Ok(raw) = std::fs::read_to_string(&their_sidecar) {
        if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
            sidecar.insert("capture".to_string(), parsed);
        }
        let _ = std::fs::remove_file(&their_sidecar);
    }
}

/// Merge the canvas's own `<out>.meta.json` (`{widgetRect, scale}` ONLY --
/// confirmed against a canvas-side contract update: the canvas never
/// writes `element`/`elementRect` there, and `what=element` at the ipc
/// level always fails, never called any more, see [`handle_preview_shot`]'s
/// element branch) into a building sidecar, then delete it: `scale` lands
/// in OUR schema verbatim; `widgetRect` (live render geometry, no home in
/// this sidecar's own schema -- `widgetWidth`/`widgetHeight` already come
/// from `preview.json` instead) is read and discarded. A missing or
/// unparsable meta file is a silent no-op: an older canvas build that
/// skipped writing it must never fail an otherwise-successful shot.
fn merge_canvas_meta(sidecar: &mut Map<String, Value>, meta_path: &Path) {
    let Ok(raw) = std::fs::read_to_string(meta_path) else {
        return;
    };
    let Ok(Value::Object(meta)) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    if let Some(scale) = meta.get("scale") {
        sidecar.insert("scale".to_string(), scale.clone());
    }
    let _ = std::fs::remove_file(meta_path);
}

/// Convert a widget-local rect ([`JoinedNode::rect`], the SAME coordinate
/// space `preview tree`'s own dump uses) to the captured PNG's pixel space
/// via `scale` (the merged `<out>.meta.json` value), then clamp to the
/// image's actual bounds -- `None` for a degenerate (zero-area, e.g.
/// entirely off-canvas or a genuinely empty element) result. `image`
/// 0.25.10's own `DynamicImage::crop_imm` does NOT panic on a negative-
/// origin or overflowing rect -- it silently re-clamps to the image's own
/// bounds itself -- but doing that clamp explicitly here, rather than
/// leaning on `crop_imm`'s own, is what lets a degenerate (zero-area)
/// result come back as a clean `None` instead of `crop_imm`'s own
/// zero-size `DynamicImage`. Pure, so it's unit-testable with no real PNG
/// involved (review item 9's own required coverage: normal/out-of-bounds/
/// negative-origin/degenerate).
fn clamp_crop(
    rect: (f64, f64, f64, f64),
    scale: f64,
    img_w: u32,
    img_h: u32,
) -> Option<(u32, u32, u32, u32)> {
    let (x, y, w, h) = rect;
    let px_x = x * scale;
    let px_y = y * scale;
    let px_w = w * scale;
    let px_h = h * scale;

    let x0 = px_x.max(0.0).min(img_w as f64);
    let y0 = px_y.max(0.0).min(img_h as f64);
    let x1 = (px_x + px_w).max(0.0).min(img_w as f64);
    let y1 = (px_y + px_h).max(0.0).min(img_h as f64);

    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some((
        x0.round() as u32,
        y0.round() as u32,
        (x1 - x0).round() as u32,
        (y1 - y0).round() as u32,
    ))
}

// ─────────────────────────── `preview tree` ───────────────────────────

fn handle_preview_tree(inv: &Invocation) -> Outcome {
    let cmd = "preview.tree";
    let root = match super::preview::resolve_root(inv.flags.get("root").map(String::as_str)) {
        Ok(r) => r,
        Err(e) => return Outcome::usage(cmd, e),
    };
    let Some(control) = super::preview::read_control(&root.join("preview.json")) else {
        return Outcome::error(
            cmd,
            format!(
                "no preview at {} -- run `lyra preview --no-launch` first",
                root.display()
            ),
        );
    };

    // `--at` is validated BEFORE the canvas round-trip below (review item
    // 6a) -- a malformed `--at` is a pure usage error that needs no ipc
    // call to detect, and should never pay for (or wait on) one.
    let at = match inv.flags.get("at") {
        Some(at) => match parse_xy(at) {
            Some(xy) => Some(xy),
            None => return Outcome::usage(cmd, format!("--at `{at}` is not `x,y`")),
        },
        None => None,
    };

    let joined = match build_joined_tree(&root, &control) {
        Ok(j) => j,
        Err(e) => return Outcome::error(cmd, e).with_data(json!({"reason": "tree-unavailable"})),
    };

    if let Some((x, y)) = at {
        return match deepest_path_at(std::slice::from_ref(&joined), x, y) {
            Some(path) => {
                let human = path
                    .iter()
                    .enumerate()
                    .map(|(i, n)| render_tree_line(i, n))
                    .collect::<Vec<_>>()
                    .join("\n");
                // Named `chain`, not `path` -- each node already carries
                // its OWN `path` (the canvas's element-path string,
                // `joined_to_json`); this key is the different concept of
                // "which ancestors did we walk through to reach it"
                // ("one name per thing").
                let data = json!({"chain": path.iter().map(|n| joined_to_json_shallow(n)).collect::<Vec<_>>()});
                Outcome::ok(cmd, human).with_data(data)
            }
            None => Outcome::ok(cmd, format!("no visible node contains ({x}, {y})"))
                .with_data(json!({"chain": []})),
        };
    }

    let mut lines = Vec::new();
    render_tree_rec(&joined, 0, &mut lines);
    Outcome::ok(cmd, lines.join("\n")).with_data(joined_to_json(&joined))
}

fn parse_xy(s: &str) -> Option<(f64, f64)> {
    let (x, y) = s.split_once(',')?;
    Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
}

fn rect_contains(rect: (f64, f64, f64, f64), x: f64, y: f64) -> bool {
    let (rx, ry, rw, rh) = rect;
    x >= rx && x < rx + rw && y >= ry && y < ry + rh
}

/// The deepest VISIBLE node (root..leaf, leaf last) whose rect contains
/// `(x, y)` — `None` when nothing at the top level even contains the
/// point. Tries EVERY visible+containing sibling at each level, not just
/// the first one found, and keeps whichever yields the longest resulting
/// path (review item 8, coordinator's live end-to-end run): overlapping
/// siblings are legal QML (a `Loader`'s own bounds and its loaded item's
/// bounds coincide, for instance), and the first one in DOM order is not
/// necessarily the one with visible descendants under the point -- a
/// `--at` that landed on a shallow overlapping sibling instead of a deep
/// one produced a useless one-node "Item/Loader" answer where a real
/// descendant (a `Text`/`Rectangle` several components down) was sitting
/// right there.
fn deepest_path_at<'a>(nodes: &'a [JoinedNode], x: f64, y: f64) -> Option<Vec<&'a JoinedNode>> {
    let mut best: Option<Vec<&'a JoinedNode>> = None;
    for n in nodes {
        if !n.visible || !rect_contains(n.rect, x, y) {
            continue;
        }
        let mut path = vec![n];
        if let Some(mut deeper) = deepest_path_at(&n.children, x, y) {
            path.append(&mut deeper);
        }
        if best.as_ref().is_none_or(|b| path.len() > b.len()) {
            best = Some(path);
        }
    }
    best
}

fn render_tree_rec(node: &JoinedNode, depth: usize, out: &mut Vec<String>) {
    out.push(render_tree_line(depth, node));
    for c in &node.children {
        render_tree_rec(c, depth + 1, out);
    }
}

/// `Type#objectName  x,y w×h  -> file:line (match)` — the brief's own human
/// format, one line per node, indented two spaces per depth.
fn render_tree_line(depth: usize, n: &JoinedNode) -> String {
    let name = match &n.object_name {
        Some(o) => format!("{}#{o}", n.ty),
        None => n.ty.clone(),
    };
    let loc = match &n.source {
        Some(s) => format!("{s} ({})", n.match_kind),
        None => format!("unresolved ({})", n.match_kind),
    };
    format!(
        "{}{name}  {:.0},{:.0} {:.0}\u{00d7}{:.0}  -> {loc}",
        "  ".repeat(depth),
        n.rect.0,
        n.rect.1,
        n.rect.2,
        n.rect.3
    )
}

/// Every field a `JoinedNode` puts in JSON EXCEPT `children` -- the shared
/// body behind [`joined_to_json`] (full recursive dump) and
/// [`joined_to_json_shallow`] (one node, `--at`'s own `chain` entries,
/// review follow-up part B2). Neither caller is complete on its own; each
/// adds its own `children` handling on top of this.
fn joined_to_json_fields(n: &JoinedNode) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".to_string(), json!(n.ty));
    if let Some(o) = &n.object_name {
        m.insert("objectName".to_string(), json!(o));
    }
    // The canvas's own element-path string, carried verbatim -- feed this
    // straight back into `--element`/`--rect`-less `--element` flags with
    // no re-derivation on either side.
    m.insert("path".to_string(), json!(n.path));
    m.insert(
        "rect".to_string(),
        json!({"x": n.rect.0, "y": n.rect.1, "w": n.rect.2, "h": n.rect.3}),
    );
    m.insert("visible".to_string(), json!(n.visible));
    if let Some(t) = &n.text {
        m.insert("text".to_string(), json!(t));
    }
    if let Some(i) = &n.id {
        m.insert("id".to_string(), json!(i));
    }
    m.insert("match".to_string(), json!(n.match_kind));
    if let Some(s) = &n.source {
        m.insert("source".to_string(), json!(s));
    }
    m
}

fn joined_to_json(n: &JoinedNode) -> Value {
    let mut m = joined_to_json_fields(n);
    m.insert(
        "children".to_string(),
        Value::Array(n.children.iter().map(joined_to_json).collect()),
    );
    Value::Object(m)
}

/// [`joined_to_json`]'s own fields with NO `children` key at all -- not
/// even an empty array (review follow-up part B2: `--at`'s `chain` reused
/// `joined_to_json` whole per ancestor, so EVERY entry re-embedded its
/// entire subtree -- a 6-node chain outweighing the full dump, 2.45MB for
/// what should be a few KB). `chain` only ever needs each ancestor's OWN
/// identity, never what hangs off it -- that's what `preview tree`'s own
/// full dump, one call away, is for.
fn joined_to_json_shallow(n: &JoinedNode) -> Value {
    Value::Object(joined_to_json_fields(n))
}

// ─────────────────────────── the tree join ───────────────────────────

/// One node of the canvas's LIVE item tree (`qs ipc call preview tree
/// <out.json>`'s own shape): `{type, objectName, path, rect:{x,y,w,h},
/// visible, text?, children:[…]}`, widget-local coordinates. `path` is the
/// canvas's OWN element-path string for this exact node (confirmed against
/// a real 421KB live dump: the root carries `path: ""`, a leaf might carry
/// `"Loader[0]/SessionMenu[0]/TextEdit[0]"`) -- authoritative, carried
/// verbatim rather than re-derived (see this file's module doc, "Element
/// path grammar").
#[derive(Debug, Clone)]
struct RuntimeNode {
    ty: String,
    object_name: String,
    path: String,
    rect: (f64, f64, f64, f64),
    visible: bool,
    text: Option<String>,
    children: Vec<RuntimeNode>,
}

fn parse_runtime_node(v: &Value) -> Option<RuntimeNode> {
    let obj = v.as_object()?;
    let ty = obj.get("type")?.as_str()?.to_string();
    let object_name = obj
        .get("objectName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let path = obj
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let rect_obj = obj.get("rect")?.as_object()?;
    let rect = (
        rect_obj.get("x").and_then(Value::as_f64).unwrap_or(0.0),
        rect_obj.get("y").and_then(Value::as_f64).unwrap_or(0.0),
        rect_obj.get("w").and_then(Value::as_f64).unwrap_or(0.0),
        rect_obj.get("h").and_then(Value::as_f64).unwrap_or(0.0),
    );
    let visible = obj.get("visible").and_then(Value::as_bool).unwrap_or(true);
    let text = obj.get("text").and_then(Value::as_str).map(String::from);
    let children = obj
        .get("children")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(parse_runtime_node).collect())
        .unwrap_or_default();
    Some(RuntimeNode {
        ty,
        object_name,
        path,
        rect,
        visible,
        text,
        children,
    })
}

/// One node of the STATIC parse of a widget's own QML source
/// ([`parse_static_qml`]) — `line` is 1-indexed, the line its opening
/// `Type {` was found on.
#[derive(Debug, Clone, Default)]
struct StaticNode {
    ty: String,
    id: Option<String>,
    object_name: Option<String>,
    line: usize,
    children: Vec<StaticNode>,
    /// `Some(name)` when this node is an inline `component Name: Type {
    /// ... }` TYPE declaration rather than an instance — [`parse_static_qml`]
    /// still opens a stack frame for it (so its own nested children nest
    /// correctly instead of leaking into whatever is one level up), but
    /// never attaches it to any parent's `children`; it comes back via
    /// `parse_static_qml`'s own second return value instead, for
    /// [`build_component_map`] to register into the `ComponentMap` under
    /// `name` — GLOBAL scope, not per-file (review follow-up part A: the
    /// simpler of the two options named, since QML component names are
    /// already expected to be unique within a project; the LAST file
    /// parsed with a given name wins on a collision). `ty` on a node like
    /// this is the component's own BASE type (`Rectangle` for `component
    /// Action: Rectangle`), not `name` itself.
    component_name: Option<String>,
    /// `Some(name)` when this node was opened by a BINDING line —
    /// `delegate: Column {`, `contentItem: Rectangle {`, `background:
    /// Rectangle {`, `sourceComponent: Component {` — rather than a bare
    /// `Type {` ([`line_opens_bound_node`], review follow-up part B1).
    /// `name` is the property/binding name (`"delegate"`, …); the node
    /// itself is otherwise ordinary — a real child of whatever is
    /// currently open, with its own real nested children — this field
    /// exists only so [`join_level`]'s `Repeater`-delegate rule can find
    /// it again by name.
    binding: Option<String>,
}

/// A joined tree node — everything [`RuntimeNode`] carries, plus whatever
/// [`join_level`] could attach from the static side: `id`, `source`
/// (`<file>:<line>`), and `match_kind` (`"file"` | `"objectName"` |
/// `"positional"` | `"wrapper"` | `"none"`) — `"file"` is a match onto
/// another parsed component ([`ComponentMap`], either a `watch`-listed
/// FILE keyed by stem or an inline `component Name: Type { ... }`
/// declaration keyed by `Name`), checked before and independently of the
/// other three; `"wrapper"` is a runtime-only container with no static
/// counterpart of its own (`source` borrowed from its nearest matched
/// ancestor) whose children join against the SAME static list it failed
/// on, rather than against nothing.
#[derive(Debug, Clone)]
struct JoinedNode {
    ty: String,
    object_name: Option<String>,
    path: String,
    rect: (f64, f64, f64, f64),
    visible: bool,
    text: Option<String>,
    id: Option<String>,
    match_kind: &'static str,
    source: Option<String>,
    children: Vec<JoinedNode>,
}

/// One `*.qml` file parsed once and keyed by its own stem (`SessionCard.
/// qml` -> `SessionCard`, [`build_component_map`]) — a runtime node whose
/// `type` names one of these is joined against THAT file's own static
/// parse ([`join_level`]'s `"file"` match), rather than stopping at
/// `"none"` the moment the widget's own file runs out of matching
/// siblings.
struct ComponentFile {
    path: PathBuf,
    roots: Vec<StaticNode>,
}

type ComponentMap = std::collections::HashMap<String, ComponentFile>;

/// Every `*.qml` file this preview's `watch` list names (`preview.json`'s
/// own `watch` field — the current song's `widgets/` directory plus the
/// previewed widget's own file, `commands::preview::compute_watch_list`),
/// parsed once and keyed by file stem, PLUS the widget's own file (in case
/// it lives somewhere `watch` doesn't cover, e.g. a foreign song or an
/// out-of-songbook path), PLUS every inline `component Name: Type { ... }`
/// declaration any of those files contain, keyed by `Name` (review
/// follow-up part A) — same `ComponentFile` shape either way (an inline
/// component's `roots` is a single synthetic entry: its own base type,
/// declaration line, and parsed children), so [`join_level`]'s `"file"`
/// branch never needs to know which kind it got. GLOBAL scope: a name
/// collision between two files is resolved by last-parsed-wins, same as a
/// file stem collision would be. A file that fails to read or parse is
/// simply absent from the map — best-effort, same posture as the rest of
/// this join (a widget with no `watch` list at all still joins against its
/// own file exactly as before this existed).
fn build_component_map(control: &Map<String, Value>, widget_abs: Option<&Path>) -> ComponentMap {
    let mut files: Vec<PathBuf> = control
        .get("watch")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default();
    if let Some(w) = widget_abs {
        if !files.iter().any(|f| f == w) {
            files.push(w.to_path_buf());
        }
    }

    let mut map = ComponentMap::new();
    for path in files {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let (roots, inline) = parse_static_qml(&text);
        map.insert(
            stem.to_string(),
            ComponentFile {
                path: path.clone(),
                roots,
            },
        );
        for comp in inline {
            let Some(name) = comp.component_name.clone() else {
                continue;
            };
            map.insert(
                name,
                ComponentFile {
                    path: path.clone(),
                    roots: vec![comp],
                },
            );
        }
    }
    map
}

/// Join one level of runtime siblings against a (possibly absent) static
/// sibling list, THEN recurse. `statics: None` means the local static
/// context never matched (or this is the unmatched side of an earlier
/// `"none"`) — every node at and below this level is `"none"` too, UNLESS
/// its own `type` names a component in `components` (checked FIRST,
/// unconditionally, review item 7): that switches the static context to
/// THAT component's own root node regardless of what the local `statics`
/// context was, which is what lets a basename-typed or inline-component-
/// typed descendant resolve even under an unresolved ancestor
/// (`conductor.qml`'s `Loader` -> `SessionMenu` -> `SessionCard` -> …,
/// `SessionCard` an INLINE `component` in `conductor.qml` itself, not a
/// file of its own — review follow-up part A). `parent_source` is the
/// nearest already-resolved ancestor's own `source` (or whatever it
/// inherited, transitively) — carried along purely for a `"wrapper"` node
/// (part B) to report SOMETHING traceable rather than `None`.
fn join_level(
    runtime: &[RuntimeNode],
    statics: Option<&[StaticNode]>,
    file: &Path,
    components: &ComponentMap,
    parent_source: Option<&str>,
) -> Vec<JoinedNode> {
    let mut used = vec![false; statics.map(|s| s.len()).unwrap_or(0)];

    runtime
        .iter()
        .map(|rn| {
            if let Some(comp) = components.get(rn.ty.as_str()) {
                let comp_root = comp.roots.first();
                let id = comp_root.and_then(|r| r.id.clone());
                let source = comp_root.map(|r| format!("{}:{}", comp.path.display(), r.line));
                // `rn` itself already IS the component's root object — the
                // canvas reports the instantiation's own type as the
                // component's name, on the SAME node whose rect/visible are
                // the root's own (confirmed live: `SessionMenu[0]`'s own
                // children are `SessionMenu.qml`'s root's declared children
                // directly, no extra wrapper level; `SessionCard[0]` the
                // same for the INLINE component case). So the next level
                // matches against the root's own `.children`, never
                // `comp.roots` again (that list just holds the root itself,
                // which `rn` already consumed) — reusing it here silently
                // turned every one of a component's real children into
                // `"none"` (review follow-up: live SessionMenu.qml run,
                // 1054 none vs 34 resolved).
                let child_statics: Vec<StaticNode> =
                    comp_root.map(|r| r.children.clone()).unwrap_or_default();
                return JoinedNode {
                    ty: rn.ty.clone(),
                    object_name: if rn.object_name.is_empty() {
                        None
                    } else {
                        Some(rn.object_name.clone())
                    },
                    path: rn.path.clone(),
                    rect: rn.rect,
                    visible: rn.visible,
                    text: rn.text.clone(),
                    id,
                    match_kind: "file",
                    source: source.clone(),
                    children: join_level(
                        &rn.children,
                        Some(&child_statics),
                        &comp.path,
                        components,
                        source.as_deref(),
                    ),
                };
            }

            let mut matched: Option<usize> = None;
            let mut kind = "none";
            if let Some(statics) = statics {
                if !rn.object_name.is_empty() {
                    if let Some(i) = statics.iter().enumerate().position(|(i, sn)| {
                        !used[i] && sn.object_name.as_deref() == Some(rn.object_name.as_str())
                    }) {
                        matched = Some(i);
                        kind = "objectName";
                    }
                }
                if matched.is_none() {
                    if let Some(i) = statics
                        .iter()
                        .enumerate()
                        .position(|(i, sn)| !used[i] && sn.ty == rn.ty)
                    {
                        matched = Some(i);
                        kind = "positional";
                    }
                }
            }

            // `Repeater` delegate re-attachment (review follow-up part
            // B1): a `Repeater`'s own `delegate:`-bound child is a REAL
            // static child of the `Repeater` (parsed as a proper node
            // now, `line_opens_bound_node`), but every instance the
            // `Repeater` stamps out at RUNTIME lands as a SIBLING of the
            // `Repeater` itself, never as its child — so a runtime node
            // that matched nothing at this level gets one more try: does
            // a `Repeater` among these SAME static siblings carry a
            // `delegate`-bound child of this exact type? If so, EVERY
            // instance (there may be many) resolves to that ONE static
            // child, sharing its line/id — never marked `used[]`, since
            // it was never a member of `statics` to begin with, only
            // nested one level inside one of them. Scoped to `delegate`
            // only: `contentItem`/`background`/`sourceComponent` are
            // ordinary single-value properties the runtime tree already
            // nests as real children, reached by plain positional
            // matching once the parser opens them as real nodes at all.
            if matched.is_none() {
                if let Some(statics) = statics {
                    if let Some(delegate) = statics
                        .iter()
                        .filter(|sn| sn.ty == "Repeater")
                        .find_map(|sn| {
                            sn.children
                                .iter()
                                .find(|c| c.binding.as_deref() == Some("delegate") && c.ty == rn.ty)
                        })
                    {
                        let source = format!("{}:{}", file.display(), delegate.line);
                        return JoinedNode {
                            ty: rn.ty.clone(),
                            object_name: if rn.object_name.is_empty() {
                                None
                            } else {
                                Some(rn.object_name.clone())
                            },
                            path: rn.path.clone(),
                            rect: rn.rect,
                            visible: rn.visible,
                            text: rn.text.clone(),
                            id: delegate.id.clone(),
                            match_kind: "positional",
                            source: Some(source.clone()),
                            children: join_level(
                                &rn.children,
                                Some(&delegate.children),
                                file,
                                components,
                                Some(&source),
                            ),
                        };
                    }
                }
            }

            // Transparent wrapper pass-through (review follow-up part B):
            // a runtime node that matched NOTHING, where the static side
            // doesn't merely have every same-typed sibling already
            // claimed but has ZERO of that type at this level AT ALL, is a
            // framework-synthesized container standing in the runtime
            // tree with no static counterpart of its own (`Flickable`'s
            // `contentItem`, `ListView`'s `contentItem`, a bare `Loader`
            // item, …) — never something the widget author actually wrote.
            // Its OWN runtime children are handed the SAME static sibling
            // list it failed to match against (not descended), since those
            // children are the widget's real, declared content, one
            // runtime hop further down than the static source expects. A
            // node whose type DOES have static siblings here (all already
            // `used`, or none matching by objectName) is a genuine
            // mismatch — stays `"none"`, statics are NOT hidden past it.
            if matched.is_none() {
                if let Some(statics) = statics {
                    let ty_has_a_static_sibling_here = statics.iter().any(|sn| sn.ty == rn.ty);
                    if !ty_has_a_static_sibling_here {
                        return JoinedNode {
                            ty: rn.ty.clone(),
                            object_name: if rn.object_name.is_empty() {
                                None
                            } else {
                                Some(rn.object_name.clone())
                            },
                            path: rn.path.clone(),
                            rect: rn.rect,
                            visible: rn.visible,
                            text: rn.text.clone(),
                            id: None,
                            match_kind: "wrapper",
                            source: parent_source.map(str::to_string),
                            children: join_level(
                                &rn.children,
                                Some(statics),
                                file,
                                components,
                                parent_source,
                            ),
                        };
                    }
                }
            }

            let (id, source, child_statics) = match matched {
                Some(i) => {
                    used[i] = true;
                    let sn = &statics.unwrap()[i];
                    (
                        sn.id.clone(),
                        Some(format!("{}:{}", file.display(), sn.line)),
                        Some(sn.children.clone()),
                    )
                }
                None => (None, None, None),
            };
            JoinedNode {
                ty: rn.ty.clone(),
                object_name: if rn.object_name.is_empty() {
                    None
                } else {
                    Some(rn.object_name.clone())
                },
                path: rn.path.clone(),
                rect: rn.rect,
                visible: rn.visible,
                text: rn.text.clone(),
                id,
                match_kind: kind,
                source: source.clone(),
                children: join_level(
                    &rn.children,
                    child_statics.as_deref(),
                    file,
                    components,
                    source.as_deref(),
                ),
            }
        })
        .collect()
}

/// Fetch the canvas's LIVE item tree and join it against a static parse of
/// the previewed widget's own QML source, plus every OTHER component file
/// its `watch` list names ([`build_component_map`], review item 7) — the
/// ONE join implementation `preview tree`, `preview shot --what element`,
/// and `preview notes`'s read path all share. `Err` on anything short of a
/// fully joined root: a down canvas, a timed-out/malformed runtime dump,
/// or an unreadable widget source. Callers treating this as best-effort
/// enrichment (`shot`, `notes`) simply skip on `Err`; `handle_preview_tree`
/// surfaces it as the command's own error.
fn build_joined_tree(root: &Path, control: &Map<String, Value>) -> Result<JoinedNode, String> {
    let widget_field = control
        .get("widget")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let widget_abs =
        super::preview::resolve_widget_abs(&aoide_storage::fs::flake_root(), widget_field);

    let tree_out = root.join("tree.json");
    qs_ipc_call(root, "tree", &[&tree_out.to_string_lossy()])
        .map_err(|tail| format!("canvas ipc call failed: {tail}"))?;
    poll_for_file(&tree_out, POLL_TIMEOUT, POLL_INTERVAL)
        .map_err(|e| format!("canvas did not write {}: {e}", tree_out.display()))?;

    let raw = std::fs::read_to_string(&tree_out)
        .map_err(|e| format!("reading {}: {e}", tree_out.display()))?;
    let runtime_value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("parsing {}: {e}", tree_out.display()))?;
    let runtime = parse_runtime_node(&runtime_value)
        .ok_or_else(|| format!("{}: not a valid runtime tree", tree_out.display()))?;

    let static_roots = match &widget_abs {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("reading widget source {}: {e}", p.display()))?;
            // `.0`: just the widget's own top-level roots for THIS call's
            // outermost match. Any inline `component Name: Type {}` this
            // same file declares is captured separately, below, by
            // `build_component_map`'s own pass over this same text.
            parse_static_qml(&text).0
        }
        None => Vec::new(),
    };
    let file_display = widget_abs
        .clone()
        .unwrap_or_else(|| PathBuf::from(widget_field));
    let components = build_component_map(control, widget_abs.as_deref());

    join_level(
        std::slice::from_ref(&runtime),
        Some(&static_roots),
        &file_display,
        &components,
        None,
    )
    .into_iter()
    .next()
    .ok_or_else(|| "empty runtime tree".to_string())
}

/// Find the node whose own [`JoinedNode::path`] equals `path`, exactly —
/// a plain recursive string-equality search, since the canvas is the
/// authority on this string (this file's module doc, "Element path
/// grammar"): re-deriving it via Type[i] index-counting would get a
/// `Repeater`'s generated items wrong (they land as SIBLINGS of the
/// `Repeater` in `children`, not nested under it).
fn resolve_element_path<'a>(root: &'a JoinedNode, path: &str) -> Option<&'a JoinedNode> {
    if root.path == path {
        return Some(root);
    }
    root.children
        .iter()
        .find_map(|c| resolve_element_path(c, path))
}

// ─────────────────────────── static QML parser ───────────────────────────

/// Blank out `//` comments and string-literal contents (single/double
/// quote, backslash-escape aware) while preserving every other byte in
/// place — brace counting and the node-opening scan run against this
/// scrubbed text so a brace sitting inside a comment or a string never
/// confuses either (`id:`/`objectName:` VALUE extraction needs the actual
/// string content instead, so it runs against [`strip_comments_only`]'s
/// gentler scrub, not this one). No multi-line `/* */` support (this
/// file's own module doc names the limit).
fn strip_comments_and_strings(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    let mut in_string: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = in_string {
            if c == '\\' {
                out.push(' ');
                if chars.next().is_some() {
                    out.push(' ');
                }
                continue;
            }
            if c == q {
                in_string = None;
            }
            out.push(' ');
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = Some(c);
            out.push(' ');
            continue;
        }
        if c == '/' {
            let mut lookahead = chars.clone();
            if lookahead.next() == Some('/') {
                break;
            }
        }
        out.push(c);
    }
    out
}

/// Blank out a trailing `//` comment ONLY — unlike
/// [`strip_comments_and_strings`], string-literal CONTENT is left intact,
/// since `id:`/`objectName:` extraction needs the actual quoted value
/// (`strip_comments_and_strings` blanks that too, protecting brace
/// counting, which makes it wrong for THIS use: a real bug this file's own
/// test caught, `objectName: "highlightBox"` reading back as `None`). Still
/// string-quote-aware, so a `//` sitting inside a string is never mistaken
/// for a comment opener.
fn strip_comments_only(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    let mut in_string: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = in_string {
            out.push(c);
            if c == '\\' {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
                continue;
            }
            if c == q {
                in_string = None;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = Some(c);
            out.push(c);
            continue;
        }
        if c == '/' {
            let mut lookahead = chars.clone();
            if lookahead.next() == Some('/') {
                break;
            }
        }
        out.push(c);
    }
    out
}

/// Does a (scrubbed) line open a node? `^\s*([A-Z][A-Za-z0-9_.]*)\s*\{` —
/// leading whitespace, an identifier starting uppercase (dots allowed, for
/// `Namespace.Type` spellings), then optional whitespace and a literal
/// `{`. Returns the type NAME with a dotted spelling stripped to its last
/// segment (`MoodFaces.Face` -> `Face`) — the brief's own rule.
fn line_opens_node(line: &str) -> Option<String> {
    let rest = line.trim_start();
    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }
    let mut end = first.len_utf8();
    for (i, c) in rest.char_indices().skip(1) {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    let ident = &rest[..end];
    let after = rest[end..].trim_start();
    if after.starts_with('{') {
        Some(ident.rsplit('.').next().unwrap_or(ident).to_string())
    } else {
        None
    }
}

/// Does a (scrubbed) line open an inline `component Name: Type { ... }`
/// TYPE declaration? These start lowercase (`line_opens_node` already
/// returns `None` for them) but still open a brace this widget's other
/// declarations nest inside — `parse_static_qml` needs its own frame for
/// one, both so its real children don't escape to whatever scope is
/// currently open AND (review follow-up part A) so it can be registered
/// as its own joinable component. Returns `(Name, base Type)` — `Type` is
/// resolved via [`line_opens_node`] on everything after the `:`, so it
/// gets the same dotted-spelling stripping a normal opener does.
fn line_opens_inline_component(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("component ")?.trim_start();
    let (name, after_colon) = rest.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || !name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let ty = line_opens_node(after_colon.trim_start())?;
    Some((name.to_string(), ty))
}

/// Does a (scrubbed) line open a BOUND node — `<ident>: Type { ... }`, e.g.
/// `delegate: Column {`, `contentItem: Rectangle {`, `background:
/// Rectangle {`, `sourceComponent: Component {` (review follow-up part
/// B1)? [`line_opens_node`] only accepts a bare `Type {` as the FIRST
/// thing on a line, so every one of these was invisible to it —
/// `conductor.qml`'s own `Repeater`s all write their delegate exactly this
/// way, never as a standalone `Column {` — and the delegate's real
/// children silently reattached one level too shallow, onto whatever node
/// the ENCLOSING scope opened (live: the `Repeater`'s own `id` field
/// reading its delegate's `id: movement`). Only tries the FIRST identifier
/// on the (already left-trimmed) line — never a later one — so `readonly
/// property color hue:` and similar multi-token declarations never match:
/// their first token is `readonly`/`property`, not a name directly
/// followed by `:`. Returns `(binding name, Type)`, `Type` resolved
/// through [`line_opens_node`] on everything after the `:` so it gets the
/// same dotted-spelling stripping a normal opener does. `property var x: {
/// ... }` (a JS expression block used as a property's value, not a
/// component) needs no special exclusion: its first token is `property`,
/// not `x`, so the immediate-`:` check already fails it, same as the
/// multi-token case above.
fn line_opens_bound_node(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start();
    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let mut end = first.len_utf8();
    for (i, c) in rest.char_indices().skip(1) {
        if c.is_ascii_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    let name = &rest[..end];
    let after = rest[end..].trim_start().strip_prefix(':')?.trim_start();
    let ty = line_opens_node(after)?;
    Some((name.to_string(), ty))
}

/// Find `word` in `line` as a whole word (not a substring of a longer
/// identifier) — the shared engine behind [`extract_after_word`]/
/// [`extract_quoted_after_word`], standing in for `\bword\b` with no
/// `regex` dependency in this workspace (same "hand-rolled, good enough"
/// posture `commands::preview`'s flat base16 line parser already holds).
fn find_word(line: &str, word: &str) -> Option<usize> {
    let mut start = 0usize;
    while start <= line.len() {
        let rel = line[start..].find(word)?;
        let idx = start + rel;
        let before_ok = idx == 0 || {
            let prev = line[..idx].chars().next_back().unwrap();
            !(prev.is_alphanumeric() || prev == '_')
        };
        let after_idx = idx + word.len();
        let after_ok = after_idx >= line.len() || {
            let next = line[after_idx..].chars().next().unwrap();
            !(next.is_alphanumeric() || next == '_')
        };
        if before_ok && after_ok {
            return Some(idx);
        }
        start = idx + word.len().max(1);
    }
    None
}

/// `id:\s*(\w+)` at the given (already-scrubbed) line, standing in for the
/// brief's own regex.
fn extract_after_word(line: &str, word: &str) -> Option<String> {
    let idx = find_word(line, word)?;
    let rest = line[idx + word.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(rest[..end].to_string())
    }
}

/// `objectName:\s*"([^"]+)"` at the given (already-scrubbed) line.
fn extract_quoted_after_word(line: &str, word: &str) -> Option<String> {
    let idx = find_word(line, word)?;
    let rest = line[idx + word.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The static parser: a stack-based single pass over `text`'s lines. Each
/// line is scrubbed ([`strip_comments_and_strings`]) once, then: does it
/// open a node ([`line_opens_node`])? attach `id`/`objectName` to whichever
/// node is CURRENTLY open; count net brace movement, popping (and
/// attaching to the new top, or to `roots` when the stack empties) every
/// time a `}` closes back past a node's own opening depth. Returns
/// `(roots, inline_components)` — the second list holds every inline
/// `component Name: Type { ... }` declaration found ([`line_opens_inline_
/// component`]), each carrying `component_name: Some(Name)`, for
/// [`build_component_map`] to register; they never appear in `roots` or in
/// any real node's `children`.
fn parse_static_qml(text: &str) -> (Vec<StaticNode>, Vec<StaticNode>) {
    let mut stack: Vec<(StaticNode, i64)> = Vec::new();
    let mut roots: Vec<StaticNode> = Vec::new();
    let mut inline_components: Vec<StaticNode> = Vec::new();
    let mut depth: i64 = 0;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        // Two different scrubs of the SAME line, for two different jobs:
        // node-opening/brace-counting needs braces-inside-strings blanked
        // out (`strip_comments_and_strings`), but `id:`/`objectName:`
        // extraction needs the actual quoted VALUE, which that same blank-
        // everything scrub destroys -- hence `strip_comments_only`, which
        // strips just a trailing `//` and leaves string content alone.
        let scrubbed = strip_comments_and_strings(raw_line);
        let comment_stripped = strip_comments_only(raw_line);
        let opened = line_opens_node(&scrubbed);

        let mut consume_one_open = false;
        if let Some(ty) = opened {
            depth += 1;
            stack.push((
                StaticNode {
                    ty,
                    line: line_no,
                    ..Default::default()
                },
                depth,
            ));
            consume_one_open = true;
        } else if let Some((name, base_ty)) = line_opens_inline_component(&scrubbed) {
            // `component Action: Rectangle {` — a TYPE declaration, not an
            // instance (`line_opens_node` already skips it, `component`
            // starts lowercase). Still needs its own stack frame: without
            // one, everything it declares INSIDE it (its own `Text {}` /
            // `MouseArea {}` etc.) has nowhere real to nest and falls
            // through to whatever the stack's current top is — silently
            // becoming an extra, bogus child of the widget's actual root
            // (live SessionMenu.qml run: `component Action: Rectangle`'s
            // own `Text`/`MouseArea` leaked out as if they were the root
            // Item's own children). A `component_name`-carrying frame
            // keeps depth counting identical to a normal node while never
            // attaching to a parent's `children` — it comes back via
            // `inline_components` instead (review follow-up part A).
            depth += 1;
            stack.push((
                StaticNode {
                    ty: base_ty,
                    line: line_no,
                    component_name: Some(name),
                    ..Default::default()
                },
                depth,
            ));
            consume_one_open = true;
        } else if let Some((binding, ty)) = line_opens_bound_node(&scrubbed) {
            // `delegate: Column {` / `contentItem: Rectangle {` / etc.
            // (review follow-up part B1) — a REAL instance, unlike the
            // `component Name: Type {` case above, so it attaches to its
            // parent's `children` normally once it closes; `binding`
            // just remembers WHICH property put it there, for
            // `join_level`'s `Repeater`-delegate rule to find again.
            depth += 1;
            stack.push((
                StaticNode {
                    ty,
                    line: line_no,
                    binding: Some(binding),
                    ..Default::default()
                },
                depth,
            ));
            consume_one_open = true;
        }

        if let Some((node, _)) = stack.last_mut() {
            if let Some(id) = extract_after_word(&comment_stripped, "id") {
                node.id = Some(id);
            }
            if let Some(name) = extract_quoted_after_word(&comment_stripped, "objectName") {
                node.object_name = Some(name);
            }
        }

        for ch in scrubbed.chars() {
            match ch {
                '{' => {
                    if consume_one_open {
                        consume_one_open = false;
                    } else {
                        depth += 1;
                    }
                }
                '}' => {
                    depth -= 1;
                    while let Some(&(_, d)) = stack.last() {
                        if d > depth {
                            let (node, _) = stack.pop().unwrap();
                            if node.component_name.is_some() {
                                // A `component Name: Type { ... }` decl —
                                // never attached to a parent's `children`;
                                // returned separately for registration.
                                inline_components.push(node);
                                continue;
                            }
                            match stack.last_mut() {
                                Some((parent, _)) => parent.children.push(node),
                                None => roots.push(node),
                            }
                        } else {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Defensive only (malformed/truncated input): flush anything still open
    // at EOF rather than silently dropping it (a `component_name` frame is
    // still routed to `inline_components`, same as a clean close).
    while let Some((node, _)) = stack.pop() {
        if node.component_name.is_some() {
            inline_components.push(node);
            continue;
        }
        match stack.last_mut() {
            Some((parent, _)) => parent.children.push(node),
            None => roots.push(node),
        }
    }

    (roots, inline_components)
}

// ─────────────────────────── qs ipc + polling ───────────────────────────

/// `qs -p <root>/run/qml/WidgetPreview.qml ipc call preview <function>
/// <args...>` — see this file's own module doc for the argv shape and the
/// stdout-carries-failures note. `Ok` carries stdout (trimmed) on success;
/// `Err` carries a joined stdout+stderr tail, never empty.
fn qs_ipc_call(root: &Path, function: &str, args: &[&str]) -> Result<String, String> {
    let qml = root.join("run").join("qml").join("WidgetPreview.qml");
    let out = Command::new("qs")
        .arg("-p")
        .arg(&qml)
        .args(["ipc", "call", "preview", function])
        .args(args)
        .output()
        .map_err(|e| format!("spawning qs: {e}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr = stderr.trim();
    let mut tail = stdout;
    if !stderr.is_empty() {
        if !tail.is_empty() {
            tail.push_str("; ");
        }
        tail.push_str(stderr);
    }
    if tail.is_empty() {
        tail = format!("qs exited {:?} with no message", out.status.code());
    }
    Err(tail)
}

fn poll_for_file(path: &Path, timeout: Duration, interval: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "{} never appeared (or stayed empty) within {timeout:?}",
                path.display()
            ));
        }
        std::thread::sleep(interval);
    }
}

/// Poll for `shot`'s own success/failure pair (this file's module doc):
/// success writes `out` (non-empty, same test as [`poll_for_file`]);
/// failure writes `error_path` (plain text) and no `out` at all. Returns
/// `error_path`'s own text as `Err` the moment it appears; a plain timeout
/// message when NEITHER appears in time.
fn poll_for_shot(
    out: &Path,
    error_path: &Path,
    timeout: Duration,
    interval: Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if error_path.is_file() {
            let text = std::fs::read_to_string(error_path)
                .unwrap_or_else(|e| format!("reading {}: {e}", error_path.display()));
            return Err(text.trim().to_string());
        }
        if std::fs::metadata(out).map(|m| m.len() > 0).unwrap_or(false) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "neither {} nor {} appeared within {timeout:?}",
                out.display(),
                error_path.display()
            ));
        }
        std::thread::sleep(interval);
    }
}

// ─────────────────────────── `preview notes` ───────────────────────────

fn empty_notes_doc() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("schemaVersion".to_string(), json!(NOTES_SCHEMA_VERSION));
    m.insert("notes".to_string(), json!([]));
    m
}

fn read_notes(path: &Path) -> Map<String, Value> {
    match std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    {
        Some(Value::Object(m)) => m,
        _ => empty_notes_doc(),
    }
}

fn write_notes(path: &Path, doc: &Map<String, Value>) -> Result<(), String> {
    let pretty = serde_json::to_string_pretty(&Value::Object(doc.clone()))
        .map_err(|e| e.to_string())?
        + "\n";
    aoide_storage::fs::atomic_write(path, &pretty)
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

fn parse_rect(s: &str) -> Option<(f64, f64, f64, f64)> {
    let parts: Vec<&str> = s.split(',').map(str::trim).collect();
    if parts.len() != 4 {
        return None;
    }
    let mut nums = [0.0f64; 4];
    for (i, p) in parts.iter().enumerate() {
        nums[i] = p.parse().ok()?;
    }
    Some((nums[0], nums[1], nums[2], nums[3]))
}

fn handle_preview_notes(inv: &Invocation) -> Outcome {
    let cmd = "preview.notes";
    let root = match super::preview::resolve_root(inv.flags.get("root").map(String::as_str)) {
        Ok(r) => r,
        Err(e) => return Outcome::usage(cmd, e),
    };
    let notes_path = root.join("notes.json");

    if inv.flag_present("clear") {
        // Reads the EXISTING doc first and only overwrites `notes` --
        // review item 2: building a fresh `empty_notes_doc()` here dropped
        // any unknown top-level key the file happened to carry.
        let mut doc = read_notes(&notes_path);
        doc.insert("notes".to_string(), json!([]));
        doc.entry("schemaVersion".to_string())
            .or_insert_with(|| json!(NOTES_SCHEMA_VERSION));
        if let Err(e) = write_notes(&notes_path, &doc) {
            return Outcome::error(cmd, e);
        }
        return Outcome::ok(cmd, "notes cleared")
            .with_data(json!({"notes": []}))
            .changed(vec![notes_path.to_string_lossy().into_owned()]);
    }

    if let Some(done_s) = inv.flags.get("done") {
        let Ok(n) = done_s.parse::<u64>() else {
            return Outcome::usage(cmd, format!("--done `{done_s}` is not a whole number"));
        };
        let mut doc = read_notes(&notes_path);
        let found = doc
            .get_mut("notes")
            .and_then(Value::as_array_mut)
            .and_then(|arr| {
                arr.iter_mut()
                    .find(|note| note.get("n").and_then(Value::as_u64) == Some(n))
            });
        let Some(note) = found else {
            return Outcome::error(cmd, format!("no note #{n} at {}", notes_path.display()));
        };
        note["done"] = json!(true);
        if let Err(e) = write_notes(&notes_path, &doc) {
            return Outcome::error(cmd, e);
        }
        return Outcome::ok(cmd, format!("note #{n} marked done"))
            .with_data(Value::Object(doc))
            .changed(vec![notes_path.to_string_lossy().into_owned()]);
    }

    if inv.flag_present("add") {
        let Some(text) = inv.flags.get("text") else {
            return Outcome::usage(cmd, "--add requires --text");
        };
        let rect_flag = inv.flags.get("rect");
        let element_flag = inv.flags.get("element");
        if rect_flag.is_some() && element_flag.is_some() {
            return Outcome::usage(cmd, "--rect and --element are mutually exclusive");
        }
        let shape = match inv.flags.get("shape") {
            None => None,
            Some(s) => match s.as_str() {
                "rect" | "ellipse" | "arrow" | "line" => Some(s.clone()),
                other => {
                    return Outcome::usage(
                        cmd,
                        format!("--shape `{other}` is not one of: rect, ellipse, arrow, line"),
                    )
                }
            },
        };
        let rect = match rect_flag {
            None => None,
            Some(r) => match parse_rect(r) {
                Some((x, y, w, h)) => Some(json!({"x": x, "y": y, "w": w, "h": h})),
                None => return Outcome::usage(cmd, format!("--rect `{r}` is not `x,y,w,h`")),
            },
        };
        let kind = if element_flag.is_some() {
            "highlight"
        } else if shape.is_some() {
            "shape"
        } else {
            "note"
        };

        let mut doc = read_notes(&notes_path);
        let next_n = doc
            .get("notes")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|n| n.get("n").and_then(Value::as_u64))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
            + 1;

        let mut entry = Map::new();
        entry.insert("n".to_string(), json!(next_n));
        entry.insert("kind".to_string(), json!(kind));
        if let Some(s) = &shape {
            entry.insert("shape".to_string(), json!(s));
        }
        if let Some(r) = &rect {
            entry.insert("rect".to_string(), r.clone());
        }
        if let Some(e) = element_flag {
            entry.insert("element".to_string(), json!(e));
        }
        entry.insert("text".to_string(), json!(text));
        entry.insert(
            "createdAt".to_string(),
            json!(aoide_storage::time::now_iso_utc()),
        );
        entry.insert("done".to_string(), json!(false));

        // Normalise `notes` to `[]` first when it exists but isn't a JSON
        // array (a hand-edited or corrupt notes.json) -- review item 1,
        // this used to `.expect()` straight through and panic.
        if !doc.get("notes").is_some_and(Value::is_array) {
            doc.insert("notes".to_string(), json!([]));
        }
        doc.get_mut("notes")
            .and_then(Value::as_array_mut)
            .expect("just normalised to an array above")
            .push(Value::Object(entry));
        doc.entry("schemaVersion".to_string())
            .or_insert_with(|| json!(NOTES_SCHEMA_VERSION));

        if let Err(e) = write_notes(&notes_path, &doc) {
            return Outcome::error(cmd, e);
        }
        return Outcome::ok(cmd, format!("note #{next_n} added"))
            .with_data(Value::Object(doc))
            .changed(vec![notes_path.to_string_lossy().into_owned()]);
    }

    // ── default: read, resolving element -> source when the canvas is up ──
    let doc = read_notes(&notes_path);
    let notes: Vec<Value> = doc
        .get("notes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // The real failure reason (no preview at this root, canvas down,
    // malformed runtime dump, unreadable widget source) is now KEPT and
    // named in the fallback message below, rather than discarded via
    // `.ok()` into one fixed generic string (review item 6c).
    let control = super::preview::read_control(&root.join("preview.json"));
    let joined_result: Result<JoinedNode, String> = match &control {
        Some(c) => build_joined_tree(&root, c),
        None => Err(format!(
            "no preview at {} -- run `lyra preview --no-launch` first",
            root.display()
        )),
    };
    let joined = joined_result.as_ref().ok();

    let mut resolved_notes = Vec::with_capacity(notes.len());
    let mut lines = Vec::with_capacity(notes.len());
    for note in &notes {
        let mut note_obj = note.as_object().cloned().unwrap_or_default();
        let target = match (note.get("element").and_then(Value::as_str), joined) {
            (Some(elem), Some(tree)) => resolve_element_path(tree, elem),
            _ => None,
        };
        if let Some(t) = target {
            if let Some(src) = &t.source {
                note_obj.insert("source".to_string(), json!(src));
            }
        }
        lines.push(render_note_line(&note_obj, target));
        resolved_notes.push(Value::Object(note_obj));
    }

    let mut message = if lines.is_empty() {
        "no notes".to_string()
    } else {
        lines.join("\n")
    };
    if let Err(e) = &joined_result {
        message.push_str(&format!("\n(element sources unresolved -- {e})"));
    }

    Outcome::ok(cmd, message).with_data(json!({"notes": resolved_notes}))
}

/// `#n [kind] Type#obj (file:line) — text`, done ones prefixed `\u{2713}`
/// and dimmed (ANSI SGR "faint") — the brief's own human line, one per
/// note. `target` is the resolved joined node (when the canvas was up and
/// the note names an `element`); a `rect`-anchored note with no resolvable
/// element falls back to printing its own rect instead of a type/name.
fn render_note_line(note: &Map<String, Value>, target: Option<&JoinedNode>) -> String {
    let n = note.get("n").and_then(Value::as_u64).unwrap_or(0);
    let kind = note.get("kind").and_then(Value::as_str).unwrap_or("note");
    let text = note.get("text").and_then(Value::as_str).unwrap_or("");
    let done = note.get("done").and_then(Value::as_bool).unwrap_or(false);

    let locator = if let Some(t) = target {
        let name = match &t.object_name {
            Some(o) => format!("{}#{o}", t.ty),
            None => t.ty.clone(),
        };
        match &t.source {
            Some(src) => format!("{name} ({src})"),
            None => name,
        }
    } else if let Some(rect) = note.get("rect") {
        format!(
            "rect {},{} {}\u{00d7}{}",
            rect.get("x").and_then(Value::as_f64).unwrap_or(0.0),
            rect.get("y").and_then(Value::as_f64).unwrap_or(0.0),
            rect.get("w").and_then(Value::as_f64).unwrap_or(0.0),
            rect.get("h").and_then(Value::as_f64).unwrap_or(0.0),
        )
    } else {
        String::new()
    };

    let prefix = if done { "\u{2713} " } else { "" };
    let line = if locator.is_empty() {
        format!("{prefix}#{n} [{kind}] \u{2014} {text}")
    } else {
        format!("{prefix}#{n} [{kind}] {locator} \u{2014} {text}")
    };
    if done {
        format!("\x1b[2m{line}\x1b[0m")
    } else {
        line
    }
}

// ─────────────────────────── tests ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide_lyra_preview_tools_test_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn inv_path(path: &[&str], flags: &[(&str, &str)]) -> Invocation {
        let mut m = BTreeMap::new();
        for (k, v) in flags {
            m.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: vec![],
            flags: m,
            door: aoide_protocol::Door::Cli,
        }
    }
    fn inv_shot(flags: &[(&str, &str)]) -> Invocation {
        inv_path(&["preview", "shot"], flags)
    }
    fn inv_notes(flags: &[(&str, &str)]) -> Invocation {
        inv_path(&["preview", "notes"], flags)
    }
    fn inv_tree(flags: &[(&str, &str)]) -> Invocation {
        inv_path(&["preview", "tree"], flags)
    }

    fn write_fake_qs(dir: &Path, script: &str) {
        let path = dir.join("qs");
        std::fs::write(&path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    /// PREPENDS `dir` (the fake `qs` binary's own directory) onto the REAL
    /// `PATH` -- unlike most fixtures here, whose fake `qs` script is pure
    /// shell builtins (`printf`, redirects) and so can get away with
    /// replacing `PATH` outright, a script that also shells `cp` (to serve
    /// a synthetic fixture file) needs `cp` itself still resolvable too,
    /// or it exits 127 with nothing written and no error text -- a fake
    /// binary standing in for the ONE thing under test (`qs`) must not
    /// also swallow every OTHER external command the fixture script needs.
    fn set_path_with_fake_bin_first(dir: &Path) {
        let mut new_path = std::ffi::OsString::from(dir.as_os_str());
        if let Some(existing) = std::env::var_os("PATH") {
            new_path.push(":");
            new_path.push(existing);
        }
        std::env::set_var("PATH", new_path);
    }

    // ── shot: usage errors, reachable with no preview root at all ────────

    #[test]
    fn shot_rejects_an_unknown_what() {
        let out = handle_preview_shot(&inv_shot(&[("what", "nonsense")]));
        assert_eq!(out.status, Status::Usage, "{:?}", out.message);
    }

    #[test]
    fn shot_element_without_the_element_flag_is_a_usage_error() {
        let out = handle_preview_shot(&inv_shot(&[("what", "element")]));
        assert_eq!(out.status, Status::Usage, "{:?}", out.message);
        assert!(out.message.contains("--element"), "{}", out.message);
    }

    #[test]
    fn shot_element_with_a_non_element_what_is_a_usage_error() {
        // Review item 6b: only the reverse direction (`--what element`
        // requiring `--element`) used to be enforced.
        let out = handle_preview_shot(&inv_shot(&[("what", "widget"), ("element", "Item[0]")]));
        assert_eq!(out.status, Status::Usage, "{:?}", out.message);
        assert!(out.message.contains("--element"), "{}", out.message);
    }

    /// The minimal `preview.json` [`super::super::preview::read_control`]
    /// will accept -- just enough for `handle_preview_shot`'s "does a
    /// preview exist at this root" gate to pass, so a test can reach
    /// whatever check comes after it without a real `lyra preview` build.
    fn write_minimal_control(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            root.join("preview.json"),
            r#"{"widget":"songs/sonata/conductor.qml","song":"sonata"}"#,
        )
        .unwrap();
    }

    #[test]
    fn shot_without_a_preview_root_is_a_clean_error() {
        let root = scratch("shot_no_root");
        let out = handle_preview_shot(&inv_shot(&[("root", root.to_str().unwrap())]));
        assert_eq!(out.status, Status::Error);
        assert!(out.message.contains("no preview at"), "{}", out.message);
    }

    // ── shot: pure sidecar helpers ─────────────────────────────────────

    #[test]
    fn default_shot_out_matches_the_brief_naming_with_pid_and_seq_disambiguation() {
        let root = PathBuf::from("/tmp/root");
        assert_eq!(
            default_shot_out(&root, "widget", "20260912T000000Z", 4242, 7),
            root.join("shots/widget-20260912T000000Z-4242-7.png")
        );
    }

    #[test]
    fn next_auto_name_seq_is_monotonic() {
        let a = next_auto_name_seq();
        let b = next_auto_name_seq();
        assert!(b > a);
    }

    #[test]
    fn merge_canvas_meta_merges_scale_only_and_deletes_the_file() {
        // The canvas's own meta.json is `{widgetRect, scale}` ONLY now
        // (contract update landed after `elementRect` was ever real) --
        // an `elementRect` key in the file, if one somehow appeared, must
        // NOT be merged in: our own sidecar's `elementRect` comes solely
        // from our own crop (item 9), never from the canvas.
        let base = scratch("merge_meta");
        let meta_path = base.join("out.meta.json");
        std::fs::write(&meta_path, r#"{"widgetRect":{"x":0,"y":0,"w":10,"h":10},"scale":0.5,"elementRect":{"x":1,"y":2,"w":3,"h":4}}"#).unwrap();
        let mut sidecar = Map::new();
        merge_canvas_meta(&mut sidecar, &meta_path);
        assert_eq!(sidecar.get("scale"), Some(&json!(0.5)));
        assert!(
            sidecar.get("elementRect").is_none(),
            "elementRect is never read from the canvas's own meta file"
        );
        assert!(
            sidecar.get("widgetRect").is_none(),
            "widgetRect has no home in this sidecar's own schema"
        );
        assert!(!meta_path.exists());
    }

    #[test]
    fn merge_canvas_meta_is_a_silent_no_op_when_the_file_is_absent() {
        let base = scratch("merge_meta_absent");
        let mut sidecar = Map::new();
        merge_canvas_meta(&mut sidecar, &base.join("nope.meta.json"));
        assert!(sidecar.is_empty());
    }

    // ── fold_screen_sidecar: review item 3 (orphan file, never a real
    // collision -- a different path than ours) ──────────────────────────

    #[test]
    fn fold_screen_sidecar_embeds_their_sidecar_and_deletes_the_orphan() {
        let base = scratch("fold_screen_sidecar");
        let out = base.join("out.png");
        std::fs::write(&out, b"PNGDATA").unwrap();
        // `aoide_screen::capture::shot`'s own convention: `with_extension`,
        // never `append_suffix` -- a DIFFERENT path from ours.
        let their_sidecar = out.with_extension("json");
        std::fs::write(&their_sidecar, r#"{"format":"png","scale":1.0}"#).unwrap();

        let mut sidecar = Map::new();
        fold_screen_sidecar(&mut sidecar, &out);

        assert_eq!(sidecar["capture"]["format"], "png");
        assert!(
            !their_sidecar.exists(),
            "the orphan must be deleted once folded in"
        );
    }

    #[test]
    fn fold_screen_sidecar_is_a_silent_no_op_when_their_sidecar_is_absent() {
        let base = scratch("fold_screen_sidecar_absent");
        let out = base.join("out.png");
        let mut sidecar = Map::new();
        fold_screen_sidecar(&mut sidecar, &out);
        assert!(sidecar.is_empty());
    }

    // ── clamp_crop: review item 9's own required coverage ───────────────

    #[test]
    fn clamp_crop_scales_and_crops_a_normal_rect() {
        assert_eq!(
            clamp_crop((10.0, 20.0, 30.0, 40.0), 2.0, 1000, 1000),
            Some((20, 40, 60, 80))
        );
    }

    #[test]
    fn clamp_crop_clamps_a_rect_hanging_off_the_far_edge() {
        // Rect at scale 1 would span x in [90, 130), but the image is only
        // 100px wide -- the crop must stop at the image's own edge.
        assert_eq!(
            clamp_crop((90.0, 0.0, 40.0, 10.0), 1.0, 100, 100),
            Some((90, 0, 10, 10))
        );
    }

    #[test]
    fn clamp_crop_clamps_a_negative_origin_to_zero() {
        assert_eq!(
            clamp_crop((-10.0, -5.0, 30.0, 20.0), 1.0, 100, 100),
            Some((0, 0, 20, 15))
        );
    }

    #[test]
    fn clamp_crop_is_none_for_a_rect_entirely_off_the_image() {
        assert!(clamp_crop((200.0, 200.0, 10.0, 10.0), 1.0, 100, 100).is_none());
    }

    #[test]
    fn clamp_crop_is_none_for_a_zero_area_rect() {
        assert!(clamp_crop((10.0, 10.0, 0.0, 0.0), 1.0, 100, 100).is_none());
    }

    // ── qs ipc: fake `qs` on PATH (never the real canvas -- module doc) ──

    #[test]
    fn qs_ipc_call_surfaces_the_stdout_tail_on_failure() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let dir = scratch("qs_down");
        write_fake_qs(
            &dir,
            "#!/bin/sh\necho 'No running instances for \"x\"'\nexit 255\n",
        );
        std::env::set_var("PATH", &dir);

        let err =
            qs_ipc_call(Path::new("/tmp/whatever-root"), "tree", &["/tmp/out.json"]).unwrap_err();
        assert!(err.contains("No running instances"), "{err}");

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn qs_ipc_call_returns_stdout_on_success() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let dir = scratch("qs_up");
        write_fake_qs(&dir, "#!/bin/sh\necho ok\nexit 0\n");
        std::env::set_var("PATH", &dir);

        let out = qs_ipc_call(Path::new("/tmp/whatever-root"), "tree", &["/tmp/out.json"]).unwrap();
        assert_eq!(out, "ok");

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    // ── shot: widget kind end-to-end, against P7's real file-naming
    // convention (literal-append, `.error` on failure) ───────────────────

    #[test]
    fn shot_widget_success_merges_meta_via_the_literal_append_path() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("shot_widget_ok");
        write_minimal_control(&root);
        let dir = scratch("shot_widget_ok_bin");
        write_fake_qs(
            &dir,
            r#"#!/bin/sh
out="$9"
printf 'PNGDATA' > "$out"
printf '{"widgetRect":{"x":0,"y":0,"w":360,"h":520},"scale":0.5}' > "$out.meta.json"
exit 0
"#,
        );
        std::env::set_var("PATH", &dir);

        let out_path = root.join("shot.png");
        let outcome = handle_preview_shot(&inv_shot(&[
            ("root", root.to_str().unwrap()),
            ("what", "widget"),
            ("out", out_path.to_str().unwrap()),
        ]));
        assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.message);

        // The image itself lands untouched at the literal `--out` path...
        assert_eq!(std::fs::read_to_string(&out_path).unwrap(), "PNGDATA");
        // ...the sidecar is `<out>` with `.json` LITERALLY APPENDED (never
        // `with_extension`, which would replace `.png` and land at
        // `shot.json` instead of the real `shot.png.json`)...
        let sidecar_path = append_suffix(&out_path, "json");
        assert!(sidecar_path.exists(), "{}", sidecar_path.display());
        let sidecar: Value =
            serde_json::from_str(&std::fs::read_to_string(&sidecar_path).unwrap()).unwrap();
        assert_eq!(sidecar["scale"], 0.5);
        // ...and the canvas's own `<out>.meta.json` was consumed and deleted.
        assert!(!append_suffix(&out_path, "meta.json").exists());

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn shot_widget_failure_surfaces_the_dot_error_files_own_text() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("shot_widget_err");
        write_minimal_control(&root);
        let dir = scratch("shot_widget_err_bin");
        write_fake_qs(
            &dir,
            r#"#!/bin/sh
out="$9"
printf 'element not found: Nope[9]' > "$out.error"
exit 0
"#,
        );
        std::env::set_var("PATH", &dir);

        let out_path = root.join("shot.png");
        let outcome = handle_preview_shot(&inv_shot(&[
            ("root", root.to_str().unwrap()),
            ("what", "widget"),
            ("out", out_path.to_str().unwrap()),
        ]));
        assert_eq!(outcome.status, Status::Error);
        assert!(
            outcome.message.contains("element not found: Nope[9]"),
            "{}",
            outcome.message
        );
        assert!(
            !out_path.exists(),
            "no image is ever written on a failed shot"
        );

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    // ── shot: `--what element` is a Rust-side crop, never a second ipc
    // "kind" (review item 9 -- the canvas's own element-kind ipc call is
    // permanently broken by design) ──────────────────────────────────────

    #[test]
    fn shot_what_element_always_calls_the_canvas_with_widget_never_element() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("shot_element_ipc_kind");
        write_minimal_control(&root);
        let dir = scratch("shot_element_ipc_kind_bin");
        write_fake_qs(
            &dir,
            r#"#!/bin/sh
if [ "$6" = "shot" ]; then
    if [ "$7" != "widget" ]; then
        printf 'ipc called with what=%s, expected widget' "$7" > "$9.error"
        exit 0
    fi
    out="$9"
    printf 'PNGDATA' > "$out"
    printf '{"widgetRect":{"x":0,"y":0,"w":10,"h":10},"scale":1.0}' > "$out.meta.json"
fi
exit 0
"#,
        );
        std::env::set_var("PATH", &dir);

        // No `--element` resolution reachable here (no `tree` branch in
        // the fake `qs` above) -- this test only proves the ipc "kind"
        // argument, so it uses `--what widget` (the element crop path is
        // covered end-to-end by the test below).
        let out_path = root.join("shot.png");
        let outcome = handle_preview_shot(&inv_shot(&[
            ("root", root.to_str().unwrap()),
            ("what", "widget"),
            ("out", out_path.to_str().unwrap()),
        ]));
        assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.message);

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn shot_what_element_crops_the_widget_capture_to_the_elements_live_rect() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("shot_element_crop");
        write_minimal_control(&root);

        // A real synthetic PNG (via the `image` crate, not a stub file) so
        // this test crosses the SAME decode/crop boundary a live capture
        // would -- and a hand-written runtime tree dump the fake `qs`
        // below serves for the `tree` ipc function, giving `--element
        // Rectangle[0]` a live rect to crop to.
        let fixtures = scratch("shot_element_crop_fixtures");
        let synth_png = fixtures.join("synthetic.png");
        image::RgbaImage::from_pixel(100, 100, image::Rgba([10, 20, 30, 255]))
            .save(&synth_png)
            .unwrap();
        let synth_tree = fixtures.join("tree.json");
        std::fs::write(
            &synth_tree,
            r#"{"type":"Item","objectName":"","path":"","rect":{"x":0,"y":0,"w":100,"h":100},"visible":true,"children":[{"type":"Rectangle","objectName":"","path":"Rectangle[0]","rect":{"x":10,"y":20,"w":30,"h":40},"visible":true,"children":[]}]}"#,
        )
        .unwrap();

        let dir = scratch("shot_element_crop_bin");
        write_fake_qs(
            &dir,
            &format!(
                r#"#!/bin/sh
case "$6" in
  shot)
    out="$9"
    cp '{png}' "$out"
    printf '{{"widgetRect":{{"x":0,"y":0,"w":100,"h":100}},"scale":1.0}}' > "$out.meta.json"
    ;;
  tree)
    out="$7"
    cp '{tree}' "$out"
    ;;
esac
exit 0
"#,
                png = synth_png.display(),
                tree = synth_tree.display(),
            ),
        );
        set_path_with_fake_bin_first(&dir);

        let out_path = root.join("element.png");
        let outcome = handle_preview_shot(&inv_shot(&[
            ("root", root.to_str().unwrap()),
            ("what", "element"),
            ("element", "Rectangle[0]"),
            ("out", out_path.to_str().unwrap()),
        ]));
        assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.message);

        let cropped = image::open(&out_path).unwrap();
        assert_eq!((cropped.width(), cropped.height()), (30, 40));

        let sidecar: Value = serde_json::from_str(
            &std::fs::read_to_string(append_suffix(&out_path, "json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            sidecar["elementRect"],
            json!({"x": 10, "y": 20, "w": 30, "h": 40})
        );

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn shot_what_element_is_an_error_when_the_element_path_is_unresolvable() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("shot_element_missing");
        write_minimal_control(&root);
        let fixtures = scratch("shot_element_missing_fixtures");
        let synth_png = fixtures.join("synthetic.png");
        image::RgbaImage::from_pixel(10, 10, image::Rgba([0, 0, 0, 255]))
            .save(&synth_png)
            .unwrap();
        let synth_tree = fixtures.join("tree.json");
        std::fs::write(&synth_tree, r#"{"type":"Item","objectName":"","path":"","rect":{"x":0,"y":0,"w":10,"h":10},"visible":true,"children":[]}"#).unwrap();

        let dir = scratch("shot_element_missing_bin");
        write_fake_qs(
            &dir,
            &format!(
                r#"#!/bin/sh
case "$6" in
  shot)
    out="$9"
    cp '{png}' "$out"
    printf '{{"widgetRect":{{"x":0,"y":0,"w":10,"h":10}},"scale":1.0}}' > "$out.meta.json"
    ;;
  tree)
    out="$7"
    cp '{tree}' "$out"
    ;;
esac
exit 0
"#,
                png = synth_png.display(),
                tree = synth_tree.display(),
            ),
        );
        set_path_with_fake_bin_first(&dir);

        let out_path = root.join("element.png");
        let outcome = handle_preview_shot(&inv_shot(&[
            ("root", root.to_str().unwrap()),
            ("what", "element"),
            ("element", "Rectangle[9]"),
            ("out", out_path.to_str().unwrap()),
        ]));
        assert_eq!(outcome.status, Status::Error);
        assert!(
            outcome.message.contains("element not found: Rectangle[9]"),
            "{}",
            outcome.message
        );

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    // ── tree ─────────────────────────────────────────────────────────────

    #[test]
    fn tree_validates_at_before_touching_the_canvas() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("tree_at_validation");
        write_minimal_control(&root);
        // An empty PATH -- no `qs` binary reachable at all, so if `--at`
        // validation happened AFTER `build_joined_tree`'s canvas
        // round-trip (review item 6a), this would surface as a canvas
        // `Error` (a failed `qs` spawn), never a `Usage` error.
        let empty_bin = scratch("tree_at_validation_bin");
        std::env::set_var("PATH", &empty_bin);

        let out = handle_preview_tree(&inv_tree(&[
            ("root", root.to_str().unwrap()),
            ("at", "not-a-point"),
        ]));
        assert_eq!(out.status, Status::Usage, "{:?}", out.message);

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn tree_dumps_the_joined_tree_and_at_returns_the_deepest_chain() {
        let _guard = aoide_test_support::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("PATH");
        let root = scratch("tree_dump");
        write_minimal_control(&root);
        let synth_tree = root.join("synthetic-tree.json");
        std::fs::write(
            &synth_tree,
            r#"{"type":"Item","objectName":"","path":"","rect":{"x":0,"y":0,"w":100,"h":100},"visible":true,"children":[{"type":"Rectangle","objectName":"box","path":"Rectangle[0]","rect":{"x":10,"y":10,"w":50,"h":50},"visible":true,"children":[]}]}"#,
        )
        .unwrap();
        let dir = scratch("tree_dump_bin");
        write_fake_qs(
            &dir,
            &format!(
                "#!/bin/sh\nout=\"$7\"\ncp '{}' \"$out\"\nexit 0\n",
                synth_tree.display()
            ),
        );
        set_path_with_fake_bin_first(&dir);

        let dump = handle_preview_tree(&inv_tree(&[("root", root.to_str().unwrap())]));
        assert_eq!(dump.status, Status::Ok, "{:?}", dump.message);
        assert!(dump.message.contains("Rectangle#box"), "{}", dump.message);

        let at = handle_preview_tree(&inv_tree(&[
            ("root", root.to_str().unwrap()),
            ("at", "20,20"),
        ]));
        assert_eq!(at.status, Status::Ok, "{:?}", at.message);
        let chain = at.data.unwrap()["chain"].as_array().unwrap().len();
        assert_eq!(chain, 2, "Item then Rectangle#box");

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    // ── polling ────────────────────────────────────────────────────────

    #[test]
    fn poll_for_file_succeeds_immediately_when_bytes_are_already_there() {
        let base = scratch("poll_ready");
        let f = base.join("f.png");
        std::fs::write(&f, b"x").unwrap();
        assert!(poll_for_file(&f, Duration::from_millis(50), Duration::from_millis(10)).is_ok());
    }

    #[test]
    fn poll_for_file_times_out_when_the_file_never_appears() {
        let base = scratch("poll_timeout");
        let f = base.join("never.png");
        let err =
            poll_for_file(&f, Duration::from_millis(30), Duration::from_millis(10)).unwrap_err();
        assert!(err.contains("never.png"), "{err}");
    }

    #[test]
    fn poll_for_shot_succeeds_when_only_the_output_file_appears() {
        let base = scratch("poll_shot_ok");
        let out = base.join("out.png");
        std::fs::write(&out, b"x").unwrap();
        let err_path = base.join("out.png.error");
        assert!(poll_for_shot(
            &out,
            &err_path,
            Duration::from_millis(50),
            Duration::from_millis(10)
        )
        .is_ok());
    }

    #[test]
    fn poll_for_shot_surfaces_the_error_files_text_and_never_the_missing_output() {
        let base = scratch("poll_shot_err");
        let out = base.join("out.png");
        let err_path = base.join("out.png.error");
        std::fs::write(&err_path, "element not found: Nope[9]\n").unwrap();
        let err = poll_for_shot(
            &out,
            &err_path,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .unwrap_err();
        assert_eq!(err, "element not found: Nope[9]");
    }

    #[test]
    fn poll_for_shot_times_out_when_neither_file_appears() {
        let base = scratch("poll_shot_timeout");
        let out = base.join("out.png");
        let err_path = base.join("out.png.error");
        let err = poll_for_shot(
            &out,
            &err_path,
            Duration::from_millis(30),
            Duration::from_millis(10),
        )
        .unwrap_err();
        assert!(err.contains("out.png"), "{err}");
    }

    // ── append_suffix: literal append, never `with_extension` ──────────

    #[test]
    fn append_suffix_appends_literally_rather_than_replacing_the_extension() {
        let out = PathBuf::from("/tmp/root/shots/widget-x.png");
        assert_eq!(
            append_suffix(&out, "json"),
            PathBuf::from("/tmp/root/shots/widget-x.png.json")
        );
        assert_eq!(
            append_suffix(&out, "meta.json"),
            PathBuf::from("/tmp/root/shots/widget-x.png.meta.json")
        );
        assert_eq!(
            append_suffix(&out, "error"),
            PathBuf::from("/tmp/root/shots/widget-x.png.error")
        );
    }

    // ── static parser ─────────────────────────────────────────────────

    const FIXTURE_QML: &str = "import QtQuick\nItem {\n    id: root\n    // a comment with a brace { that must not count\n    property string note: \"a string with a brace { inside\"\n    Rectangle {\n        id: box\n        objectName: \"highlightBox\"\n        color: \"red\" // trailing comment\n        MoodFaces.Face {\n            id: face\n        }\n    }\n    Rectangle {\n        width: 10\n    }\n}\n";

    #[test]
    fn static_parser_builds_the_nested_tree_with_ids_object_names_dotted_types_and_lines() {
        let (roots, inline) = parse_static_qml(FIXTURE_QML);
        assert!(
            inline.is_empty(),
            "no inline `component` declarations in this fixture"
        );
        assert_eq!(roots.len(), 1);
        let root = &roots[0];
        assert_eq!(root.ty, "Item");
        assert_eq!(root.id.as_deref(), Some("root"));
        assert_eq!(root.line, 2);
        assert_eq!(root.children.len(), 2);

        let boxed = &root.children[0];
        assert_eq!(boxed.ty, "Rectangle");
        assert_eq!(boxed.id.as_deref(), Some("box"));
        assert_eq!(boxed.object_name.as_deref(), Some("highlightBox"));
        assert_eq!(boxed.line, 6);
        assert_eq!(boxed.children.len(), 1);
        assert_eq!(
            boxed.children[0].ty, "Face",
            "MoodFaces.Face strips to its last segment"
        );
        assert_eq!(boxed.children[0].id.as_deref(), Some("face"));

        let second_rect = &root.children[1];
        assert_eq!(second_rect.ty, "Rectangle");
        assert!(second_rect.id.is_none());
    }

    #[test]
    fn strip_comments_and_strings_blanks_braces_inside_both() {
        let scrubbed =
            strip_comments_and_strings("property string s: \"a { brace\" // and a { comment brace");
        assert!(!scrubbed.contains('{'), "{scrubbed}");
    }

    // ── runtime parse ────────────────────────────────────────────────

    #[test]
    fn parse_runtime_node_reads_the_canvas_shape() {
        let v: Value = serde_json::from_str(
            r#"{"type":"Rectangle","objectName":"box","path":"Rectangle[0]","rect":{"x":1,"y":2,"w":3,"h":4},"visible":true,"text":"hi","children":[]}"#,
        )
        .unwrap();
        let n = parse_runtime_node(&v).unwrap();
        assert_eq!(n.ty, "Rectangle");
        assert_eq!(n.object_name, "box");
        assert_eq!(n.path, "Rectangle[0]");
        assert_eq!(n.rect, (1.0, 2.0, 3.0, 4.0));
        assert_eq!(n.text.as_deref(), Some("hi"));
    }

    #[test]
    fn resolve_element_path_matches_a_real_p7_evidence_subtree_verbatim() {
        // A real subtree from a live P7 `preview tree` dump
        // (/tmp/aoide-widget-team/preview/evidence/p7-tree.json), pruned to
        // three levels but otherwise byte-identical -- not a hand-typed
        // fixture. Proves `path` round-trips exactly and that lookup needs
        // no Type[i] re-derivation on real canvas output.
        const REAL_SUBTREE: &str = r#"{"type":"Loader","objectName":"","path":"Loader[0]","rect":{"x":0,"y":0,"w":360,"h":520},"visible":true,"children":[{"type":"SessionMenu","objectName":"","path":"Loader[0]/SessionMenu[0]","rect":{"x":0,"y":0,"w":360,"h":520},"visible":false,"children":[{"type":"TextEdit","objectName":"","path":"Loader[0]/SessionMenu[0]/TextEdit[0]","rect":{"x":0,"y":0,"w":0,"h":22},"visible":false,"text":""},{"type":"MouseArea","objectName":"","path":"Loader[0]/SessionMenu[0]/MouseArea[0]","rect":{"x":0,"y":0,"w":360,"h":520},"visible":false},{"type":"Rectangle","objectName":"","path":"Loader[0]/SessionMenu[0]/Rectangle[0]","rect":{"x":5,"y":5,"w":292,"h":86},"visible":false}]}]}"#;
        let v: Value = serde_json::from_str(REAL_SUBTREE).unwrap();
        let runtime = parse_runtime_node(&v).unwrap();
        let joined = join_level(
            std::slice::from_ref(&runtime),
            None,
            Path::new("dummy.qml"),
            &ComponentMap::new(),
            None,
        );
        let root = &joined[0];

        let text_edit = resolve_element_path(root, "Loader[0]/SessionMenu[0]/TextEdit[0]").unwrap();
        assert_eq!(text_edit.ty, "TextEdit");
        assert_eq!(text_edit.text.as_deref(), Some(""));
        assert!(!text_edit.visible);

        let rect = resolve_element_path(root, "Loader[0]/SessionMenu[0]/Rectangle[0]").unwrap();
        assert_eq!(rect.rect, (5.0, 5.0, 292.0, 86.0));

        assert!(resolve_element_path(root, "Loader[0]/SessionMenu[0]/Nope[9]").is_none());
    }

    // ── join ─────────────────────────────────────────────────────────

    fn rt(
        ty: &str,
        object_name: &str,
        path: &str,
        rect: (f64, f64, f64, f64),
        children: Vec<RuntimeNode>,
    ) -> RuntimeNode {
        RuntimeNode {
            ty: ty.to_string(),
            object_name: object_name.to_string(),
            path: path.to_string(),
            rect,
            visible: true,
            text: None,
            children,
        }
    }
    fn st(
        ty: &str,
        id: Option<&str>,
        object_name: Option<&str>,
        line: usize,
        children: Vec<StaticNode>,
    ) -> StaticNode {
        StaticNode {
            ty: ty.to_string(),
            id: id.map(String::from),
            object_name: object_name.map(String::from),
            line,
            children,
            component_name: None,
            binding: None,
        }
    }
    /// A `<binding>: Type { ... }`-opened node (review follow-up part B1),
    /// e.g. a `Repeater`'s own `delegate: Column { id: m }`.
    fn st_bound(
        ty: &str,
        binding: &str,
        id: Option<&str>,
        line: usize,
        children: Vec<StaticNode>,
    ) -> StaticNode {
        StaticNode {
            ty: ty.to_string(),
            id: id.map(String::from),
            object_name: None,
            line,
            children,
            component_name: None,
            binding: Some(binding.to_string()),
        }
    }

    #[test]
    fn join_matches_by_object_name_first_even_out_of_order() {
        let runtime = vec![rt(
            "Rectangle",
            "box",
            "Rectangle[0]",
            (0.0, 0.0, 10.0, 10.0),
            vec![],
        )];
        let statics = vec![
            st("Rectangle", Some("otherId"), None, 5, vec![]),
            st("Rectangle", Some("boxId"), Some("box"), 9, vec![]),
        ];
        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("w.qml"),
            &ComponentMap::new(),
            None,
        );
        assert_eq!(joined[0].match_kind, "objectName");
        assert_eq!(joined[0].id.as_deref(), Some("boxId"));
        assert_eq!(joined[0].source.as_deref(), Some("w.qml:9"));
        assert_eq!(
            joined[0].path, "Rectangle[0]",
            "the canvas's own path is carried through the join untouched"
        );
    }

    #[test]
    fn join_falls_back_to_positional_among_same_type_siblings() {
        let runtime = vec![
            rt(
                "Rectangle",
                "",
                "Rectangle[0]",
                (0.0, 0.0, 1.0, 1.0),
                vec![],
            ),
            rt(
                "Rectangle",
                "",
                "Rectangle[1]",
                (0.0, 0.0, 1.0, 1.0),
                vec![],
            ),
        ];
        let statics = vec![
            st("Rectangle", Some("first"), None, 3, vec![]),
            st("Rectangle", Some("second"), None, 4, vec![]),
        ];
        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("w.qml"),
            &ComponentMap::new(),
            None,
        );
        assert_eq!(joined[0].id.as_deref(), Some("first"));
        assert_eq!(joined[0].match_kind, "positional");
        assert_eq!(joined[1].id.as_deref(), Some("second"));
    }

    #[test]
    fn join_is_wrapper_when_no_static_sibling_of_that_type_exists_at_all() {
        // Updated for review follow-up part B: a runtime type with ZERO
        // static siblings of ITS OWN type at this level (not merely "all
        // already claimed") is no longer assumed to be a genuine mismatch
        // -- it may be a framework-synthesized container standing in for
        // the widget's real declared content one runtime hop early
        // (`Flickable`'s `contentItem`, etc.), so it reads `"wrapper"`,
        // not `"none"` (see the next test for what that unlocks for ITS
        // children, and `wrapper_pass_through_does_not_apply_when_a_real_
        // static_sibling_of_that_type_exists` for the genuine-mismatch
        // case this does NOT cover).
        let runtime = vec![rt("Text", "", "Text[0]", (0.0, 0.0, 1.0, 1.0), vec![])];
        let statics = vec![st("Rectangle", None, None, 3, vec![])];
        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("w.qml"),
            &ComponentMap::new(),
            None,
        );
        assert_eq!(joined[0].match_kind, "wrapper");
        assert!(
            joined[0].source.is_none(),
            "no parent source was supplied to this top-level call"
        );
    }

    #[test]
    fn join_wrapper_hands_its_own_children_the_same_statics_it_failed_on() {
        // Updated for part B: `Text` (zero static siblings of type "Text"
        // here) is a `"wrapper"`, and its child `Rectangle` now gets a
        // real chance to match against the SAME static list `Text` itself
        // failed on -- succeeding, since a static `Rectangle` genuinely
        // exists at that level. Bare-type version of the exact shape a
        // real `Flickable -> (synthetic Item) -> Column` join needs (see
        // `wrapper_pass_through_resolves_a_column_hidden_behind_a_
        // synthetic_contentitem` for that realistic naming).
        let runtime = vec![rt(
            "Text",
            "",
            "Text[0]",
            (0.0, 0.0, 1.0, 1.0),
            vec![rt(
                "Rectangle",
                "",
                "Text[0]/Rectangle[0]",
                (0.0, 0.0, 1.0, 1.0),
                vec![],
            )],
        )];
        let statics = vec![st("Rectangle", Some("would-be"), None, 1, vec![])];
        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("w.qml"),
            &ComponentMap::new(),
            None,
        );
        assert_eq!(joined[0].match_kind, "wrapper");
        assert_eq!(joined[0].children[0].match_kind, "positional");
        assert_eq!(joined[0].children[0].id.as_deref(), Some("would-be"));
    }

    #[test]
    fn wrapper_pass_through_does_not_apply_when_a_real_static_sibling_of_that_type_exists() {
        // The excluded case named alongside part B's rule: a static
        // sibling of the SAME type genuinely exists at this level (here,
        // already claimed by an earlier same-type sibling) -- that is a
        // real mismatch (an extra instance the static side never
        // declared), not a synthetic wrapper, so it stays "none" and does
        // NOT hand statics down to its own children.
        let statics = vec![st(
            "Item",
            None,
            None,
            1,
            vec![st("Text", None, None, 2, vec![])],
        )];
        let runtime = vec![
            rt("Item", "", "Item[0]", (0.0, 0.0, 1.0, 1.0), vec![]),
            rt(
                "Item",
                "",
                "Item[1]",
                (0.0, 0.0, 1.0, 1.0),
                vec![rt(
                    "Text",
                    "",
                    "Item[1]/Text[0]",
                    (0.0, 0.0, 1.0, 1.0),
                    vec![],
                )],
            ),
        ];
        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("w.qml"),
            &ComponentMap::new(),
            None,
        );
        assert_eq!(
            joined[0].match_kind, "positional",
            "claims the one declared static Item"
        );
        assert_eq!(
            joined[1].match_kind, "none",
            "a static Item sibling exists (already claimed) -- genuine mismatch"
        );
        assert_eq!(
            joined[1].children[0].match_kind, "none",
            "\"none\" does not hand statics down, unlike \"wrapper\""
        );
    }

    #[test]
    fn wrapper_pass_through_resolves_a_column_hidden_behind_a_synthetic_contentitem() {
        // The concrete real-world shape review follow-up part B exists
        // for: `Flickable { Column { ... } }` in QML, but at RUNTIME
        // `Flickable` synthesizes its own `contentItem` -- reported here
        // as a bare `Item` with no static counterpart -- between itself
        // and its real declared `Column`. `statics` stands in for
        // Flickable's own already-matched static children list (as if
        // this call were already one level inside a matched Flickable).
        let flickable_children = vec![st("Column", None, None, 2, vec![])];
        let runtime = vec![rt(
            "Item",
            "",
            "Flickable[0]/Item[0]",
            (0.0, 0.0, 10.0, 10.0),
            vec![rt(
                "Column",
                "",
                "Flickable[0]/Item[0]/Column[0]",
                (0.0, 0.0, 10.0, 10.0),
                vec![],
            )],
        )];
        let joined = join_level(
            &runtime,
            Some(&flickable_children),
            Path::new("w.qml"),
            &ComponentMap::new(),
            Some("w.qml:1"),
        );
        let item = &joined[0];
        assert_eq!(
            item.match_kind, "wrapper",
            "Item has zero static siblings of type Item at this level"
        );
        assert_eq!(
            item.source.as_deref(),
            Some("w.qml:1"),
            "wrapper inherits its PARENT's source, not its own (it has none)"
        );
        let column = &item.children[0];
        assert_eq!(
            column.match_kind, "positional",
            "joined against the SAME static sibling list the wrapper itself failed on"
        );
        assert_eq!(column.source.as_deref(), Some("w.qml:2"));
    }

    // ── cross-file component join (review item 7: a `Loader`-nested widget
    // whose visible body lives in OTHER files must not read back "none"
    // for its entire subtree) ────────────────────────────────────────────

    // The reviewer's own suggested fixture: a `Loader { sourceComponent }`
    // is hard to fake statically, so this uses a plain component instead
    // -- `root.qml` declaring `Card {}`, `Card.qml` declaring the actual
    // `Rectangle { objectName: "body" }` with a `Text {}` child, so the
    // fixture exercises a component that HAS something below its own root
    // (a live run confirmed the runtime reports the component-typed node
    // itself AS the root object, not a wrapper around it -- see the next
    // test's own note).
    const ROOT_QML_FOR_COMPONENT_JOIN: &str = "Item {\n    Card {}\n}\n";
    const CARD_QML_FOR_COMPONENT_JOIN: &str =
        "Rectangle {\n    objectName: \"body\"\n    Text {}\n}\n";

    #[test]
    fn join_level_resolves_a_basename_typed_child_against_its_own_component_file() {
        let (root_statics, _) = parse_static_qml(ROOT_QML_FOR_COMPONENT_JOIN);
        let (card_statics, _) = parse_static_qml(CARD_QML_FOR_COMPONENT_JOIN);

        let mut components = ComponentMap::new();
        components.insert(
            "Card".to_string(),
            ComponentFile {
                path: PathBuf::from("Card.qml"),
                roots: card_statics,
            },
        );

        // Runtime tree: Item -> Card -> Text. `Card` itself IS Card.qml's
        // root Rectangle (its id/source come off that root node directly,
        // matched below) -- its own runtime children are the ROOT's own
        // declared children, i.e. `Text`, not the root again.
        let runtime = vec![rt(
            "Item",
            "",
            "",
            (0.0, 0.0, 100.0, 100.0),
            vec![rt(
                "Card",
                "",
                "Card[0]",
                (0.0, 0.0, 100.0, 100.0),
                vec![rt(
                    "Text",
                    "",
                    "Card[0]/Text[0]",
                    (0.0, 0.0, 50.0, 20.0),
                    vec![],
                )],
            )],
        )];

        let joined = join_level(
            &runtime,
            Some(&root_statics),
            Path::new("root.qml"),
            &components,
            None,
        );
        let item = &joined[0];
        assert_eq!(item.match_kind, "positional");
        assert_eq!(item.source.as_deref(), Some("root.qml:1"));

        let card = &item.children[0];
        assert_eq!(
            card.match_kind, "file",
            "Card's own runtime type names a parsed component file"
        );
        assert_eq!(
            card.source.as_deref(),
            Some("Card.qml:1"),
            "Card IS Card.qml's own root, not a wrapper around it"
        );

        let text = &card.children[0];
        assert_eq!(text.match_kind, "positional", "matched against Card.qml's ROOT's own children, never `comp.roots` (the root itself) again");
        assert_eq!(text.source.as_deref(), Some("Card.qml:3"));
    }

    #[test]
    fn join_level_file_match_is_unconditional_even_under_an_unmatched_none_ancestor() {
        let (card_statics, _) = parse_static_qml(CARD_QML_FOR_COMPONENT_JOIN);
        let mut components = ComponentMap::new();
        components.insert(
            "Card".to_string(),
            ComponentFile {
                path: PathBuf::from("Card.qml"),
                roots: card_statics,
            },
        );

        // Nothing in `statics` can match a `Loader` (empty static root
        // list -- as if `conductor.qml` never declared one at all, and
        // zero static siblings of type `Loader` exist here, so part B's
        // rule reads it as `"wrapper"`, not a real mismatch): its
        // "Card"-typed child must STILL resolve via the component map,
        // unconditionally, regardless of whether the ancestor reads
        // "none" OR "wrapper" -- the actual bug a live end-to-end run
        // found (the entire visible body below `conductor.qml`'s `Loader`
        // read "none").
        let runtime = vec![rt(
            "Loader",
            "",
            "Loader[0]",
            (0.0, 0.0, 100.0, 100.0),
            vec![rt(
                "Card",
                "",
                "Loader[0]/Card[0]",
                (0.0, 0.0, 100.0, 100.0),
                vec![],
            )],
        )];
        let statics: Vec<StaticNode> = vec![];

        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("conductor.qml"),
            &components,
            None,
        );
        assert_eq!(joined[0].match_kind, "wrapper");
        assert_eq!(
            joined[0].children[0].match_kind, "file",
            "a `wrapper` (or `none`) ancestor must not close off a basename-typed descendant"
        );
        assert_eq!(joined[0].children[0].source.as_deref(), Some("Card.qml:1"));
    }

    #[test]
    fn build_component_map_parses_every_watch_listed_file_keyed_by_stem() {
        let base = scratch("component_map");
        let root_qml = base.join("root.qml");
        std::fs::write(&root_qml, ROOT_QML_FOR_COMPONENT_JOIN).unwrap();
        let card_qml = base.join("Card.qml");
        std::fs::write(&card_qml, CARD_QML_FOR_COMPONENT_JOIN).unwrap();

        let mut control = Map::new();
        control.insert(
            "watch".to_string(),
            json!([root_qml.to_string_lossy(), card_qml.to_string_lossy()]),
        );

        let map = build_component_map(&control, None);
        assert_eq!(map.len(), 2);
        let card = &map["Card"];
        assert_eq!(card.path, card_qml);
        assert_eq!(card.roots[0].ty, "Rectangle");
        assert_eq!(card.roots[0].object_name.as_deref(), Some("body"));
    }

    #[test]
    fn build_component_map_adds_the_widgets_own_file_even_when_watch_omits_it() {
        let base = scratch("component_map_widget_fallback");
        let widget_qml = base.join("widget.qml");
        std::fs::write(&widget_qml, ROOT_QML_FOR_COMPONENT_JOIN).unwrap();

        let control = Map::new(); // no "watch" key at all
        let map = build_component_map(&control, Some(&widget_qml));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("widget"));
    }

    /// The real fixture behind the `join_level`/`parse_static_qml` fixes
    /// above: a live run against `song/songbook/sonata/widgets/
    /// SessionMenu.qml` found every child below a `"file"` match reading
    /// "none" (1054 none vs 34 resolved). Skips (never fails) when this
    /// checkout doesn't have the song present.
    fn read_session_menu_qml() -> Option<String> {
        let path =
            aoide_storage::fs::flake_root().join("song/songbook/sonata/widgets/SessionMenu.qml");
        match std::fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(e) => {
                eprintln!("skipping: {} unreadable ({e})", path.display());
                None
            }
        }
    }

    #[test]
    fn session_menu_qml_top_level_children_match_the_real_checkout() {
        let Some(text) = read_session_menu_qml() else {
            return;
        };
        let (roots, _) = parse_static_qml(&text);
        assert_eq!(
            roots.len(),
            1,
            "SessionMenu.qml has exactly one top-level Item"
        );
        assert_eq!(roots[0].ty, "Item");

        let got: Vec<(&str, usize)> = roots[0]
            .children
            .iter()
            .map(|c| (c.ty.as_str(), c.line))
            .collect();
        assert_eq!(
            got,
            vec![("TextEdit", 67), ("FolderDialog", 134), ("FileView", 165), ("FileView", 179), ("MouseArea", 186), ("Rectangle", 187)],
            "the inline `component Action: Rectangle {{ ... }}` at line 275 (and its own nested Text/MouseArea) must never appear here -- it's a type declaration, not a child instance"
        );
    }

    #[test]
    fn file_matched_node_children_resolve_positionally_against_the_real_session_menu_children() {
        let Some(text) = read_session_menu_qml() else {
            return;
        };
        let path =
            aoide_storage::fs::flake_root().join("song/songbook/sonata/widgets/SessionMenu.qml");
        let mut components = ComponentMap::new();
        components.insert(
            "SessionMenu".to_string(),
            ComponentFile {
                path: path.clone(),
                roots: parse_static_qml(&text).0,
            },
        );

        // Loader[0]/SessionMenu[0] -- the exact live shape reported: the
        // Loader itself matches nothing (empty statics), but its
        // SessionMenu-typed child resolves via the component map, and
        // THAT node's own runtime children resolve positionally against
        // SessionMenu.qml's real root children.
        let runtime = vec![rt(
            "Loader",
            "",
            "Loader[0]",
            (0.0, 0.0, 100.0, 100.0),
            vec![rt(
                "SessionMenu",
                "",
                "Loader[0]/SessionMenu[0]",
                (0.0, 0.0, 100.0, 100.0),
                vec![
                    rt(
                        "TextEdit",
                        "",
                        "Loader[0]/SessionMenu[0]/TextEdit[0]",
                        (0.0, 0.0, 10.0, 10.0),
                        vec![],
                    ),
                    rt(
                        "MouseArea",
                        "",
                        "Loader[0]/SessionMenu[0]/MouseArea[0]",
                        (0.0, 0.0, 10.0, 10.0),
                        vec![],
                    ),
                    rt(
                        "Rectangle",
                        "",
                        "Loader[0]/SessionMenu[0]/Rectangle[0]",
                        (0.0, 0.0, 10.0, 10.0),
                        vec![],
                    ),
                ],
            )],
        )];
        let statics: Vec<StaticNode> = vec![];

        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("conductor.qml"),
            &components,
            None,
        );
        let menu = &joined[0].children[0];
        assert_eq!(menu.match_kind, "file");
        assert_eq!(
            menu.source.as_deref(),
            Some(format!("{}:7", path.display())).as_deref()
        );

        assert_eq!(menu.children[0].match_kind, "positional");
        assert_eq!(
            menu.children[0].source.as_deref(),
            Some(format!("{}:67", path.display())).as_deref()
        );
        assert_eq!(menu.children[1].match_kind, "positional");
        assert_eq!(
            menu.children[1].source.as_deref(),
            Some(format!("{}:186", path.display())).as_deref()
        );
        assert_eq!(menu.children[2].match_kind, "positional");
        assert_eq!(
            menu.children[2].source.as_deref(),
            Some(format!("{}:187", path.display())).as_deref()
        );
    }

    /// The real fixture behind review follow-up part A: `SessionCard` is
    /// declared INLINE inside `conductor.qml` (`component SessionCard:
    /// FocusScope { ... }`, no file of its own), so before part A it could
    /// never get a `"file"` match at all -- everything below it stayed
    /// "none" regardless of the SessionMenu fix. Skips (never fails) when
    /// this checkout doesn't have the song present.
    fn read_conductor_qml() -> Option<(PathBuf, String)> {
        let path =
            aoide_storage::fs::flake_root().join("song/songbook/sonata/widgets/conductor.qml");
        match std::fs::read_to_string(&path) {
            Ok(text) => Some((path, text)),
            Err(e) => {
                eprintln!("skipping: {} unreadable ({e})", path.display());
                None
            }
        }
    }

    #[test]
    fn conductor_qml_registers_its_inline_session_card_component() {
        let Some((_, text)) = read_conductor_qml() else {
            return;
        };
        let (_, inline) = parse_static_qml(&text);
        let card = inline
            .iter()
            .find(|c| c.component_name.as_deref() == Some("SessionCard"))
            .expect("conductor.qml declares `component SessionCard: FocusScope { ... }`");
        assert_eq!(card.ty, "FocusScope", "the component's own BASE type");
        assert_eq!(
            card.line,
            line_of(&text, 1, "component SessionCard: FocusScope {")
        );
        assert!(!card.children.is_empty(), "SessionCard's own declared body");
    }

    #[test]
    fn file_matched_inline_component_children_resolve_positionally_against_conductors_real_session_card(
    ) {
        let Some((path, text)) = read_conductor_qml() else {
            return;
        };
        let (_, inline) = parse_static_qml(&text);
        let card_node = inline
            .into_iter()
            .find(|c| c.component_name.as_deref() == Some("SessionCard"))
            .expect("conductor.qml declares SessionCard");
        let card_line = card_node.line;
        let column_line = line_of(&text, card_line + 1, "Column {");

        let mut components = ComponentMap::new();
        components.insert(
            "SessionCard".to_string(),
            ComponentFile {
                path: path.clone(),
                roots: vec![card_node],
            },
        );

        // SessionCard's own real top-level children (in conductor.qml, in
        // order) are Rectangle:1443, Rectangle:1458, Rectangle:1467,
        // Column:1475, MouseArea:2328 -- a runtime `Column` child
        // positionally matches the one declared `Column` among them.
        let runtime = vec![rt(
            "SessionCard",
            "",
            "Repeater[0]/SessionCard[0]",
            (0.0, 0.0, 328.0, 165.0),
            vec![rt(
                "Column",
                "",
                "Repeater[0]/SessionCard[0]/Column[0]",
                (0.0, 0.0, 300.0, 150.0),
                vec![],
            )],
        )];
        let statics: Vec<StaticNode> = vec![];

        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("conductor.qml"),
            &components,
            None,
        );
        let card = &joined[0];
        assert_eq!(card.match_kind, "file");
        assert_eq!(
            card.source.as_deref(),
            Some(format!("{}:{card_line}", path.display())).as_deref()
        );

        let column = &card.children[0];
        assert_eq!(column.match_kind, "positional");
        assert_eq!(
            column.source.as_deref(),
            Some(format!("{}:{column_line}", path.display())).as_deref()
        );
    }

    /// Depth-first search for the first node matching `pred` -- `conductor
    /// .qml`'s own `Repeater { delegate: Column { id: movement ... } } }`
    /// sits several levels down, not at `roots` top level.
    fn find_node<'a>(
        nodes: &'a [StaticNode],
        pred: &dyn Fn(&StaticNode) -> bool,
    ) -> Option<&'a StaticNode> {
        for n in nodes {
            if pred(n) {
                return Some(n);
            }
            if let Some(found) = find_node(&n.children, pred) {
                return Some(found);
            }
        }
        None
    }

    /// The real fixture behind review follow-up part B1: before
    /// `line_opens_bound_node`, `delegate: Column {` never opened a node at
    /// all -- `id: movement` (the very next line) fell through to whatever
    /// WAS open, the enclosing `Repeater` itself, and the delegate's real
    /// children (`rowsBay`, `rowsCol`, ...) silently became the
    /// `Repeater`'s own children one level too shallow. Skips (never
    /// fails) when this checkout doesn't have the song present.
    #[test]
    fn conductor_qmls_repeater_delegate_is_a_real_child_never_the_repeaters_own_id() {
        let Some((_, text)) = read_conductor_qml() else {
            return;
        };
        let (roots, _) = parse_static_qml(&text);
        // The MOVEMENTS loop: the first `delegate: Column {` and the
        // `Repeater {` opening just above it -- located by content, since
        // the checkout's conductor.qml is edited live by other lanes.
        let delegate_line = line_of(&text, 1, "delegate: Column {");
        let repeater_line = last_line_of_before(&text, delegate_line, "Repeater {");
        let repeater = find_node(&roots, &|n| n.ty == "Repeater" && n.line == repeater_line)
            .expect("conductor.qml's own MOVEMENTS Repeater");
        assert_eq!(
            repeater.id, None,
            "`id: movement` belongs to the DELEGATE -- it must never leak onto the Repeater itself"
        );
        assert_eq!(
            repeater.children.len(),
            1,
            "the Repeater's only real child is its own delegate"
        );

        let delegate = &repeater.children[0];
        assert_eq!(delegate.ty, "Column");
        assert_eq!(delegate.line, delegate_line, "`delegate: Column {{` itself");
        assert_eq!(delegate.id.as_deref(), Some("movement"));
        assert_eq!(delegate.binding.as_deref(), Some("delegate"));
        assert!(!delegate.children.is_empty(), "the delegate's own declared body (rowsBay, rowsCol, ...) nests under IT now, not the Repeater");
    }

    #[test]
    fn join_resolves_every_repeater_delegate_instance_to_the_same_static_delegate_child() {
        // static Repeater{ delegate: Column{ id: m } }
        let statics = vec![st(
            "Repeater",
            None,
            None,
            10,
            vec![st_bound("Column", "delegate", Some("m"), 12, vec![])],
        )];

        // runtime: the Repeater itself (matches positionally, ordinary
        // case) plus three delegate INSTANCES landing as its SIBLINGS --
        // never its children -- the shape a real `Repeater` produces.
        let runtime = vec![
            rt("Repeater", "", "Repeater[0]", (0.0, 0.0, 0.0, 0.0), vec![]),
            rt("Column", "", "Column[0]", (0.0, 0.0, 10.0, 10.0), vec![]),
            rt("Column", "", "Column[1]", (0.0, 10.0, 10.0, 10.0), vec![]),
            rt("Column", "", "Column[2]", (0.0, 20.0, 10.0, 10.0), vec![]),
        ];

        let joined = join_level(
            &runtime,
            Some(&statics),
            Path::new("w.qml"),
            &ComponentMap::new(),
            None,
        );
        assert_eq!(
            joined[0].match_kind, "positional",
            "the Repeater itself, ordinary same-level match"
        );

        for col in &joined[1..] {
            assert_eq!(col.match_kind, "positional");
            assert_eq!(col.id.as_deref(), Some("m"));
            assert_eq!(col.source.as_deref(), Some("w.qml:12"), "every instance shares the delegate's OWN line -- never one line each, never `used` up after the first");
        }
    }

    // ── element path grammar (resolve_element_path: verbatim lookup) ────

    fn jn(
        ty: &str,
        object_name: Option<&str>,
        path: &str,
        rect: (f64, f64, f64, f64),
        visible: bool,
        children: Vec<JoinedNode>,
    ) -> JoinedNode {
        JoinedNode {
            ty: ty.to_string(),
            object_name: object_name.map(String::from),
            path: path.to_string(),
            rect,
            visible,
            text: None,
            id: None,
            match_kind: "none",
            source: None,
            children,
        }
    }

    #[test]
    fn resolve_element_path_finds_a_node_by_its_verbatim_canvas_path() {
        let leaf = jn(
            "Text",
            None,
            "Rectangle[0]/Text[1]",
            (0.0, 0.0, 1.0, 1.0),
            true,
            vec![],
        );
        let other = jn(
            "Text",
            None,
            "Rectangle[0]/Text[0]",
            (0.0, 0.0, 1.0, 1.0),
            true,
            vec![],
        );
        let mid = jn(
            "Rectangle",
            None,
            "Rectangle[0]",
            (0.0, 0.0, 1.0, 1.0),
            true,
            vec![other, leaf],
        );
        let root = jn("Item", None, "", (0.0, 0.0, 1.0, 1.0), true, vec![mid]);
        let found = resolve_element_path(&root, "Rectangle[0]/Text[1]").unwrap();
        assert!(std::ptr::eq(found, &root.children[0].children[1]));
    }

    #[test]
    fn resolve_element_path_finds_the_root_itself_for_an_empty_path() {
        let root = jn("Item", None, "", (0.0, 0.0, 1.0, 1.0), true, vec![]);
        assert!(std::ptr::eq(
            resolve_element_path(&root, "").unwrap(),
            &root
        ));
    }

    #[test]
    fn resolve_element_path_is_none_for_an_unknown_path() {
        let root = jn("Item", None, "", (0.0, 0.0, 1.0, 1.0), true, vec![]);
        assert!(resolve_element_path(&root, "Rectangle[0]").is_none());
    }

    // ── --at deepest-node picking ──────────────────────────────────────

    #[test]
    fn at_picks_the_deepest_visible_node_containing_the_point() {
        let inner = jn(
            "Text",
            None,
            "Rectangle[0]/Text[0]",
            (10.0, 10.0, 5.0, 5.0),
            true,
            vec![],
        );
        let outer = jn(
            "Rectangle",
            None,
            "Rectangle[0]",
            (0.0, 0.0, 100.0, 100.0),
            true,
            vec![inner],
        );
        let path = deepest_path_at(std::slice::from_ref(&outer), 12.0, 12.0).unwrap();
        assert_eq!(path.len(), 2);
        assert_eq!(path[1].ty, "Text");
    }

    #[test]
    fn at_skips_an_invisible_node_and_reports_its_visible_ancestor() {
        let inner = jn(
            "Text",
            None,
            "Rectangle[0]/Text[0]",
            (10.0, 10.0, 5.0, 5.0),
            false,
            vec![],
        );
        let outer = jn(
            "Rectangle",
            None,
            "Rectangle[0]",
            (0.0, 0.0, 100.0, 100.0),
            true,
            vec![inner],
        );
        let path = deepest_path_at(std::slice::from_ref(&outer), 12.0, 12.0).unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].ty, "Rectangle");
    }

    #[test]
    fn at_is_none_when_the_point_lies_outside_every_node() {
        let outer = jn(
            "Rectangle",
            None,
            "Rectangle[0]",
            (0.0, 0.0, 10.0, 10.0),
            true,
            vec![],
        );
        assert!(deepest_path_at(std::slice::from_ref(&outer), 500.0, 500.0).is_none());
    }

    #[test]
    fn at_picks_the_deepest_of_several_overlapping_containing_siblings() {
        // Two visible siblings both contain the point -- a shallow one
        // (no children) and a deep one (its own child also contains the
        // point). The FIRST containing sibling in DOM order is the
        // shallow one; picking it and stopping there (the old behaviour)
        // is exactly the live bug review item 8 found (`tree --at
        // 180,200` stopping at "Item/Loader" instead of descending into
        // the Loader's own child, which also contained the point and had
        // children of its own).
        let deep_leaf = jn(
            "Text",
            None,
            "Rectangle[1]/Text[0]",
            (0.0, 0.0, 100.0, 100.0),
            true,
            vec![],
        );
        let shallow = jn(
            "Rectangle",
            None,
            "Rectangle[0]",
            (0.0, 0.0, 100.0, 100.0),
            true,
            vec![],
        );
        let deep = jn(
            "Rectangle",
            None,
            "Rectangle[1]",
            (0.0, 0.0, 100.0, 100.0),
            true,
            vec![deep_leaf],
        );
        let siblings = vec![shallow, deep];

        let path = deepest_path_at(&siblings, 12.0, 12.0).unwrap();
        assert_eq!(
            path.len(),
            2,
            "must descend through the deep sibling, not stop at the shallow one"
        );
        assert_eq!(path[0].path, "Rectangle[1]");
        assert_eq!(path[1].ty, "Text");
    }

    /// Review follow-up part B2: `--at`'s own `chain` used to reuse
    /// `joined_to_json` whole per ancestor, so each of a handful of entries
    /// re-embedded its ENTIRE subtree (a 6-node chain outweighing the full
    /// dump, 2.45MB deep) -- `joined_to_json_shallow` carries every OTHER
    /// field but drops `children` entirely, not even as an empty array.
    #[test]
    fn at_chain_json_entries_carry_no_children_key_at_all() {
        let leaf = JoinedNode {
            ty: "Text".to_string(),
            object_name: None,
            path: "Rectangle[0]/Text[0]".to_string(),
            rect: (0.0, 0.0, 10.0, 10.0),
            visible: true,
            text: Some("hi".to_string()),
            id: None,
            match_kind: "positional",
            source: Some("w.qml:3".to_string()),
            children: vec![],
        };
        let mid = JoinedNode {
            ty: "Rectangle".to_string(),
            object_name: None,
            path: "Rectangle[0]".to_string(),
            rect: (0.0, 0.0, 50.0, 50.0),
            visible: true,
            text: None,
            id: None,
            match_kind: "positional",
            source: Some("w.qml:2".to_string()),
            children: vec![leaf.clone()],
        };
        let root = JoinedNode {
            ty: "Item".to_string(),
            object_name: None,
            path: String::new(),
            rect: (0.0, 0.0, 100.0, 100.0),
            visible: true,
            text: None,
            id: None,
            match_kind: "positional",
            source: Some("w.qml:1".to_string()),
            children: vec![mid.clone()],
        };
        let chain: Vec<&JoinedNode> = vec![&root, &mid, &leaf];

        let json: Vec<Value> = chain.iter().map(|n| joined_to_json_shallow(n)).collect();
        for (i, entry) in json.iter().enumerate() {
            assert!(
                entry.as_object().unwrap().get("children").is_none(),
                "entry {i} carries a children key: {entry:?}"
            );
        }
        // every OTHER field still comes through, on the deepest entry too.
        assert_eq!(json[2]["type"], "Text");
        assert_eq!(json[2]["source"], "w.qml:3");
        assert_eq!(json[2]["text"], "hi");
    }

    // ── notes: add / done / clear / numbering ─────────────────────────

    #[test]
    fn parse_rect_reads_four_comma_separated_numbers() {
        assert_eq!(parse_rect("1,2,3,4"), Some((1.0, 2.0, 3.0, 4.0)));
        assert_eq!(parse_rect("1,2,3"), None);
        assert_eq!(parse_rect("a,2,3,4"), None);
    }

    #[test]
    fn notes_add_numbers_from_one_and_defaults_kind_to_note() {
        let root = scratch("notes_add");
        let out1 = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "fix the padding"),
        ]));
        assert_eq!(out1.status, Status::Ok, "{:?}", out1.message);
        let data1 = out1.data.unwrap();
        assert_eq!(data1["notes"][0]["n"], 1);
        assert_eq!(data1["notes"][0]["kind"], "note");
        assert_eq!(data1["notes"][0]["done"], false);

        let out2 = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "second"),
        ]));
        let data2 = out2.data.unwrap();
        assert_eq!(
            data2["notes"][1]["n"], 2,
            "numbering never resets on a second add"
        );
    }

    #[test]
    fn notes_add_kind_follows_element_then_shape_then_plain() {
        let root = scratch("notes_kinds");
        let highlight = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
            ("element", "Item[0]#foo"),
        ]));
        assert_eq!(highlight.data.unwrap()["notes"][0]["kind"], "highlight");

        let shape = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t2"),
            ("rect", "1,2,3,4"),
            ("shape", "arrow"),
        ]));
        assert_eq!(shape.data.unwrap()["notes"][1]["kind"], "shape");
    }

    #[test]
    fn notes_add_rejects_rect_and_element_together() {
        let root = scratch("notes_rect_element_conflict");
        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
            ("rect", "1,2,3,4"),
            ("element", "Item[0]"),
        ]));
        assert_eq!(out.status, Status::Usage);
    }

    #[test]
    fn notes_add_rejects_an_unknown_shape() {
        let root = scratch("notes_bad_shape");
        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
            ("shape", "hexagon"),
        ]));
        assert_eq!(out.status, Status::Usage);
    }

    #[test]
    fn notes_done_marks_the_matching_note() {
        let root = scratch("notes_done");
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
        ]));
        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("done", "1"),
        ]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.message);
        assert_eq!(out.data.unwrap()["notes"][0]["done"], true);
    }

    #[test]
    fn notes_done_on_an_unknown_number_is_an_error_naming_it() {
        let root = scratch("notes_done_missing");
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
        ]));
        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("done", "42"),
        ]));
        assert_eq!(out.status, Status::Error);
        assert!(out.message.contains("42"));
    }

    #[test]
    fn notes_clear_empties_the_list_but_keeps_the_file() {
        let root = scratch("notes_clear");
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
        ]));
        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("clear", "true"),
        ]));
        assert_eq!(out.status, Status::Ok);
        assert!(root.join("notes.json").is_file());
        let doc = read_notes(&root.join("notes.json"));
        assert_eq!(doc["notes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn notes_clear_preserves_unknown_top_level_keys() {
        // Review item 2: `--clear` used to build a brand-new
        // `empty_notes_doc()` from scratch, silently dropping any unknown
        // top-level key the file happened to carry.
        let root = scratch("notes_clear_preserves_keys");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("notes.json"), r#"{"schemaVersion":0,"notes":[{"n":1,"kind":"note","text":"t","createdAt":"x","done":false}],"futureField":"kept"}"#).unwrap();

        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("clear", "true"),
        ]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.message);
        let doc = read_notes(&root.join("notes.json"));
        assert_eq!(doc["notes"].as_array().unwrap().len(), 0);
        assert_eq!(
            doc["futureField"], "kept",
            "an unknown top-level key must survive --clear"
        );
    }

    #[test]
    fn notes_add_normalises_a_non_array_notes_value_instead_of_panicking() {
        // Review item 1 BLOCKER: a hand-edited/corrupt notes.json with
        // `notes` present but not an array used to `.expect()` straight
        // into a panic on the very next `--add`.
        let root = scratch("notes_add_non_array");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("notes.json"),
            r#"{"schemaVersion":0,"notes":"not-an-array"}"#,
        )
        .unwrap();

        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "recovered"),
        ]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.message);
        let data = out.data.unwrap();
        assert_eq!(data["notes"].as_array().unwrap().len(), 1);
        assert_eq!(data["notes"][0]["n"], 1);
        assert_eq!(data["notes"][0]["text"], "recovered");
    }

    #[test]
    fn notes_schema_version_is_the_json_number_zero_not_a_string() {
        // Review item 5: the real canvas writes `schemaVersion` as a JSON
        // NUMBER in notes.json (unlike `preview.json`'s own, which is a
        // string) -- confirmed against a live canvas run.
        let root = scratch("notes_schema_version_numeric");
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
        ]));
        let raw = std::fs::read_to_string(root.join("notes.json")).unwrap();
        let doc: Value = serde_json::from_str(&raw).unwrap();
        assert!(doc["schemaVersion"].is_number(), "{}", doc["schemaVersion"]);
        assert_eq!(doc["schemaVersion"], 0);

        let cleared = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("clear", "true"),
        ]));
        assert_eq!(cleared.status, Status::Ok);
        let raw = std::fs::read_to_string(root.join("notes.json")).unwrap();
        let doc: Value = serde_json::from_str(&raw).unwrap();
        assert!(doc["schemaVersion"].is_number(), "{}", doc["schemaVersion"]);
    }

    #[test]
    fn notes_numbering_restarts_after_a_clear() {
        let root = scratch("notes_renumber_after_clear");
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
        ]));
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("clear", "true"),
        ]));
        let out = handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "again"),
        ]));
        assert_eq!(out.data.unwrap()["notes"][0]["n"], 1);
    }

    #[test]
    fn notes_read_without_a_canvas_omits_source_and_says_so() {
        let root = scratch("notes_read_no_canvas");
        handle_preview_notes(&inv_notes(&[
            ("root", root.to_str().unwrap()),
            ("add", "true"),
            ("text", "t"),
            ("element", "Item[0]#foo"),
        ]));
        let out = handle_preview_notes(&inv_notes(&[("root", root.to_str().unwrap())]));
        assert_eq!(out.status, Status::Ok);
        // No `preview.json` at this root at all -- the fallback message
        // now names the REAL reason (review item 6c) rather than a fixed
        // generic "canvas not running" regardless of actual cause.
        assert!(
            out.message.contains("element sources unresolved"),
            "{}",
            out.message
        );
        assert!(out.message.contains("no preview at"), "{}", out.message);
        let data = out.data.unwrap();
        assert!(data["notes"][0].get("source").is_none());
    }

    #[test]
    fn notes_read_on_an_empty_root_reports_no_notes() {
        let root = scratch("notes_empty");
        let out = handle_preview_notes(&inv_notes(&[("root", root.to_str().unwrap())]));
        assert_eq!(out.status, Status::Ok);
        assert!(out.message.contains("no notes"));
    }

    /// 1-based number of the first line at or after `from` (1-based) that
    /// contains `needle` -- real-file tests locate their anchors by content,
    /// never by a pinned line number, because the checkout is edited live.
    fn line_of(text: &str, from: usize, needle: &str) -> usize {
        text.lines()
            .enumerate()
            .skip(from.saturating_sub(1))
            .find(|(_, l)| l.contains(needle))
            .map(|(i, _)| i + 1)
            .unwrap_or_else(|| panic!("no line containing `{needle}` at or after line {from}"))
    }

    /// 1-based number of the last line BEFORE `before` (1-based) containing `needle`.
    fn last_line_of_before(text: &str, before: usize, needle: &str) -> usize {
        text.lines()
            .enumerate()
            .take(before.saturating_sub(1))
            .filter(|(_, l)| l.contains(needle))
            .map(|(i, _)| i + 1)
            .last()
            .unwrap_or_else(|| panic!("no line containing `{needle}` before line {before}"))
    }
}
