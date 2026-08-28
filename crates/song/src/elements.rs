//! Element descriptors + the render pipeline
//! (docs/architecture/ELEMENTS.md, L-E1) — the seam that lets a non-QML
//! program (waybar, dunst, a compositor, anything with a config file) become
//! a first-class rice target with the same EDIT/SAVE/DRAFT loop the QML
//! widgets already have.
//!
//! A song carries raw config files byte-for-byte under
//! `songbook/<song>/elements/<element>/`, plus ONE small descriptor
//! (`element.json`, v0 — [`Descriptor`]) naming which files land where
//! under `run/elements/<element>/`, verbatim or livery-templated, and how
//! the element starts. [`seed_tree`]/[`seed_song`] are the render pipeline:
//! verbatim byte copy for `template: false` files,
//! `crate::livery::emit::file::render` for `template: true` ones, against
//! the resolved livery. A render error fails only that element and leaves
//! its existing `run/elements/<element>/` untouched — every file for one
//! element is rendered into memory FIRST, and only written once all of them
//! succeed (`render_files` / `write_files`'s own split).
//!
//! `commands::elements` (`element seed <song>`) is the shell-reachable
//! bridge this module backs; `rice stage` (L-E2) and the elements facet's
//! activation hook (L-E3) are later phases calling the same [`seed_song`]/
//! [`seed_tree`] primitives — nothing here is facet- or stage-specific.

use crate::livery::resolve::Resolved;
use serde::Deserialize;
use std::fmt;
use std::path::{Path, PathBuf};

/// The only descriptor version this module understands. An `element.json`
/// naming any other `v` refuses with a taught error — never a silent
/// best-effort parse.
pub const DESCRIPTOR_VERSION: u64 = 0;

/// One `element.json`, v0 (docs/architecture/ELEMENTS.md, "The descriptor").
#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    pub v: u64,
    pub element: String,
    pub files: Vec<FileEntry>,
    #[serde(default)]
    pub surfaces: Vec<String>,
    pub run: RunSpec,
    #[serde(default)]
    pub reload: Option<String>,
    #[serde(default)]
    pub restart: Option<String>,
}

/// One entry in `files` — `src` relative to the element dir, `dest`
/// relative to `run/elements/<element>/` (defaults to `src`).
#[derive(Debug, Clone, Deserialize)]
pub struct FileEntry {
    pub src: String,
    #[serde(default)]
    pub dest: Option<String>,
    #[serde(default)]
    pub template: bool,
}

/// How the element starts (`run.exec` + `run.via`).
#[derive(Debug, Clone, Deserialize)]
pub struct RunSpec {
    pub exec: String,
    pub via: String,
}

/// A structured elements-pipeline error (descriptor refusal, render
/// failure, I/O). Never a panic.
#[derive(Debug, Clone)]
pub struct ElementsError {
    pub message: String,
}

impl ElementsError {
    pub fn new(message: impl Into<String>) -> Self {
        ElementsError {
            message: message.into(),
        }
    }
}

impl fmt::Display for ElementsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ElementsError {}

/// Parse and validate one `element.json`'s raw bytes, taught: unknown `v`,
/// a name shape/mismatch, an invalid `run.via`, or a traversing `src`/
/// `dest` all refuse with a structured message naming the exact problem —
/// never a guess, never a partial descriptor.
///
/// `dir_name` is the element directory `raw` was read from — [`Descriptor::element`]
/// must equal it, the same "declared name matches directory name" discipline
/// `rice compose`'s own song-name validation holds.
pub fn parse_descriptor(dir_name: &str, raw: &str) -> Result<Descriptor, ElementsError> {
    let d: Descriptor = serde_json::from_str(raw)
        .map_err(|e| ElementsError::new(format!("element.json is not valid JSON: {e}")))?;

    if d.v != DESCRIPTOR_VERSION {
        return Err(ElementsError::new(format!(
            "element.json \"v\": {} is not supported (only v{DESCRIPTOR_VERSION} is known)",
            d.v
        )));
    }
    if !crate::compose::valid_song_name(&d.element) {
        return Err(ElementsError::new(format!(
            "\"element\": \"{}\" is not a valid element name: must match \
             `^[a-z0-9][a-z0-9-]*$` (lowercase letters, digits, hyphens; no leading hyphen)",
            d.element
        )));
    }
    if d.element != dir_name {
        return Err(ElementsError::new(format!(
            "\"element\": \"{}\" does not match its directory name \"{dir_name}\"",
            d.element
        )));
    }
    if d.files.is_empty() {
        return Err(ElementsError::new(
            "\"files\" must declare at least one file",
        ));
    }
    for f in &d.files {
        validate_relative_path(&f.src, "files[].src")?;
        if let Some(dest) = &f.dest {
            validate_relative_path(dest, "files[].dest")?;
        }
    }
    match d.run.via.as_str() {
        "unit" | "exec-once" => {}
        other => {
            return Err(ElementsError::new(format!(
                "\"run\".\"via\": \"{other}\" is invalid (only \"unit\" or \"exec-once\")"
            )));
        }
    }

    Ok(d)
}

/// Reject anything but a plain relative path made of ordinary segments — no
/// `..`, no leading `/`, no bare `.`. This is the traversal guard both
/// `src` (relative to the element dir) and `dest` (relative to
/// `run/elements/<element>/`) share: every path component must be
/// [`std::path::Component::Normal`], nothing else.
fn validate_relative_path(p: &str, field: &str) -> Result<(), ElementsError> {
    if p.is_empty() {
        return Err(ElementsError::new(format!("{field} must not be empty")));
    }
    let path = Path::new(p);
    if path.is_absolute() {
        return Err(ElementsError::new(format!(
            "{field} \"{p}\" must be relative, not absolute"
        )));
    }
    for component in path.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(ElementsError::new(format!(
                "{field} \"{p}\" must not traverse (no `..`, no `.`, no root)"
            )));
        }
    }
    Ok(())
}

/// Substitute the literal `{run}` token in `run.exec` with the absolute
/// `run/elements/<element>` path. Done at generation time (the facet
/// generating a unit/exec-once line, L-E3) — the finished string is what
/// ships, never re-expanded at runtime.
pub fn substitute_run_token(exec: &str, run_dir: &Path) -> String {
    exec.replace("{run}", &run_dir.to_string_lossy())
}

/// One rendered file, staged in memory — not yet written.
#[derive(Debug, Clone)]
pub struct RenderedFile {
    pub dest: PathBuf,
    pub bytes: Vec<u8>,
}

/// Render every file `descriptor` declares, without writing anything.
/// Verbatim byte copy for `template: false`; `crate::livery::emit::file::render`
/// for `template: true`, against `resolved`. Bails on the FIRST error and
/// writes nothing — so a caller that only commits the result on `Ok` never
/// leaves an element's existing `run/elements/<element>/` partially
/// overwritten by a render failure partway through its file list.
pub fn render_files(
    element_dir: &Path,
    run_dir: &Path,
    descriptor: &Descriptor,
    resolved: &Resolved,
) -> Result<Vec<RenderedFile>, ElementsError> {
    let mut out = Vec::with_capacity(descriptor.files.len());
    for f in &descriptor.files {
        let src_path = element_dir.join(&f.src);
        let dest_rel = f.dest.as_deref().unwrap_or(&f.src);
        let dest_path = run_dir.join(dest_rel);

        let bytes = std::fs::read(&src_path)
            .map_err(|e| ElementsError::new(format!("cannot read {}: {e}", src_path.display())))?;

        let rendered = if f.template {
            let text = String::from_utf8(bytes).map_err(|e| {
                ElementsError::new(format!(
                    "{} is not valid UTF-8, cannot template: {e}",
                    src_path.display()
                ))
            })?;
            crate::livery::emit::file::render(&text, resolved)
                .map_err(|e| ElementsError::new(format!("{}: {e}", src_path.display())))?
                .into_bytes()
        } else {
            bytes
        };

        out.push(RenderedFile {
            dest: dest_path,
            bytes: rendered,
        });
    }
    Ok(out)
}

/// Write every rendered file atomically (`aoide_storage::fs::atomic_write_bytes`
/// — write-temp-then-rename), creating each file's parent directory first.
/// Called only once [`render_files`] has already succeeded for the WHOLE
/// element, so a render failure never reaches here.
pub fn write_files(files: &[RenderedFile]) -> Result<(), ElementsError> {
    for f in files {
        if let Some(parent) = f.dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ElementsError::new(format!("cannot create {}: {e}", parent.display()))
            })?;
        }
        aoide_storage::fs::atomic_write_bytes(&f.dest, &f.bytes)
            .map_err(|e| ElementsError::new(format!("failed to write {}: {e}", f.dest.display())))?;
    }
    Ok(())
}

/// One element's render outcome — always reported, never silently dropped,
/// whether it succeeded or not (the structured per-element status
/// `docs/architecture/ELEMENTS.md`'s stage flow calls for).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ElementOutcome {
    pub element: String,
    pub ok: bool,
    pub files: usize,
    pub error: Option<String>,
}

/// The whole-songbook render report — one [`ElementOutcome`] per element
/// directory walked.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SeedReport {
    pub elements: Vec<ElementOutcome>,
}

impl SeedReport {
    pub fn any_failed(&self) -> bool {
        self.elements.iter().any(|e| !e.ok)
    }
}

/// Render one already-located element directory: read + parse its
/// `element.json`, render every declared file, write on success. Never
/// panics — every failure mode (missing descriptor, bad JSON, a refused
/// descriptor, a render error, a write error) folds into one
/// [`ElementOutcome`] with `ok: false` and a message, so one bad element
/// never stops [`seed_tree`] from finishing the rest.
fn render_one_element(element_dir: &Path, run_dir: &Path, name: &str, resolved: &Resolved) -> ElementOutcome {
    let descriptor_path = element_dir.join("element.json");
    let raw = match std::fs::read_to_string(&descriptor_path) {
        Ok(s) => s,
        Err(e) => {
            return ElementOutcome {
                element: name.to_string(),
                ok: false,
                files: 0,
                error: Some(format!("cannot read {}: {e}", descriptor_path.display())),
            };
        }
    };
    let descriptor = match parse_descriptor(name, &raw) {
        Ok(d) => d,
        Err(e) => {
            return ElementOutcome {
                element: name.to_string(),
                ok: false,
                files: 0,
                error: Some(e.to_string()),
            };
        }
    };
    let rendered = match render_files(element_dir, run_dir, &descriptor, resolved) {
        Ok(f) => f,
        Err(e) => {
            return ElementOutcome {
                element: name.to_string(),
                ok: false,
                files: 0,
                error: Some(e.to_string()),
            };
        }
    };
    if let Err(e) = write_files(&rendered) {
        return ElementOutcome {
            element: name.to_string(),
            ok: false,
            files: 0,
            error: Some(e.to_string()),
        };
    }
    ElementOutcome {
        element: name.to_string(),
        ok: true,
        files: rendered.len(),
        error: None,
    }
}

/// Render every element under `elements_root` into `run_root`, against
/// `resolved`. `_`-prefixed directories are skipped (the same shelving
/// convention `elements/_waybar/` gets everywhere a `_widgets/` slot would),
/// as are non-directory entries. A missing `elements_root` reports an empty
/// [`SeedReport`], not an error — most songs carry no elements at all.
///
/// Pure with respect to global state (explicit paths only) so it's testable
/// without touching `$AOIDE_ROOT`/`$AOIDE_STAGE_DIR` — [`seed_song`] is the
/// thin env-resolving wrapper around this.
pub fn seed_tree(elements_root: &Path, run_root: &Path, resolved: &Resolved) -> Result<SeedReport, ElementsError> {
    let mut report = SeedReport::default();
    if !elements_root.is_dir() {
        return Ok(report);
    }

    let mut entries: Vec<_> = std::fs::read_dir(elements_root)
        .map_err(|e| ElementsError::new(format!("cannot read {}: {e}", elements_root.display())))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('_') {
            continue; // shelved
        }
        let element_dir = elements_root.join(&name);
        let run_dir = run_root.join(&name);
        report
            .elements
            .push(render_one_element(&element_dir, &run_dir, &name, resolved));
    }

    Ok(report)
}

/// Full render of `song`'s committed `elements/*/element.json` into
/// `run/elements/` — the shell-reachable bridge `element seed` calls,
/// against `song`'s own committed `livery.json` (the "declared" tier,
/// docs/architecture/ELEMENTS.md's "Declared" flow — a rebuild's activation
/// hook re-seeds from the STORE copy the same way).
pub fn seed_song(song: &str) -> Result<SeedReport, ElementsError> {
    let elements_root = aoide_storage::fs::songbook_dir(song).join("elements");
    let run_root = aoide_storage::fs::run_elements_dir();

    let notes_path = aoide_storage::fs::songbook_notes(song);
    let raw_notes = std::fs::read_to_string(&notes_path)
        .map_err(|e| ElementsError::new(format!("cannot read {}: {e}", notes_path.display())))?;
    let notes: serde_json::Value = serde_json::from_str(&raw_notes)
        .map_err(|e| ElementsError::new(format!("invalid JSON in {}: {e}", notes_path.display())))?;
    let validation = crate::livery::lint(&notes);
    if !validation.ok {
        return Err(ElementsError::new(format!(
            "{}: livery schema validation failed: {}",
            notes_path.display(),
            validation.errors.join("; ")
        )));
    }
    let resolved = crate::livery::resolve(&notes)
        .map_err(|e| ElementsError::new(format!("{}: {e}", notes_path.display())))?;

    seed_tree(&elements_root, &run_root, &resolved)
}

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn resolved() -> Resolved {
        let raw = std::fs::read_to_string("tests/fixtures/valid.json").unwrap();
        let container: serde_json::Value = serde_json::from_str(&raw).unwrap();
        crate::livery::resolve(&container).unwrap()
    }

    fn valid_json(element: &str) -> String {
        format!(
            r#"{{
  "v": 0,
  "element": "{element}",
  "files": [
    {{ "src": "config.jsonc", "dest": "config", "template": false }},
    {{ "src": "style.css", "template": true }}
  ],
  "surfaces": ["bar"],
  "run": {{ "exec": "waybar -c {{run}}/config -s {{run}}/style.css", "via": "unit" }},
  "reload": "pkill -SIGUSR2 -x waybar"
}}"#
        )
    }

    // ── descriptor parse/refuse vectors ──────────────────────────────────

    #[test]
    fn parse_descriptor_accepts_a_valid_v0_descriptor() {
        let d = parse_descriptor("waybar", &valid_json("waybar")).unwrap();
        assert_eq!(d.v, 0);
        assert_eq!(d.element, "waybar");
        assert_eq!(d.files.len(), 2);
        assert_eq!(d.surfaces, vec!["bar".to_string()]);
        assert_eq!(d.run.via, "unit");
        assert_eq!(d.reload.as_deref(), Some("pkill -SIGUSR2 -x waybar"));
        assert!(d.restart.is_none());
    }

    #[test]
    fn parse_descriptor_refuses_an_unknown_version() {
        let raw = r#"{ "v": 1, "element": "waybar", "files": [{"src":"a"}], "run": {"exec":"x","via":"unit"} }"#;
        let err = parse_descriptor("waybar", raw).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_a_name_that_does_not_match_the_directory() {
        let err = parse_descriptor("dunst", &valid_json("waybar")).unwrap_err();
        assert!(err.to_string().contains("does not match its directory name"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_a_malformed_name_shape() {
        let raw = r#"{ "v": 0, "element": "Way_Bar", "files": [{"src":"a"}], "run": {"exec":"x","via":"unit"} }"#;
        let err = parse_descriptor("Way_Bar", raw).unwrap_err();
        assert!(err.to_string().contains("not a valid element name"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_traversal_in_src() {
        let raw = r#"{ "v": 0, "element": "waybar", "files": [{"src":"../../etc/passwd"}], "run": {"exec":"x","via":"unit"} }"#;
        let err = parse_descriptor("waybar", raw).unwrap_err();
        assert!(err.to_string().contains("must not traverse"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_traversal_in_dest() {
        let raw = r#"{ "v": 0, "element": "waybar", "files": [{"src":"config","dest":"../outside"}], "run": {"exec":"x","via":"unit"} }"#;
        let err = parse_descriptor("waybar", raw).unwrap_err();
        assert!(err.to_string().contains("must not traverse"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_an_absolute_src() {
        let raw = r#"{ "v": 0, "element": "waybar", "files": [{"src":"/etc/passwd"}], "run": {"exec":"x","via":"unit"} }"#;
        let err = parse_descriptor("waybar", raw).unwrap_err();
        assert!(err.to_string().contains("must be relative"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_an_invalid_via() {
        let raw = r#"{ "v": 0, "element": "waybar", "files": [{"src":"a"}], "run": {"exec":"x","via":"timer"} }"#;
        let err = parse_descriptor("waybar", raw).unwrap_err();
        assert!(err.to_string().contains("run\".\"via\""), "{err}");
    }

    #[test]
    fn parse_descriptor_accepts_exec_once_via() {
        let raw = r#"{ "v": 0, "element": "waybar", "files": [{"src":"a"}], "run": {"exec":"x","via":"exec-once"} }"#;
        assert_eq!(parse_descriptor("waybar", raw).unwrap().run.via, "exec-once");
    }

    #[test]
    fn parse_descriptor_refuses_an_empty_files_list() {
        let raw = r#"{ "v": 0, "element": "waybar", "files": [], "run": {"exec":"x","via":"unit"} }"#;
        let err = parse_descriptor("waybar", raw).unwrap_err();
        assert!(err.to_string().contains("at least one file"), "{err}");
    }

    #[test]
    fn parse_descriptor_refuses_invalid_json() {
        let err = parse_descriptor("waybar", "not json").unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "{err}");
    }

    // ── {run} substitution ───────────────────────────────────────────────

    #[test]
    fn substitute_run_token_replaces_every_occurrence() {
        let run_dir = Path::new("/home/x/.aoide/run/elements/waybar");
        let out = substitute_run_token("waybar -c {run}/config -s {run}/style.css", run_dir);
        assert_eq!(
            out,
            "waybar -c /home/x/.aoide/run/elements/waybar/config -s /home/x/.aoide/run/elements/waybar/style.css"
        );
    }

    #[test]
    fn substitute_run_token_passes_through_when_absent() {
        let run_dir = Path::new("/run/elements/dunst");
        assert_eq!(substitute_run_token("dunst", run_dir), "dunst");
    }

    // ── render pipeline: byte-identity + template render ─────────────────

    #[test]
    fn render_files_copies_verbatim_files_byte_for_byte() {
        let dir = aoide_test_support::unique_tmp("elements-verbatim");
        let element_dir = dir.join("elements").join("waybar");
        std::fs::create_dir_all(&element_dir).unwrap();
        let bytes: Vec<u8> = vec![0, 159, 146, 150, b'\n', b'x']; // arbitrary, non-UTF8-safe
        std::fs::write(element_dir.join("config.jsonc"), &bytes).unwrap();

        let descriptor = parse_descriptor(
            "waybar",
            r#"{ "v": 0, "element": "waybar", "files": [{"src":"config.jsonc","dest":"config","template":false}], "run": {"exec":"x","via":"unit"} }"#,
        )
        .unwrap();

        let run_dir = dir.join("run").join("elements").join("waybar");
        let rendered = render_files(&element_dir, &run_dir, &descriptor, &resolved()).unwrap();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].dest, run_dir.join("config"));
        assert_eq!(rendered[0].bytes, bytes, "verbatim copy must be byte-identical");

        write_files(&rendered).unwrap();
        assert_eq!(std::fs::read(run_dir.join("config")).unwrap(), bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_files_renders_a_template_file_against_the_resolved_livery() {
        let dir = aoide_test_support::unique_tmp("elements-template");
        let element_dir = dir.join("elements").join("waybar");
        std::fs::create_dir_all(&element_dir).unwrap();
        std::fs::write(
            element_dir.join("style.css"),
            "window#waybar { background: {{palette.bg}}; color: {{palette.fg}}; }\n",
        )
        .unwrap();

        let descriptor = parse_descriptor(
            "waybar",
            r#"{ "v": 0, "element": "waybar", "files": [{"src":"style.css","template":true}], "run": {"exec":"x","via":"unit"} }"#,
        )
        .unwrap();

        let run_dir = dir.join("run").join("elements").join("waybar");
        let r = resolved();
        let rendered = render_files(&element_dir, &run_dir, &descriptor, &r).unwrap();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].dest, run_dir.join("style.css"), "no dest defaults to src");
        let out = String::from_utf8(rendered[0].bytes.clone()).unwrap();
        assert_eq!(
            out,
            format!(
                "window#waybar {{ background: {}; color: {}; }}\n",
                r.palette.iter().find(|(k, _)| k == "bg").unwrap().1,
                r.palette.iter().find(|(k, _)| k == "fg").unwrap().1,
            )
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_files_reports_an_unknown_placeholder_as_a_structured_error() {
        let dir = aoide_test_support::unique_tmp("elements-unknown-placeholder");
        let element_dir = dir.join("elements").join("waybar");
        std::fs::create_dir_all(&element_dir).unwrap();
        std::fs::write(element_dir.join("style.css"), "bg: {{bogus.nope}};\n").unwrap();

        let descriptor = parse_descriptor(
            "waybar",
            r#"{ "v": 0, "element": "waybar", "files": [{"src":"style.css","template":true}], "run": {"exec":"x","via":"unit"} }"#,
        )
        .unwrap();

        let run_dir = dir.join("run").join("elements").join("waybar");
        let err = render_files(&element_dir, &run_dir, &descriptor, &resolved()).unwrap_err();
        assert!(err.to_string().contains("unknown placeholder"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_files_fails_the_whole_element_on_a_missing_source_file() {
        let dir = aoide_test_support::unique_tmp("elements-missing-src");
        let element_dir = dir.join("elements").join("waybar");
        std::fs::create_dir_all(&element_dir).unwrap();
        // config.jsonc deliberately not written.

        let descriptor = parse_descriptor(
            "waybar",
            r#"{ "v": 0, "element": "waybar", "files": [{"src":"config.jsonc"}], "run": {"exec":"x","via":"unit"} }"#,
        )
        .unwrap();

        let run_dir = dir.join("run").join("elements").join("waybar");
        let err = render_files(&element_dir, &run_dir, &descriptor, &resolved()).unwrap_err();
        assert!(err.to_string().contains("cannot read"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── seed_tree: render-error isolation, `_`-shelving, whole-song walk ──

    #[test]
    fn seed_tree_renders_every_element_and_reports_per_element_status() {
        let dir = aoide_test_support::unique_tmp("elements-seed-tree");
        let elements_root = dir.join("songbook").join("moonlight").join("elements");

        // waybar: valid, template:false only.
        let waybar_dir = elements_root.join("waybar");
        std::fs::create_dir_all(&waybar_dir).unwrap();
        std::fs::write(waybar_dir.join("config.jsonc"), "{}").unwrap();
        std::fs::write(
            waybar_dir.join("element.json"),
            r#"{ "v": 0, "element": "waybar", "files": [{"src":"config.jsonc","template":false}], "run": {"exec":"waybar -c {run}/config.jsonc","via":"unit"} }"#,
        )
        .unwrap();

        // dunst: broken descriptor (bad via) — must fail in isolation.
        let dunst_dir = elements_root.join("dunst");
        std::fs::create_dir_all(&dunst_dir).unwrap();
        std::fs::write(dunst_dir.join("dunstrc"), "x").unwrap();
        std::fs::write(
            dunst_dir.join("element.json"),
            r#"{ "v": 0, "element": "dunst", "files": [{"src":"dunstrc"}], "run": {"exec":"dunst","via":"timer"} }"#,
        )
        .unwrap();

        // `_shelved`: skipped entirely, valid-looking descriptor and all.
        let shelved_dir = elements_root.join("_shelved");
        std::fs::create_dir_all(&shelved_dir).unwrap();
        std::fs::write(shelved_dir.join("x"), "x").unwrap();
        std::fs::write(
            shelved_dir.join("element.json"),
            r#"{ "v": 0, "element": "_shelved", "files": [{"src":"x"}], "run": {"exec":"x","via":"unit"} }"#,
        )
        .unwrap();

        let run_root = dir.join("run").join("elements");
        let report = seed_tree(&elements_root, &run_root, &resolved()).unwrap();

        assert_eq!(report.elements.len(), 2, "the `_shelved` dir must be skipped: {report:?}");
        assert!(report.any_failed());

        let waybar = report.elements.iter().find(|e| e.element == "waybar").unwrap();
        assert!(waybar.ok, "{waybar:?}");
        assert_eq!(waybar.files, 1);
        assert!(run_root.join("waybar").join("config.jsonc").is_file());

        let dunst = report.elements.iter().find(|e| e.element == "dunst").unwrap();
        assert!(!dunst.ok);
        assert!(dunst.error.as_deref().unwrap_or_default().contains("via"), "{dunst:?}");
        assert!(
            !run_root.join("dunst").exists(),
            "a refused descriptor must write nothing for that element"
        );

        assert!(
            !run_root.join("_shelved").exists(),
            "a shelved element must never be rendered"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_tree_reports_empty_when_the_elements_dir_is_absent() {
        let dir = aoide_test_support::unique_tmp("elements-seed-tree-absent");
        let elements_root = dir.join("songbook").join("moonlight").join("elements");
        let run_root = dir.join("run").join("elements");

        let report = seed_tree(&elements_root, &run_root, &resolved()).unwrap();
        assert!(report.elements.is_empty());
        assert!(!report.any_failed());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_tree_leaves_an_existing_config_in_place_when_a_later_file_fails_to_render() {
        // Two files in one element: the first renders fine, the second hits
        // an unknown placeholder. Nothing for this element may be written —
        // not even the first file — matching ELEMENTS.md's "a render error
        // fails that element, leaves its old config in place."
        let dir = aoide_test_support::unique_tmp("elements-seed-tree-partial");
        let elements_root = dir.join("songbook").join("moonlight").join("elements");
        let waybar_dir = elements_root.join("waybar");
        std::fs::create_dir_all(&waybar_dir).unwrap();
        std::fs::write(waybar_dir.join("config.jsonc"), "{}").unwrap();
        std::fs::write(waybar_dir.join("style.css"), "{{bogus.nope}}").unwrap();
        std::fs::write(
            waybar_dir.join("element.json"),
            r#"{ "v": 0, "element": "waybar", "files": [
                {"src":"config.jsonc","template":false},
                {"src":"style.css","template":true}
            ], "run": {"exec":"waybar","via":"unit"} }"#,
        )
        .unwrap();

        let run_root = dir.join("run").join("elements");
        let report = seed_tree(&elements_root, &run_root, &resolved()).unwrap();
        let waybar = report.elements.iter().find(|e| e.element == "waybar").unwrap();
        assert!(!waybar.ok);
        assert!(
            !run_root.join("waybar").exists(),
            "the first (valid) file must not be written when the second fails to render"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
