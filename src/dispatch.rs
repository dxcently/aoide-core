//! The single command dispatcher.
//!
//! Both the CLI door (`bin/aoide.rs`) and the MCP door (`mcp.rs`) call
//! [`dispatch`] with a command path + parsed args/flags. There is ONE
//! implementation of every command; the two doors cannot drift because both
//! land here (concepts/Agent-Interface: "two doors, one schema").

use crate::daemon::{self, Door};
use crate::guide::GUIDE;
use crate::output::Outcome;
use crate::schema;
use crate::{notes, shellbridge};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Parsed invocation handed to the dispatcher.
#[derive(Debug)]
pub struct Invocation {
    /// Command path, e.g. `["rice", "gen"]`.
    pub path: Vec<String>,
    /// Positional args in order.
    pub args: Vec<String>,
    /// Named flags (`--foo bar`, or `--foo` → `"true"`).
    pub flags: BTreeMap<String, String>,
    /// Which door this came through (for the audit log).
    pub door: Door,
}

impl Invocation {
    pub fn flag_present(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
    pub fn dotted(&self) -> String {
        self.path.join(".")
    }
}

/// Look up the schema entry for a command path.
fn schema_for(path: &[String]) -> Option<schema::Command> {
    schema::commands()
        .into_iter()
        .find(|c| c.path.len() == path.len() && c.path.iter().zip(path).all(|(a, b)| *a == b))
}

/// The audit-log path in effect (flag override → `aoide.auditLog` default).
fn audit_log_path(inv: &Invocation) -> std::path::PathBuf {
    if let Some(p) = inv.flags.get("audit-log") {
        return std::path::PathBuf::from(p);
    }
    daemon::default_audit_log()
}

/// Dispatch one invocation to its handler and return the structured outcome.
/// Every path here also appends to the single audit log — both doors inherit
/// the same policy surface (concepts/Governance).
pub fn dispatch(inv: &Invocation) -> Outcome {
    let cmd = inv.dotted();
    let meta = schema_for(&inv.path);

    let outcome = match inv
        .path
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["guide"] => Outcome::ok("guide", "printed the four-tier onboarding")
            .with_data(json!({ "text": GUIDE })),

        ["schema"] => {
            let doc = schema::schema();
            let val = serde_json::to_value(&doc).unwrap_or(Value::Null);
            Outcome::ok("schema", "emitted the v0 command + state-file schema").with_data(val)
        }

        ["rice", "lint"] => handle_rice_lint(inv),
        ["rice", "preview"] => handle_rice_preview(inv),

        ["mcp", "serve"] => Outcome::ok(
            "mcp.serve",
            "MCP stdio server is spawned via the binary entrypoint; \
             its tool list is generated from `schema --json`",
        )
        .with_data(json!({
            "hint": "run `aoide mcp serve --stdio` to serve; tools derive from the schema",
            "toolCount": schema::commands().len(),
        })),

        ["daemon"] => {
            let log = audit_log_path(inv);
            let status = daemon::run(log);
            Outcome::ok("daemon", "aoided skeleton self-check complete").with_data(status)
        }

        // ── graph: project/session DAG viewer + manager (graph.rs) ──────────
        ["graph", "view"] => crate::graph::view(inv),
        ["graph", "project", "add"] => crate::graph::project_add(inv),
        ["graph", "project", "remove"] => crate::graph::project_remove(inv),
        ["graph", "project", "list"] => crate::graph::project_list(inv),
        ["graph", "link"] => crate::graph::link(inv),
        ["graph", "session", "start"] => crate::graph::session_start(inv),
        ["graph", "session", "phase"] => crate::graph::session_phase(inv),
        ["graph", "session", "end"] => crate::graph::session_end(inv),
        ["graph", "session", "hook"] => crate::graph::session_hook(inv),
        ["graph", "focus"] => crate::graph::focus(inv),
        ["graph", "prune"] => crate::graph::prune(inv),
        ["graph", "emit"] => crate::graph::emit(inv),

        ["shellbridge"] => {
            let status = crate::shellbridge::run();
            Outcome::ok("shellbridge", "shellbridge skeleton self-check complete").with_data(status)
        }

        // `baton` is interactive: like `mcp serve --stdio`, the loop itself is
        // resolved at the entry point (lib.rs) — everything below stays
        // frontend-agnostic. This arm only RECORDS the launch (so the audit log
        // carries the door-open the baton then tails) and, for a non-interactive
        // door (MCP/daemon), returns the "run it from a terminal" outcome. The
        // CLI door short-circuits in run_cli AFTER dispatching here, so on the
        // Cli path this is the audit record, not a stub.
        ["baton"] => match inv.door {
            Door::Cli => Outcome::ok("baton", "raising the baton over the agent sessions")
                .with_data(json!({
                    "interactive": true,
                    "stageDir": crate::shellbridge::stage_dir().to_string_lossy(),
                })),
            _ => Outcome::ok(
                "baton",
                "baton is interactive; run `aoide baton` from a terminal (not over this door)",
            )
            .with_data(json!({ "interactive": true, "door": "non-cli" })),
        },

        ["adapter", "melete"] => {
            let status = crate::adapter::run_melete();
            Outcome::ok(
                "adapter.melete",
                "melete-adapter skeleton self-check complete",
            )
            .with_data(status)
        }

        // ── Structured "not-implemented" stubs (walking skeleton) ───────────
        _ => match &meta {
            Some(m) => Outcome::not_implemented(cmd.clone(), m.gated).with_data(json!({
                "path": m.path,
                "args": inv.args,
                "flags": inv.flags,
            })),
            None => Outcome::usage(
                cmd.clone(),
                format!("unknown command: `{}`", cmd.replace('.', " ")),
            ),
        },
    };

    // Wire the audit-log append as a real code path for every dispatch.
    let log = audit_log_path(inv);
    let _ = daemon::audit(
        &log,
        inv.door,
        daemon::EventClass::Audit,
        &cmd,
        match outcome.status {
            crate::output::Status::Ok => "ok",
            crate::output::Status::Error => "error",
            crate::output::Status::Usage => "usage",
            crate::output::Status::NotImplemented => "not-implemented",
        },
        &outcome.message,
    );

    // Mark gated commands so both doors surface the gate uniformly.
    match meta {
        Some(m) if m.gated => outcome.gated(true),
        _ => outcome,
    }
}

/// Resolve the `notes.json` a `rice` verb should act on:
///
/// * **no arg** — the staged notes (`<stage>/notes.json`) if present, else a
///   usage error (exit 2). We never delegate to drachma with no file.
/// * **an arg that names an existing file** — taken as a literal path.
/// * **otherwise the arg is a committed-song NAME** →
///   `<song>/repertoire/<name>/notes.json` (resolved through the same stage-dir
///   seam as `graph emit`, so an `AOIDE_STAGE_DIR` override relocates it too).
fn resolve_rice_notes(inv: &Invocation, cmd: &str) -> Result<PathBuf, Outcome> {
    match inv.args.first() {
        None => {
            let staged = shellbridge::stage_dir().join("notes.json");
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
                Ok(shellbridge::repertoire_notes(arg))
            }
        }
    }
}

/// `rice lint [<name>|<path>]` — validate a rice against the note schema.
///
/// Delegates to `drachma lint <notes.json>`, tolerating drachma's absence. The
/// no-arg form lints the staged rice; a bare `<name>` resolves to the committed
/// song's notes (never passed to drachma as a literal path). An error envelope
/// always carries a non-zero exit (drachma failure → exit 1).
fn handle_rice_lint(inv: &Invocation) -> Outcome {
    let target = match resolve_rice_notes(inv, "rice.lint") {
        Ok(p) => p,
        Err(o) => return o,
    };
    let run = notes::run_lint(&[target.to_string_lossy().into_owned()]);
    match run.located {
        None => Outcome::error(
            "rice.lint",
            "drachma not found; set $AOIDE_DRACHMA_BIN or put it on PATH",
        )
        .with_data(json!({
            "reason": "notes-binary-unavailable",
            "searched": ["$AOIDE_DRACHMA_BIN", "PATH"],
            "notes": target.to_string_lossy(),
        })),
        Some(bin) => {
            let ok = run.exit_code == Some(0);
            let out = if ok {
                Outcome::ok("rice.lint", "note schema validation passed")
            } else {
                // Error status → exit 1 (never a status:error with exit 0).
                Outcome::error("rice.lint", "note schema validation reported problems")
            };
            out.with_data(json!({
                "delegate": bin.to_string_lossy(),
                "notes": target.to_string_lossy(),
                "exitCode": run.exit_code,
                "stdout": run.stdout,
                "stderr": run.stderr,
            }))
        }
    }
}

/// Extensions we recognise as cover art, in preference order.
const COVER_EXTS: &[&str] = &["webp", "png", "jpg", "jpeg"];

/// Derive a physical cover-art file for a song, or `None` when none exists.
///
/// v0 notes carry no runtime cover field (the schema is palette-closed; the
/// build-time `aoide.notes.wallpaper` is a nix path, not a song/ runtime read),
/// so a cover is only ever staged when one is physically present: first a
/// `cover.<ext>` co-located with the song, then `<covers>/<name>.<ext>`.
fn derive_cover(name: &str) -> Option<PathBuf> {
    if let Some(dir) = shellbridge::repertoire_notes(name).parent() {
        for ext in COVER_EXTS {
            let p = dir.join(format!("cover.{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let covers = shellbridge::covers_dir();
    for ext in COVER_EXTS {
        let p = covers.join(format!("{name}.{ext}"));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// `rice preview <name>` — rehearse a committed song live: stage its
/// `notes.json` (and a derivable cover) into `<stage>/` so the Quickshell
/// surfaces hot-reload it. Nothing is committed; no compositor dispatch in v1.
///
/// This is the honest form of the hand-copy agents had been doing: drive the
/// repertoire notes into the stage so the shell has a palette to render.
fn handle_rice_preview(inv: &Invocation) -> Outcome {
    let name = match inv.args.first() {
        Some(n) => n.clone(),
        None => {
            return Outcome::usage("rice.preview", "usage: aoide rice preview <name> [--json]")
                .with_data(json!({ "reason": "missing-name" }));
        }
    };

    let notes_src = shellbridge::repertoire_notes(&name);
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
    // (full schema validation is `rice lint`'s job / drachma's).
    if let Err(e) = serde_json::from_str::<Value>(&raw) {
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

    let stage = shellbridge::stage_dir();
    let notes_dst = stage.join("notes.json");
    if let Err(e) = shellbridge::atomic_write(&notes_dst, &raw) {
        return Outcome::error("rice.preview", format!("failed to stage notes.json: {e}"))
            .with_data(json!({ "reason": "stage-write-failed", "target": notes_dst.to_string_lossy() }));
    }
    let mut changed: Vec<String> = vec![notes_dst.to_string_lossy().into_owned()];

    // Cover: staged only when physically derivable; otherwise left untouched.
    let cover = derive_cover(&name);
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
        "seam": "compositor dispatch (hyprctl/OSC) not performed in v1; \
                 Quickshell hot-reloads stage/notes.json",
    }))
}

// ── Tests (rice lint resolution + rice preview staging) ──────────────────────
//
// These drive process-global env (`AOIDE_STAGE_DIR`, and `PATH`/
// `AOIDE_DRACHMA_BIN` to force drachma un-locatable so a lint outcome is
// deterministic without the note engine on the sandbox PATH). They serialise
// on the crate-wide env lock.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Status;

    fn unique_tmp(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "aoide-dispatch-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn inv(path: &[&str], args: &[&str]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: BTreeMap::new(),
            door: Door::Cli,
        }
    }

    // Restore env vars on drop so a panicking assertion never leaks state.
    struct EnvSaver {
        keys: Vec<(&'static str, Option<String>)>,
    }
    impl EnvSaver {
        fn capture(keys: &[&'static str]) -> Self {
            EnvSaver {
                keys: keys.iter().map(|k| (*k, std::env::var(k).ok())).collect(),
            }
        }
    }
    impl Drop for EnvSaver {
        fn drop(&mut self) {
            for (k, v) in &self.keys {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    const VALID_NOTES: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"} }"##;

    // Force drachma un-locatable so lint outcomes don't depend on the sandbox
    // PATH (drachma is not a build dep of aoide; the checkPhase has no PATH copy).
    fn hide_drachma() {
        std::env::set_var("PATH", "");
        std::env::set_var("AOIDE_DRACHMA_BIN", "");
    }

    #[test]
    fn lint_no_arg_without_staged_notes_is_usage_exit_2() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("lint-nostage"); // exists, but no notes.json
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[]));
        assert_eq!(out.status, Status::Usage, "no-arg + no staged notes → usage");
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn lint_no_arg_resolves_staged_default_and_errors_nonzero() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "PATH", "AOIDE_DRACHMA_BIN"]);
        let stage = unique_tmp("lint-staged");
        std::fs::write(stage.join("notes.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        hide_drachma();

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[]));
        // Resolved the STAGED default (else this would be a Usage error), and
        // with drachma absent the envelope is an error → exit 1, never 0.
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert!(notes.ends_with("notes.json"), "lint targeted the staged notes: {notes}");
        assert!(notes.starts_with(stage.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn lint_bare_name_resolves_to_repertoire_notes_not_a_literal_path() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "PATH", "AOIDE_DRACHMA_BIN"]);
        let root = unique_tmp("lint-name");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        hide_drachma();

        // `moonlight` is a NAME, not a path — it must resolve under repertoire/.
        let out = handle_rice_lint(&inv(&["rice", "lint"], &["moonlight"]));
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert!(
            notes.ends_with("repertoire/moonlight/notes.json"),
            "bare name resolved to the repertoire song: {notes}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lint_existing_path_arg_is_taken_literally() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "PATH", "AOIDE_DRACHMA_BIN"]);
        let root = unique_tmp("lint-path");
        let file = root.join("elsewhere.json");
        std::fs::write(&file, VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", root.join("stage"));
        hide_drachma();

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[file.to_str().unwrap()]));
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert_eq!(notes, file.to_string_lossy(), "an existing path is literal");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preview_stages_notes_and_reports_no_derivable_cover() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("preview-ok");
        let stage = root.join("stage");
        let song = root.join("repertoire").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("notes.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        // notes.json landed in the stage, byte-identical to the source.
        let staged = std::fs::read_to_string(stage.join("notes.json")).unwrap();
        assert_eq!(staged, VALID_NOTES);
        assert!(out
            .changed
            .iter()
            .any(|c| c.ends_with("stage/notes.json")));
        // No cover exists for moonlight → cover.json is left untouched.
        assert!(!stage.join("cover.json").exists());
        assert!(out.data.unwrap()["cover"].is_null());
        assert!(out.message.contains("cover.json left untouched"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preview_stages_a_derivable_cover_from_covers_dir() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("preview-cover");
        let stage = root.join("stage");
        let song = root.join("repertoire").join("dusk");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(song.join("notes.json"), VALID_NOTES).unwrap();
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
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("preview-missing").join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["nope"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "song-not-found");
    }

    #[test]
    fn preview_missing_name_is_usage_exit_2() {
        let out = handle_rice_preview(&inv(&["rice", "preview"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
    }
}
