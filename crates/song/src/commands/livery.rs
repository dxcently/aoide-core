//! `livery emit` / `livery resolve` / `livery lint` — the native note-engine
//! verb group (LIVERY-MERGE.md Phase 1): the `drachma` CLI's surface,
//! native, inside aoide's `Invocation`/`Outcome` shell.
//!
//! The handlers carry the engine's raw byte output in `data["stdout"]` — the
//! exact bytes the Node CLI printed (resolve JSON, shell-quoted hyprctl
//! lines, the OSC stream, the compact `{ok, …}` envelopes) — so the CLI door
//! can print them raw (see the `livery` special case in `cli/src/lib.rs`,
//! mirroring `schema`/`guide`) and the MCP/A2A doors still get the
//! structured envelope.

use crate::livery;
use crate::livery::emit::hyprctl::render_lines;
use crate::livery::emit::{EmitOpts, EmitOutput, emitter};
use crate::livery::json::{JVal, write_compact};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use aoide_storage::fs as shellbridge;
use serde_json::json;
use std::path::{Path, PathBuf};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["livery", "emit"],
        summary: "Emit the fully-resolved note set through a backend: stage JSON, hyprctl keyword lines, terminal OSC sequences, or a file template ({{group.key}}).",
        args: [
            arg!("target", "string", true, "Emitter backend: stage, hyprctl, osc, or file."),
            arg!("name", "string", false, "Song name or path to a note file; defaults to the staged notes."),
        ],
        flags: [
            flag!("out", "string", "Write the emitted bytes to PATH atomically instead of stdout."),
            flag!("template", "string", "Template for the file backend ({{palette.bg}}-style placeholders)."),
        ],
        gated: false,
        implemented: true,
        handler: handle_livery_emit,
    ));
    r.insert(cmd!(
        path: ["livery", "resolve"],
        summary: "Resolve a note file to the flat, fully-resolved set (aliases deref'd, component fallbacks applied) and print it.",
        args: [arg!("name", "string", false, "Song name or path to a note file; defaults to the staged notes.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_livery_resolve,
    ));
    r.insert(cmd!(
        path: ["livery", "lint"],
        summary: "Validate a note file against the closed v0 schema (the drachma lint contract, native).",
        args: [arg!("name", "string", false, "Song name or path to a note file; defaults to the staged notes.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_livery_lint,
    ));
}

/// Resolve the note file a `livery` verb should act on — the same seam as
/// `rice lint`, but RE-IMPLEMENTED here (not reusing
/// `resolve_rice_notes` in `commands/rice.rs`): `resolve_notes` is the
/// `livery`-local copy with a `skip` offset for the verb's own leading
/// positionals — two implementations, one resolution rule:
///
/// * **no arg** — the staged notes (`<stage>/drachma.json`) if present, else
///   a usage error (exit 2),
/// * **an arg that names an existing file** — taken as a literal path,
/// * **otherwise the arg is a committed-song NAME** →
///   `<song>/songbook/<name>/drachma.json`.
///
/// `skip` offsets past the verb's own leading positionals (`livery emit`
/// takes `<target>` first, so its note name lives at args[1]).
fn resolve_notes(inv: &Invocation, cmd: &str, skip: usize) -> Result<PathBuf, Outcome> {
    match inv.args.get(skip) {
        None => {
            let staged = shellbridge::stage_dir().join("drachma.json");
            if staged.is_file() {
                Ok(staged)
            } else {
                Err(Outcome::usage(
                    cmd,
                    format!(
                        "no note named and no staged notes at {}; \
                         usage: aoide {cmd} [<name>|<path>] [--json]",
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

/// Read + parse a note file, with the Node engine's exact failure strings
/// (`cannot read {file}: {e}` / `invalid JSON in {file}: {e}`).
fn read_notes(target: &Path, cmd: &str) -> Result<serde_json::Value, Outcome> {
    let raw = match std::fs::read_to_string(target) {
        Ok(s) => s,
        Err(e) => {
            return Err(Outcome::error(
                cmd,
                format!("cannot read {}: {e}", target.display()),
            ));
        }
    };
    match serde_json::from_str(&raw) {
        Ok(v) => Ok(v),
        Err(e) => {
            Err(Outcome::error(
                cmd,
                format!("invalid JSON in {}: {e}", target.display()),
            ))
        }
    }
}

/// The Node lint envelope, byte-faithful (`{"ok":true,"schemaVersion":"0"}`
/// / `{"ok":false,"errors":[…]}` — compact, ok-first), as a string + "\n".
fn lint_envelope(ok: bool, errors: &[String]) -> String {
    let mut out = String::new();
    if ok {
        write_compact(
            &mut out,
            &JVal::obj(vec![
                ("ok".into(), JVal::boolean(true)),
                ("schemaVersion".into(), JVal::str(livery::SCHEMA_VERSION)),
            ]),
        );
    } else {
        write_compact(
            &mut out,
            &JVal::obj(vec![
                ("ok".into(), JVal::boolean(false)),
                (
                    "errors".into(),
                    JVal::arr(errors.iter().map(|e| JVal::str(e)).collect()),
                ),
            ]),
        );
    }
    out.push('\n');
    out
}

/// The shared validation-failure envelope (exit 1, never 0).
fn validation_failure(cmd: &str, target: &Path, errors: &[String]) -> Outcome {
    Outcome::error(cmd, "note schema validation reported problems").with_data(json!({
        "ok": false,
        "errors": errors,
        "notes": target.to_string_lossy(),
        "stdout": lint_envelope(false, errors),
    }))
}

/// `livery lint [<name>|<path>]` — validate against the closed v0 schema.
fn handle_livery_lint(inv: &Invocation) -> Outcome {
    let target = match resolve_notes(inv, "livery.lint", 0) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let notes = match read_notes(&target, "livery.lint") {
        Ok(v) => v,
        Err(o) => return o,
    };
    let v = livery::lint(&notes);
    if v.ok {
        Outcome::ok("livery.lint", "note schema validation passed").with_data(json!({
            "ok": true,
            "schemaVersion": livery::SCHEMA_VERSION,
            "notes": target.to_string_lossy(),
            "stdout": lint_envelope(true, &[]),
        }))
    } else {
        validation_failure("livery.lint", &target, &v.errors)
    }
}

/// `livery resolve [<name>|<path>]` — the flat, fully-resolved note set.
fn handle_livery_resolve(inv: &Invocation) -> Outcome {
    let target = match resolve_notes(inv, "livery.resolve", 0) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let notes = match read_notes(&target, "livery.resolve") {
        Ok(v) => v,
        Err(o) => return o,
    };
    let v = livery::lint(&notes);
    if !v.ok {
        return validation_failure("livery.resolve", &target, &v.errors);
    }
    match livery::resolve(&notes) {
        Ok(r) => {
            let mut stdout = livery::resolve::to_json_string(&r);
            stdout.push('\n');
            Outcome::ok("livery.resolve", "resolved").with_data(json!({
                "notes": target.to_string_lossy(),
                "stdout": stdout,
            }))
        }
        Err(e) => Outcome::error("livery.resolve", e.to_string()).with_data(json!({
            "reason": "resolve-failed",
            "notes": target.to_string_lossy(),
        })),
    }
}

/// `livery emit <target> [<name>|<path>] [--out PATH] [--template STR]` —
/// run the resolved set through one backend and print (or atomically write)
/// its bytes. `--out` generalizes the Node `emit stage --out` contract to
/// every target.
fn handle_livery_emit(inv: &Invocation) -> Outcome {
    let target = match inv.args.first() {
        Some(t) => t.clone(),
        None => {
            return Outcome::usage(
                "livery.emit",
                "usage: aoide livery emit <target> [<name>|<path>] [--out PATH] [--template STR] [--json]",
            )
            .with_data(json!({ "reason": "missing-target" }));
        }
    };
    let notes_path = match resolve_notes(inv, "livery.emit", 1) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let notes = match read_notes(&notes_path, "livery.emit") {
        Ok(v) => v,
        Err(o) => return o,
    };
    let v = livery::lint(&notes);
    if !v.ok {
        return validation_failure("livery.emit", &notes_path, &v.errors);
    }
    let resolved = match livery::resolve(&notes) {
        Ok(r) => r,
        Err(e) => {
            return Outcome::error("livery.emit", e.to_string()).with_data(json!({
                "reason": "resolve-failed",
                "notes": notes_path.to_string_lossy(),
            }));
        }
    };
    let backend = match emitter(&target) {
        Some(b) => b,
        None => {
            return Outcome::usage(
                "livery.emit",
                format!("emit: unknown target \"{target}\" (stage|hyprctl|osc|file)"),
            )
            .with_data(json!({ "reason": "unknown-target", "target": target }));
        }
    };
    let template = inv.flags.get("template").map(|s| s.as_str());
    let output = match backend.emit(&resolved, &EmitOpts { template }) {
        Ok(o) => o,
        Err(e) => {
            return Outcome::error("livery.emit", e.to_string()).with_data(json!({
                "reason": "emit-failed",
                "target": target,
            }));
        }
    };
    let stdout = match &output {
        EmitOutput::Json(v) => serde_json::to_string_pretty(v).unwrap_or_default() + "\n",
        EmitOutput::Lines(cmds) => render_lines(cmds),
        EmitOutput::Text(s) => s.clone(),
    };

    if let Some(out_path) = inv.flags.get("out") {
        if let Err(e) = shellbridge::atomic_write(Path::new(out_path), &stdout) {
            return Outcome::error("livery.emit", format!("failed to write {out_path}: {e}"))
                .with_data(json!({ "reason": "write-failed", "target": out_path }));
        }
        // The Node `--out` envelope: `{"ok":true,"wrote":<path>}`.
        let mut envelope = String::new();
        write_compact(
            &mut envelope,
            &JVal::obj(vec![
                ("ok".into(), JVal::boolean(true)),
                ("wrote".into(), JVal::str(out_path)),
            ]),
        );
        envelope.push('\n');
        return Outcome::ok("livery.emit", format!("wrote {out_path}"))
            .changed(vec![out_path.clone()])
            .with_data(json!({
                "ok": true,
                "wrote": out_path,
                "notes": notes_path.to_string_lossy(),
                "stdout": envelope,
            }));
    }

    Outcome::ok("livery.emit", format!("emitted {target}")).with_data(json!({
        "target": target,
        "notes": notes_path.to_string_lossy(),
        "stdout": stdout,
    }))
}
