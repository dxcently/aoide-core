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
        ["rice", "mint"] => handle_rice_mint(inv),

        // ── cover: the live wallpaper write-path (song/covers/ → stage) ──────
        ["cover", "set"] => handle_cover_set(inv),

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
        ["graph", "wrap"] => crate::graph::session_wrap(inv),
        ["graph", "send"] => crate::graph::session_send(inv),
        ["graph", "focus"] => crate::graph::focus(inv),
        ["graph", "prune"] => crate::graph::prune(inv),
        ["graph", "reap"] => crate::reap::reap(inv),
        ["graph", "emit"] => crate::graph::emit(inv),

        // ── conduct: the PTY-backed conductable wrap (graph.rs) ─────────────
        ["conduct"] => crate::graph::session_conduct(inv),

        ["shellbridge"] => {
            let status = crate::shellbridge::run();
            Outcome::ok("shellbridge", "shellbridge skeleton self-check complete").with_data(status)
        }

        // `conductor` is interactive: like `mcp serve --stdio`, the loop itself
        // is resolved at the entry point (lib.rs) — everything below stays
        // frontend-agnostic. This arm only RECORDS the launch (so the audit log
        // carries the door-open the conductor then tails) and, for a
        // non-interactive door (MCP/daemon), returns the "run it from a
        // terminal" outcome. The CLI door short-circuits in run_cli AFTER
        // dispatching here, so on the Cli path this is the audit record, not a
        // stub.
        ["conductor"] => match inv.door {
            Door::Cli => Outcome::ok("conductor", "raising the conductor over the agent sessions")
                .with_data(json!({
                    "interactive": true,
                    "stageDir": crate::shellbridge::stage_dir().to_string_lossy(),
                })),
            _ => Outcome::ok(
                "conductor",
                "conductor is interactive; run `aoide conductor` from a terminal (not over this door)",
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

/// Resolve the `drachma.json` a `rice` verb should act on:
///
/// * **no arg** — the staged notes (`<stage>/drachma.json`) if present, else a
///   usage error (exit 2). We never delegate to drachma with no file.
/// * **an arg that names an existing file** — taken as a literal path.
/// * **otherwise the arg is a committed-song NAME** →
///   `<song>/songbook/<name>/drachma.json` (resolved through the same stage-dir
///   seam as `graph emit`, so an `AOIDE_STAGE_DIR` override relocates it too).
fn resolve_rice_notes(inv: &Invocation, cmd: &str) -> Result<PathBuf, Outcome> {
    match inv.args.first() {
        None => {
            let staged = shellbridge::stage_dir().join("drachma.json");
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
/// Delegates to `drachma lint <drachma.json>`, tolerating drachma's absence. The
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
/// build-time `aoide.drachma.wallpaper` is a nix path, not a song/ runtime read),
/// so a cover is only ever staged when one is physically present. Covers live
/// in the shared library `song/covers/` — one dir any song (or other consumer)
/// draws from — so the derivable name is `<name>.<ext>` there (a bare
/// `cover.<ext>` would be ambiguous in a shared dir).
fn derive_cover(name: &str) -> Option<PathBuf> {
    let covers = shellbridge::song_dir().join("covers");
    for ext in COVER_EXTS {
        let p = covers.join(format!("{name}.{ext}"));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// `rice preview <name>` — rehearse a committed song live: stage its
/// `drachma.json` (and a derivable cover) into `<stage>/` so the Quickshell
/// surfaces hot-reload it, AND best-effort live-apply its geometry + border
/// colours to the running compositor via `hyprctl --batch keyword …`
/// (guarded on `$HYPRLAND_INSTANCE_SIGNATURE`; see hypr.rs). Nothing is
/// committed; the hyprctl call is keyword-only (never `reload`) and never
/// fatal — a failed/absent hyprctl still leaves the stage file updated.
///
/// This is the honest form of the hand-copy agents had been doing: drive the
/// songbook notes into the stage so the shell has a palette to render.
fn handle_rice_preview(inv: &Invocation) -> Outcome {
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
    // (full schema validation is `rice lint`'s job / drachma's).
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
    let hypr_keywords = crate::hypr::geometry_keywords(&parsed);

    // Inject the song name into the staged notes: DrachmaState.qml's
    // `songName` property reads this to resolve per-song flavor widgets
    // (StagingEngine.qml / WidgetSlot.qml) — CONTRACTS.md §4's "additive"
    // precedent (mirrors `parentSessionId` on session records). When the
    // notes don't parse as an object (shouldn't happen for a valid drachma
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
    let notes_dst = stage.join("drachma.json");
    if let Err(e) = shellbridge::atomic_write(&notes_dst, &staged) {
        return Outcome::error("rice.preview", format!("failed to stage drachma.json: {e}"))
            .with_data(json!({ "reason": "stage-write-failed", "target": notes_dst.to_string_lossy() }));
    }
    let mut changed: Vec<String> = vec![notes_dst.to_string_lossy().into_owned()];

    // Live-apply geometry + border colours on the compositor side (best-effort,
    // guarded, non-fatal). The stage-file write above is already the source of
    // truth for the hot-reload half (Quickshell's FileView); this hyprctl call
    // is on top of it, never a precondition for it — a failed/absent hyprctl
    // never turns this preview into an error. No `hyprctl reload`: see hypr.rs.
    let hyprctl_status = crate::hypr::apply_live(&hypr_keywords);

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
        "hyprctl": hyprctl_status,
        "seam": "Quickshell hot-reloads stage/drachma.json (palette + component tiers); \
                 geometry + border colours are ALSO applied live via best-effort, \
                 guarded `hyprctl --batch keyword …` (see hypr.rs) — keyword-only, \
                 never `hyprctl reload`",
    }))
}

/// A valid `rice mint`/`rice new` song name: `^[a-z0-9][a-z0-9-]*$`. This one
/// check also rejects path traversal (`..`, `/`) and case/underscore variance
/// by construction — nothing outside `[a-z0-9-]` is accepted, and the first
/// character can never be a `-`.
fn valid_song_name(name: &str) -> bool {
    let mut chars = name.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Render one JSON scalar as a nix literal. The notes tiers `rice mint` reads
/// (palette / window / geometry) are leaves only — string, bool, number, or
/// null — so this never needs to handle arrays/objects.
fn nix_scalar(v: &Value) -> String {
    // ORDER MATTERS: backslash first (so the later escapes don't get
    // double-escaped), then the closing quote, then `$` — `\$` is the Nix
    // double-quoted-string escape that neutralizes `${…}` interpolation, so a
    // notes value like `"${builtins.readFile /etc/hostname}"` round-trips
    // into `rice.nix` as an inert literal, never live Nix interpolation.
    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
    }
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", escape(s)),
        other => format!("\"{}\"", escape(&other.to_string())),
    }
}

/// Render `key = value;` lines (one per line, `indent`-prefixed) for a FIXED
/// key list, pulling each value from `obj` (missing key → `null`). Used for
/// the window/geometry tiers so a partially-set source still yields the full
/// fixed key set — never a ragged subset a reader has to guess is exhaustive.
fn nix_fixed_fields(obj: Option<&serde_json::Map<String, Value>>, keys: &[&str], indent: &str) -> String {
    keys.iter()
        .map(|k| {
            let v = obj.and_then(|o| o.get(*k)).cloned().unwrap_or(Value::Null);
            format!("{indent}{k} = {};\n", nix_scalar(&v))
        })
        .collect()
}

/// The geometry tier's fixed key set, in the order CONTRACTS.md §1's table
/// lists them.
const GEOMETRY_KEYS: &[&str] = &[
    "gapsOut", "gapsIn", "borderSize", "rounding", "blurEnabled", "blurSize", "blurPasses",
];
/// The window (border-colour) component tier's fixed key set.
const WINDOW_KEYS: &[&str] = &["border", "borderInactive"];

/// Render one `rice.nix` for `rice mint`: a self-gating skeleton copying
/// `notes`' palette/window/geometry into `aoide.drachma.<tier>` under
/// `config.aoide.song == "<name>"` — the same shape as every committed song
/// (CONTRACTS.md §5). `had_geometry`/`had_window` distinguish "copied from
/// `from`" from "`from` set no opinion here, this is a fill template" in the
/// leading comment of each block, so a reader never mistakes an all-null
/// template for an intentional all-null override.
fn render_rice_nix(name: &str, from: &str, notes: &Value) -> String {
    let palette_lines = notes
        .get("palette")
        .and_then(Value::as_object)
        .map(|p| {
            p.iter()
                .map(|(k, v)| format!("      \"{k}\" = {};\n", nix_scalar(v)))
                .collect::<String>()
        })
        .unwrap_or_default();

    let window_obj = notes.get("window").and_then(Value::as_object);
    let window_lines = nix_fixed_fields(window_obj, WINDOW_KEYS, "      ");
    let window_comment = if window_obj.is_some() {
        format!("inherited from song \"{from}\"")
    } else {
        format!("\"{from}\" set no window-colour overrides — null falls back to palette.accent/bg")
    };

    let geometry_obj = notes.get("geometry").and_then(Value::as_object);
    let geometry_lines = nix_fixed_fields(geometry_obj, GEOMETRY_KEYS, "      ");
    let geometry_comment = if geometry_obj.is_some() {
        format!("inherited from song \"{from}\"")
    } else {
        format!(
            "fill template — \"{from}\" carries no geometry tier; null leaves the \
             host/compositor default (CONTRACTS.md §1)"
        )
    };

    let mut s = String::new();
    s.push_str(&format!(
        "# song/songbook/{name}/rice.nix — scaffolded via `aoide rice mint` from song \"{from}\".\n"
    ));
    s.push_str("#\n");
    s.push_str("# HOST-AGNOSTIC DISCIPLINE (CONTRACTS.md §5): a song sets ONLY aoide.drachma.\n");
    s.push_str("# All drachma values are literal nix expressions (no song/ runtime reads).\n");
    s.push_str("{ lib, config, ... }:\n");
    s.push_str("{\n");
    s.push_str(&format!(
        "  config = lib.mkIf (config.aoide.song == \"{name}\") {{\n"
    ));

    s.push_str("\n    aoide.drachma.palette = {\n");
    s.push_str(&palette_lines);
    s.push_str("    };\n");

    s.push_str(&format!("\n    # {window_comment}\n"));
    s.push_str("    aoide.drachma.window = {\n");
    s.push_str(&window_lines);
    s.push_str("    };\n");

    s.push_str(&format!("\n    # {geometry_comment}\n"));
    s.push_str("    aoide.drachma.geometry = {\n");
    s.push_str(&geometry_lines);
    s.push_str("    };\n");

    s.push_str("  };\n");
    s.push_str("}\n");
    s
}

/// Render `design/intent.md` for `rice mint`: honest-empty — no fabricated
/// rationale, just what IS true (inherited from `from`, retune it) and where
/// to go to actually fill it in.
fn render_intent_md(name: &str, from: &str) -> String {
    format!(
        "# {name} — Design Intent\n\
         \n\
         **Rice:** {name}\n\
         **Palette/geometry:** inherited from `{from}` — retune\n\
         \n\
         ---\n\
         \n\
         ## Palette Rationale\n\
         \n\
         (not yet written — this rice was scaffolded from `{from}` via `aoide rice mint`, not designed)\n\
         \n\
         ## Component Tier\n\
         \n\
         (not yet written)\n\
         \n\
         ## Geometry\n\
         \n\
         (not yet written)\n\
         \n\
         ## Iteration Log\n\
         \n\
         ## How to fill this rice\n\
         \n\
         - Slot catalog (which slots a host wires today, what each expects): \
           `modules/facets/quickshell/qml/slots.md`\n\
         - Per-song widget contract: `CONTRACTS.md` §5, \"Per-song flavor widgets\"\n\
         - Songbook playbook: `song/songbook/update-playbook.md`\n\
         - Drop a `widgets/<slot>.qml` here to dress a slot — any file under `widgets/` \
           becomes a slot named for its basename; nothing renders until a host surface \
           embeds a `WidgetSlot` anchor for that name.\n"
    )
}

/// `rice mint <name> [--from <song>] [--force]` — scaffold a new committed
/// song under `song/songbook/<name>/` by copying an existing song's notes.
/// `aoide rice new` (cli.rs) is a pure parse alias for this same path — there
/// is only ONE registry entry (`rice.mint`).
///
/// Writes ONLY inside `song/songbook/<name>/` (house rule 1): `rice.nix` (a
/// self-gating skeleton — the sole `.nix` file, satisfying `checks.song-shape`),
/// `drachma.json` (a mirror of `--from`'s, INCLUDING any geometry block, so
/// `aoide rice preview <name>` renders + live-applies immediately),
/// `design/intent.md` (honest-empty — no fabricated rationale), and
/// `widgets/.gitkeep` (no per-song widgets yet). No `hypr/` dir: geometry
/// lives in drachma, not a build fragment.
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

    if !valid_song_name(&name) {
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

    if !valid_song_name(&from) {
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

    let rice_nix = render_rice_nix(&name, &from, &from_parsed);
    let intent_md = render_intent_md(&name, &from);

    let writes: [(PathBuf, String); 4] = [
        (target.join("rice.nix"), rice_nix),
        (target.join("drachma.json"), raw_notes.clone()),
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

/// `cover set <path>` — switch the live wallpaper by staging a new cover.
///
/// This is the WRITE path the Quickshell wallpaper picker shells out to (QML has
/// no file-write primitive). It resolves `<path>` to an absolute cover file, then
/// atomic-writes `{ "path": "<abs>" }` to `<stage>/cover.json` — exactly the seam
/// [`handle_rice_preview`] uses, which `AoideWallpaper.qml`'s FileView watches and
/// hot-swaps live. Nothing is committed; the baked `AOIDE_WALLPAPER` remains the
/// boot/rebuild fallback.
///
/// Resolution: an absolute `<path>` is taken literally; a bare filename resolves
/// against the shared cover library `song/covers/`. A path that names no existing
/// file is a clear error (exit 1) — we never stage a wallpaper that can't render.
fn handle_cover_set(inv: &Invocation) -> Outcome {
    let arg = match inv.args.first() {
        Some(a) => a.clone(),
        None => {
            return Outcome::usage(
                "cover.set",
                "usage: aoide cover set <path|name> [--json]",
            )
            .with_data(json!({ "reason": "missing-path" }));
        }
    };

    // Absolute path → literal; anything else → the shared covers/ library.
    let literal = PathBuf::from(&arg);
    let resolved = if literal.is_absolute() {
        literal
    } else {
        shellbridge::song_dir().join("covers").join(&arg)
    };

    if !resolved.is_file() {
        return Outcome::error(
            "cover.set",
            format!("no cover at {}: not a file", resolved.display()),
        )
        .with_data(json!({
            "reason": "cover-not-found",
            "arg": arg,
            "resolved": resolved.to_string_lossy(),
        }));
    }

    // Stage cover.json exactly like handle_rice_preview: pretty `{ "path": … }`
    // with a trailing newline, atomic write into the stage dir.
    let stage = shellbridge::stage_dir();
    let cover_dst = stage.join("cover.json");
    let body = serde_json::to_string_pretty(&json!({ "path": resolved.to_string_lossy() }))
        .unwrap_or_default()
        + "\n";
    if let Err(e) = shellbridge::atomic_write(&cover_dst, &body) {
        return Outcome::error("cover.set", format!("failed to stage cover.json: {e}"))
            .with_data(json!({
                "reason": "stage-write-failed",
                "target": cover_dst.to_string_lossy(),
            }));
    }

    Outcome::ok(
        "cover.set",
        format!("wallpaper set to {} — stage/cover.json live for hot-swap", resolved.display()),
    )
    .changed(vec![cover_dst.to_string_lossy().into_owned()])
    .with_data(json!({
        "cover": resolved.to_string_lossy(),
        "coverJson": cover_dst.to_string_lossy(),
        "seam": "AoideWallpaper.qml FileView-watches stage/cover.json and hot-swaps live",
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

    // Carries a `window` block (border colours), so `hyprctl` keyword-batch
    // construction has something to resolve — VALID_NOTES deliberately does
    // not, to exercise the "empty batch" path elsewhere.
    const NOTES_WITH_WINDOW: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
        "window": {"border":"#82aaff","borderInactive":"#0b1021"} }"##;

    // A song with palette + window + a full geometry block, for `rice mint`
    // tests that need to assert every tier round-trips.
    const NOTES_WITH_GEOMETRY: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
        "window": {"border":"#82aaff","borderInactive":"#0b1021"},
        "geometry": {"gapsOut":10,"gapsIn":4,"borderSize":3,"rounding":6,
                     "blurEnabled":false,"blurSize":5,"blurPasses":2} }"##;

    // A hostile palette value carrying live Nix interpolation syntax — proves
    // `nix_scalar` neutralizes `${…}` rather than letting it round-trip into
    // `rice.nix` as a real interpolation (a real injection: a value like
    // `"${builtins.readFile /etc/hostname}"` would otherwise EVALUATE).
    const NOTES_WITH_INTERPOLATION: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"${builtins.currentTime}","fg":"#c8d3f5",
                     "accent":"#82aaff","urgent":"#ff757f"} }"##;

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
        let stage = unique_tmp("lint-nostage"); // exists, but no drachma.json
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
        std::fs::write(stage.join("drachma.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        hide_drachma();

        let out = handle_rice_lint(&inv(&["rice", "lint"], &[]));
        // Resolved the STAGED default (else this would be a Usage error), and
        // with drachma absent the envelope is an error → exit 1, never 0.
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert!(notes.ends_with("drachma.json"), "lint targeted the staged notes: {notes}");
        assert!(notes.starts_with(stage.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn lint_bare_name_resolves_to_songbook_notes_not_a_literal_path() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "PATH", "AOIDE_DRACHMA_BIN"]);
        let root = unique_tmp("lint-name");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        hide_drachma();

        // `moonlight` is a NAME, not a path — it must resolve under songbook/.
        let out = handle_rice_lint(&inv(&["rice", "lint"], &["moonlight"]));
        let notes = out.data.unwrap()["notes"].as_str().unwrap().to_string();
        assert!(
            notes.ends_with("songbook/moonlight/drachma.json"),
            "bare name resolved to the songbook song: {notes}"
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
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("drachma.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_preview(&inv(&["rice", "preview"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok);
        // drachma.json landed in the stage with the song name injected, and
        // its original fields (e.g. the palette) survived the round-trip.
        let staged = std::fs::read_to_string(stage.join("drachma.json")).unwrap();
        let parsed: Value = serde_json::from_str(&staged).unwrap();
        assert_eq!(parsed["song"], "moonlight");
        assert_eq!(parsed["palette"]["bg"], "#0b1021");
        assert!(out
            .changed
            .iter()
            .any(|c| c.ends_with("stage/drachma.json")));
        // No cover exists for moonlight → cover.json is left untouched.
        assert!(!stage.join("cover.json").exists());
        assert!(out.data.unwrap()["cover"].is_null());
        assert!(out.message.contains("cover.json left untouched"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preview_stages_a_derivable_cover_from_the_covers_library() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("preview-cover");
        let stage = root.join("stage");
        let song = root.join("songbook").join("dusk");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(song.join("drachma.json"), VALID_NOTES).unwrap();
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

    // ── cover set ────────────────────────────────────────────────────────────

    #[test]
    fn cover_set_stages_an_absolute_path() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-abs");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let img = root.join("elsewhere.png");
        std::fs::write(&img, b"\x89PNG stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &[img.to_str().unwrap()]));
        assert_eq!(out.status, Status::Ok);
        // cover.json landed in the stage and points at the absolute path.
        let cover = std::fs::read_to_string(stage.join("cover.json")).unwrap();
        assert!(cover.contains("elsewhere.png"), "cover.json points at the file: {cover}");
        assert!(cover.ends_with("\n"), "trailing newline mirrors handle_rice_preview");
        assert!(out.changed.iter().any(|c| c.ends_with("cover.json")));
        assert_eq!(
            out.data.unwrap()["cover"].as_str().unwrap(),
            img.to_string_lossy()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_resolves_a_bare_name_against_the_covers_library() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-name");
        let stage = root.join("stage");
        let covers = root.join("covers");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&covers).unwrap();
        std::fs::write(covers.join("sonata.webp"), b"RIFF stub").unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &["sonata.webp"]));
        assert_eq!(out.status, Status::Ok);
        let staged = out.data.unwrap()["cover"].as_str().unwrap().to_string();
        assert!(
            staged.ends_with("covers/sonata.webp"),
            "bare name resolved under the shared covers library: {staged}"
        );
        let cover = std::fs::read_to_string(stage.join("cover.json")).unwrap();
        assert!(cover.contains("covers/sonata.webp"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_missing_file_is_error_exit_1() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("cover-missing");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_cover_set(&inv(&["cover", "set"], &["nope.png"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "cover-not-found");
        // Nothing was staged for a missing file.
        assert!(!stage.join("cover.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cover_set_missing_arg_is_usage_exit_2() {
        let out = handle_cover_set(&inv(&["cover", "set"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
    }

    // ── rice preview: the hyprctl live-apply guard (Phase F) ─────────────────

    #[test]
    fn preview_off_hyprland_skips_hyprctl_without_panicking() {
        // The common test path: no compositor, `hyprctl` may not even exist on
        // PATH — the guard must trip on the env var alone, never touching the
        // process spawn.
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let root = unique_tmp("preview-hypr-off");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("drachma.json"), NOTES_WITH_WINDOW).unwrap();
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
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR", "HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");
        let root = unique_tmp("preview-hypr-empty");
        let stage = root.join("stage");
        let song = root.join("songbook").join("moonlight");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&song).unwrap();
        std::fs::write(song.join("drachma.json"), VALID_NOTES).unwrap();
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

    #[test]
    fn nix_scalar_neutralizes_dollar_interpolation() {
        // `${` must never survive into the emitted literal live — `\$`
        // (backslash-then-quote-then-dollar ordering) is what makes a Nix
        // double-quoted string treat it as inert text.
        assert_eq!(
            nix_scalar(&Value::String("${builtins.currentTime}".to_string())),
            "\"\\${builtins.currentTime}\""
        );
        assert_eq!(
            nix_scalar(&Value::String("${x}".to_string())),
            "\"\\${x}\""
        );
        // Backslash-first ordering: a literal backslash ahead of `$` must not
        // get swallowed by the `$`-escape pass.
        assert_eq!(
            nix_scalar(&Value::String("\\${x}".to_string())),
            "\"\\\\\\${x}\""
        );
    }

    #[test]
    fn mint_neutralizes_nix_interpolation_in_notes() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-interpolation");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("default");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("drachma.json"), NOTES_WITH_INTERPOLATION).unwrap();
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
            assert_eq!(out.render(false).1, crate::output::exit::ERROR);
            assert_eq!(out.data.unwrap()["reason"], "invalid-name", "for `{bad}`");
        }
    }

    #[test]
    fn mint_rejects_invalid_from() {
        let _g = crate::env_lock().lock().unwrap();
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
            assert_eq!(out.render(false).1, crate::output::exit::ERROR);
            assert_eq!(out.data.unwrap()["reason"], "invalid-from", "for `--from {bad}`");
            assert!(!target.exists(), "nothing written for `--from {bad}`");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mint_rejects_from_equal_to_name() {
        let _g = crate::env_lock().lock().unwrap();
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
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "from-equals-name");
        assert!(!target.exists(), "nothing written when --from == name");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn valid_song_name_accepts_the_expected_shape() {
        for good in ["moonlight", "dusk2", "a", "song-two-3"] {
            assert!(valid_song_name(good), "`{good}` should be valid");
        }
        for bad in ["Dusk", "dusk_two", "-dusk", "dusk/two", "..", ""] {
            assert!(!valid_song_name(bad), "`{bad}` should be invalid");
        }
    }

    #[test]
    fn mint_missing_name_is_usage_exit_2() {
        let out = handle_rice_mint(&inv(&["rice", "mint"], &[]));
        assert_eq!(out.status, Status::Usage);
        assert_eq!(out.render(false).1, crate::output::exit::USAGE);
    }

    #[test]
    fn mint_missing_from_song_is_error() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-nofrom");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["moonlight"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
        assert_eq!(out.data.unwrap()["reason"], "from-song-not-found");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mint_scaffolds_every_file_from_a_from_song_with_no_window_or_geometry() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-ok");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("default");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("drachma.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["moonlight"]));
        assert_eq!(out.status, Status::Ok, "{:?}", out.data);
        assert_eq!(out.changed.len(), 4);

        let target = root.join("songbook").join("moonlight");
        assert!(target.join("rice.nix").is_file());
        assert!(target.join("drachma.json").is_file());
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

        let mirrored = std::fs::read_to_string(target.join("drachma.json")).unwrap();
        assert_eq!(mirrored, VALID_NOTES, "drachma.json mirrors --from exactly");

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
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-geo");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("sonata");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::write(from_dir.join("drachma.json"), NOTES_WITH_GEOMETRY).unwrap();
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

        let mirrored = std::fs::read_to_string(target.join("drachma.json")).unwrap();
        assert_eq!(mirrored, NOTES_WITH_GEOMETRY, "geometry block mirrored verbatim");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mint_refuses_to_overwrite_without_force_then_succeeds_with_it() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let root = unique_tmp("mint-exists");
        let stage = root.join("stage");
        let from_dir = root.join("songbook").join("default");
        let target = root.join("songbook").join("dusk");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&from_dir).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(from_dir.join("drachma.json"), VALID_NOTES).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_rice_mint(&inv(&["rice", "mint"], &["dusk"]));
        assert_eq!(out.status, Status::Error);
        assert_eq!(out.render(false).1, crate::output::exit::ERROR);
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
