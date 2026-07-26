//! The `aoide schema --json` source of truth (CONTRACTS.md §3, v0).
//!
//! Every command in the tree is described here ONCE. The CLI dispatcher, the
//! `schema --json` emitter, and the MCP tool list all derive from this single
//! table — the "two doors, one schema" contract (concepts/Agent-Interface).
//! Nothing else in the crate enumerates commands.

use serde::Serialize;

/// Contract versions (CONTRACTS.md "Versioning").
pub const SCHEMA_VERSION: &str = "0";
pub const AOIDE_VERSION: &str = "0.0.0";
/// Stage-file format version (CONTRACTS.md §4).
pub const STAGE_NOTES_VERSION: &str = "0";

/// A positional argument of a command.
#[derive(Debug, Clone, Serialize)]
pub struct Arg {
    pub name: &'static str,
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub required: bool,
    pub description: &'static str,
}

/// A `--flag` of a command.
#[derive(Debug, Clone, Serialize)]
pub struct Flag {
    pub name: &'static str,
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub description: &'static str,
}

/// One command (a leaf in the command tree).
#[derive(Debug, Clone, Serialize)]
pub struct Command {
    /// The invocation path, e.g. `["rice", "gen"]`.
    pub path: &'static [&'static str],
    pub summary: &'static str,
    pub args: &'static [Arg],
    pub flags: &'static [Flag],
    /// Routes through the user rebuild gate (CONTRACTS.md §3).
    pub gated: bool,
    /// Actually mutates the live system? (walking skeleton: many are stubs).
    #[serde(skip_serializing)]
    pub implemented: bool,
    #[serde(rename = "exitCodes", serialize_with = "exit_codes")]
    pub exit_codes: (),
}

/// The whole `schema --json` document.
#[derive(Debug, Serialize)]
pub struct Schema {
    #[serde(rename = "schemaVersion")]
    pub schema_version: &'static str,
    pub aoide: &'static str,
    #[serde(rename = "stageNotesVersion")]
    pub stage_notes_version: &'static str,
    pub commands: Vec<Command>,
}

/// The canonical exit-code map, identical for every command (CONTRACTS.md §3).
fn exit_codes<S: serde::Serializer>(_: &(), s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut m = s.serialize_map(Some(4))?;
    m.serialize_entry("0", "ok")?;
    m.serialize_entry("1", "error")?;
    m.serialize_entry("2", "usage")?;
    m.serialize_entry("64", "not-implemented")?;
    m.end()
}

// ── The `--json` flag every command carries (the contract) ──────────────────
const JSON_FLAG: Flag = Flag {
    name: "json",
    ty: "bool",
    description: "Structured I/O — emit a machine-readable JSON envelope.",
};

/// Small helper: a leaf command whose only flag is `--json`.
macro_rules! cmd {
    (
        path: [$($seg:literal),*],
        summary: $summary:literal,
        args: [$($arg:expr),* $(,)?],
        flags: [$($flag:expr),* $(,)?],
        gated: $gated:expr,
        implemented: $impl:expr $(,)?
    ) => {
        Command {
            path: &[$($seg),*],
            summary: $summary,
            args: &[$($arg),*],
            flags: &[JSON_FLAG, $($flag),*],
            gated: $gated,
            implemented: $impl,
            exit_codes: (),
        }
    };
}

macro_rules! arg {
    ($name:literal, $ty:literal, $req:expr, $desc:literal) => {
        Arg { name: $name, ty: $ty, required: $req, description: $desc }
    };
}

macro_rules! flag {
    ($name:literal, $ty:literal, $desc:literal) => {
        Flag { name: $name, ty: $ty, description: $desc }
    };
}

/// The complete command table — the single source of truth.
pub fn commands() -> Vec<Command> {
    vec![
        cmd!(
            path: ["guide"],
            summary: "Print the four-tier agent onboarding (tier map + house rules).",
            args: [],
            flags: [],
            gated: false,
            implemented: true,
        ),
        cmd!(
            path: ["schema"],
            summary: "Emit the versioned machine-readable schema of every command and state file.",
            args: [],
            flags: [],
            gated: false,
            implemented: true,
        ),
        // ── rice: the self-ricing loop (concepts/Self-Ricing) ───────────────
        cmd!(
            path: ["rice", "gen"],
            summary: "Generate a rice from a prompt or wallpaper (reads songbook/ first).",
            args: [arg!("prompt", "string", false, "Prompt or wallpaper path; defaults to shipped rice.")],
            flags: [flag!("full", "bool", "Full orchestration tier (greeter, per-app, chimes).")],
            gated: false,
            implemented: false,
        ),
        cmd!(
            path: ["rice", "lint"],
            summary: "Validate a rice against the note schema (delegates to aoide-notes).",
            args: [arg!("name", "string", false, "Rice/song name to lint; defaults to the staged rice.")],
            flags: [],
            gated: false,
            implemented: true,
        ),
        cmd!(
            path: ["rice", "preview"],
            summary: "Rehearse a rice live (stage/notes.json hot-reload); nothing committed.",
            args: [arg!("name", "string", false, "Rice/song name to preview.")],
            flags: [],
            gated: false,
            implemented: false,
        ),
        cmd!(
            path: ["rice", "adopt"],
            summary: "Commit a previewed rice and propose the gated rebuild (user gates this).",
            args: [arg!("name", "string", true, "Rice/song name to adopt.")],
            flags: [],
            gated: true,
            implemented: false,
        ),
        cmd!(
            path: ["rice", "transpose"],
            summary: "Replay a song in another key (palette) from song/keys/.",
            args: [
                arg!("rice", "string", true, "Source song name."),
                arg!("palette", "string", true, "Key/palette name to transpose into."),
            ],
            flags: [],
            gated: false,
            implemented: false,
        ),
        // ── content: the pipeline (concepts/Content-Pipeline) ───────────────
        cmd!(
            path: ["content", "register"],
            summary: "Register a content source folder (points in place; never copies).",
            args: [arg!("path", "string", true, "Path to the source folder (must hold .aoide/manifest.toml).")],
            flags: [],
            gated: false,
            implemented: false,
        ),
        cmd!(
            path: ["content", "propose"],
            summary: "Propose a discovered source for admission through the approve gate.",
            args: [arg!("path", "string", true, "Path to the candidate source folder.")],
            flags: [],
            gated: false,
            implemented: false,
        ),
        cmd!(
            path: ["content", "approve"],
            summary: "Admit a proposed source (the user admits; non-negotiable gate).",
            args: [arg!("path", "string", true, "Path to the proposed source folder.")],
            flags: [],
            gated: true,
            implemented: false,
        ),
        cmd!(
            path: ["content", "ingest"],
            summary: "Index an approved source in place, then lint (fail → quarantine).",
            args: [arg!("path", "string", false, "Source to ingest; defaults to all approved sources.")],
            flags: [],
            gated: false,
            implemented: false,
        ),
        cmd!(
            path: ["content", "query"],
            summary: "Query the content index.",
            args: [arg!("query", "string", true, "Query string.")],
            flags: [flag!("limit", "int", "Max results to return.")],
            gated: false,
            implemented: false,
        ),
        // ── make: the widget-maker (concepts/Widget-Maker) ──────────────────
        cmd!(
            path: ["make"],
            summary: "Widget-maker entry: generate a dendrite + widget + adapter from an intent.",
            args: [arg!("intent", "string", true, "Natural-language intent, e.g. \"show my scheduled jobs\".")],
            flags: [],
            gated: false,
            implemented: false,
        ),
        // ── update: the gated-rebuild proposer (concepts/Governance) ────────
        cmd!(
            path: ["update"],
            summary: "Fetch upstream, merge framework paths, run checks, propose the rebuild.",
            args: [],
            flags: [flag!("check-only", "bool", "Only detect contract bumps; do not merge.")],
            gated: true,
            implemented: false,
        ),
        // ── onboard: first-boot flow ────────────────────────────────────────
        cmd!(
            path: ["onboard"],
            summary: "First-boot flow: register the fork, seed songbook, print the guide.",
            args: [],
            flags: [],
            gated: false,
            implemented: false,
        ),
        // ── mcp: the façade (concepts/Agent-Interface) ──────────────────────
        cmd!(
            path: ["mcp", "serve"],
            summary: "Run the stdio MCP server; its tool list is generated from this schema.",
            args: [],
            flags: [flag!("stdio", "bool", "Serve over stdio (the per-session agent form).")],
            gated: false,
            implemented: true,
        ),
        // ── daemon: aoided from the trunk (concepts/aoided) ─────────────────
        cmd!(
            path: ["daemon"],
            summary: "Run the aoided daemon skeleton (policy, lint, gate, single audit log).",
            args: [],
            flags: [flag!("audit-log", "string", "Override the audit log path (default aoide.auditLog).")],
            gated: false,
            implemented: true,
        ),
        // ── shellbridge: session/hook state bridge (concepts/shellbridge) ───
        cmd!(
            path: ["shellbridge"],
            summary: "Run the shellbridge process: publish session/hook state to song/stage/ atomically.",
            args: [],
            flags: [flag!("run", "bool", "Run the long-lived shellbridge process.")],
            gated: false,
            implemented: true,
        ),
        // ── adapter: per-agent event-stream consumers (entities/aoided) ─────
        cmd!(
            path: ["adapter", "melete"],
            summary: "Run the melete-adapter: consume the neutral event stream (default-deny per class).",
            args: [],
            flags: [flag!("run", "bool", "Run the long-lived adapter process.")],
            gated: false,
            implemented: true,
        ),
    ]
}

/// Build the full schema document.
pub fn schema() -> Schema {
    Schema {
        schema_version: SCHEMA_VERSION,
        aoide: AOIDE_VERSION,
        stage_notes_version: STAGE_NOTES_VERSION,
        commands: commands(),
    }
}

impl Command {
    /// The dotted path used as an MCP tool name, e.g. `rice.gen`.
    pub fn dotted(&self) -> String {
        self.path.join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_valid_json_with_stable_top_level_keys() {
        let doc = schema();
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["schemaVersion"], "0");
        assert_eq!(v["aoide"], "0.0.0");
        assert!(v["commands"].as_array().unwrap().len() >= 15);
    }

    #[test]
    fn every_command_carries_the_json_flag_and_exit_codes() {
        for c in commands() {
            assert!(
                c.flags.iter().any(|f| f.name == "json"),
                "{} missing --json",
                c.dotted()
            );
            let v = serde_json::to_value(&c).unwrap();
            assert_eq!(v["exitCodes"]["0"], "ok");
            assert_eq!(v["exitCodes"]["64"], "not-implemented");
        }
    }

    #[test]
    fn command_paths_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in commands() {
            assert!(seen.insert(c.dotted()), "duplicate command {}", c.dotted());
        }
    }
}
