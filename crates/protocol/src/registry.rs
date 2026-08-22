//! The self-registering command registry (CONTRACTS.md §3, v0).
//!
//! Every command in the tree is described here ONCE, alongside the handler
//! that runs it. The CLI dispatcher (`dispatch.rs`), the `schema --json`
//! emitter, the MCP tool list, and the A2A AgentCard (`a2a.rs`) all derive
//! from this single [`Registry`] — the "three doors, one schema" contract
//! (concepts/Agent-Interface). Nothing else in the crate enumerates commands.
//!
//! Each command group lives in its DOMAIN crate's `commands` module (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md) and contributes its
//! entries via a `register(&mut Registry)` function; the root package's
//! `commands/mod.rs::all()` assembles them (in the order that reproduces the
//! historical `schema.rs` table order byte-for-byte — `schema --json` and the
//! MCP tool list must never reorder). Nothing outside those `register()`
//! functions enumerates commands.

use crate::invocation::Invocation;
use crate::output::Outcome;
use serde::Serialize;

/// Contract versions (CONTRACTS.md "Versioning").
pub const SCHEMA_VERSION: &str = "0";
/// The Aoide RELEASE version (prebeta `0.0.X`, root README.md's
/// "Versioning" section) — derives from THIS crate's own Cargo.toml, which
/// itself inherits `pkgs/aoide/Cargo.toml`'s `[workspace.package].version`
/// (versioning start, 2026-08-22). Never a second hardcoded literal: a
/// release bump is one edit to the workspace manifest, not a search for
/// every place this string was repeated.
pub const AOIDE_VERSION: &str = env!("CARGO_PKG_VERSION");
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
    /// Additive field (CONTRACTS.md §3): serialized so a discovery consumer —
    /// the A2A AgentCard (CONTRACTS.md §6) is the first one — can filter to
    /// only the commands that are live, without a second command inventory.
    pub implemented: bool,
    #[serde(rename = "exitCodes", serialize_with = "exit_codes")]
    pub exit_codes: (),
    /// Invocation examples shown by `<cmd> --help` (the human door only —
    /// MCP/A2A consumers get them through `schema --json` when present).
    /// Additive field (CONTRACTS.md §3), like `implemented` before it:
    /// skipped when empty so a command without examples serializes
    /// byte-identical to before this field existed.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub examples: &'static [&'static str],
    /// The handler `dispatch()` calls when `implemented` is true. Unused
    /// (never invoked) for stub commands — see `commands/stubs.rs`.
    #[serde(skip)]
    pub handler: fn(&Invocation) -> Outcome,
    /// Reserved for future conditional availability (e.g. env-gated
    /// commands); not yet consulted by `dispatch()`. Defaults to `|| true`.
    #[serde(skip)]
    pub available: fn() -> bool,
}

impl Command {
    /// The dotted path used as an MCP tool name, e.g. `rice.lint`.
    pub fn dotted(&self) -> String {
        self.path.join(".")
    }
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
pub const JSON_FLAG: Flag = Flag {
    name: "json",
    ty: "bool",
    description: "Structured I/O — emit a machine-readable JSON envelope.",
};

/// The command registry: every known command, in registration order.
/// Iteration order MUST match the historical `schema.rs` table order —
/// `schema --json` and the MCP tool list are byte-sensitive to it.
#[derive(Default)]
pub struct Registry {
    entries: Vec<Command>,
}

impl Registry {
    pub fn new() -> Self {
        Registry { entries: Vec::new() }
    }

    /// Append one command. Panics on a duplicate path — a self-registering
    /// registry must never silently shadow an earlier entry.
    pub fn insert(&mut self, cmd: Command) {
        assert!(
            self.get(&cmd.path.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .is_none(),
            "duplicate command path: {}",
            cmd.dotted()
        );
        self.entries.push(cmd);
    }

    /// Look up the command entry for a parsed invocation path.
    pub fn get(&self, path: &[String]) -> Option<&Command> {
        self.entries
            .iter()
            .find(|c| c.path.len() == path.len() && c.path.iter().zip(path).all(|(a, b)| *a == b))
    }

    /// Every registered command, in registration order.
    pub fn commands(&self) -> impl Iterator<Item = &Command> {
        self.entries.iter()
    }

    /// Build the full `schema --json` document from this registry.
    pub fn schema(&self) -> Schema {
        Schema {
            schema_version: SCHEMA_VERSION,
            aoide: AOIDE_VERSION,
            stage_notes_version: STAGE_NOTES_VERSION,
            commands: self.entries.clone(),
        }
    }
}

/// Small helper: a leaf command whose only flag is `--json`, wired to a
/// handler fn. Every command group's `register()` uses this to build its
/// `Command` entries — metadata copied verbatim from the pre-registry
/// `schema.rs` table.
///
/// Moved from the root package's `src/registry.rs` (Phase 9 restructure,
/// docs/architecture/PACKAGE-LAYOUT.md) so every domain crate's
/// `commands::register()` can describe its own verbs; the `$crate::registry::*`
/// expansions resolve identically inside THIS crate, which owns the types.
#[macro_export]
macro_rules! cmd {
    // The examples-carrying arm is listed FIRST: macro arms are tried in
    // order, so the more specific matcher must precede the general one below
    // — a call site that passes `examples:` lands here, everything else falls
    // through to the no-examples arm (which defaults `examples: &[]`).
    (
        path: [$($seg:literal),*],
        summary: $summary:literal,
        args: [$($arg:expr),* $(,)?],
        flags: [$($flag:expr),* $(,)?],
        gated: $gated:expr,
        implemented: $impl:expr,
        handler: $handler:expr,
        examples: [$($ex:literal),* $(,)?] $(,)?
    ) => {
        $crate::registry::Command {
            path: &[$($seg),*],
            summary: $summary,
            args: &[$($arg),*],
            flags: &[$crate::registry::JSON_FLAG, $($flag),*],
            gated: $gated,
            implemented: $impl,
            exit_codes: (),
            examples: &[$($ex),*],
            handler: $handler,
            available: || true,
        }
    };
    (
        path: [$($seg:literal),*],
        summary: $summary:literal,
        args: [$($arg:expr),* $(,)?],
        flags: [$($flag:expr),* $(,)?],
        gated: $gated:expr,
        implemented: $impl:expr,
        handler: $handler:expr $(,)?
    ) => {
        $crate::registry::Command {
            path: &[$($seg),*],
            summary: $summary,
            args: &[$($arg),*],
            flags: &[$crate::registry::JSON_FLAG, $($flag),*],
            gated: $gated,
            implemented: $impl,
            exit_codes: (),
            examples: &[],
            handler: $handler,
            available: || true,
        }
    };
}

#[macro_export]
macro_rules! arg {
    ($name:literal, $ty:literal, $req:expr, $desc:literal) => {
        $crate::registry::Arg {
            name: $name,
            ty: $ty,
            required: $req,
            description: $desc,
        }
    };
}

#[macro_export]
macro_rules! flag {
    ($name:literal, $ty:literal, $desc:literal) => {
        $crate::registry::Flag {
            name: $name,
            ty: $ty,
            description: $desc,
        }
    };
}

// Re-export at this module's path too, so a domain crate's
// `use aoide_protocol::registry::{arg, cmd, flag, Registry};` reads exactly
// like the root package's historical `use crate::registry::{…}`.
pub use crate::{arg, cmd, flag};
