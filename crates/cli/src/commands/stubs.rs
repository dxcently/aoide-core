//! Metadata-only registrations for the walking-skeleton stub commands: arg
//! parsing and schema are real, the live-system action is not yet
//! implemented. `dispatch()` never calls `handler` for these (it short-
//! circuits on `implemented == false` before reaching the handler call), so
//! every entry here shares one placeholder handler.
//!
//! Split into several small `register_*` functions (rather than one) because
//! the historical `schema --json` command order interleaves these stubs
//! between the implemented `rice`/`graph` groups — `commands/mod.rs::all()`
//! calls each at the point that reproduces that order exactly.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, flag, Registry};

/// Never invoked — `dispatch()` returns the not-implemented envelope itself
/// for any command with `implemented: false`, without calling `handler`.
fn unimplemented(_inv: &Invocation) -> Outcome {
    unreachable!("dispatch() never calls the handler of a not-implemented command")
}

/// `rice declare` / `rice transpose` — sit after `cover set` in the historical
/// order.
pub fn register_rice_late(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "declare"],
        summary: "Commit a staged rice into declarative state and propose the gated rebuild (user gates this).",
        args: [arg!("name", "string", true, "Rice/song name to declare.")],
        flags: [],
        gated: true,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["rice", "transpose"],
        summary: "Replay a song in another key (palette) from the song's songbook/<song>/palette/.",
        args: [
            arg!("rice", "string", true, "Source song name."),
            arg!("palette", "string", true, "Key/palette name to transpose into."),
        ],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
}

/// `content register|propose|approve|ingest|query` (concepts/Content-Pipeline).
pub fn register_content(r: &mut Registry) {
    r.insert(cmd!(
        path: ["content", "register"],
        summary: "Register a content source folder (points in place; never copies).",
        args: [arg!("path", "string", true, "Path to the source folder (must hold .aoide/manifest.toml).")],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["content", "propose"],
        summary: "Propose a discovered source for admission through the approve gate.",
        args: [arg!("path", "string", true, "Path to the candidate source folder.")],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["content", "approve"],
        summary: "Admit a proposed source (the user admits; non-negotiable gate).",
        args: [arg!("path", "string", true, "Path to the proposed source folder.")],
        flags: [],
        gated: true,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["content", "ingest"],
        summary: "Index an approved source in place, then lint (fail → quarantine).",
        args: [arg!("path", "string", false, "Source to ingest; defaults to all approved sources.")],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
    r.insert(cmd!(
        path: ["content", "query"],
        summary: "Query the content index.",
        args: [arg!("query", "string", true, "Query string.")],
        flags: [flag!("limit", "int", "Max results to return.")],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
}

/// `make` — the widget-maker entry (concepts/Widget-Maker).
pub fn register_make(r: &mut Registry) {
    r.insert(cmd!(
        path: ["make"],
        summary: "Widget-maker entry: generate a dendrite + widget + adapter from an intent.",
        args: [arg!("intent", "string", true, "Natural-language intent, e.g. \"show my scheduled jobs\".")],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
}

/// `update` — the gated-rebuild proposer (concepts/Governance).
pub fn register_update(r: &mut Registry) {
    r.insert(cmd!(
        path: ["update"],
        summary: "Fetch upstream, merge framework paths, run checks, propose the rebuild.",
        args: [],
        flags: [flag!("check-only", "bool", "Only detect contract bumps; do not merge.")],
        gated: true,
        implemented: false,
        handler: unimplemented,
    ));
}

/// `onboard` — first-boot flow.
pub fn register_onboard(r: &mut Registry) {
    r.insert(cmd!(
        path: ["onboard"],
        summary: "First-boot flow: register the fork, seed songbook, print the guide.",
        args: [],
        flags: [],
        gated: false,
        implemented: false,
        handler: unimplemented,
    ));
}
