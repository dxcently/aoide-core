//! Metadata-only registrations for lyra's walking-skeleton stub commands:
//! arg parsing and schema are real, the live-system action is not yet
//! implemented. `dispatch()` never calls `handler` for these (it short-
//! circuits on `implemented == false` before reaching the handler call), so
//! both entries here share one placeholder handler.
//!
//! Only `rice declare`/`rice transpose` move to lyra (P-A4 plan) — the
//! `content`/`make`/`update`/`onboard` stub groups in `aoide-cli`'s own
//! `commands/stubs.rs` are core identity and stay there untouched.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, Registry};

/// Never invoked — `dispatch()` returns the not-implemented envelope itself
/// for any command with `implemented: false`, without calling `handler`.
fn unimplemented(_inv: &Invocation) -> Outcome {
    unreachable!("dispatch() never calls the handler of a not-implemented command")
}

/// `rice declare` / `rice transpose` — sit after `cover set`/`livery` in the
/// historical order (same relative position core's `commands/mod.rs::all()`
/// gives them).
pub fn register_rice_late(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "declare"],
        summary: "Commit a staged rice into declarative state and propose the gated rebuild (user gates this).",
        args: [arg!("name", "string", true, "Rice/song name to declare.")],
        flags: [],
        gated: true,
        implemented: false,
        handler: unimplemented,
        examples: ["rice declare moonlight"],
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
