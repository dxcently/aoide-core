//! The herald's CLI verb: `herald push`, dunst's `script` hook.
//!
//! One verb, and a machine-facing one — a human never types it. dunst runs it
//! per notification with the `DUNST_*` environment set (see
//! `modules/dendrites/dunst.nix`), and it forwards the record to the
//! shellbridge, which files it into `stage/herald.json` for the QML herald to
//! draw. The reading side is the ledger file itself, not a verb.

use aoide_protocol::cmd;
use aoide_protocol::registry::Registry;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["herald", "push"],
        summary: "File one notification into the herald ledger (stage/herald.json) for the Quickshell herald to draw. Reads the DUNST_* environment dunst's `script` hook sets — this is the daemon-to-desktop feed, not a way to send a notification (use `notify-send` for that). Forwarded through the shellbridge so concurrent notifications cannot race each other's writes.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::herald::herald_push,
    ));
}
