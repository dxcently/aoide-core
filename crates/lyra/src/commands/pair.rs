//! `lyra pair ask`/`lyra pair show` — the pairing ceremony's own two dialog
//! shapes, both reusing the shared quickshell surface in
//! [`super::dialog_qml`] (root `AGENTS.md` house rule 7's "reused, never
//! copied"):
//!
//! - **`pair ask`** — a TYPED-CODE entry dialog: the SAME six-boxes-
//!   plus-dash digit ENTRY surface `lyra secrets ask` (P3) renders,
//!   spawned by `aoide pair watch --popup` in place of `zenity
//!   --entry` once `aoide_client::pair_watch::resolve_lyra_bin` finds this
//!   binary — **on BOTH pairing directions now (the mutual-code redesign,
//!   R1)**, never a bare yes/no on either. The INBOUND (approver) leg types
//!   the code shown on the REQUESTER's screen; the OUTBOUND (requester) leg
//!   types the reply code shown on the APPROVER's screen — a genuinely
//!   different, far surface either way, out-of-band. Neither leg's code
//!   arrives as a flag: this dialog never carries a `--code` flag at all,
//!   because there is nothing of this instance's own to show — the whole
//!   gate is typing a value read from elsewhere (`aoide_client::pair_watch`'s
//!   own module doc has the full "never echo the expected value" reasoning,
//!   now holding unconditionally on both legs rather than only one).
//! - **`pair show`** — the REPLY-CODE DISPLAY dialog (R2): shows a code
//!   this instance already derived (`dialog_qml::render_code_show_qml`)
//!   large and plain, a **Copy** control, and a **Done** control — no
//!   reject control at all. Spawned by `aoide pair watch --popup`
//!   immediately after a popup-driven INBOUND commit succeeds, carrying the
//!   reply code `approve_inbound`'s own outcome data already computed
//!   (`replySas`). It commits nothing and rejects nothing — it fires AFTER
//!   the commit, not before — so Esc and the native window close are
//!   Done-equivalent (nothing is at stake either way,
//!   `dialog_qml::render_code_show_qml`'s own doc). **This command is `pair
//!   confirm` (P-PV3, task #132), repurposed and renamed**, not a new
//!   surface: that command was originally the OUTBOUND leg's own
//!   Approve/Reject shape, days before the mutual-code redesign (R1) gave
//!   the outbound leg a genuine second code to gate on and moved it onto
//!   `pair ask` above. A command whose only remaining job is showing a code
//!   the operator did not just decide on keeps `confirm`'s QML family and
//!   machinery but not its name — a name that states a falsehood for a
//!   pure display surface is worse than no name at all.
//!
//! **Why NOT `lyra secrets ask` verbatim for either (orchestrator-resolved
//! fork, P-PV3's own brief)**: that command is hard-coupled to the secrets
//! registry's own wording ("release `SECRET` -> CONSUMER") and flag
//! surface (`--secret`/`--consumer`/`--seconds`) — a generic dialog with
//! caller-supplied title/context text did not exist before this phase. The
//! fix is the [`super::dialog_qml`] extraction (that module's own doc has
//! the shared contract); these two commands add nothing duplicated, only
//! the pairing-specific flags/wording sitting on top of it, exactly as
//! `commands::secrets` now does for its own.
//!
//! **Untrusted display data.** `--context` on both commands carries a line
//! `aoide_client::pair_watch` already builds ONCE — "pairing request from
//! `<name>` (<host>) · id <id>" (inbound `pair ask`), "type the reply code
//! shown on `<name>`'s screen · id <id>" (outbound `pair ask`), or "read
//! this code back to `<name>`'s operator · id <id>" (`pair show`) — the
//! same "one place this wording lives" discipline
//! `aoide_secrets::watch::format_origin_line` holds for its own `--from`.
//! `name`/`host` are PEER-SUPPLIED (a `pair-parked`/`pair-revealed` feed
//! record, or an outbound/inbound entry's own recorded name), so this text
//! is rendered byte-for-byte, never interpreted, and the shared renderer's
//! `qml_escape` is what keeps it from ever breaking out of its own QML
//! string literal. **`pair show`'s `--code` is NOT the same trust class**:
//! it is THIS instance's own locally-derived reply SAS, safe to display
//! (never a leak — `aoide pair`'s own CLI outcome already prints it) and
//! never compared against anything (a display dialog has no typed value to
//! compare in the first place — it fires after the gate that mattered
//! already passed).
//!
//! **Output contract — identical shape for both, distinct on-close
//! payload**: `pair ask` puts the typed code on stdout with exit 0, and
//! shares exit 1 + `"Reject request"` on stdout for an explicit dismiss,
//! exit 1 with empty stdout for a bare Esc/close. `pair show` puts NOTHING
//! meaningful on stdout for its own exit 0 (an empty completion, the same
//! "no payload" shape a zenity `--info` OK produces) regardless of WHICH of
//! Done/Esc/close the operator reached for — it has no dismiss path at all
//! (no reject control exists to dismiss). Both share
//! [`EXIT_INFRA_FAILURE`] (exit 3) for a spawn/marker-less failure.
//! `aoide_client::pair_watch::run_entry_dialog`/`run_show_dialog` are the
//! readers of these contracts — don't change either here without updating
//! that module's own doc in the SAME commit.
//!
//! **The QML is paint only** (root `AGENTS.md` house rule 7's "delete
//! every `.qml`" test) — the capability (approving a pairing request with a
//! typed code on either leg, or reading back a reply code) stays reachable
//! with nothing but a shell: `aoide pair <id> --code <code>` and each
//! command's own zenity fallback both work with this file deleted
//! entirely.

use super::dialog_qml::{self, EXIT_INFRA_FAILURE as DIALOG_EXIT_INFRA_FAILURE, HeaderLine};
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use aoide_protocol::Door;
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["pair", "ask"],
        summary: "Render a quickshell code-entry dialog for one actionable pairing request, EITHER direction -- the same six-digit-boxes-plus-dash surface `lyra secrets ask` renders, collecting a TYPED SAS code read from the far side's own screen (the requester's screen on the approver's INBOUND leg, the approver's reply code on the requester's OUTBOUND leg). CLI-only: the counterpart `aoide pair watch --popup` spawns in place of `zenity --entry` when this binary resolves.",
        args: [],
        flags: [
            flag!("id", "string", "The pairing request id (display + audit only)."),
            flag!("name", "string", "The peer's claimed name -- used for the dialog's window title (untrusted display data)."),
            flag!("context", "string", "The pre-formatted context line -- 'pairing request from `name` (host) . id <id>' (inbound) or 'type the reply code shown on `name`'s screen . id <id>' (outbound), already built once by the caller so zenity and this dialog render byte-identical wording.")
        ],
        gated: false,
        implemented: true,
        handler: handle_pair_ask,
    ));
    r.insert(cmd!(
        path: ["pair", "show"],
        summary: "Render a quickshell display dialog for one pairing request's reply code -- shows this instance's own locally-derived reply SAS large and plain, a Copy control, and a Done control. No reject control: this fires AFTER the approver's own commit already succeeded, so there is nothing left to approve or reject. CLI-only: the counterpart `aoide pair watch --popup` spawns in place of `zenity --info --no-markup` when this binary resolves.",
        args: [],
        flags: [
            flag!("id", "string", "The pairing request id (display + audit only)."),
            flag!("name", "string", "The peer's claimed name -- used for the dialog's window title (untrusted display data)."),
            flag!("context", "string", "The pre-formatted context line -- 'read this code back to `name`'s operator . id <id>', already built once by the caller so zenity and this dialog render byte-identical wording."),
            flag!("code", "string", "This instance's own locally-derived reply SAS -- shown large and plain with a Copy control, never compared against anything (a display dialog has no typed value to compare).")
        ],
        gated: false,
        implemented: true,
        handler: handle_pair_show,
    ));
}

/// This ceremony's own marker prefix, shared by both commands — never run
/// concurrently in one process's own stdout stream (each invocation is a
/// wholly separate `quickshell` child), so one marker suffices; distinct
/// from `lyra secrets ask`'s `AOIDE_SECRETS_ASK_RESULT:` so a stray line
/// from that OTHER ceremony's dialog can never be misread as a result here
/// ([`super::dialog_qml`]'s own doc).
const RESULT_MARKER: &str = "AOIDE_PAIR_ASK_RESULT:";

/// `aoide_client::pair_watch::REJECT_LABEL`, restated here as a literal —
/// this crate cannot depend on `aoide-client` for one string constant, the
/// same "no shared Rust type across the core/paint boundary" posture
/// `aoide_protocol::dialog::LYRA_INFRA_FAILURE_EXIT`'s own doc holds for
/// its own mirrored constant. `pair ask` alone reads it now — `pair show`
/// carries no reject control, so it has no dismiss label to render.
const DISMISS_TEXT: &str = "Reject request";

const QUICKSHELL_CMD: &str = dialog_qml::QUICKSHELL_CMD;

/// Mirrors `commands::secrets::EXIT_INFRA_FAILURE` — `lib.rs`'s `special`
/// hooks for `["pair", "ask"]`/`["pair", "show"]` read it at this path.
pub const EXIT_INFRA_FAILURE: i32 = DIALOG_EXIT_INFRA_FAILURE;

fn handle_pair_ask(inv: &Invocation) -> Outcome {
    let cmd = "pair.ask";
    if inv.door != Door::Cli {
        return Outcome::usage(cmd, "pair ask is a desktop dialog -- CLI-only");
    }
    let Some(id) = inv.flags.get("id").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair ask requires --id <id>");
    };
    let Some(name) = inv.flags.get("name").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair ask requires --name <name>");
    };
    let Some(context) = inv.flags.get("context").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair ask requires --context <line>");
    };

    let title = format!("aoide \u{b7} pairing with {name}");
    let header = vec![HeaderLine::bold(context.clone())];

    match dialog_qml::run_code_entry_dialog(QUICKSHELL_CMD, "aoide-pair-ask", &title, &header, DISMISS_TEXT, RESULT_MARKER) {
        Ok(dialog_qml::AskResult::Approved(typed)) => {
            Outcome::ok(cmd, "code entered").with_data(json!({ "result": "approved", "code": typed, "id": id }))
        }
        Ok(dialog_qml::AskResult::Dismissed) => Outcome::ok(cmd, "rejected").with_data(json!({ "result": "dismissed", "id": id })),
        Ok(dialog_qml::AskResult::Cancelled) => Outcome::ok(cmd, "cancelled").with_data(json!({ "result": "cancelled", "id": id })),
        Ok(dialog_qml::AskResult::Failed(reason)) => Outcome::error(cmd, reason).with_data(json!({ "result": "failed", "id": id })),
        Err(e) => Outcome::error(cmd, e).with_data(json!({ "result": "failed", "id": id })),
    }
}

fn handle_pair_show(inv: &Invocation) -> Outcome {
    let cmd = "pair.show";
    if inv.door != Door::Cli {
        return Outcome::usage(cmd, "pair show is a desktop dialog -- CLI-only");
    }
    let Some(id) = inv.flags.get("id").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair show requires --id <id>");
    };
    let Some(name) = inv.flags.get("name").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair show requires --name <name>");
    };
    let Some(context) = inv.flags.get("context").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair show requires --context <line>");
    };
    let Some(code) = inv.flags.get("code").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair show requires --code <sas>");
    };

    let title = format!("aoide \u{b7} pairing with {name}");
    let header = vec![HeaderLine::bold(context.clone())];

    match dialog_qml::run_code_show_dialog(QUICKSHELL_CMD, "aoide-pair-show", &title, &header, code, RESULT_MARKER) {
        // Done, Esc, and the native window close all reach here alike (the
        // show template emits the identical `DONE` marker for all three,
        // `dialog_qml::render_code_show_qml`'s own doc) — there is nothing
        // to distinguish, since this dialog never had anything to approve
        // or reject in the first place.
        Ok(dialog_qml::AskResult::Approved(_)) => Outcome::ok(cmd, "shown").with_data(json!({ "result": "shown", "id": id })),
        // Neither variant is ever produced by the show template (no reject
        // control exists to dismiss) — kept as a defensive fallback so the
        // shared marker reader's full `AskResult` never needs an
        // unreachable-panic arm here, read identically to a normal close.
        Ok(dialog_qml::AskResult::Dismissed) | Ok(dialog_qml::AskResult::Cancelled) => {
            Outcome::ok(cmd, "shown").with_data(json!({ "result": "shown", "id": id }))
        }
        Ok(dialog_qml::AskResult::Failed(reason)) => Outcome::error(cmd, reason).with_data(json!({ "result": "failed", "id": id })),
        Err(e) => Outcome::error(cmd, e).with_data(json!({ "result": "failed", "id": id })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(path: &[&str], door: Door, flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = std::collections::BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation { path: path.iter().map(|s| s.to_string()).collect(), args: vec![], flags: flag_map, door }
    }

    // ── handle_pair_ask door/flag validation (no live quickshell) ────────

    #[test]
    fn handle_pair_ask_is_cli_only() {
        let i = inv(&["pair", "ask"], Door::Mcp, &[("id", "abc"), ("name", "box-a"), ("context", "x")]);
        assert_eq!(handle_pair_ask(&i).status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_pair_ask_requires_id_name_and_context() {
        assert_eq!(handle_pair_ask(&inv(&["pair", "ask"], Door::Cli, &[])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(handle_pair_ask(&inv(&["pair", "ask"], Door::Cli, &[("id", "abc")])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(
            handle_pair_ask(&inv(&["pair", "ask"], Door::Cli, &[("id", "abc"), ("name", "box-a")])).status,
            aoide_protocol::output::Status::Usage
        );
    }

    // ── handle_pair_show door/flag validation (no live quickshell) ───────

    #[test]
    fn handle_pair_show_is_cli_only() {
        let i = inv(&["pair", "show"], Door::Mcp, &[("id", "abc"), ("name", "box-b"), ("context", "x"), ("code", "111-222")]);
        assert_eq!(handle_pair_show(&i).status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_pair_show_requires_id_name_context_and_code() {
        assert_eq!(handle_pair_show(&inv(&["pair", "show"], Door::Cli, &[])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(
            handle_pair_show(&inv(&["pair", "show"], Door::Cli, &[("id", "abc"), ("name", "box-b")])).status,
            aoide_protocol::output::Status::Usage
        );
        assert_eq!(
            handle_pair_show(&inv(&["pair", "show"], Door::Cli, &[("id", "abc"), ("name", "box-b"), ("context", "x")])).status,
            aoide_protocol::output::Status::Usage,
            "code is required -- a display dialog with nothing to show would be a blank window"
        );
    }
}
