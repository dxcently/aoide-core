//! `lyra pair ask`/`lyra pair confirm` (P-PV3, task #132) — the pairing
//! ceremony's own two dialog shapes, one per direction, both reusing the
//! shared quickshell surface in [`super::dialog_qml`] (root `AGENTS.md`
//! house rule 7's "reused, never copied"):
//!
//! - **`pair ask`** — the INBOUND (approver) dialog: the SAME six-boxes-
//!   plus-dash digit ENTRY surface `lyra secrets ask` (P3) renders,
//!   spawned by `aoide peer pair watch --popup` in place of `zenity
//!   --entry` once `aoide_client::pair_watch::resolve_lyra_bin` finds this
//!   binary. The approver's code arrives from ELSEWHERE (the requester's
//!   own screen, read aloud or glanced at out-of-band) and is TYPED here
//!   blind — this dialog never carries a `--code` flag at all, because
//!   there is nothing of this instance's own to show.
//! - **`pair confirm`** — the OUTBOUND (requester) dialog: a CONFIRM shape
//!   (`dialog_qml::render_code_confirm_qml`), spawned in place of `zenity
//!   --question`. This instance generated the SAS itself
//!   (`aoide_storage::pairing::derive_sas`, already known before the
//!   dialog ever opens) — the dialog shows it large and plain, and the
//!   operator's whole job is a single Approve/Dismiss action, never a
//!   retype. **This is a REVERT to the ceremony's original shape** (a
//!   design fix, task #132's own review round): an earlier pass on this
//!   same phase collected a typed retype on the outbound arm too, which a
//!   review correctly called out as copy-the-pixels theater — the code is
//!   already on screen in the SAME window, so retyping it proves nothing
//!   an Approve click doesn't already prove. The INBOUND arm is the one
//!   place typed entry has real meaning, because there the code truly
//!   comes from a DIFFERENT surface than the one it's typed into.
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
//! **Untrusted display data.** `--context` on both commands carries the
//! "pairing request from `<name>` (<host>) · id <id>" (or the outbound
//! "confirm pairing with...") line `aoide_client::pair_watch` already
//! builds ONCE (the same "one place this wording lives" discipline
//! `aoide_secrets::watch::format_origin_line` holds for its own `--from`)
//! — `name`/`host` are PEER-SUPPLIED (a `pair-parked`/`pair-revealed` feed
//! record, or an outbound entry's own recorded name), so this text is
//! rendered byte-for-byte, never interpreted, and the shared renderer's
//! `qml_escape` is what keeps it from ever breaking out of its own QML
//! string literal. **`pair confirm`'s `--code` is NOT the same trust
//! class**: it is THIS instance's own locally-derived SAS, safe to display
//! (never a leak — the CLI's own `y`/`N` confirm already prints it) and
//! never compared against the dialog's own output (a confirm has no typed
//! value to compare in the first place).
//!
//! **Output contract — identical shape for both, distinct on-approve
//! payload**: `pair ask` puts the typed code on stdout with exit 0; `pair
//! confirm` puts NOTHING meaningful on stdout for its own exit 0 (an empty
//! approval, the same "no payload" shape zenity's own `--question` OK
//! produces). Both share exit 1 + `"Reject request"` on stdout for
//! dismiss, exit 1 with empty stdout for a bare Esc/close, and
//! [`EXIT_INFRA_FAILURE`] (exit 3) for a spawn/marker-less failure.
//! `aoide_client::pair_watch::run_entry_dialog` is the one reader of both
//! contracts — don't change either here without updating that module's own
//! doc in the SAME commit.
//!
//! **The QML is paint only** (root `AGENTS.md` house rule 7's "delete
//! every `.qml`" test) — the capability (approving a pairing request,
//! inbound with a typed code or outbound with a confirm) stays reachable
//! with nothing but a shell: `aoide peer pair approve <id> [--code
//! <code>]` and each command's own zenity fallback both work with this
//! file deleted entirely.

use super::dialog_qml::{self, EXIT_INFRA_FAILURE as DIALOG_EXIT_INFRA_FAILURE, HeaderLine};
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use aoide_protocol::Door;
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["pair", "ask"],
        summary: "Render a quickshell code-entry dialog for one actionable INBOUND pairing request -- the same six-digit-boxes-plus-dash surface `lyra secrets ask` renders, collecting a TYPED SAS code read from the requester's own screen. CLI-only: the counterpart `aoide peer pair watch --popup` spawns in place of `zenity --entry` when this binary resolves.",
        args: [],
        flags: [
            flag!("id", "string", "The pairing request id (display + audit only)."),
            flag!("name", "string", "The peer's claimed name -- used for the dialog's window title (untrusted display data)."),
            flag!("context", "string", "The pre-formatted context line -- 'pairing request from `name` (host) . id <id>', already built once by the caller so zenity and this dialog render byte-identical wording.")
        ],
        gated: false,
        implemented: true,
        handler: handle_pair_ask,
    ));
    r.insert(cmd!(
        path: ["pair", "confirm"],
        summary: "Render a quickshell confirm dialog for one actionable OUTBOUND pairing request -- shows this instance's own locally-derived SAS large and plain, a single Approve/Dismiss action, never a retype. CLI-only: the counterpart `aoide peer pair watch --popup` spawns in place of `zenity --question` when this binary resolves.",
        args: [],
        flags: [
            flag!("id", "string", "The pairing request id (display + audit only)."),
            flag!("name", "string", "The peer's claimed name -- used for the dialog's window title (untrusted display data)."),
            flag!("context", "string", "The pre-formatted context line -- 'confirm pairing with `name` . id <id>', already built once by the caller so zenity and this dialog render byte-identical wording."),
            flag!("code", "string", "This instance's own locally-derived SAS -- shown large and plain, never compared against anything (a confirm has no typed value to compare).")
        ],
        gated: false,
        implemented: true,
        handler: handle_pair_confirm,
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
/// its own mirrored constant.
const DISMISS_TEXT: &str = "Reject request";

const QUICKSHELL_CMD: &str = dialog_qml::QUICKSHELL_CMD;

/// Mirrors `commands::secrets::EXIT_INFRA_FAILURE` — `lib.rs`'s `special`
/// hooks for `["pair", "ask"]`/`["pair", "confirm"]` read it at this path.
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

fn handle_pair_confirm(inv: &Invocation) -> Outcome {
    let cmd = "pair.confirm";
    if inv.door != Door::Cli {
        return Outcome::usage(cmd, "pair confirm is a desktop dialog -- CLI-only");
    }
    let Some(id) = inv.flags.get("id").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair confirm requires --id <id>");
    };
    let Some(name) = inv.flags.get("name").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair confirm requires --name <name>");
    };
    let Some(context) = inv.flags.get("context").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair confirm requires --context <line>");
    };
    let Some(code) = inv.flags.get("code").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "pair confirm requires --code <sas>");
    };

    let title = format!("aoide \u{b7} pairing with {name}");
    let header = vec![HeaderLine::bold(context.clone())];

    match dialog_qml::run_code_confirm_dialog(QUICKSHELL_CMD, "aoide-pair-confirm", &title, &header, code, DISMISS_TEXT, RESULT_MARKER) {
        Ok(dialog_qml::AskResult::Approved(_)) => Outcome::ok(cmd, "approved").with_data(json!({ "result": "approved", "id": id })),
        Ok(dialog_qml::AskResult::Dismissed) => Outcome::ok(cmd, "rejected").with_data(json!({ "result": "dismissed", "id": id })),
        Ok(dialog_qml::AskResult::Cancelled) => Outcome::ok(cmd, "cancelled").with_data(json!({ "result": "cancelled", "id": id })),
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

    // ── handle_pair_confirm door/flag validation (no live quickshell) ────

    #[test]
    fn handle_pair_confirm_is_cli_only() {
        let i = inv(&["pair", "confirm"], Door::Mcp, &[("id", "abc"), ("name", "box-b"), ("context", "x"), ("code", "111-222")]);
        assert_eq!(handle_pair_confirm(&i).status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_pair_confirm_requires_id_name_context_and_code() {
        assert_eq!(handle_pair_confirm(&inv(&["pair", "confirm"], Door::Cli, &[])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(
            handle_pair_confirm(&inv(&["pair", "confirm"], Door::Cli, &[("id", "abc"), ("name", "box-b")])).status,
            aoide_protocol::output::Status::Usage
        );
        assert_eq!(
            handle_pair_confirm(&inv(&["pair", "confirm"], Door::Cli, &[("id", "abc"), ("name", "box-b"), ("context", "x")])).status,
            aoide_protocol::output::Status::Usage,
            "code is required -- a confirm dialog with nothing to show would be a blank window"
        );
    }
}
