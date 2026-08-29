//! `lyra pair ask` (P-PV3, task #132) — the rice-shaped code-entry dialog
//! `aoide peer pair watch --popup` spawns instead of `zenity --entry` once
//! `aoide_client::pair_watch::resolve_lyra_bin` finds this binary — the
//! SAME six-boxes-plus-dash digit entry surface `lyra secrets ask` (P3)
//! renders, REUSED via [`super::dialog_qml`] (root `AGENTS.md` house rule
//! 7's "reused, never copied"), never a second copy of that component: this
//! module's own job is only the pairing-ceremony's flags and wording —
//! `--id`/`--name`/`--context`/`--code` and this command's own
//! `AOIDE_PAIR_ASK_RESULT:` marker/`"Reject request"` dismiss label.
//!
//! **Why NOT `lyra secrets ask` verbatim (orchestrator-resolved fork,
//! P-PV3's own brief)**: that command is hard-coupled to the secrets
//! registry's own wording ("release `SECRET` -> CONSUMER") and flag
//! surface (`--secret`/`--consumer`/`--seconds`) — a generic code-entry
//! surface with caller-supplied title/context text did not exist before
//! this phase. The fix is the [`super::dialog_qml`] extraction (this
//! module's own doc has the shared contract); THIS command adds nothing
//! duplicated, only the pairing-specific flags/wording sitting on top of
//! it, exactly as `commands::secrets` now does for its own.
//!
//! **Untrusted display data.** `--context` carries the "pairing request
//! from `<name>` (<host>) · id <id>" (or the outbound "confirm pairing
//! with..." ) line `aoide_client::pair_watch` already builds ONCE (the same
//! "one place this wording lives" discipline `aoide_secrets::watch::
//! format_origin_line` holds for its own `--from`) — `name`/`host` are
//! PEER-SUPPLIED (a `pair-parked`/`pair-revealed` feed record, or an
//! outbound entry's own recorded name), so this text is rendered
//! byte-for-byte, never interpreted, and the shared renderer's
//! `qml_escape` is what keeps it from ever breaking out of its own QML
//! string literal. **`--code` (optional — outbound direction only) is NOT
//! the same trust class**: it is THIS instance's own locally-derived SAS
//! (`aoide_storage::pairing::derive_sas`), shown so the requester's own
//! operator can read it aloud and then retype it — never received for the
//! INBOUND direction, where the approver's whole gate is typing a code
//! read from ELSEWHERE (showing it here would collapse the out-of-band
//! comparison into a copy exercise, the same reasoning
//! `aoide_client::commands::approve_inbound`'s own doc gives for why its
//! CLI prompt never echoes the SAS either).
//!
//! **Output contract — identical to `lyra secrets ask`'s, different
//! marker/label**: the typed code on stdout with exit 0; the literal
//! string `"Reject request"` on stdout with exit 1 (`REJECT_LABEL` —
//! `aoide_client::pair_watch`'s own constant, restated here as a literal
//! since this crate cannot depend on `aoide-client`); a bare Esc/window-
//! close for exit 1 with no stdout; [`EXIT_INFRA_FAILURE`] (exit 3) for a
//! spawn/marker-less failure. `aoide_client::pair_watch::run_entry_dialog`
//! is the one reader of this contract — don't change it here without
//! updating that module's own doc in the SAME commit.
//!
//! **The QML is paint only** (root `AGENTS.md` house rule 7's "delete
//! every `.qml`" test) — the capability (approving a pairing request with
//! a typed code) stays reachable with nothing but a shell: `aoide peer
//! pair approve <id> --code <code>` and the zenity fallback both work with
//! this file deleted entirely.

use super::dialog_qml::{self, EXIT_INFRA_FAILURE as DIALOG_EXIT_INFRA_FAILURE, HeaderLine};
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use aoide_protocol::Door;
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["pair", "ask"],
        summary: "Render a quickshell code-entry dialog for one actionable pairing request -- the same six-digit-boxes-plus-dash surface `lyra secrets ask` renders, collecting a TYPED SAS code rather than a bare Approve/Reject. CLI-only: the counterpart `aoide peer pair watch --popup` spawns in place of zenity when this binary resolves.",
        args: [],
        flags: [
            flag!("id", "string", "The pairing request id (display + audit only)."),
            flag!("name", "string", "The peer's claimed name -- used for the dialog's window title (untrusted display data)."),
            flag!("context", "string", "The pre-formatted context line -- 'pairing request from `name` (host) . id <id>' or the outbound equivalent, already built once by the caller so zenity and this dialog render byte-identical wording."),
            flag!("code", "string", "Optional: this instance's own locally-derived SAS, shown ONLY on the outbound (requester) direction so the operator can read it aloud and retype it -- never passed on the inbound (approver) direction, where the code must come from elsewhere.")
        ],
        gated: false,
        implemented: true,
        handler: handle_pair_ask,
    ));
}

/// This command's own marker prefix — distinct from `lyra secrets ask`'s
/// `AOIDE_SECRETS_ASK_RESULT:` so a stray line from one dialog can never be
/// misread as a result from the other ([`super::dialog_qml`]'s own doc).
const RESULT_MARKER: &str = "AOIDE_PAIR_ASK_RESULT:";

/// `aoide_client::pair_watch::REJECT_LABEL`, restated here as a literal —
/// this crate cannot depend on `aoide-client` for one string constant, the
/// same "no shared Rust type across the core/paint boundary" posture
/// `aoide_protocol::dialog::LYRA_INFRA_FAILURE_EXIT`'s own doc holds for
/// its own mirrored constant.
const DISMISS_TEXT: &str = "Reject request";

const QUICKSHELL_CMD: &str = dialog_qml::QUICKSHELL_CMD;

/// Mirrors `commands::secrets::EXIT_INFRA_FAILURE` — `lib.rs`'s `special`
/// hook for `["pair", "ask"]` reads it at this path.
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
    let code = inv.flags.get("code").filter(|s| !s.is_empty()).map(String::as_str);

    let title = format!("aoide \u{b7} pairing with {name}");
    let header = build_header(context, code);

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

/// This command's own header wording — the context line always bold, the
/// SAS line (outbound only) muted underneath it. Pure and independently
/// testable with no quickshell involved, the same shape
/// `commands::secrets::build_header` holds for its own flags.
fn build_header(context: &str, code: Option<&str>) -> Vec<HeaderLine> {
    let mut header = vec![HeaderLine::bold(context.to_string())];
    if let Some(c) = code {
        header.push(HeaderLine::muted(format!("code: {c}")));
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_texts(header: &[HeaderLine]) -> Vec<&str> {
        header.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn build_header_carries_only_the_context_line_when_code_is_absent() {
        let header = build_header("pairing request from `box-a` (10.0.0.5) \u{b7} id abc12345", None);
        assert_eq!(header_texts(&header), vec!["pairing request from `box-a` (10.0.0.5) \u{b7} id abc12345"]);
    }

    #[test]
    fn build_header_appends_the_code_line_when_present() {
        let header = build_header("confirm pairing with `box-b` \u{b7} id deadbeef", Some("111-222"));
        assert_eq!(header_texts(&header), vec!["confirm pairing with `box-b` \u{b7} id deadbeef", "code: 111-222"]);
    }

    // ── handle_pair_ask door/flag validation (no live quickshell) ────────

    fn inv(door: Door, flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = std::collections::BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation { path: vec!["pair".to_string(), "ask".to_string()], args: vec![], flags: flag_map, door }
    }

    #[test]
    fn handle_pair_ask_is_cli_only() {
        let i = inv(Door::Mcp, &[("id", "abc"), ("name", "box-a"), ("context", "x")]);
        assert_eq!(handle_pair_ask(&i).status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_pair_ask_requires_id_name_and_context() {
        assert_eq!(handle_pair_ask(&inv(Door::Cli, &[])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(handle_pair_ask(&inv(Door::Cli, &[("id", "abc")])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(
            handle_pair_ask(&inv(Door::Cli, &[("id", "abc"), ("name", "box-a")])).status,
            aoide_protocol::output::Status::Usage
        );
    }
}
