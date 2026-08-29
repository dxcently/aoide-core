//! `lyra secrets ask` — the rice-shaped code-entry dialog `aoide secrets
//! watch --popup` spawns instead of `zenity --entry` once
//! `aoide_secrets::watch::resolve_lyra_bin` finds this binary
//! (`crates/secrets/src/watch.rs`'s own P3 doc). Six individually-boxed
//! digit inputs, grouped `[X][X][X] - [X][X][X]`, auto-submitting the
//! instant all six are filled; Esc or the window's own close button
//! cancels; a quiet "Dismiss ask" text control sends a real refusal. The
//! entry SURFACE itself — the boxes, the dash, the underlying `TextInput`,
//! the spawn/wait/parse/cleanup orchestration — lives in
//! [`super::dialog_qml`] now (P-PV3, task #132): a SECOND caller
//! ([`super::pair`]'s own `lyra pair ask`) is what forced that extraction,
//! see that module's own doc for the shared component and its output
//! contract. This module keeps only what is genuinely secrets-shaped: the
//! `--secret`/`--consumer`/`--seconds`/`--reason`/`--from` flags, this
//! command's own header wording ("release `X` -> Y", the reason/origin/
//! countdown lines), and its own `AOIDE_SECRETS_ASK_RESULT:` marker.
//!
//! **Output contract — byte-identical to zenity's** (`super::dialog_qml`'s
//! own doc has the full shape): the typed code on stdout with exit 0; the
//! literal string `Dismiss ask` on stdout with exit 1; a bare Esc/window-
//! close for exit 1 with no stdout; [`EXIT_INFRA_FAILURE`] (exit 3, a
//! re-export of `dialog_qml::EXIT_INFRA_FAILURE`) for a spawn/marker-less
//! failure. Don't change this contract here without updating
//! `crates/secrets/src/watch.rs`'s module doc AND `crates/secrets/
//! README.md`'s "Popup mode" section in the SAME commit.
//!
//! **The QML is paint only** (root `AGENTS.md` house rule 7's "delete every
//! `.qml`" test) — the capability (entering a TOTP code) stays reachable
//! with nothing but a shell: `aoide secrets approve <id> --totp <code>` and
//! the zenity fallback both work with this file deleted entirely.

use super::dialog_qml::{self, EXIT_INFRA_FAILURE as DIALOG_EXIT_INFRA_FAILURE, HeaderLine};
use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, flag, Registry};
use aoide_protocol::Door;
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["secrets", "ask"],
        summary: "Render a quickshell code-entry dialog for one parked TOTP ask -- six digit boxes grouped [X][X][X]-[X][X][X], auto-submitting once all six are filled. CLI-only: the counterpart `aoide secrets watch --popup` spawns in place of zenity when this binary resolves. Speaks zenity's own output contract (code on stdout + exit 0; `Dismiss ask` on stdout + exit 1; else non-zero) so the caller never needs to know which binary answered.",
        args: [],
        flags: [
            flag!("secret", "string", "The secret name this ask is for (display only)."),
            flag!("consumer", "string", "The consumer name asking (display only)."),
            flag!("seconds", "string", "Remaining seconds before this ask's park times out (display only, baked in at spawn -- never a live countdown, the same limitation zenity's own --text bakes)."),
            flag!("reason", "string", "Free-text context for why this ask exists (display only, self-asserted -- rendered verbatim, never interpreted)."),
            flag!("from", "string", "A pre-formatted 'from: ...' origin line (display only -- already rendered by the caller so every ask surface shows byte-identical wording, aoide-secrets' own watch::format_origin_line).")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_ask,
    ));
}

/// The prefix every result line [`super::dialog_qml`]'s `console.log` calls
/// carry for THIS command — [`super::pair`]'s own `lyra pair ask` carries a
/// distinct marker of its own, so a stray line from one dialog can never be
/// misread as a result from the other.
const RESULT_MARKER: &str = "AOIDE_SECRETS_ASK_RESULT:";

/// The on-screen dismiss control's label AND the literal stdout value
/// `aoide_secrets::watch::run_entry_dialog` compares against for the
/// `Dismissed` case (`aoide_protocol::dialog::DISMISS_LABEL`, restated here
/// as a literal since this command has no reason to depend on
/// `aoide-protocol`'s `dialog` module just for one string it already knows
/// by contract).
const DISMISS_TEXT: &str = "Dismiss ask";

const QUICKSHELL_CMD: &str = dialog_qml::QUICKSHELL_CMD;

/// Re-exported at this path since before the P-PV3 extraction —
/// `lib.rs`'s `special` hook reads it as `commands::secrets::
/// EXIT_INFRA_FAILURE` and there is no reason to touch that call site for
/// a purely internal reorganization.
pub const EXIT_INFRA_FAILURE: i32 = DIALOG_EXIT_INFRA_FAILURE;

fn handle_secrets_ask(inv: &Invocation) -> Outcome {
    let cmd = "secrets.ask";
    if inv.door != Door::Cli {
        return Outcome::usage(cmd, "secrets ask is a desktop dialog -- CLI-only");
    }
    let Some(secret) = inv.flags.get("secret").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "secrets ask requires --secret <name>");
    };
    let Some(consumer) = inv.flags.get("consumer").filter(|s| !s.is_empty()) else {
        return Outcome::usage(cmd, "secrets ask requires --consumer <name>");
    };
    let Some(seconds) = inv.flags.get("seconds").and_then(|s| s.parse::<u64>().ok()) else {
        return Outcome::usage(cmd, "secrets ask requires --seconds <n> (a non-negative integer)");
    };
    let reason = inv.flags.get("reason").filter(|s| !s.is_empty()).map(String::as_str);
    let from_line = inv.flags.get("from").filter(|s| !s.is_empty()).map(String::as_str);

    let title = format!("aoide \u{b7} {secret}");
    let header = build_header(secret, consumer, seconds, reason, from_line);

    match dialog_qml::run_code_entry_dialog(QUICKSHELL_CMD, "aoide-secrets-ask", &title, &header, DISMISS_TEXT, RESULT_MARKER) {
        Ok(dialog_qml::AskResult::Approved(code)) => {
            Outcome::ok(cmd, "code entered").with_data(json!({ "result": "approved", "code": code }))
        }
        Ok(dialog_qml::AskResult::Dismissed) => Outcome::ok(cmd, "dismissed").with_data(json!({ "result": "dismissed" })),
        Ok(dialog_qml::AskResult::Cancelled) => Outcome::ok(cmd, "cancelled").with_data(json!({ "result": "cancelled" })),
        Ok(dialog_qml::AskResult::Failed(reason)) => Outcome::error(cmd, reason).with_data(json!({ "result": "failed" })),
        Err(e) => Outcome::error(cmd, e).with_data(json!({ "result": "failed" })),
    }
}

/// This command's own header wording — the ONE place "release `X` -> Y"
/// plus the optional reason/origin lines and the always-present countdown
/// are composed, pure and independently testable with no quickshell
/// involved. Mirrors `aoide_secrets::watch::format_prompt_header`'s own
/// line order (that function's doc).
fn build_header(secret: &str, consumer: &str, seconds: u64, reason: Option<&str>, from_line: Option<&str>) -> Vec<HeaderLine> {
    let mut header = vec![HeaderLine::bold(format!("release `{secret}` \u{2192} {consumer}"))];
    if let Some(r) = reason {
        header.push(HeaderLine::italic(format!("for: \"{r}\"")));
    }
    if let Some(f) = from_line {
        header.push(HeaderLine::muted(f.to_string()));
    }
    header.push(HeaderLine::muted(format!("{seconds}s left")));
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_texts(header: &[HeaderLine]) -> Vec<&str> {
        header.iter().map(|l| l.text.as_str()).collect()
    }

    #[test]
    fn build_header_carries_the_release_line_and_countdown_with_no_reason_or_from() {
        let header = build_header("db-prod", "claude", 120, None, None);
        let texts = header_texts(&header);
        assert_eq!(texts, vec!["release `db-prod` \u{2192} claude", "120s left"]);
    }

    #[test]
    fn build_header_includes_reason_and_from_when_present_in_order() {
        let header = build_header("db-prod", "claude", 120, Some("sudo nixos-rebuild switch"), Some("from: khoa @ yomi-strix"));
        let texts = header_texts(&header);
        assert_eq!(
            texts,
            vec!["release `db-prod` \u{2192} claude", "for: \"sudo nixos-rebuild switch\"", "from: khoa @ yomi-strix", "120s left"]
        );
    }

    // ── handle_secrets_ask door/flag validation (no live quickshell) ─────

    fn inv(door: Door, flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = std::collections::BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation { path: vec!["secrets".to_string(), "ask".to_string()], args: vec![], flags: flag_map, door }
    }

    #[test]
    fn handle_secrets_ask_is_cli_only() {
        let i = inv(Door::Mcp, &[("secret", "t"), ("consumer", "m"), ("seconds", "1")]);
        assert_eq!(handle_secrets_ask(&i).status, aoide_protocol::output::Status::Usage);
    }

    #[test]
    fn handle_secrets_ask_requires_secret_consumer_and_seconds() {
        assert_eq!(handle_secrets_ask(&inv(Door::Cli, &[])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(handle_secrets_ask(&inv(Door::Cli, &[("secret", "t")])).status, aoide_protocol::output::Status::Usage);
        assert_eq!(
            handle_secrets_ask(&inv(Door::Cli, &[("secret", "t"), ("consumer", "m")])).status,
            aoide_protocol::output::Status::Usage
        );
        assert_eq!(
            handle_secrets_ask(&inv(Door::Cli, &[("secret", "t"), ("consumer", "m"), ("seconds", "not-a-number")])).status,
            aoide_protocol::output::Status::Usage
        );
    }
}
