//! The hyprctl emitter — compositor dispatch commands. Port of
//! `emitters.js::emitHyprctl`.
//!
//! Window decoration is the compositor's v0 surface. hyprctl expects colours
//! as `rgb(rrggbb)` / `rgba(rrggbbaa)`; we emit the two border colours as
//! keyword setters — argv-style lines, well-formed and quoting-safe.
//! Byte-order-sensitive: the CLI joins them shell-quoted one per line and the
//! golden is byte-compared, so [`shell_quote`] lives here (it IS part of the
//! emitted bytes, ported from the Node CLI's `shellQuote`).

use crate::livery::emit::{EmitError, EmitOpts, EmitOutput, Emitter};
use crate::livery::resolve::Resolved;

/// `emitHyprctl` — the two border-keyword argv lines, in fixed order
/// (active, then inactive).
pub struct Hyprctl;

impl Emitter for Hyprctl {
    fn target(&self) -> &'static str {
        "hyprctl"
    }

    fn emit(&self, r: &Resolved, _o: &EmitOpts) -> Result<EmitOutput, EmitError> {
        Ok(EmitOutput::Lines(emit_hyprctl(r)))
    }
}

fn hypr_color(hex: &str) -> String {
    // JS: `String(hex).replace(/^#/, "")` → `rgb(...)`.
    format!("rgb({})", hex.trim_start_matches('#'))
}

pub fn emit_hyprctl(r: &Resolved) -> Vec<Vec<String>> {
    let get = |k: &str| {
        r.window
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    vec![
        vec![
            "hyprctl".to_string(),
            "keyword".to_string(),
            "general:col.active_border".to_string(),
            hypr_color(&get("border")),
        ],
        vec![
            "hyprctl".to_string(),
            "keyword".to_string(),
            "general:col.inactive_border".to_string(),
            hypr_color(&get("borderInactive")),
        ],
    ]
}

/// The Node CLI's `shellQuote`: safe-char classes pass through unquoted,
/// anything else gets single-quoted with `'\''` escapes. This join is part
/// of the emitted byte contract, so it is the engine's, not the CLI's.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:/=()-".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Render argv lines as one shell-ready command per line (the CLI's stdout
/// bytes for `emit hyprctl` — and the golden's).
pub fn render_lines(cmds: &[Vec<String>]) -> String {
    let mut out = String::new();
    for argv in cmds {
        let quoted: Vec<String> = argv.iter().map(|a| shell_quote(a)).collect();
        out.push_str(&quoted.join(" "));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::livery::resolve::resolve;
    use serde_json::Value;

    fn resolved(fixture: &str) -> Resolved {
        let raw = std::fs::read_to_string(format!("tests/fixtures/{fixture}")).unwrap();
        let container: Value = serde_json::from_str(&raw).unwrap();
        resolve(&container).unwrap()
    }

    #[test]
    fn hyprctl_emits_two_border_keywords_in_fixed_order() {
        let cmds = emit_hyprctl(&resolved("valid.json"));
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0][0..3], ["hyprctl", "keyword", "general:col.active_border"]);
        assert_eq!(cmds[0][3], "rgb(89b4fa)");
        assert_eq!(cmds[1][2], "general:col.inactive_border");
        assert_eq!(cmds[1][3], "rgb(1e1e2e)");
    }

    #[test]
    fn hyprctl_output_matches_golden_bytes_for_all_valid_fixtures() {
        for fix in ["valid", "valid-hot", "valid-base16"] {
            let cmds = emit_hyprctl(&resolved(&format!("{fix}.json")));
            let golden =
                std::fs::read_to_string(format!("tests/goldens/{fix}.emit-hyprctl.golden"))
                    .unwrap();
            assert_eq!(
                render_lines(&cmds),
                golden,
                "{fix}: hyprctl output must be byte-identical to the Node engine"
            );
        }
    }

    #[test]
    fn shell_quote_passes_safe_characters_unquoted() {
        assert_eq!(shell_quote("hyprctl"), "hyprctl");
        assert_eq!(shell_quote("rgb(89b4fa)"), "rgb(89b4fa)");
        assert_eq!(shell_quote("general:col.active_border"), "general:col.active_border");
    }

    #[test]
    fn shell_quote_wraps_hostile_characters() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}
