//! The terminal OSC emitter — `emitters.js::emitOsc`.
//!
//! OSC 10 = foreground, OSC 11 = background, OSC 12 = cursor, and OSC 4 sets
//! palette entries. The v0 palette maps onto the conventional slots. Each
//! sequence is `ESC ] <ps> ; <color> BEL`, concatenated raw (no separators).
//! Byte-order- and byte-sensitive — golden-compared verbatim.

use crate::livery::emit::{EmitError, EmitOpts, EmitOutput, Emitter};
use crate::livery::resolve::Resolved;

/// The OSC stream emitter.
pub struct Osc;

impl Emitter for Osc {
    fn target(&self) -> &'static str {
        "osc"
    }

    fn emit(&self, r: &Resolved, _o: &EmitOpts) -> Result<EmitOutput, EmitError> {
        Ok(EmitOutput::Text(emit_osc(r)))
    }
}

/// `oscRgb` — `#rrggbb` → terminal's doubled-channel `rgb:rrrr/gggg/bbbb`.
fn osc_rgb(hex: &str) -> String {
    let h = hex.trim_start_matches('#');
    let (r, g, b) = (&h[0..2], &h[2..4], &h[4..6]);
    format!("rgb:{r}{r}/{g}{g}/{b}{b}")
}

pub fn emit_osc(r: &Resolved) -> String {
    const BEL: char = '\u{0007}';
    const ESC: char = '\u{001b}';
    let get = |k: &str| {
        r.palette
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let (bg, fg, accent, urgent) = (get("bg"), get("fg"), get("accent"), get("urgent"));
    let seq = |ps: &str, color: &str| format!("{ESC}]{ps};{}{BEL}", osc_rgb(color));

    let mut out = String::new();
    out.push_str(&seq("11", &bg)); // background
    out.push_str(&seq("10", &fg)); // foreground
    out.push_str(&seq("12", &accent)); // cursor
    // Map the four base colours onto base16-ish ANSI slots (minimal v0 subset).
    out.push_str(&format!("{ESC}]4;0;{}{BEL}", osc_rgb(&bg))); // ansi 0  (black/bg)
    out.push_str(&format!("{ESC}]4;4;{}{BEL}", osc_rgb(&accent))); // ansi 4  (blue/accent)
    out.push_str(&format!("{ESC}]4;1;{}{BEL}", osc_rgb(&urgent))); // ansi 1  (red/urgent)
    out.push_str(&format!("{ESC}]4;7;{}{BEL}", osc_rgb(&fg))); // ansi 7  (white/fg)
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
    fn osc_sequence_order_is_bg_fg_cursor_then_ansi_slots() {
        let s = emit_osc(&resolved("valid.json"));
        let esc = '\u{001b}';
        let bel = '\u{0007}';
        let expected = format!(
            "{esc}]11;rgb:1e1e/1e1e/2e2e{bel}{esc}]10;rgb:cdcd/d6d6/f4f4{bel}\
             {esc}]12;rgb:8989/b4b4/fafa{bel}{esc}]4;0;rgb:1e1e/1e1e/2e2e{bel}\
             {esc}]4;4;rgb:8989/b4b4/fafa{bel}{esc}]4;1;rgb:f3f3/8b8b/a8a8{bel}\
             {esc}]4;7;rgb:cdcd/d6d6/f4f4{bel}"
        );
        assert_eq!(s, expected);
    }

    #[test]
    fn osc_output_matches_golden_bytes_for_all_valid_fixtures() {
        for fix in ["valid", "valid-hot", "valid-base16"] {
            let s = emit_osc(&resolved(&format!("{fix}.json")));
            let golden =
                std::fs::read_to_string(format!("tests/goldens/{fix}.emit-osc.golden")).unwrap();
            assert_eq!(s, golden, "{fix}: osc output must be byte-identical to the Node engine");
        }
    }
}
