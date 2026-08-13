//! The stage emitter — `song/stage/livery.json` for Quickshell
//! (CONTRACTS.md §4). Port of `emitters.js::emitStage`.
//!
//! The resolved, flattened values — component fallbacks are already applied
//! by `resolve`, so Quickshell reads concrete colours, never null. Shape
//! matches CONTRACTS.md §4 exactly: schemaVersion + palette + bar/notif/window,
//! with base16 riding through when the note carries it. Serde's JSON map is
//! BTreeMap-backed, so the emitted `Value`'s key order is alphabetical —
//! readers (Quickshell `LiveryState.qml`, the conductor) read by key, and
//! the golden parity contract for stage is SEMANTIC (parse + compare), not
//! byte-for-byte (that's osc/hyprctl).

use crate::livery::emit::{EmitError, EmitOpts, EmitOutput, Emitter};
use crate::livery::resolve::Resolved;
use serde_json::{Value, json};

/// `emitStage` — the stage document.
pub struct Stage;

impl Emitter for Stage {
    fn target(&self) -> &'static str {
        "stage"
    }

    fn emit(&self, r: &Resolved, _o: &EmitOpts) -> Result<EmitOutput, EmitError> {
        Ok(EmitOutput::Json(emit_stage(r)))
    }
}

fn pairs(m: &[(String, String)]) -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in m {
        out.insert(k.clone(), Value::String(v.clone()));
    }
    Value::Object(out)
}

pub fn emit_stage(r: &Resolved) -> Value {
    let mut out = json!({
        "schemaVersion": r.schema_version,
        "palette": pairs(&r.palette),
        "bar": pairs(&r.bar),
        "notif": pairs(&r.notif),
        "window": pairs(&r.window),
    });
    // The base16 tier rides through untouched when present (Quickshell reads
    // the wireframe accents from it — LiveryState.qml). Omitted when the
    // note lacks it.
    if let Some(b16) = &r.base16 {
        out["base16"] = pairs(b16);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_shape_carries_every_tier_fully_resolved() {
        let raw = std::fs::read_to_string("tests/fixtures/valid.json").unwrap();
        let container: Value = serde_json::from_str(&raw).unwrap();
        let r = crate::livery::resolve::resolve(&container).unwrap();
        let stage = emit_stage(&r);
        assert_eq!(stage["schemaVersion"], "0");
        assert_eq!(stage["palette"]["bg"], "#1e1e2e");
        assert_eq!(stage["bar"]["bg"], "#1e1e2e", "fallback applied, never null");
        assert_eq!(stage["window"]["border"], "#89b4fa");
        assert!(stage.get("base16").is_none(), "base16 omitted when absent");
        // No nulls anywhere (CONTRACTS.md §4: Quickshell never reads null).
        let body = serde_json::to_string(&stage).unwrap();
        assert!(!body.contains("null"), "stage carries concrete colours only");
    }

    #[test]
    fn stage_includes_base16_when_the_note_carries_it() {
        let raw = std::fs::read_to_string("tests/fixtures/valid-base16.json").unwrap();
        let container: Value = serde_json::from_str(&raw).unwrap();
        let r = crate::livery::resolve::resolve(&container).unwrap();
        let stage = emit_stage(&r);
        assert_eq!(stage["base16"]["base00"], "#0a0a0d");
        assert_eq!(stage["base16"]["base0F"], "#9a6b8f");
    }
}
