//! `guide` / `schema` — lyra's own onboarding text and machine-readable
//! command schema. Mirrors `aoide-cli`'s `commands/meta.rs`, reading lyra's
//! own assembled registry rather than core's.

use crate::dispatch::Invocation;
use crate::guide::GUIDE;
use crate::output::Outcome;
use crate::registry::{cmd, Registry};
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["guide"],
        summary: "Print lyra's tier-0 onboarding (the rice/screen/herald bundle map).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_guide,
    ));
    r.insert(cmd!(
        path: ["schema"],
        summary: "Emit the versioned machine-readable schema of every lyra command.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_schema,
    ));
}

fn handle_guide(_inv: &Invocation) -> Outcome {
    Outcome::ok("guide", "printed lyra's tier-0 onboarding").with_data(json!({ "text": GUIDE }))
}

fn handle_schema(_inv: &Invocation) -> Outcome {
    let doc = crate::dispatch::registry().schema();
    let val = serde_json::to_value(&doc).unwrap_or(Value::Null);
    Outcome::ok("schema", "emitted lyra's v0 command schema").with_data(val)
}
