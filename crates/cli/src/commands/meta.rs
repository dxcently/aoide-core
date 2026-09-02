//! `guide` / `schema` — the agent onboarding text and the machine-readable
//! command + state-file schema.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, Registry};
use serde_json::{json, Value};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["guide"],
        summary: "Print the four-tier agent onboarding (tier map + house rules).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_guide,
    ));
    r.insert(cmd!(
        path: ["schema"],
        summary: "Emit the versioned machine-readable schema of every command and state file.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_schema,
    ));
}

fn handle_guide(_inv: &Invocation) -> Outcome {
    let text = crate::guide::render(crate::dispatch::registry());
    Outcome::ok("guide", "printed the four-tier onboarding").with_data(json!({ "text": text }))
}

fn handle_schema(_inv: &Invocation) -> Outcome {
    let doc = crate::dispatch::registry().schema("aoide");
    let val = serde_json::to_value(&doc).unwrap_or(Value::Null);
    Outcome::ok("schema", "emitted the v0 command + state-file schema").with_data(val)
}
