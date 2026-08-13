//! The authoritative v0 note schema — port of `pkgs/drachma/src/schema.js`
//! (CONTRACTS.md §1).
//!
//! This is what `livery lint` (and, transitively, `rice lint`) validates
//! against. The nix option type (modules/nucleus/options.nix) is a permissive
//! gate; THIS is the authoritative validator.
//!
//! v0 lives inside a W3C design-tokens container: a note is a W3C design-token
//! `$value` (and optionally `$type`). References use the `{group.name}` alias
//! syntax that Style Dictionary resolves. The palette tier is base16-closed; the
//! component tier is bar.* / notif.* / window.*, each field `nullOr hex` where
//! null means "fall back to the palette" (the FACET applies the fallback; the
//! stage emitter resolves it fully — see resolve.rs).
//!
//! Port faithfulness: every error string is byte-identical to the Node
//! original, including its JS-isms — a non-string non-`$value` leaf reports as
//! "required" at the palette tier but "missing (expected hex #rrggbb)" at the
//! component tier, and a missing key validates exactly like an explicit `null`
//! (JS `node == null` catches both). The unit tests mirror
//! `pkgs/drachma/test/run.js` cases 1–9 against the SAME fixtures.
//!
//! One known residual divergence (D3), in the RESOLVER not the errors: a
//! W3C-wrapped non-string leaf (`{"$value": 42}`) — which `lint` rejects in
//! BOTH engines with the same string, so it is unreachable through either
//! CLI — would stage-emit as the string `"42"` in Rust where Node's
//! `withHash` passes the number through untouched (Node's behavior is
//! accidental).

use serde_json::Value;

/// A hex colour: optional `#`, then exactly six hex digits
/// (`/^#?[0-9a-fA-F]{6}$/`).
pub fn is_hex(s: &str) -> bool {
    let body = match s.strip_prefix('#') {
        Some(b) => b,
        None => s,
    };
    body.len() == 6 && body.chars().all(|c| c.is_ascii_hexdigit())
}

/// A `{group.name}` reference (`/^\{[^}]+\}$/`).
pub fn is_ref(s: &str) -> bool {
    s.len() >= 3 && s.starts_with('{') && s.ends_with('}') && !s[1..s.len() - 1].contains('}')
}

/// The closed v0 shape: which keys exist in each tier, and the component→palette
/// fallback map (CONTRACTS.md §1). Component values may also be null.
pub const PALETTE_KEYS: [&str; 4] = ["bg", "fg", "accent", "urgent"];

/// Optional palette keys — present or absent, but when present must be a hex
/// colour (never null). `hot` is the one-neon trace/highlight colour (the
/// reference stills' optic-nerve green): notes WITHOUT it stay valid, and a
/// facet falls the surface back to `accent` when it is absent. Keeping it
/// optional preserves the v0 contract for every existing note file.
pub const PALETTE_OPTIONAL_KEYS: [&str; 1] = ["hot"];

/// The base16 tier — an OPTIONAL top-level block (sibling of `palette`) carrying
/// the full sixteen-slot terminal scheme (the "pantheon bw" ramp + accent set).
/// All-or-nothing and CLOSED, exactly like the palette: when the block is present
/// every slot base00..base0F must be given (each a hex, never null), and any key
/// outside the sixteen is rejected. Notes WITHOUT it stay valid — a facet falls
/// the wireframe accents back to `accent` when the block is absent, so the v0
/// contract is preserved for every existing note file (same posture as `hot`).
pub const BASE16_KEYS: [&str; 16] = [
    "base00", "base01", "base02", "base03", "base04", "base05", "base06", "base07",
    "base08", "base09", "base0A", "base0B", "base0C", "base0D", "base0E", "base0F",
];

/// Component tier → palette fallback source per field (CONTRACTS.md §1).
pub const COMPONENT_FALLBACK: [(&str, &[(&str, &str)]); 3] = [
    ("bar", &[("bg", "bg"), ("fg", "fg"), ("accent", "accent")]),
    ("notif", &[("bg", "bg"), ("fg", "fg"), ("urgent", "urgent")]),
    ("window", &[("border", "accent"), ("borderInactive", "bg")]),
];

/// The v0 schema version, carried into every resolved/emitted document.
pub const SCHEMA_VERSION: &str = "0";

// ── JS-shape helpers ─────────────────────────────────────────────────────────
//
// JS `typeof [] === "object"` and `Object.keys(arr)` yields index strings —
// the Node validator treats arrays as key-less objects, and so do we (for
// pathological inputs the error surface matches; the closed-set errors are
// identical either way).

/// `typeof v === "object"` in JS (objects AND arrays; `null` excluded).
fn is_objectish(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

/// `Object.keys(v)`: object keys in insertion order; array indices as strings.
fn object_keys(v: &Value) -> Vec<String> {
    match v {
        Value::Object(m) => m.keys().cloned().collect(),
        Value::Array(a) => (0..a.len()).map(|i| i.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// `v[key]` for an objectish value; `None` when the key is absent (JS
/// `undefined`).
fn object_get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(key),
        Value::Array(a) => key.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    }
}

// ── The validator ────────────────────────────────────────────────────────────

/// `noteValue(node)` — accept a bare string or a W3C design-token object
/// (`{ $value, $type }`). Returns:
/// * `Some(Some(v))` — a leaf value (string, or a `$value` of any type),
/// * `Some(None)` — JS `null` (missing key, `null`, or `undefined` — JS
///   `node == null` treats them alike),
/// * `None` — "not a note leaf" (JS `undefined`): any other scalar or an
///   object without `$value`.
pub(crate) fn note_value(node: Option<&Value>) -> Option<Option<&Value>> {
    match node {
        None => Some(None),
        Some(Value::Null) => Some(None),
        // The leaf IS the string node itself (borrowed from `node`).
        Some(v @ Value::String(_)) => Some(Some(v)),
        Some(v @ Value::Object(_)) => match object_get(v, "$value") {
            // JS-null leaf: `{"$value": null}` — Node's `noteValue` returns
            // `null`, indistinguishable from a bare null or a missing key.
            Some(Value::Null) => Some(None),
            other => other.map(Some),
        },
        Some(_) => None,
    }
}

/// JS `typeof` for error strings.
fn js_typeof(v: &Value) -> &'static str {
    match v {
        Value::Object(_) | Value::Array(_) => "object",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::String(_) => "string",
        Value::Null => "null",
    }
}

/// `checkColor` — validate a (dereferenced) leaf: must be hex, or null for a
/// component field (null is legal at the schema tier; the emitter resolves it).
/// An unresolved `{group.key}` reference passes at this tier (the resolver
/// checks the target).
///
/// Takes the FULL `note_value` result (`Option<Option<&Value>>`): JS's
/// `checkColor` receives `noteValue(…)` output, where `undefined` and `null`
/// are both the "missing" case (`value === null || value === undefined`).
fn check_color(
    value: Option<Option<&Value>>,
    path: &str,
    errors: &mut Vec<String>,
    allow_null: bool,
) {
    match value {
        // JS `value === null || value === undefined`.
        None | Some(None) => {
            if !allow_null {
                errors.push(format!("{path}: missing (expected hex #rrggbb)"));
            }
        }
        Some(Some(Value::String(s))) => {
            if is_ref(s) {
                return;
            }
            if !is_hex(s) {
                errors.push(format!("{path}: \"{s}\" is not a hex colour (#rrggbb)"));
            }
        }
        Some(Some(other)) => errors.push(format!(
            "{path}: expected hex string, got {}",
            js_typeof(other)
        )),
    }
}

/// The result of validating one note container (JS `{ ok, errors }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    pub ok: bool,
    pub errors: Vec<String>,
}

/// Validate a v0 note container. Works on the RAW container (references still
/// present) — reference targets are checked structurally, full resolution is
/// validated separately after deref.
pub fn validate(container: &Value) -> Validation {
    let mut errors: Vec<String> = Vec::new();

    if !is_objectish(container) {
        return Validation {
            ok: false,
            errors: vec!["root: note file must be a JSON object".to_string()],
        };
    }

    // Palette tier — required and closed.
    let palette = object_get(container, "palette");
    let palette = match palette {
        None | Some(Value::Null) => {
            errors.push("palette: required group missing".to_string());
            None
        }
        Some(p) if !is_objectish(p) => {
            errors.push("palette: required group missing".to_string());
            None
        }
        Some(p) => Some(p),
    };
    if let Some(palette) = palette {
        for k in PALETTE_KEYS {
            // JS: `v === undefined` → "required"; anything else (including
            // missing → null) goes through checkColor.
            match note_value(object_get(palette, k)) {
                None => errors.push(format!("palette.{k}: required")),
                Some(leaf) => check_color(Some(leaf), &format!("palette.{k}"), &mut errors, false),
            }
        }
        // Optional keys — validated only when present (never null when given).
        for k in PALETTE_OPTIONAL_KEYS {
            if object_get(palette, k).is_none() {
                continue;
            }
            let v = note_value(object_get(palette, k));
            check_color(v, &format!("palette.{k}"), &mut errors, false);
        }
        for k in object_keys(palette) {
            if !PALETTE_KEYS.contains(&k.as_str()) && !PALETTE_OPTIONAL_KEYS.contains(&k.as_str()) {
                errors.push(format!("palette.{k}: unknown key (v0 palette is closed)"));
            }
        }
    }

    // Base16 tier — optional, all-or-nothing, closed. Validated only when the
    // block is present; then every slot is required (a hex, never null) and no
    // key outside the sixteen is allowed. Mirrors the palette's closed handling.
    if object_get(container, "base16").is_some() {
        let base16 = object_get(container, "base16").unwrap();
        if !is_objectish(base16) {
            errors.push("base16: expected a note group object".to_string());
        } else {
            for k in BASE16_KEYS {
                match note_value(object_get(base16, k)) {
                    None => errors.push(format!("base16.{k}: required (base16 is all-or-nothing)")),
                    Some(leaf) => check_color(Some(leaf), &format!("base16.{k}"), &mut errors, false),
                }
            }
            for k in object_keys(base16) {
                if !BASE16_KEYS.contains(&k.as_str()) {
                    errors.push(format!("base16.{k}: unknown key (base16 is closed)"));
                }
            }
        }
    }

    // Component tier — optional groups, each field nullOr hex.
    for (group, fields) in COMPONENT_FALLBACK {
        let g = object_get(container, group);
        let g = match g {
            None | Some(Value::Null) => continue, // whole group optional
            Some(g) if !is_objectish(g) => {
                errors.push(format!("{group}: expected a note group object"));
                continue;
            }
            Some(g) => g,
        };
        for field in object_keys(g) {
            if !fields.iter().any(|(f, _)| *f == field) {
                errors.push(format!("{group}.{field}: unknown key (v0 {group} is closed)"));
                continue;
            }
            let v = note_value(object_get(g, &field));
            check_color(v, &format!("{group}.{field}"), &mut errors, true);
        }
    }

    Validation {
        ok: errors.is_empty(),
        errors,
    }
}

// ── Tests — mirror pkgs/drachma/test/run.js cases 1–9 ───────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> Value {
        let raw = std::fs::read_to_string(format!("tests/fixtures/{name}")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn check(name: &str, cond: bool) {
        assert!(cond, "FAIL — {name}");
    }

    // 1. The baseline v0 fixture (no `hot`) stays valid — optionality preserved.
    #[test]
    fn valid_json_no_hot_is_accepted() {
        let r = validate(&load("valid.json"));
        check("valid.json (no hot) is accepted", r.ok);
    }

    // 2. A palette WITH a well-formed `hot` hex is accepted (hot-accepted).
    #[test]
    fn palette_hot_good_hex_is_accepted() {
        let r = validate(&load("valid-hot.json"));
        check("palette.hot (good hex) is accepted", r.ok);
    }

    // 3. A palette with a bad `hot` hex is rejected, and the error names it.
    #[test]
    fn palette_hot_bad_hex_is_rejected_and_named() {
        let r = validate(&load("invalid-hot.json"));
        check("palette.hot (bad hex) is rejected", !r.ok);
        check(
            "rejection error names palette.hot",
            r.errors.iter().any(|e| e.contains("palette.hot")),
        );
    }

    // 4. `hot` is truly optional — an unknown *other* key still fails.
    #[test]
    fn unknown_palette_key_rejected_and_hot_is_allowlisted() {
        let mut bad = load("valid.json");
        bad["palette"]["bogus"] = Value::String("#000000".to_string());
        let r = validate(&bad);
        check("an unrelated unknown palette key is still rejected", !r.ok);
        check(
            "hot is in the optional-key allowlist",
            PALETTE_OPTIONAL_KEYS.contains(&"hot"),
        );
    }

    // 5. The base16 tier — a full sixteen-slot block is accepted.
    #[test]
    fn valid_base16_full_sixteen_is_accepted() {
        let r = validate(&load("valid-base16.json"));
        check("valid-base16.json (full sixteen) is accepted", r.ok);
    }

    // 6. A base16 block missing a slot is rejected, naming the slot.
    #[test]
    fn base16_missing_slot_rejected_and_named() {
        let r = validate(&load("invalid-base16-missing.json"));
        check("base16 missing a slot is rejected", !r.ok);
        check(
            "rejection error names the missing base16 slot",
            r.errors.iter().any(|e| e.contains("base16.base0F")),
        );
    }

    // 7. A base16 block with a bad hex is rejected, naming the slot.
    #[test]
    fn base16_bad_hex_rejected_and_named() {
        let r = validate(&load("invalid-base16-hex.json"));
        check("base16 with a bad hex is rejected", !r.ok);
        check(
            "rejection error names the bad base16 slot",
            r.errors.iter().any(|e| e.contains("base16.base0F")),
        );
    }

    // 8. An unknown key INSIDE the base16 block is rejected (base16 is closed).
    #[test]
    fn unknown_key_inside_base16_rejected_and_keyset_is_sixteen() {
        let mut bad = load("valid-base16.json");
        bad["base16"]["base10"] = serde_json::json!({ "$type": "color", "$value": "#000000" });
        let r = validate(&bad);
        check("an unknown key inside base16 is rejected", !r.ok);
        check("base16 exposes the full sixteen-slot keyset", BASE16_KEYS.len() == 16);
    }

    // 9. base16 stays truly OPTIONAL — the baseline fixture is valid.
    #[test]
    fn valid_json_no_base16_is_still_accepted() {
        let r = validate(&load("valid.json"));
        check("valid.json (no base16) is still accepted", r.ok);
    }

    // 10. A palette key with a JS-null `$value` (`{"$value": null}`) is
    // rejected with Node's EXACT string (D2) — never "got null".
    #[test]
    fn palette_null_value_rejected_with_exact_node_string() {
        let mut bad = load("valid.json");
        bad["palette"]["bg"] = serde_json::json!({ "$value": null });
        let r = validate(&bad);
        check("palette.bg with $value null is rejected", !r.ok);
        check(
            "error string is byte-identical to Node's",
            r.errors
                .iter()
                .any(|e| e == "palette.bg: missing (expected hex #rrggbb)"),
        );
    }

    // 11. A component field with a JS-null `$value` is ACCEPTED at lint
    // (D1) — Node treats `{"$value": null}` as a null leaf; the emitter
    // resolves the palette fallback.
    #[test]
    fn component_null_value_accepted_at_lint() {
        let mut v = load("valid.json");
        v["bar"]["bg"] = serde_json::json!({ "$value": null });
        let r = validate(&v);
        check("bar.bg with $value null is accepted at lint", r.ok);
        check("no errors reported", r.errors.is_empty());
    }
}
