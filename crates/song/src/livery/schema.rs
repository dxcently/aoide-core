//! The authoritative v0 note schema validator (CONTRACTS.md §1).
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
//! the original JS test suite's cases 1–9 against the SAME fixtures.
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

/// The widgets-tier per-entry field set (CONTRACTS.md §5 "Per-song flavor
/// widgets"; `modules/nucleus/options.nix`'s `widgetType` submodule — this
/// validator is that option's authoritative Rust-side twin, same
/// permissive-nix/authoritative-Rust split as the rest of this file). Each
/// entry under the top-level `widgets` key is CLOSED, exactly like the
/// palette/base16/component groups above.
pub const WIDGET_KEYS: [&str; 6] =
    ["kind", "namespace", "layer", "shortcut", "blur", "order"];

/// The only valid `widgets.<slot>.layer` values (`options.nix`'s
/// `types.enum [ "overlay" "top" ]`).
pub const WIDGET_LAYER_VALUES: [&str; 2] = ["overlay", "top"];

/// The only valid `widgets.<slot>.kind` values (`options.nix`'s
/// `types.enum [ "surface" "dock" ]`). `"surface"` mounts into a layer-shell
/// surface (`namespace`/`layer`/`shortcut`/`blur` apply); `"dock"` mounts
/// into `AoidePanel`'s gadget column instead (`order` applies) — the two
/// kinds' extra fields are mutually exclusive, enforced below.
pub const WIDGET_KIND_VALUES: [&str; 2] = ["surface", "dock"];

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

    // Widgets tier — optional top-level key, an object keyed by slot name
    // (CONTRACTS.md §5; `aoide.arrangement.widgets`, options.nix). Absent
    // means "no declared widget types", treated as `{}` — same posture the
    // build-time walk already uses (`modules/facets/quickshell/default.nix`'s
    // `.widgets // {}`). These fields are plain configuration, not W3C
    // design-token notes (no `{group.key}` refs, no `$value` wrapping), so
    // they are matched directly against `Value`, unlike the colour tiers
    // above.
    match object_get(container, "widgets") {
        None | Some(Value::Null) => {}
        Some(w) if !is_objectish(w) => {
            errors.push("widgets: expected an object keyed by slot name".to_string());
        }
        Some(widgets) => {
            for slot in object_keys(widgets) {
                let entry = object_get(widgets, &slot).unwrap();
                let path = format!("widgets.{slot}");
                if !is_objectish(entry) {
                    errors.push(format!("{path}: expected a widget declaration object"));
                    continue;
                }

                // kind — required; "surface" or "dock" are the valid v1
                // values (WIDGET_KIND_VALUES). Captured for the
                // kind-conditional field checks below: `namespace`/`layer`/
                // `shortcut`/`blur` are surface-only, `order` is dock-only.
                let kind: Option<&str> = match object_get(entry, "kind") {
                    None | Some(Value::Null) => {
                        errors.push(format!("{path}.kind: required"));
                        None
                    }
                    Some(Value::String(s)) => {
                        if WIDGET_KIND_VALUES.contains(&s.as_str()) {
                            Some(s.as_str())
                        } else {
                            errors.push(format!(
                                "{path}.kind: \"{s}\" is not a valid kind (expected \"surface\" or \"dock\")"
                            ));
                            None
                        }
                    }
                    Some(other) => {
                        errors.push(format!(
                            "{path}.kind: expected string, got {}",
                            js_typeof(other)
                        ));
                        None
                    }
                };

                // namespace — optional string; null/absent both mean
                // "derive from the slot name" (options.nix
                // `widgetType.namespace`). Surface-only: a dock entry has no
                // layer-shell surface, so a namespace on one is almost
                // certainly a copy-paste mistake.
                match object_get(entry, "namespace") {
                    None | Some(Value::Null) => {}
                    Some(_) if kind == Some("dock") => errors.push(format!(
                        "{path}.namespace: not valid for kind \"dock\" (namespace only applies to kind \"surface\")"
                    )),
                    Some(Value::String(_)) => {}
                    Some(other) => errors.push(format!(
                        "{path}.namespace: expected string, got {}",
                        js_typeof(other)
                    )),
                }

                // layer — optional string; surface-only, same posture as
                // namespace. When present for "surface", must be "overlay"
                // or "top" (default "overlay" is applied downstream, not
                // here).
                match object_get(entry, "layer") {
                    None => {}
                    Some(_) if kind == Some("dock") => errors.push(format!(
                        "{path}.layer: not valid for kind \"dock\" (layer only applies to kind \"surface\")"
                    )),
                    Some(Value::String(s)) if WIDGET_LAYER_VALUES.contains(&s.as_str()) => {}
                    Some(Value::String(s)) => errors.push(format!(
                        "{path}.layer: \"{s}\" is not a valid layer (expected \"overlay\" or \"top\")"
                    )),
                    Some(other) => errors.push(format!(
                        "{path}.layer: expected string, got {}",
                        js_typeof(other)
                    )),
                }

                // shortcut — optional string or null; surface-only, same
                // posture as namespace.
                match object_get(entry, "shortcut") {
                    None | Some(Value::Null) => {}
                    Some(_) if kind == Some("dock") => errors.push(format!(
                        "{path}.shortcut: not valid for kind \"dock\" (shortcut only applies to kind \"surface\")"
                    )),
                    Some(Value::String(_)) => {}
                    Some(other) => errors.push(format!(
                        "{path}.shortcut: expected string, got {}",
                        js_typeof(other)
                    )),
                }

                // blur — optional bool; surface-only, same posture as
                // namespace/layer/shortcut (default true is applied
                // downstream, not here).
                match object_get(entry, "blur") {
                    None => {}
                    Some(_) if kind == Some("dock") => errors.push(format!(
                        "{path}.blur: not valid for kind \"dock\" (blur only applies to kind \"surface\")"
                    )),
                    Some(Value::Bool(_)) => {}
                    Some(other) => errors.push(format!(
                        "{path}.blur: expected boolean, got {}",
                        js_typeof(other)
                    )),
                }

                // order — optional integer; dock-only (dock-column
                // ordering — surfaces don't participate in the dock column,
                // so an order on one is almost certainly a copy-paste
                // mistake).
                match object_get(entry, "order") {
                    None | Some(Value::Null) => {}
                    Some(_) if kind == Some("surface") => errors.push(format!(
                        "{path}.order: not valid for kind \"surface\" (order only applies to kind \"dock\")"
                    )),
                    Some(Value::Number(n)) if n.is_i64() => {}
                    Some(other) => errors.push(format!(
                        "{path}.order: expected integer, got {}",
                        js_typeof(other)
                    )),
                }

                // Unknown keys — widget entries are closed.
                for k in object_keys(entry) {
                    if !WIDGET_KEYS.contains(&k.as_str()) {
                        errors.push(format!("{path}.{k}: unknown key ({path} is closed)"));
                    }
                }
            }
        }
    }

    Validation {
        ok: errors.is_empty(),
        errors,
    }
}

// ── Tests — mirror the original JS test suite, cases 1–9 ────────────────────
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

    // ── Widgets tier (CONTRACTS.md §5 / options.nix `widgetType`) ───────────

    // 12. widgets absent stays valid — same optionality as base16/hot.
    #[test]
    fn widgets_absent_is_accepted() {
        let r = validate(&load("valid.json"));
        check("valid.json (no widgets) is accepted", r.ok);
    }

    // 13. An empty widgets object is accepted.
    #[test]
    fn widgets_empty_object_is_accepted() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({});
        let r = validate(&v);
        check("widgets: {} is accepted", r.ok);
    }

    // 14. A fully-specified valid widget entry is accepted.
    #[test]
    fn widgets_full_entry_is_accepted() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({
            "grimoire": {
                "kind": "surface",
                "namespace": "aoide-grimoire",
                "layer": "top",
                "shortcut": "aoide:grimoire",
                "blur": false
            }
        });
        let r = validate(&v);
        check("a full valid widget entry is accepted", r.ok);
    }

    // 15. A widget entry with only the required `kind` field is accepted —
    // namespace/layer/shortcut/blur are all optional.
    #[test]
    fn widgets_entry_with_only_kind_is_accepted() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "grimoire": { "kind": "surface" } });
        let r = validate(&v);
        check("a widget entry with only `kind` is accepted", r.ok);
    }

    // 16. A missing `kind` is rejected, naming the slot.
    #[test]
    fn widgets_missing_kind_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "grimoire": {} });
        let r = validate(&v);
        check("a widget entry with no kind is rejected", !r.ok);
        check(
            "rejection error names widgets.grimoire.kind",
            r.errors.iter().any(|e| e == "widgets.grimoire.kind: required"),
        );
    }

    // 17. An invalid `kind` value is rejected — "surface" and "dock" are the
    // only v1 values, and the error enumerates both.
    #[test]
    fn widgets_invalid_kind_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "grimoire": { "kind": "popup" } });
        let r = validate(&v);
        check("kind \"popup\" is rejected", !r.ok);
        check(
            "rejection error enumerates both valid kind values",
            r.errors.iter().any(|e| {
                e == "widgets.grimoire.kind: \"popup\" is not a valid kind (expected \"surface\" or \"dock\")"
            }),
        );
    }

    // 18. An invalid `layer` value is rejected — only overlay/top are valid.
    #[test]
    fn widgets_invalid_layer_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] =
            serde_json::json!({ "grimoire": { "kind": "surface", "layer": "bottom" } });
        let r = validate(&v);
        check("layer \"bottom\" is rejected", !r.ok);
        check(
            "rejection error names widgets.grimoire.layer",
            r.errors.iter().any(|e| e.contains("widgets.grimoire.layer")),
        );
    }

    // 19. `namespace`/`shortcut` explicit `null` are tolerated (both mean
    // "derive"/"none"), same JS-`== null` posture as the colour tiers.
    #[test]
    fn widgets_null_namespace_and_shortcut_are_accepted() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({
            "grimoire": { "kind": "surface", "namespace": null, "shortcut": null }
        });
        let r = validate(&v);
        check("null namespace/shortcut are accepted", r.ok);
    }

    // 20. A non-bool `blur` is rejected, naming the slot.
    #[test]
    fn widgets_non_bool_blur_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "grimoire": { "kind": "surface", "blur": "yes" } });
        let r = validate(&v);
        check("a non-bool blur is rejected", !r.ok);
        check(
            "rejection error names widgets.grimoire.blur",
            r.errors.iter().any(|e| e.contains("widgets.grimoire.blur")),
        );
    }

    // 21. An unknown key inside a widget entry is rejected — widget entries
    // are closed, same discipline as base16/palette/component.
    #[test]
    fn widgets_unknown_key_inside_entry_is_rejected() {
        let mut v = load("valid.json");
        v["widgets"] =
            serde_json::json!({ "grimoire": { "kind": "surface", "bogus": "nope" } });
        let r = validate(&v);
        check("an unknown key inside a widget entry is rejected", !r.ok);
        check(
            "rejection error names widgets.grimoire.bogus",
            r.errors.iter().any(|e| e.contains("widgets.grimoire.bogus")),
        );
    }

    // 22. `widgets` itself must be an object keyed by slot name.
    #[test]
    fn widgets_non_object_is_rejected() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!("nope");
        let r = validate(&v);
        check("a non-object widgets value is rejected", !r.ok);
        check(
            "rejection error names widgets",
            r.errors.iter().any(|e| e.starts_with("widgets:")),
        );
    }

    // ── `kind: "dock"` (Phase 9 v2 expansion) ────────────────────────────────

    // 23. A `dock`-kind entry with ONLY `kind` is accepted — namespace,
    // layer, shortcut, and blur are surface-only, and `order` is optional
    // even for dock.
    #[test]
    fn widgets_dock_kind_with_only_kind_is_accepted() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "dockwidget": { "kind": "dock" } });
        let r = validate(&v);
        check("a dock-kind entry with only `kind` is accepted", r.ok);
    }

    // 24. A `dock`-kind entry with `kind` and `order` is accepted.
    #[test]
    fn widgets_dock_kind_with_order_is_accepted() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "dockwidget": { "kind": "dock", "order": 2 } });
        let r = validate(&v);
        check("a dock-kind entry with kind + order is accepted", r.ok);
    }

    // 25. A `dock`-kind entry with `namespace` present is rejected —
    // namespace is surface-only; the error names both the field and the
    // entry's actual kind.
    #[test]
    fn widgets_dock_kind_with_namespace_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] =
            serde_json::json!({ "dockwidget": { "kind": "dock", "namespace": "aoide-dock" } });
        let r = validate(&v);
        check("dock + namespace is rejected", !r.ok);
        check(
            "error names widgets.dockwidget.namespace and kind \"dock\"",
            r.errors.iter().any(|e| {
                e == "widgets.dockwidget.namespace: not valid for kind \"dock\" (namespace only applies to kind \"surface\")"
            }),
        );
    }

    // 26. A `dock`-kind entry with `layer` present is rejected — same
    // surface-only posture as namespace.
    #[test]
    fn widgets_dock_kind_with_layer_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "dockwidget": { "kind": "dock", "layer": "top" } });
        let r = validate(&v);
        check("dock + layer is rejected", !r.ok);
        check(
            "error names widgets.dockwidget.layer and kind \"dock\"",
            r.errors.iter().any(|e| {
                e == "widgets.dockwidget.layer: not valid for kind \"dock\" (layer only applies to kind \"surface\")"
            }),
        );
    }

    // 27. A `dock`-kind entry with `shortcut` present is rejected — same
    // surface-only posture as namespace.
    #[test]
    fn widgets_dock_kind_with_shortcut_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({
            "dockwidget": { "kind": "dock", "shortcut": "aoide:dockwidget" }
        });
        let r = validate(&v);
        check("dock + shortcut is rejected", !r.ok);
        check(
            "error names widgets.dockwidget.shortcut and kind \"dock\"",
            r.errors.iter().any(|e| {
                e == "widgets.dockwidget.shortcut: not valid for kind \"dock\" (shortcut only applies to kind \"surface\")"
            }),
        );
    }

    // 28. A `dock`-kind entry with `blur` present is rejected — same
    // surface-only posture as namespace.
    #[test]
    fn widgets_dock_kind_with_blur_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "dockwidget": { "kind": "dock", "blur": false } });
        let r = validate(&v);
        check("dock + blur is rejected", !r.ok);
        check(
            "error names widgets.dockwidget.blur and kind \"dock\"",
            r.errors.iter().any(|e| {
                e == "widgets.dockwidget.blur: not valid for kind \"dock\" (blur only applies to kind \"surface\")"
            }),
        );
    }

    // 29. A `surface`-kind entry with `order` present is rejected — order is
    // dock-only (dock-column ordering; surfaces don't participate).
    #[test]
    fn widgets_surface_kind_with_order_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "grimoire": { "kind": "surface", "order": 1 } });
        let r = validate(&v);
        check("surface + order is rejected", !r.ok);
        check(
            "error names widgets.grimoire.order and kind \"surface\"",
            r.errors.iter().any(|e| {
                e == "widgets.grimoire.order: not valid for kind \"surface\" (order only applies to kind \"dock\")"
            }),
        );
    }

    // 30. A non-integer `order` (a string) is rejected with a type-mismatch
    // error using js_typeof.
    #[test]
    fn widgets_non_integer_order_string_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "dockwidget": { "kind": "dock", "order": "first" } });
        let r = validate(&v);
        check("a string order is rejected", !r.ok);
        check(
            "rejection error names widgets.dockwidget.order via js_typeof",
            r.errors
                .iter()
                .any(|e| e == "widgets.dockwidget.order: expected integer, got string"),
        );
    }

    // 31. A non-integer `order` (a float) is rejected the same way — JS
    // makes no int/float distinction, so js_typeof still reports "number".
    #[test]
    fn widgets_non_integer_order_float_is_rejected_and_named() {
        let mut v = load("valid.json");
        v["widgets"] = serde_json::json!({ "dockwidget": { "kind": "dock", "order": 1.5 } });
        let r = validate(&v);
        check("a float order is rejected", !r.ok);
        check(
            "rejection error names widgets.dockwidget.order via js_typeof",
            r.errors
                .iter()
                .any(|e| e == "widgets.dockwidget.order: expected integer, got number"),
        );
    }
}
