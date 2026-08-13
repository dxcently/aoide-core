//! The tiered resolver — native port of the standalone Node engine's resolver.
//!
//! The Node engine hands the raw container to Style Dictionary to
//! dereference the W3C `{group.name}` alias syntax, then applies the v0
//! component-tier null→palette fallback (CONTRACTS.md §1) and returns a flat,
//! fully-resolved note set the emitters consume.
//!
//! v0's schema is closed and its refs single-level, so Style Dictionary is
//! replaceable by a native pass: look up `{a.b}` → `tree[a][b]`, recursively,
//! cycle-guarded (a reference may chain — `{a.b}` pointing at another
//! reference — so the guard is a visited-set over ref strings, matching SD's
//! circular-reference rejection). The fallback is applied HERE for the
//! live-side emitters so the stage file carries concrete colours (Quickshell
//! never reads null — CONTRACTS.md §4). The nix FACET applies the same
//! fallback independently for the baked side; both derive from identical
//! rules so preview and adopted state cannot diverge.

use crate::livery::emit::EmitError;
use crate::livery::json::{JVal, write_pretty};
use crate::livery::schema::{COMPONENT_FALLBACK, SCHEMA_VERSION, note_value};
use serde_json::Value;

/// The flat, fully-resolved note set (resolve output, emitters' input).
///
/// The palette/base16/component tiers are ORDERED key→value maps
/// (`Vec<(String, String)>`, not `serde_json::Map`): the Node engine emits
/// `JSON.stringify(…, null, 2)` in insertion order and `livery resolve` must
/// reproduce those bytes, while this workspace's `serde_json` map is
/// BTreeMap-backed (alphabetical). Component groups always carry every field
/// of `COMPONENT_FALLBACK` (fallbacks applied); base16 rides through only
/// when the note carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub schema_version: String,
    pub palette: Vec<(String, String)>,
    pub base16: Option<Vec<(String, String)>>,
    pub bar: Vec<(String, String)>,
    pub notif: Vec<(String, String)>,
    pub window: Vec<(String, String)>,
}

/// `stripHash` — drop a leading `#` (kept for API parity with resolve.js,
/// which exports it; the emitters strip inline like the Node originals).
pub fn strip_hash(v: &str) -> &str {
    v.strip_prefix('#').unwrap_or(v)
}

/// `withHash` — ensure a leading `#`. Non-strings pass through untouched
/// (in the Node original `withHash` returns non-strings as-is; here the
/// resolver only ever hands it strings).
pub fn with_hash(v: &str) -> String {
    if v.starts_with('#') {
        v.to_string()
    } else {
        format!("#{v}")
    }
}

/// Look up one `{group.key}` (or `{group}`) reference in the raw container.
fn lookup<'a>(container: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = container;
    for part in path.split('.') {
        cur = match cur {
            Value::Object(m) => m.get(part)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Dereference one leaf: resolve `{group.key}` chains against `container`,
/// cycle-guarded. `Ok(None)` = not a concrete leaf (JS `undefined` — a
/// scalar or an object without `$value`); `Ok(Some(v))` = the concrete value.
fn deref_leaf(
    node: Option<&Value>,
    container: &Value,
    seen: &mut Vec<String>,
) -> Result<Option<Value>, EmitError> {
    let v = match note_value(node) {
        Some(Some(v)) => v,
        _ => return Ok(None), // null / missing / not-a-leaf
    };
    if let Some(s) = v.as_str() {
        if crate::livery::schema::is_ref(s) {
            if seen.iter().any(|x| x == s) {
                return Err(EmitError::new(format!(
                    "resolve: circular reference: {s}"
                )));
            }
            let target = lookup(container, &s[1..s.len() - 1]).ok_or_else(|| {
                EmitError::new(format!("resolve: unknown reference: {s}"))
            })?;
            seen.push(s.to_string());
            let r = deref_leaf(Some(target), container, seen);
            seen.pop();
            return r;
        }
        return Ok(Some(Value::String(s.to_string())));
    }
    Ok(Some(v.clone()))
}

/// `leaf` — pull a concrete, `#`-prefixed value out of a (possibly
/// W3C-wrapped) resolved node.
fn leaf(node: Option<&Value>, container: &Value, seen: &mut Vec<String>) -> Result<Option<String>, EmitError> {
    Ok(deref_leaf(node, container, seen)?.map(|v| match v {
        Value::String(s) => with_hash(&s),
        other => other.to_string(),
    }))
}

/// Flatten one tier's ordered key→value map (`Object.entries(tree.tier)`).
///
/// serde_json's `Map` is BTreeMap-backed, so the raw parse loses the source
/// key order. The Node engine emits `Object.entries` order (source order);
/// the v0 schema is CLOSED, so every valid note's keys are a subset of the
/// canonical enumerations below — emitting in canonical order (then any
/// leftover, invalid-input keys after) is byte-identical to Node for every
/// valid note.
fn tier_map(
    group: Option<&Value>,
    container: &Value,
    seen: &mut Vec<String>,
    canonical: &[&str],
) -> Result<Vec<(String, String)>, EmitError> {
    let mut out = Vec::new();
    if let Some(g) = group {
        let mut leftover: Vec<String> = match g {
            Value::Object(m) => m.keys().cloned().collect(),
            Value::Array(a) => (0..a.len()).map(|i| i.to_string()).collect(),
            _ => Vec::new(),
        };
        for k in canonical {
            if let Some(idx) = leftover.iter().position(|l| l == k) {
                leftover.remove(idx);
                let node = match g {
                    Value::Object(m) => m.get(*k),
                    Value::Array(a) => k.parse::<usize>().ok().and_then(|i| a.get(i)),
                    _ => None,
                };
                if let Some(v) = leaf(node, container, seen)? {
                    out.push((k.to_string(), v));
                }
            }
        }
        // Invalid-input keys the closed schema would reject — emitted last,
        // mirroring Node's "all entries" behavior for the unreachable case.
        for k in leftover {
            let node = match g {
                Value::Object(m) => m.get(&k),
                Value::Array(a) => k.parse::<usize>().ok().and_then(|i| a.get(i)),
                _ => None,
            };
            if let Some(v) = leaf(node, container, seen)? {
                out.push((k, v));
            }
        }
    }
    Ok(out)
}

/// Look a field up in an ordered tier map.
fn get<'a>(m: &'a [(String, String)], k: &str) -> Option<&'a str> {
    m.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
}

/// The canonical palette key order — the closed v0 set, required keys then
/// optional. Style Dictionary's `exportPlatform` preserves the source
/// insertion order (it does NOT sort), so the byte-identical emission must
/// reproduce the order every fixture and songbook note actually writes —
/// which is exactly this list.
const PALETTE_CANONICAL: [&str; 5] = ["bg", "fg", "accent", "urgent", "hot"];

/// The canonical base16 key order — the closed sixteen-slot enumeration.
const BASE16_CANONICAL: [&str; 16] = [
    "base00", "base01", "base02", "base03", "base04", "base05", "base06", "base07",
    "base08", "base09", "base0A", "base0B", "base0C", "base0D", "base0E", "base0F",
];

/// Produce the fully-resolved, flattened note set. Component fields absent or
/// null fall back to their palette source per `COMPONENT_FALLBACK`.
///
/// Port note: the Node original returns JS `undefined` component fields when a
/// palette source is missing (dropped by `JSON.stringify`); for any
/// schema-valid container the fallback sources are required palette keys, so
/// this can only diverge on input `lint` already rejects — there it falls
/// back to an empty string rather than fabricating a value.
pub fn resolve(container: &Value) -> Result<Resolved, EmitError> {
    let mut seen: Vec<String> = Vec::new();
    let palette = tier_map(
        container.get("palette"),
        container,
        &mut seen,
        &PALETTE_CANONICAL,
    )?;
    let base16 = match container.get("base16") {
        Some(_) => Some(tier_map(
            container.get("base16"),
            container,
            &mut seen,
            &BASE16_CANONICAL,
        )?),
        None => None,
    };

    let mut bar = Vec::new();
    let mut notif = Vec::new();
    let mut window = Vec::new();
    for (group, fields) in COMPONENT_FALLBACK {
        let g = container.get(group);
        for (field, palette_key) in fields {
            // JS reads the SD-RESOLVED tree, so a component `$value` is
            // dereferenced here too (a `{group.key}` alias resolves against
            // the raw container, exactly like the palette/base16 tiers).
            let node = match g {
                Some(g) => match g {
                    Value::Object(m) => m.get(*field),
                    Value::Array(a) => (*field).parse::<usize>().ok().and_then(|i| a.get(i)),
                    _ => None,
                },
                None => None,
            };
            let raw = deref_leaf(node, container, &mut seen)?;
            // JS: `raw == null || raw === "" → palette[paletteKey] : withHash(raw)`.
            let value = match raw {
                Some(Value::String(s)) if !s.is_empty() => with_hash(&s),
                // null / missing / empty string → palette fallback.
                Some(Value::String(_)) | None => {
                    get(&palette, palette_key).unwrap_or("").to_string()
                }
                Some(other) => other.to_string(),
            };
            let out = match group {
                "bar" => &mut bar,
                "notif" => &mut notif,
                _ => &mut window,
            };
            out.push((field.to_string(), value));
        }
    }

    Ok(Resolved {
        schema_version: SCHEMA_VERSION.to_string(),
        palette,
        base16,
        bar,
        notif,
        window,
    })
}

/// Render the resolved set as the canonical resolve JSON — byte-identical to
/// the Node engine's `JSON.stringify(resolved, null, 2)` (insertion order:
/// schemaVersion, palette, [base16], bar, notif, window), no trailing newline.
pub fn to_json_string(r: &Resolved) -> String {
    let mut entries = vec![(
        "schemaVersion".to_string(),
        JVal::str(&r.schema_version),
    )];
    entries.push(("palette".to_string(), pairs(&r.palette)));
    if let Some(b16) = &r.base16 {
        entries.push(("base16".to_string(), pairs(b16)));
    }
    entries.push(("bar".to_string(), pairs(&r.bar)));
    entries.push(("notif".to_string(), pairs(&r.notif)));
    entries.push(("window".to_string(), pairs(&r.window)));
    let mut out = String::new();
    write_pretty(&mut out, &JVal::obj(entries));
    out
}

fn pairs(m: &[(String, String)]) -> JVal {
    JVal::obj(
        m.iter()
            .map(|(k, v)| (k.clone(), JVal::str(v)))
            .collect(),
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::livery::schema;

    fn load(name: &str) -> Value {
        let raw = std::fs::read_to_string(format!("tests/fixtures/{name}")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn get<'a>(m: &'a [(String, String)], k: &str) -> &'a str {
        m.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    #[test]
    fn resolve_flat_derefs_aliases_and_applies_component_fallbacks() {
        // valid.json: bar.bg = {palette.bg}, bar.accent concrete,
        // window.border = {palette.accent}, notif wholly absent.
        let r = resolve(&load("valid.json")).unwrap();
        assert_eq!(r.schema_version, "0");
        assert_eq!(get(&r.palette, "bg"), "#1e1e2e");
        assert_eq!(get(&r.bar, "bg"), "#1e1e2e", "bar.bg derefs {{palette.bg}}");
        assert_eq!(get(&r.bar, "accent"), "#a6e3a1", "concrete value wins");
        assert_eq!(
            get(&r.window, "border"),
            "#89b4fa",
            "window.border derefs {{palette.accent}}"
        );
        // notif absent → every field falls back to its palette source.
        assert_eq!(get(&r.notif, "bg"), "#1e1e2e");
        assert_eq!(get(&r.notif, "fg"), "#cdd6f4");
        assert_eq!(get(&r.notif, "urgent"), "#f38ba8");
        assert_eq!(get(&r.window, "borderInactive"), "#1e1e2e");
        assert!(r.base16.is_none());
    }

    #[test]
    fn resolve_preserves_optional_hot_and_base16_blocks() {
        let r = resolve(&load("valid-hot.json")).unwrap();
        assert_eq!(get(&r.palette, "hot"), "#3fe97f");
        // bar.accent in valid-hot references {palette.accent} → resolved.
        assert_eq!(get(&r.bar, "accent"), "#89b4fa");

        let r = resolve(&load("valid-base16.json")).unwrap();
        let b16 = r.base16.unwrap();
        assert_eq!(get(&b16, "base00"), "#0a0a0d");
        assert_eq!(get(&b16, "base0F"), "#9a6b8f");
    }

    #[test]
    fn resolve_emits_with_hash_for_bare_hex() {
        let mut v = load("valid.json");
        v["palette"]["bg"] = Value::String("1e1e2e".to_string());
        let r = resolve(&v).unwrap();
        assert_eq!(get(&r.palette, "bg"), "#1e1e2e");
    }

    #[test]
    fn resolve_rejects_a_circular_reference_chain() {
        let v = serde_json::json!({
            "palette": { "bg": { "$value": "{bar.bg}" }, "fg": "#cdd6f4",
                          "accent": "#89b4fa", "urgent": "#f38ba8" },
            "bar": { "bg": { "$value": "{palette.bg}" } }
        });
        let err = resolve(&v).unwrap_err();
        assert!(
            err.to_string().contains("circular reference"),
            "cycle reported: {err}"
        );
    }

    #[test]
    fn resolve_rejects_an_unknown_reference_target() {
        let v = serde_json::json!({
            "palette": { "bg": "#1e1e2e", "fg": "#cdd6f4",
                          "accent": "#89b4fa", "urgent": "#f38ba8" },
            "bar": { "bg": { "$value": "{palette.nope}" } }
        });
        let err = resolve(&v).unwrap_err();
        assert!(
            err.to_string().contains("unknown reference"),
            "missing target reported: {err}"
        );
    }

    #[test]
    fn resolve_empty_string_component_field_falls_back_to_palette() {
        let mut v = load("valid.json");
        v["window"] = serde_json::json!({ "border": "" });
        let r = resolve(&v).unwrap();
        // JS: `raw === ""` → fallback.
        assert_eq!(get(&r.window, "border"), "#89b4fa");
        assert_eq!(get(&r.window, "borderInactive"), "#1e1e2e");
    }

    #[test]
    fn resolve_null_value_component_field_falls_back_to_palette() {
        // D1: `{"$value": null}` is a JS-null leaf — lint accepts it and the
        // resolver falls back to the palette source, exactly like a bare null.
        let mut v = load("valid.json");
        v["bar"]["bg"] = serde_json::json!({ "$value": null });
        let r = resolve(&v).unwrap();
        assert_eq!(
            get(&r.bar, "bg"),
            "#1e1e2e",
            "bar.bg with $value null falls back to palette.bg"
        );
        assert_eq!(get(&r.bar, "accent"), "#a6e3a1", "concrete value wins");
    }

    #[test]
    fn resolve_ok_matches_golden_bytes_for_all_valid_fixtures() {
        for fix in ["valid", "valid-hot", "valid-base16"] {
            let container = load(&format!("{fix}.json"));
            let v = schema::validate(&container);
            assert!(v.ok, "{fix}: {v:?}");
            let r = resolve(&container).unwrap();
            let golden = std::fs::read_to_string(format!("tests/goldens/{fix}.resolve.golden")).unwrap();
            assert_eq!(
                format!("{}\n", to_json_string(&r)),
                golden,
                "{fix}: resolve output must be byte-identical to the Node engine"
            );
        }
    }
}
