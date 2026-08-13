//! A minimal ORDERED JSON writer (std-only).
//!
//! The Node engine emits `JSON.stringify(…, null, 2)` — insertion-ordered,
//! 2-space-indented. `serde_json`'s `Map` is BTreeMap-backed in this
//! workspace (no `preserve_order` feature), so its `to_string_pretty` sorts
//! keys alphabetically — fine for shape contracts, wrong for the
//! byte-identical `livery resolve` golden. This writer exists ONLY to
//! reproduce the Node byte format: fixed `group.key` insertion order, exact
//! `": "` separators, JS-compatible string escaping, and a compact mode for
//! the small `{ok, …}` envelopes the CLI prints.

/// An ordered, owned JSON value (the subset the engine's output needs:
/// objects of strings, booleans, plus string arrays for error envelopes).
#[derive(Debug, Clone)]
pub(crate) enum JVal {
    Bool(bool),
    Str(String),
    Obj(Vec<(String, JVal)>),
    Arr(Vec<JVal>),
}

impl JVal {
    pub(crate) fn boolean(b: bool) -> JVal {
        JVal::Bool(b)
    }
    pub(crate) fn str(s: impl Into<String>) -> JVal {
        JVal::Str(s.into())
    }
    pub(crate) fn obj(entries: Vec<(String, JVal)>) -> JVal {
        JVal::Obj(entries)
    }
    pub(crate) fn arr(items: Vec<JVal>) -> JVal {
        JVal::Arr(items)
    }
}

/// `JSON.stringify(val, null, 2)` — insertion order, 2-space indent, no
/// trailing newline (callers add it, exactly like the Node CLI's `+ "\n"`).
pub(crate) fn write_pretty(out: &mut String, val: &JVal) {
    write_val(out, val, 0, false);
}

/// `JSON.stringify(val)` — compact, insertion order (the `{ok, …}` envelopes).
pub(crate) fn write_compact(out: &mut String, val: &JVal) {
    write_val(out, val, 0, true);
}

fn write_val(out: &mut String, val: &JVal, level: usize, compact: bool) {
    match val {
        JVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JVal::Str(s) => write_string(out, s),
        JVal::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_val(out, item, level + 1, compact);
            }
            out.push(']');
        }
        JVal::Obj(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            if !compact {
                out.push('\n');
            }
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if !compact {
                        out.push('\n');
                    }
                }
                if !compact {
                    indent(out, level + 1);
                }
                write_string(out, k);
                out.push_str(if compact { ":" } else { ": " });
                write_val(out, v, level + 1, compact);
            }
            if !compact {
                out.push('\n');
                indent(out, level);
            }
            out.push('}');
        }
    }
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// JS `JSON.stringify` string escaping: `"` and `\` escaped, control chars
/// as `\b \t \n \f \r` or `\u00XX`, everything else raw UTF-8.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
