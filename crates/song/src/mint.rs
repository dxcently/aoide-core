//! The pure `rice mint` scaffolding engine: name validation, the Nix-literal
//! renderer, and the `rice.nix`/`design/intent.md` templates.
//!
//! Moved out of `pkgs/aoide/src/commands/rice.rs` (Phase 5b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) — everything here is a pure function
//! of its inputs (no `Outcome`/`Invocation`, no filesystem I/O). The command
//! handler (`handle_rice_mint`, still in root `commands/rice.rs`) owns the
//! I/O (reading `--from`'s notes, writing the scaffolded files) and calls
//! through to this module for the actual rendering.

use serde_json::Value;

/// A valid `rice mint`/`rice new` song name: `^[a-z0-9][a-z0-9-]*$`. This one
/// check also rejects path traversal (`..`, `/`) and case/underscore variance
/// by construction — nothing outside `[a-z0-9-]` is accepted, and the first
/// character can never be a `-`.
pub fn valid_song_name(name: &str) -> bool {
    let mut chars = name.chars();
    let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit());
    first_ok && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Render one JSON scalar as a nix literal. The notes tiers `rice mint` reads
/// (palette / window / geometry) are leaves only — string, bool, number, or
/// null — so this never needs to handle arrays/objects.
pub fn nix_scalar(v: &Value) -> String {
    // ORDER MATTERS: backslash first (so the later escapes don't get
    // double-escaped), then the closing quote, then `$` — `\$` is the Nix
    // double-quoted-string escape that neutralizes `${…}` interpolation, so a
    // notes value like `"${builtins.readFile /etc/hostname}"` round-trips
    // into `rice.nix` as an inert literal, never live Nix interpolation.
    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
    }
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", escape(s)),
        other => format!("\"{}\"", escape(&other.to_string())),
    }
}

/// Render `key = value;` lines (one per line, `indent`-prefixed) for a FIXED
/// key list, pulling each value from `obj` (missing key → `null`). Used for
/// the window/geometry tiers so a partially-set source still yields the full
/// fixed key set — never a ragged subset a reader has to guess is exhaustive.
pub fn nix_fixed_fields(obj: Option<&serde_json::Map<String, Value>>, keys: &[&str], indent: &str) -> String {
    keys.iter()
        .map(|k| {
            let v = obj.and_then(|o| o.get(*k)).cloned().unwrap_or(Value::Null);
            format!("{indent}{k} = {};\n", nix_scalar(&v))
        })
        .collect()
}

/// The geometry tier's fixed key set, in the order CONTRACTS.md §1's table
/// lists them.
pub const GEOMETRY_KEYS: &[&str] = &[
    "gapsOut", "gapsIn", "borderSize", "rounding", "blurEnabled", "blurSize", "blurPasses",
];
/// The window (border-colour) component tier's fixed key set.
pub const WINDOW_KEYS: &[&str] = &["border", "borderInactive"];

/// Render one `rice.nix` for `rice mint`: a self-gating skeleton copying
/// `notes`' palette/window/geometry into `aoide.livery.<tier>` under
/// `config.aoide.song == "<name>"` — the same shape as every committed song
/// (CONTRACTS.md §5). `had_geometry`/`had_window` distinguish "copied from
/// `from`" from "`from` set no opinion here, this is a fill template" in the
/// leading comment of each block, so a reader never mistakes an all-null
/// template for an intentional all-null override.
pub fn render_rice_nix(name: &str, from: &str, notes: &Value) -> String {
    let palette_lines = notes
        .get("palette")
        .and_then(Value::as_object)
        .map(|p| {
            p.iter()
                .map(|(k, v)| format!("      \"{k}\" = {};\n", nix_scalar(v)))
                .collect::<String>()
        })
        .unwrap_or_default();

    let window_obj = notes.get("window").and_then(Value::as_object);
    let window_lines = nix_fixed_fields(window_obj, WINDOW_KEYS, "      ");
    let window_comment = if window_obj.is_some() {
        format!("inherited from song \"{from}\"")
    } else {
        format!("\"{from}\" set no window-colour overrides — null falls back to palette.accent/bg")
    };

    let geometry_obj = notes.get("geometry").and_then(Value::as_object);
    let geometry_lines = nix_fixed_fields(geometry_obj, GEOMETRY_KEYS, "      ");
    let geometry_comment = if geometry_obj.is_some() {
        format!("inherited from song \"{from}\"")
    } else {
        format!(
            "fill template — \"{from}\" carries no geometry tier; null leaves the \
             host/compositor default (CONTRACTS.md §1)"
        )
    };

    let mut s = String::new();
    s.push_str(&format!(
        "# song/songbook/{name}/rice.nix — scaffolded via `aoide rice mint` from song \"{from}\".\n"
    ));
    s.push_str("#\n");
    s.push_str("# HOST-AGNOSTIC DISCIPLINE (CONTRACTS.md §5): a song sets ONLY aoide.livery.\n");
    s.push_str("# All livery values are literal nix expressions (no song/ runtime reads).\n");
    s.push_str("{ lib, config, ... }:\n");
    s.push_str("{\n");
    s.push_str(&format!(
        "  config = lib.mkIf (config.aoide.song == \"{name}\") {{\n"
    ));

    s.push_str("\n    aoide.livery.palette = {\n");
    s.push_str(&palette_lines);
    s.push_str("    };\n");

    s.push_str(&format!("\n    # {window_comment}\n"));
    s.push_str("    aoide.livery.window = {\n");
    s.push_str(&window_lines);
    s.push_str("    };\n");

    s.push_str(&format!("\n    # {geometry_comment}\n"));
    s.push_str("    aoide.livery.geometry = {\n");
    s.push_str(&geometry_lines);
    s.push_str("    };\n");

    s.push_str("  };\n");
    s.push_str("}\n");
    s
}

/// Render `design/intent.md` for `rice mint`: honest-empty — no fabricated
/// rationale, just what IS true (inherited from `from`, retune it) and where
/// to go to actually fill it in.
pub fn render_intent_md(name: &str, from: &str) -> String {
    format!(
        "# {name} — Design Intent\n\
         \n\
         **Rice:** {name}\n\
         **Palette/geometry:** inherited from `{from}` — retune\n\
         \n\
         ---\n\
         \n\
         ## Palette Rationale\n\
         \n\
         (not yet written — this rice was scaffolded from `{from}` via `aoide rice mint`, not designed)\n\
         \n\
         ## Component Tier\n\
         \n\
         (not yet written)\n\
         \n\
         ## Geometry\n\
         \n\
         (not yet written)\n\
         \n\
         ## Iteration Log\n\
         \n\
         ## How to fill this rice\n\
         \n\
         - Slot catalog (which slots a host wires today, what each expects): \
           `modules/facets/quickshell/qml/slots.md`\n\
         - Per-song widget contract: `CONTRACTS.md` §5, \"Per-song flavor widgets\"\n\
         - Songbook playbook: `song/songbook/update-playbook.md`\n\
         - Drop a `widgets/<slot>.qml` here to dress a slot — any file under `widgets/` \
           becomes a slot named for its basename; nothing renders until a host surface \
           embeds a `WidgetSlot` anchor for that name.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_scalar_neutralizes_dollar_interpolation() {
        // `${` must never survive into the emitted literal live — `\$`
        // (backslash-then-quote-then-dollar ordering) is what makes a Nix
        // double-quoted string treat it as inert text.
        assert_eq!(
            nix_scalar(&Value::String("${builtins.currentTime}".to_string())),
            "\"\\${builtins.currentTime}\""
        );
        assert_eq!(
            nix_scalar(&Value::String("${x}".to_string())),
            "\"\\${x}\""
        );
        // Backslash-first ordering: a literal backslash ahead of `$` must not
        // get swallowed by the `$`-escape pass.
        assert_eq!(
            nix_scalar(&Value::String("\\${x}".to_string())),
            "\"\\\\\\${x}\""
        );
    }

    #[test]
    fn valid_song_name_accepts_the_expected_shape() {
        for good in ["moonlight", "dusk2", "a", "song-two-3"] {
            assert!(valid_song_name(good), "`{good}` should be valid");
        }
        for bad in ["Dusk", "dusk_two", "-dusk", "dusk/two", "..", ""] {
            assert!(!valid_song_name(bad), "`{bad}` should be invalid");
        }
    }
}
