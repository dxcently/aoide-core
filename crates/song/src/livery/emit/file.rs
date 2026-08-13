//! The file-template emitter — the generalization proof backend (NEW; no Node
//! counterpart).
//!
//! Substitutes `{{group.key}}` placeholders (e.g. `{{palette.bg}}`,
//! `{{window.border}}`) in a caller-supplied template string with the fully
//! resolved note set — the "apply the song's livery to ANY config file"
//! primitive. Pure: no host side-effect; writing the rendered text into some
//! live config is the caller's effectful half (the deferred `management`
//! seam, per the emit/apply split in `emit/mod.rs`).
//!
//! Placeholder grammar: `{{<group>.<key>}}` where group ∈
//! {palette, base16, bar, notif, window}. A malformed or unknown placeholder
//! is a structured error — never a silent no-op, never a panic.

use crate::livery::emit::{EmitError, EmitOpts, EmitOutput, Emitter};
use crate::livery::resolve::Resolved;

/// The template renderer backend.
pub struct FileTemplate;

impl Emitter for FileTemplate {
    fn target(&self) -> &'static str {
        "file"
    }

    fn emit(&self, r: &Resolved, o: &EmitOpts) -> Result<EmitOutput, EmitError> {
        let template = o
            .template
            .ok_or_else(|| EmitError::new("file: emitter requires a --template"))?;
        Ok(EmitOutput::Text(render(template, r)?))
    }
}

/// Look one `{{group.key}}` placeholder up in the resolved set.
fn lookup<'a>(r: &'a Resolved, group: &str, key: &str) -> Option<&'a str> {
    let tier: &[(String, String)] = match group {
        "palette" => &r.palette,
        "base16" => r.base16.as_deref()?,
        "bar" => &r.bar,
        "notif" => &r.notif,
        "window" => &r.window,
        _ => return None,
    };
    tier.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Render a template: scan for `{{…}}`, substitute from the resolved set,
/// leave everything else untouched. Unknown/malformed placeholders error.
pub fn render(template: &str, r: &Resolved) -> Result<String, EmitError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        let Some(start) = rest.find("{{") else {
            out.push_str(rest);
            return Ok(out);
        };
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            return Err(EmitError::new(
                "file: unclosed placeholder in template (missing `}}`)",
            ));
        };
        let placeholder = &after[..end];
        let (group, key) = placeholder.split_once('.').ok_or_else(|| {
            EmitError::new(format!(
                "file: malformed placeholder \"{placeholder}\" (expected {{group.key}})"
            ))
        })?;
        let value = lookup(r, group, key).ok_or_else(|| {
            EmitError::new(format!(
                "file: unknown placeholder \"{placeholder}\" (no such resolved value)"
            ))
        })?;
        out.push_str(value);
        rest = &after[end + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::livery::resolve::resolve;
    use serde_json::Value;

    fn resolved() -> Resolved {
        let raw = std::fs::read_to_string("tests/fixtures/valid.json").unwrap();
        let container: Value = serde_json::from_str(&raw).unwrap();
        resolve(&container).unwrap()
    }

    #[test]
    fn template_round_trips_a_known_set_of_substitutions() {
        let r = resolved();
        let tpl = "bg={{palette.bg}} fg={{palette.fg}} border={{window.border}}\n\
                   inactive={{window.borderInactive}} bar={{bar.accent}} notif={{notif.urgent}}";
        let out = render(tpl, &r).unwrap();
        assert_eq!(
            out,
            "bg=#1e1e2e fg=#cdd6f4 border=#89b4fa\n\
             inactive=#1e1e2e bar=#a6e3a1 notif=#f38ba8"
        );
    }

    #[test]
    fn template_passes_through_text_without_placeholders() {
        let r = resolved();
        assert_eq!(render("hello world\n", &r).unwrap(), "hello world\n");
        assert_eq!(render("", &r).unwrap(), "");
        // A lone `{{` without a closing `}}` is an error, never a partial
        // substitute — templates must be well-formed.
        assert!(render("a {{b", &r).is_err());
    }

    #[test]
    fn template_base16_placeholders_resolve_when_present() {
        let raw = std::fs::read_to_string("tests/fixtures/valid-base16.json").unwrap();
        let container: Value = serde_json::from_str(&raw).unwrap();
        let r = resolve(&container).unwrap();
        assert_eq!(
            render("ramp0={{base16.base00}} rampF={{base16.base0F}}", &r).unwrap(),
            "ramp0=#0a0a0d rampF=#9a6b8f"
        );
    }

    #[test]
    fn template_unknown_placeholder_errors_not_panics() {
        let r = resolved();
        let err = render("{{bogus.bg}}", &r).unwrap_err();
        assert!(err.to_string().contains("unknown placeholder"), "{err}");
        let err = render("{{palette.nope}}", &r).unwrap_err();
        assert!(err.to_string().contains("unknown placeholder"), "{err}");
    }

    #[test]
    fn template_malformed_placeholder_errors() {
        let r = resolved();
        // Missing the group.key split.
        let err = render("{{palette}}", &r).unwrap_err();
        assert!(err.to_string().contains("malformed placeholder"), "{err}");
        // Unclosed at end of template.
        let err = render("prefix {{palette.bg", &r).unwrap_err();
        assert!(err.to_string().contains("unclosed"), "{err}");
    }

    #[test]
    fn file_emitter_requires_a_template() {
        let r = resolved();
        let err = FileTemplate
            .emit(&r, &EmitOpts::default())
            .expect_err("no template → structured error");
        assert!(err.to_string().contains("--template"), "{err}");
    }
}
