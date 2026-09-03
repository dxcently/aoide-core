//! Hyprland live-apply helpers — the compositor half of `rice stage`.
//!
//! `handle_rice_stage` (dispatch.rs) already hot-reloads the palette by
//! staging `stage/livery.json`; Quickshell's own FileView watches that file
//! and needs no compositor call. Geometry (gaps/border-size/rounding/blur)
//! and the border *colours* have no such watcher on the Hyprland side, so
//! this module turns the staged notes into a single best-effort
//! `hyprctl --batch` keyword list and (when on Hyprland) runs it.
//!
//! Every field here is live-settable via `hyprctl keyword` — there is
//! deliberately no `hyprctl reload` anywhere in this seam. `reload` re-reads
//! `hyprland.conf` from disk; nothing here rewrites that file (the baked
//! config is still the build-time source for the NEXT compositor start), so
//! a reload would find nothing new to pick up and would needlessly reset
//! every OTHER live-tweaked keyword a user has set out-of-band.

use crate::livery::schema;
use serde_json::Value;

/// Build the `hyprctl keyword …` list for one staged notes document, in the
/// fixed order CONTRACTS.md §1's geometry table lists them (gaps, border
/// size, border colours, rounding, blur).
///
/// Only emits a keyword for a field that actually resolves to a concrete
/// value:
///
/// * **Border colours** (`window.border` / `window.borderInactive`) are the
///   component tier, which the stage file always carries fully resolved
///   (CONTRACTS.md §4 — "Quickshell reads concrete colours, never `null`"),
///   so these two keywords are effectively unconditional for any valid
///   staged notes document.
/// * **Geometry** (`geometry.*`) is additive-optional (§1): a notes file with
///   no `geometry` block, or a block with a `null` field, means "this song
///   never opted in" — we skip that keyword rather than asserting the
///   compositor's own fallback constant (8/6/2/0/true/8/3). Asserting the
///   fallback here would fight a host's baked `hyprland.conf` (or a user's
///   own live tweak) on every preview of a song that carries no geometry
///   opinion; skipping lets the existing value stand.
pub fn geometry_keywords(notes: &Value) -> Vec<String> {
    let geo = notes.get("geometry");
    let mut out = Vec::new();

    push_int(&mut out, geo, "gapsOut", "general:gaps_out");
    push_int(&mut out, geo, "gapsIn", "general:gaps_in");
    push_int(&mut out, geo, "borderSize", "general:border_size");

    // `schema::is_hex` lints BEFORE the value ever reaches `to_hyprland_rgb`
    // — this string is interpolated straight into a `;`-joined `hyprctl
    // --batch` command, so anything that isn't a clean `#rrggbb`/`rrggbb` hex
    // (e.g. `0; dispatch exec <cmd>`) must never reach it. A staged notes
    // document is normally already `rice lint`-clean by the time it lands
    // here, but this is the last line of defense in the actual hot path
    // (`handle_rice_stage` stages+applies without re-linting), so an invalid
    // value is silently skipped — same "no opinion" treatment as an absent
    // geometry field — rather than passed through or defaulted.
    if let Some(hex) = notes.pointer("/window/border").and_then(Value::as_str) {
        if schema::is_hex(hex) {
            out.push(format!(
                "keyword general:col.active_border {}",
                to_hyprland_rgb(hex)
            ));
        }
    }
    if let Some(hex) = notes.pointer("/window/borderInactive").and_then(Value::as_str) {
        if schema::is_hex(hex) {
            out.push(format!(
                "keyword general:col.inactive_border {}",
                to_hyprland_rgb(hex)
            ));
        }
    }

    push_int(&mut out, geo, "rounding", "decoration:rounding");
    push_bool01(&mut out, geo, "blurEnabled", "decoration:blur:enabled");
    push_int(&mut out, geo, "blurSize", "decoration:blur:size");
    push_int(&mut out, geo, "blurPasses", "decoration:blur:passes");

    out
}

fn push_int(out: &mut Vec<String>, geo: Option<&Value>, field: &str, keyword: &str) {
    if let Some(n) = geo.and_then(|g| g.get(field)).and_then(Value::as_i64) {
        out.push(format!("keyword {keyword} {n}"));
    }
}

fn push_bool01(out: &mut Vec<String>, geo: Option<&Value>, field: &str, keyword: &str) {
    if let Some(b) = geo.and_then(|g| g.get(field)).and_then(Value::as_bool) {
        out.push(format!("keyword {keyword} {}", if b { 1 } else { 0 }));
    }
}

/// `#RRGGBB` (or bare `RRGGBB`) → Hyprland's `rgb(RRGGBB)` colour syntax.
fn to_hyprland_rgb(hex: &str) -> String {
    format!("rgb({})", hex.trim_start_matches('#'))
}

/// Join a keyword list into the single `hyprctl --batch` payload string
/// (`"keyword a b; keyword c d; …"`).
pub fn batch_command(keywords: &[String]) -> String {
    keywords.join("; ")
}

/// Guarded, best-effort live-apply. Returns a short status string for the
/// caller's outcome envelope; NEVER a `Result` — a failed or absent `hyprctl`
/// must not fail `rice stage` (the stage file is already the source of
/// truth for the hot-reload half; this is best-effort on top of it).
///
/// Guard: only runs `hyprctl` when `$HYPRLAND_INSTANCE_SIGNATURE` is set
/// (off-Hyprland — headless, VM, or the common test path — is a silent
/// no-op) and there is at least one keyword to apply.
pub fn apply_live(keywords: &[String]) -> &'static str {
    if keywords.is_empty() {
        return "skipped (no geometry/border keywords resolved)";
    }
    let on_hyprland = std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !on_hyprland {
        return "skipped (HYPRLAND_INSTANCE_SIGNATURE unset)";
    }
    match std::process::Command::new("hyprctl")
        .arg("--batch")
        .arg(batch_command(keywords))
        .output()
    {
        Ok(out) if out.status.success() => "applied",
        Ok(_) => "best-effort: hyprctl reported an error (stage file already updated)",
        Err(_) => "best-effort: hyprctl unavailable (stage file already updated)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn full_geometry_and_window_produce_every_keyword_in_order() {
        let notes = json!({
            "window": { "border": "#89b4fa", "borderInactive": "#1e1e2e" },
            "geometry": {
                "gapsOut": 8, "gapsIn": 6, "borderSize": 2, "rounding": 0,
                "blurEnabled": true, "blurSize": 8, "blurPasses": 3
            }
        });
        assert_eq!(
            geometry_keywords(&notes),
            vec![
                "keyword general:gaps_out 8".to_string(),
                "keyword general:gaps_in 6".to_string(),
                "keyword general:border_size 2".to_string(),
                "keyword general:col.active_border rgb(89b4fa)".to_string(),
                "keyword general:col.inactive_border rgb(1e1e2e)".to_string(),
                "keyword decoration:rounding 0".to_string(),
                "keyword decoration:blur:enabled 1".to_string(),
                "keyword decoration:blur:size 8".to_string(),
                "keyword decoration:blur:passes 3".to_string(),
            ]
        );
    }

    #[test]
    fn blur_disabled_emits_zero_not_the_word_false() {
        let notes = json!({ "geometry": { "blurEnabled": false } });
        assert_eq!(
            geometry_keywords(&notes),
            vec!["keyword decoration:blur:enabled 0".to_string()]
        );
    }

    #[test]
    fn no_geometry_block_still_emits_the_always_resolved_border_colours() {
        let notes = json!({ "window": { "border": "#a07414", "borderInactive": "#3f867e" } });
        assert_eq!(
            geometry_keywords(&notes),
            vec![
                "keyword general:col.active_border rgb(a07414)".to_string(),
                "keyword general:col.inactive_border rgb(3f867e)".to_string(),
            ]
        );
    }

    #[test]
    fn null_geometry_fields_are_skipped_individually() {
        // Additive-optional (§1): a present-but-null field means "no opinion",
        // never the compositor's fallback constant.
        let notes = json!({
            "geometry": { "gapsOut": null, "gapsIn": 6, "borderSize": null }
        });
        assert_eq!(
            geometry_keywords(&notes),
            vec!["keyword general:gaps_in 6".to_string()]
        );
    }

    #[test]
    fn a_non_hex_border_is_never_interpolated_into_the_batch_command() {
        // `to_hyprland_rgb` interpolates this string directly into a
        // `;`-joined `hyprctl --batch` payload (see `batch_command`) — a
        // value shaped like a second command must be dropped, not passed
        // through, since a staged notes file may not have been re-linted by
        // the time it reaches this hot path (`handle_rice_stage`).
        let notes = json!({
            "window": { "border": "0; dispatch exec touch /tmp/pwned" }
        });
        assert!(
            geometry_keywords(&notes).is_empty(),
            "an injection-shaped border value must be skipped entirely"
        );
    }

    #[test]
    fn a_non_hex_border_inactive_is_skipped_while_a_valid_border_still_emits() {
        let notes = json!({
            "window": { "border": "#89b4fa", "borderInactive": "'; rm -rf ~; '" }
        });
        assert_eq!(
            geometry_keywords(&notes),
            vec!["keyword general:col.active_border rgb(89b4fa)".to_string()],
            "the valid sibling field still emits; only the malformed one is dropped"
        );
    }

    #[test]
    fn no_geometry_and_no_window_yields_an_empty_batch() {
        let notes = json!({ "palette": { "bg": "#1e1e2e" } });
        assert!(geometry_keywords(&notes).is_empty());
    }

    #[test]
    fn batch_command_joins_with_semicolons() {
        let kw = vec!["keyword a b".to_string(), "keyword c d".to_string()];
        assert_eq!(batch_command(&kw), "keyword a b; keyword c d");
    }

    #[test]
    fn apply_live_skips_with_no_keywords_without_touching_env() {
        assert_eq!(
            apply_live(&[]),
            "skipped (no geometry/border keywords resolved)"
        );
    }

    #[test]
    fn apply_live_skips_off_hyprland() {
        // Shares `aoide_test_support::env_lock()` with every other
        // env-touching test in the crate (rice.rs's own
        // `HYPRLAND_INSTANCE_SIGNATURE`-touching tests included) — this used
        // to lock a separate crate-local mutex, racing rice.rs tests that
        // touch the SAME env var under the other lock.
        let _g = aoide_test_support::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _s = aoide_test_support::EnvSaver::capture(&["HYPRLAND_INSTANCE_SIGNATURE"]);
        std::env::remove_var("HYPRLAND_INSTANCE_SIGNATURE");

        let kw = vec!["keyword general:gaps_out 8".to_string()];
        assert_eq!(apply_live(&kw), "skipped (HYPRLAND_INSTANCE_SIGNATURE unset)");
    }
}
