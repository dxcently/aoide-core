//! The context-window ceiling for a Claude model id (pure).

/// The context-window ceiling, in tokens, for a Claude model id — published on
/// each session record (CONTRACTS.md §4) so the desktop renders a fill meter
/// without reimplementing the fact widget-side (the split-brain this replaces,
/// same discipline as `canonical_state`).
///
/// Current-generation models are natively 1M-context on the API — Sonnet 5+,
/// Opus 4.6+, Fable 5+ (and anything newer; `claude-opus-4-6`/`claude-sonnet-4-6`
/// are 1M too, not just the 4.7+/5+ tiers). Older/smaller tiers stay 200k:
/// Haiku (all known), pre-4.6 Opus, pre-5 Sonnet. An absent or unrecognised id
/// takes the conservative 200k default.
pub fn context_ceiling_for_model(model: Option<&str>) -> u64 {
    const K200: u64 = 200_000;
    const M1: u64 = 1_000_000;
    let Some(raw) = model else { return K200 };
    let id = raw.to_ascii_lowercase();

    // (major, minor) of the version that FOLLOWS a family token in the modern
    // id shape `claude-<family>-<major>[-<minor>]` (e.g. `claude-opus-4-8`,
    // `claude-sonnet-5`, `claude-haiku-4-5`). The `major < 100` guard rejects a
    // legacy dated id (`claude-3-5-sonnet-20241022` — the date is not a version),
    // which then falls through to the 200k default — correct for those old 200k
    // models. None when the family token is absent.
    fn ver_after(id: &str, family: &str) -> Option<(u32, u32)> {
        let rest = id.split_once(family)?.1;
        let mut nums = rest
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<u32>().ok());
        let major = nums.next().filter(|&n| n < 100)?;
        let minor = nums.next().filter(|&n| n < 100).unwrap_or(0);
        Some((major, minor))
    }

    // Fable: no evidence of a sub-5 Fable id anywhere in this codebase or the
    // model catalog, so the boundary stays a plain major-version check.
    if let Some((maj, _)) = ver_after(&id, "fable") {
        return if maj >= 5 { M1 } else { K200 };
    }
    if let Some((maj, min)) = ver_after(&id, "sonnet") {
        return if maj > 4 || (maj == 4 && min >= 6) { M1 } else { K200 };
    }
    if let Some((maj, min)) = ver_after(&id, "opus") {
        return if maj > 4 || (maj == 4 && min >= 6) { M1 } else { K200 };
    }
    K200 // haiku, legacy dated ids, or anything unrecognised
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_model_ids_to_the_right_ceiling() {
        assert_eq!(context_ceiling_for_model(Some("claude-sonnet-5")), 1_000_000);
        assert_eq!(context_ceiling_for_model(Some("claude-sonnet-4-6")), 1_000_000);
        assert_eq!(context_ceiling_for_model(Some("claude-opus-4-8")), 1_000_000);
        assert_eq!(context_ceiling_for_model(Some("claude-opus-4-7")), 1_000_000);
        assert_eq!(context_ceiling_for_model(Some("claude-opus-4-6")), 1_000_000);
        assert_eq!(context_ceiling_for_model(Some("claude-fable-5")), 1_000_000);
        assert_eq!(context_ceiling_for_model(Some("claude-haiku-4-5")), 200_000);
        assert_eq!(context_ceiling_for_model(None), 200_000);
        assert_eq!(context_ceiling_for_model(Some("claude-3-5-sonnet-20241022")), 200_000);
        assert_eq!(context_ceiling_for_model(Some("")), 200_000);
        assert_eq!(context_ceiling_for_model(Some("garbage")), 200_000);
        // Single-component version ids where a legacy dated snapshot lands in
        // the MINOR slot, not the major slot (the bug the minor-slot date
        // guard fixes) — these are real Anthropic API ids for 200k models.
        assert_eq!(context_ceiling_for_model(Some("claude-sonnet-4-20250514")), 200_000);
        assert_eq!(context_ceiling_for_model(Some("claude-opus-4-20250514")), 200_000);
        // Lower-side boundary, tested from below (previously only tested from
        // above the maj==4 cutoff).
        assert_eq!(context_ceiling_for_model(Some("claude-sonnet-4-5")), 200_000);
        assert_eq!(context_ceiling_for_model(Some("claude-opus-4")), 200_000);
    }
}
