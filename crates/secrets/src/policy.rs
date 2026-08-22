//! Secrets policy store types: per-secret access policy, round-trip
//! serializable. Type surface only at P-V1 — no daemon reads/writes
//! `state/policy.json` yet (the broker lands at V2); this module is
//! where V2's (de)serialization contract already lives so the wire
//! shape doesn't shift out from under it later.
//!
//! **Name validation is fresh here, not reused from
//! `aoide_storage::peer_store::valid_peer_name`** (this crate doesn't
//! depend on `aoide-storage`, and won't until a later phase needs it):
//! the plan's B2 salvage note calls for a secret name STRICTER than a
//! peer name even though both restrict to the same character set
//! (`[a-z0-9-]`) — [`valid_secret_name`] additionally forbids a leading
//! or trailing hyphen and any run of consecutive hyphens, where
//! `valid_peer_name` allows both. The superseded workstream-B design
//! (`P-B2`) is dead; only this naming decision survives into aoide-secrets.

use serde::{Deserialize, Serialize};

/// A secret's nickname: `[a-z0-9]` for the first and last character,
/// `[a-z0-9-]` in between, and no `--` run anywhere. Rejects empty
/// strings. Joined into on-disk paths by later phases (V2's backend
/// stores) the same way a peer name is — this is the traversal guard for
/// that, made stricter per the plan's salvage note (module doc).
pub fn valid_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let charset_ok = bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let ends_ok = {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        (first.is_ascii_lowercase() || first.is_ascii_digit())
            && (last.is_ascii_lowercase() || last.is_ascii_digit())
    };
    let no_double_hyphen = !name.contains("--");
    charset_ok && ends_ok && no_double_hyphen
}

/// A secret's automation gate (P-N1). OPEN (`enabled: true`) lets the
/// consumers LISTED here resolve WITHOUT a fresh TOTP code, even when the
/// policy's own `requireTotp` is set; every other caller is still gated
/// normally. CLOSED (`enabled: false`, the default — and what an existing
/// `policy.json` predating this field loads as) changes nothing:
/// `requireTotp` applies to everyone, exactly as before this field
/// existed. See [`totp_required`] for the one decision point this gate
/// feeds into.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Automation {
    #[serde(default)]
    pub enabled: bool,
    /// Consumer names matched EXACTLY (same validation as a policy's own
    /// `consumers[]` — `commands::handle_secrets_automate` checks
    /// [`valid_secret_name`] before a `grant` lands one here).
    #[serde(default)]
    pub consumers: Vec<String>,
}

/// One secret's access policy — the plan's SECRETS §Policy shape, extended
/// at P-N1: `{name, backend, key, requireTotp, consumers[], sharedWith[],
/// automation, remote}`.
///
/// **Invariant this type must never grow**: no field here may ever hold
/// the secret's VALUE. This struct derives `Serialize` and rides through
/// the audit/Outcome/JSON paths a value must never touch (this crate's
/// `AGENTS.md`) — a value field on a `Serialize` type is exactly the
/// mistake that discipline exists to prevent, written down now while the
/// type is still small enough that the rule is easy to hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    /// The secret's nickname (see [`valid_secret_name`]); not enforced
    /// by `Deserialize` itself (matching `valid_peer_name`'s precedent —
    /// storage-layer validation is a call-site concern) but MUST be
    /// checked before this policy is ever persisted, at V2.
    pub name: String,
    /// Which named backend (V3: pass/gopass/bw/sops preset) fetches this
    /// secret's value.
    pub backend: String,
    /// The backend-specific key/identifier passed into that backend's
    /// fetch-command template (e.g. the `{name}` a `pass show {name}`
    /// template substitutes).
    pub key: String,
    /// Whether release requires a fresh TOTP code (vs. a standing grant
    /// check only) — the BASELINE [`totp_required`] narrows via
    /// `automation`, never widens.
    #[serde(default)]
    pub require_totp: bool,
    /// Consumer names allowed to resolve this secret. Empty means "any
    /// consumer" (mirrors `aoide_storage`'s empty-or-contains
    /// `authorized` precedent for the superseded secret store — restated
    /// here since this type doesn't depend on that crate).
    #[serde(default)]
    pub consumers: Vec<String>,
    /// Host names this secret is shared to (Workstream SECRETS's mesh
    /// phase, P-V5) — present in the type now so the wire shape doesn't
    /// change when sharing lands; empty until then.
    #[serde(default)]
    pub shared_with: Vec<String>,
    /// The automation gate (P-N1, see [`Automation`]). Optional-with-
    /// default on load: an existing `policy.json` predating this field
    /// carries neither key and loads as `{enabled: false, consumers: []}`
    /// — automation disabled, empty — identical behavior to before this
    /// field existed.
    #[serde(default)]
    pub automation: Automation,
    /// Remote-reachability (P-N1): whether this secret may ever be
    /// released over a NON-LOCAL entry point (mesh replication, a future
    /// network door). Defaults to `false` on both a fresh policy and an
    /// existing `policy.json` that predates this field. **NO behavior
    /// change today** — there is no non-local entry point yet — but this
    /// is a crate invariant (`AGENTS.md`): every non-local entry point
    /// added later MUST refuse a secret whose `remote` is `false` before
    /// ever touching its backend.
    #[serde(default)]
    pub remote: bool,
}

impl Policy {
    /// Construct a policy with no consumers/sharing restrictions,
    /// `requireTotp` off, automation closed, and `remote` off — the
    /// caller narrows from here.
    pub fn new(name: impl Into<String>, backend: impl Into<String>, key: impl Into<String>) -> Self {
        Policy {
            name: name.into(),
            backend: backend.into(),
            key: key.into(),
            require_totp: false,
            consumers: Vec::new(),
            shared_with: Vec::new(),
            automation: Automation::default(),
            remote: false,
        }
    }
}

/// Whether a `resolve` on behalf of `consumer` must present a TOTP code,
/// given `policy` — the ONE decision point [`crate::broker::resolve_gate`]
/// routes through (P-N1). `requireTotp` is the baseline; the automation
/// gate can only ever RELAX it, never tighten it: `requireTotp: false`
/// always returns `false`, automation or not. When `requireTotp` is
/// `true`, a code is still required UNLESS automation is OPEN
/// (`automation.enabled`) AND `consumer` is one of the names LISTED in
/// `automation.consumers` (exact match) — every other caller (automation
/// closed, or open but this consumer isn't listed) is gated exactly as
/// before this field existed.
///
/// Deliberately a single, narrowly-named pure function rather than
/// inlined into `resolve_gate`: a follow-up phase (P-N2, not built here)
/// turns a no-code `true` result into a PARK instead of a flat refusal,
/// and this is the one place that phase changes.
pub fn totp_required(policy: &Policy, consumer: &str) -> bool {
    if !policy.require_totp {
        return false;
    }
    let automation_open = policy.automation.enabled && policy.automation.consumers.iter().any(|c| c == consumer);
    !automation_open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_secret_name_accepts_the_expected_shape() {
        assert!(valid_secret_name("a"));
        assert!(valid_secret_name("aoide-secrets"));
        assert!(valid_secret_name("a1-2b"));
        assert!(valid_secret_name("token9"));
    }

    #[test]
    fn valid_secret_name_rejects_what_valid_peer_name_would_accept() {
        // These are exactly the shapes `aoide_storage::peer_store::
        // valid_peer_name` allows but this stricter rule does not —
        // the "stricter than valid_peer_name" delta from the plan.
        assert!(!valid_secret_name("a-"), "trailing hyphen");
        assert!(!valid_secret_name("a--b"), "double hyphen");
        assert!(!valid_secret_name("ab--"), "trailing double hyphen");
    }

    #[test]
    fn valid_secret_name_rejects_empty_leading_hyphen_traversal_and_case() {
        assert!(!valid_secret_name(""));
        assert!(!valid_secret_name("-leading"));
        assert!(!valid_secret_name("../../evil"));
        assert!(!valid_secret_name("../etc"));
        assert!(!valid_secret_name("a/b"));
        assert!(!valid_secret_name("Upper"));
        assert!(!valid_secret_name("under_score"));
    }

    #[test]
    fn serde_round_trip_uses_the_plan_field_names() {
        let mut policy = Policy::new("db-prod", "pass", "prod/db");
        policy.require_totp = true;
        policy.consumers.push("m".into());
        policy.shared_with.push("sakaki".into());

        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(json["name"], "db-prod");
        assert_eq!(json["backend"], "pass");
        assert_eq!(json["key"], "prod/db");
        assert_eq!(json["requireTotp"], true);
        assert_eq!(json["consumers"][0], "m");
        assert_eq!(json["sharedWith"][0], "sakaki");

        let back: Policy = serde_json::from_value(json).unwrap();
        assert_eq!(back, policy);
    }

    #[test]
    fn serde_round_trip_is_byte_stable() {
        let policy = Policy::new("db-prod", "pass", "prod/db");
        let json1 = serde_json::to_string(&policy).unwrap();
        let back: Policy = serde_json::from_str(&json1).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn defaults_fill_in_when_omitted_from_json() {
        let json = r#"{"name":"t","backend":"pass","key":"k"}"#;
        let policy: Policy = serde_json::from_str(json).unwrap();
        assert!(!policy.require_totp);
        assert!(policy.consumers.is_empty());
        assert!(policy.shared_with.is_empty());
        assert!(!policy.automation.enabled);
        assert!(policy.automation.consumers.is_empty());
        assert!(!policy.remote);
    }

    // ── automation / remote (P-N1) ──────────────────────────────────────

    /// The exact live shape: an OLD `policy.json` written before P-N1
    /// carries neither `automation` nor `remote` at all — must load
    /// cleanly, treated as automation disabled/empty and remote false.
    #[test]
    fn old_shape_json_with_no_automation_or_remote_key_loads_as_closed() {
        let json = r#"{"name":"t","backend":"pass","key":"k","requireTotp":true,"consumers":["m"],"sharedWith":[]}"#;
        let policy: Policy = serde_json::from_str(json).unwrap();
        assert!(policy.require_totp);
        assert!(!policy.automation.enabled);
        assert!(policy.automation.consumers.is_empty());
        assert!(!policy.remote);
    }

    #[test]
    fn new_shape_json_round_trips_automation_and_remote() {
        let mut policy = Policy::new("db-prod", "pass", "prod/db");
        policy.require_totp = true;
        policy.automation.enabled = true;
        policy.automation.consumers.push("m".into());
        policy.remote = true;

        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(json["automation"]["enabled"], true);
        assert_eq!(json["automation"]["consumers"][0], "m");
        assert_eq!(json["remote"], true);

        let back: Policy = serde_json::from_value(json).unwrap();
        assert_eq!(back, policy);
    }

    /// The four combinations the phase brief calls out by name:
    /// `requireTotp` x automation-open-and-listed.
    #[test]
    fn totp_required_covers_the_four_combinations() {
        let mut open_and_listed = Policy::new("t", "b", "k");
        open_and_listed.require_totp = true;
        open_and_listed.automation.enabled = true;
        open_and_listed.automation.consumers = vec!["m".into()];

        let closed = {
            let mut p = Policy::new("t", "b", "k");
            p.require_totp = true; // automation stays default-closed
            p
        };

        let require_totp_off_but_automation_open = {
            let mut p = Policy::new("t", "b", "k");
            p.require_totp = false;
            p.automation.enabled = true;
            p.automation.consumers = vec!["m".into()];
            p
        };

        // requireTotp true, automation open, consumer LISTED -> not required.
        assert!(!totp_required(&open_and_listed, "m"));
        // requireTotp true, automation open, consumer NOT listed -> still required.
        assert!(totp_required(&open_and_listed, "someone-else"));
        // requireTotp true, automation closed -> required regardless of consumer.
        assert!(totp_required(&closed, "m"));
        assert!(totp_required(&closed, "anyone"));
        // requireTotp false -> never required, even with automation open+listed.
        assert!(!totp_required(&require_totp_off_but_automation_open, "m"));
    }

    #[test]
    fn round_trip_survives_a_real_file_in_a_tempdir() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-policy-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.json");

        let mut policy = Policy::new("db-prod", "pass", "prod/db");
        policy.require_totp = true;
        policy.consumers = vec!["m".into(), "verba".into()];
        let bytes = serde_json::to_vec(&policy).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(bytes, read_back);
        let policy2: Policy = serde_json::from_slice(&read_back).unwrap();
        assert_eq!(policy, policy2);

        std::fs::remove_dir_all(&dir).ok();
    }
}
