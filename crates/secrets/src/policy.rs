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

/// One secret's access policy — the plan's SECRETS §Policy shape verbatim:
/// `{name, backend, key, requireTotp, consumers[], sharedWith[]}`.
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
    /// check only).
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
}

impl Policy {
    /// Construct a policy with no consumers/sharing restrictions and
    /// `requireTotp` off — the caller narrows from here.
    pub fn new(name: impl Into<String>, backend: impl Into<String>, key: impl Into<String>) -> Self {
        Policy {
            name: name.into(),
            backend: backend.into(),
            key: key.into(),
            require_totp: false,
            consumers: Vec::new(),
            shared_with: Vec::new(),
        }
    }
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
