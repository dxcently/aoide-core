//! Optional structured letter content carried inside the existing signed text.
//! Invalid or legacy bodies remain raw text; this module performs no delivery.

use crate::mail::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MARKER: &str = "AOIDE-LETTER/1\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LetterContent {
    pub subject: String,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub body: String,
    #[serde(default, rename = "threadId", skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, rename = "replyTo", skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

impl LetterContent {
    pub fn validate(&self) -> Result<(), String> {
        for id in self.thread_id.iter().chain(self.reply_to.iter()) {
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(
                    "Thread and reply IDs must be 64 lowercase hexadecimal characters".into(),
                );
            }
        }
        if self.reply_to.is_some() && self.thread_id.is_none() {
            return Err("A reply needs a thread ID".into());
        }
        if self.subject.contains(['\r', '\n']) {
            return Err("Subject must be a single line".into());
        }
        if self.to.is_empty() {
            return Err("A letter needs a To recipient".into());
        }
        for address in self.to.iter().chain(&self.cc) {
            if !crate::node_store::valid_node_name(&address.node)
                || !crate::node_store::valid_node_name(&address.name)
            {
                return Err("Recipient node and mailbox must match ^[a-z0-9][a-z0-9-]*$".into());
            }
        }
        Ok(())
    }

    /// Encode without silently changing recipient metadata or body bytes.
    pub fn encode(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string(self)
            .map(|body| format!("{MARKER}{body}"))
            .map_err(|e| e.to_string())
    }
}

/// Exact schema only. A caller must retain the original text when this is None.
pub fn decode(text: &str) -> Option<LetterContent> {
    let json = text.strip_prefix(MARKER)?;
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    // Address is a shared permissive wire type; this body convention is closed.
    for key in ["to", "cc"] {
        for address in value.get(key)?.as_array()? {
            let fields = address.as_object()?;
            if fields.len() != 2 || !fields.contains_key("node") || !fields.contains_key("name") {
                return None;
            }
        }
    }
    // Deserialize the original JSON so duplicate top-level fields are rejected.
    let content: LetterContent = serde_json::from_str(json).ok()?;
    content.validate().ok()?;
    Some(content)
}

/// Preserve input order, deduplicate canonical endpoints, and give To precedence.
/// Resolve any local aliases before calling; display delimiters never form keys.
pub fn deduplicate_recipients(to: &[Address], cc: &[Address]) -> (Vec<Address>, Vec<Address>) {
    let mut seen = HashSet::new();
    let mut unique = |addresses: &[Address]| {
        addresses
            .iter()
            .filter(|a| seen.insert((a.node.clone(), a.name.clone())))
            .cloned()
            .collect()
    };
    (unique(to), unique(cc))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address(node: &str, name: &str) -> Address {
        Address {
            node: node.into(),
            name: name.into(),
        }
    }
    fn letter() -> LetterContent {
        LetterContent {
            thread_id: None,
            reply_to: None,
            subject: "Review 世界".into(),
            to: vec![address("osaka", "fable")],
            cc: vec![],
            body: "First\nsecond\r\n".into(),
        }
    }

    #[test]
    fn structured_roundtrip_preserves_body_and_legacy_stays_raw() {
        let content = letter();
        assert_eq!(decode(&content.encode().unwrap()), Some(content));
        for raw in [
            "ordinary text",
            "Subject: hi\n\nbody",
            "AOIDE-LETTER/2\n{}",
            "AOIDE-LETTER/1\r\n{}",
        ] {
            assert_eq!(decode(raw), None);
        }
    }

    #[test]
    fn exact_schema_and_valid_addresses_are_required() {
        let base = serde_json::to_value(letter()).unwrap();
        for key in ["subject", "to", "cc", "body"] {
            let mut value = base.clone();
            value.as_object_mut().unwrap().remove(key);
            assert!(decode(&format!("{MARKER}{value}")).is_none());
        }
        let mut extra = base.clone();
        extra["extra"] = true.into();
        assert!(decode(&format!("{MARKER}{extra}")).is_none());
        extra = base;
        extra["to"][0]["extra"] = true.into();
        assert!(decode(&format!("{MARKER}{extra}")).is_none());
        let mut bad = letter();
        bad.subject = "injected\r\nTo: other".into();
        assert!(bad.encode().is_err());
        bad = letter();
        bad.to.clear();
        assert!(bad.encode().is_err());
        bad = letter();
        bad.to[0].name = String::new();
        assert!(bad.encode().is_err());
        bad = letter();
        bad.to[0].node = "a/b".into();
        assert!(bad.encode().is_err());
    }

    #[test]
    fn deduplication_preserves_to_precedence_and_canonical_endpoint_identity() {
        let a = address("osaka", "fable");
        let b = address("yomi", "reviewer");
        assert_eq!(
            deduplicate_recipients(&[a.clone(), a.clone()], &[a.clone(), b.clone(), b.clone()]),
            (vec![a], vec![b])
        );
        let a = address("a/b", "c");
        let b = address("a", "b/c");
        assert_eq!(deduplicate_recipients(&[a, b], &[]).0.len(), 2);
    }
    #[test]
    fn optional_thread_metadata_retains_legacy_and_rejects_bad_ids() {
        let old = letter();
        let encoded = old.encode().unwrap();
        assert!(!encoded.contains("threadId"));
        assert_eq!(decode(&encoded), Some(old.clone()));
        let mut reply = old;
        reply.thread_id = Some("a".repeat(64));
        reply.reply_to = Some("1".repeat(64));
        assert_eq!(decode(&reply.encode().unwrap()), Some(reply.clone()));
        for bad in [
            String::new(),
            "a".repeat(63),
            "A".repeat(64),
            "/".repeat(64),
        ] {
            reply.thread_id = Some(bad);
            assert!(reply.encode().is_err());
        }
        reply.thread_id = None;
        assert!(reply.encode().is_err());
    }
}
