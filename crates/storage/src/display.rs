//! Render-time-only display grammar (P1 of the petnames plan): stitches
//! this box's host name, a session's DAG role, its minted petname (or the
//! raw id, for a legacy/petname-less record) and a short id tail into one
//! line — `<host>/<role>/<petname> (…<tail4>)`, e.g.
//! `sakaki/root/brave-otter (…8948)` — so every human surface (`graph
//! view`'s tree, the conductor TUI, `graph send`'s attribution prefix)
//! renders identity the same way.
//!
//! `sessionId` stays the sole canonical identity in every JSON payload,
//! socket, CONTRACTS key, and `Node::session_id`; this module only ever
//! builds a STRING for a human to read, never something read back.

use crate::records::SessionRecord;

/// This box's display name: `AOIDE_A2A_NODE_NAME` env → the OS hostname
/// (`libc::gethostname`) → the literal `"aoide"` if even that fails.
///
/// Mirrors the env/hostname half of `aoide_server::a2a::resolve_node_name`'s
/// precedence (that function also checks a `--node-name` CLI flag ahead of
/// these two; storage has no `Invocation` to read a flag off, so this starts
/// one step later in the same chain). Never panics: a `gethostname` failure,
/// truncation, or non-UTF8 all fall through to the next link instead of
/// unwrapping.
pub fn local_host_name() -> String {
    std::env::var("AOIDE_A2A_NODE_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(os_hostname)
        .unwrap_or_else(|| "aoide".to_string())
}

/// The OS hostname via `libc::gethostname`, or `None` on any failure
/// (truncated/non-UTF8/errno) — best-effort, never a panic. Ported from
/// `aoide_server::a2a::os_hostname` (moved here so conduct/conductor
/// renderers, which cannot depend on the server crate, can call it too; the
/// server copy is deleted once this one is wired in).
fn os_hostname() -> Option<String> {
    let mut buf = vec![0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The last 4 chars of a canonical id — the grep-back handle every display
/// grammar tacks on in parens. Char-based (not byte-sliced), so it is total
/// even on a non-ASCII or under-4-char id: a short id comes back whole
/// instead of panicking on a byte-index that doesn't land on a char
/// boundary.
pub fn short_tail(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// Render one session's identity for a human surface: `<host>/<role>/
/// <petname> (…<tail4>)` when the record has a minted petname, degrading to
/// `<host>/<role>/<sessionId>` — the FULL id, never a truncated fake — when
/// it doesn't (a record from before this field existed).
pub fn session_label(rec: &SessionRecord, host: &str, role: &str) -> String {
    match rec.petname.as_deref() {
        Some(petname) => format!("{host}/{role}/{petname} (…{})", short_tail(&rec.session_id)),
        None => format!("{host}/{role}/{}", rec.session_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_host_name_never_panics_and_is_never_empty() {
        // No env/hostname assumptions in a test sandbox — just prove the
        // full fallback chain (env -> gethostname -> "aoide") always lands
        // on something non-empty without unwinding.
        let name = local_host_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn short_tail_takes_last_four_chars_and_is_total_on_short_ids() {
        assert_eq!(short_tail("session-1234-5678"), "5678");
        assert_eq!(short_tail("abc"), "abc");
        assert_eq!(short_tail(""), "");
        assert_eq!(short_tail("abcd"), "abcd");
        assert_eq!(short_tail("abcde"), "bcde");
    }

    #[test]
    fn session_label_root_child_and_legacy_cases() {
        let root = SessionRecord {
            session_id: "sess-0000-8948".into(),
            petname: Some("brave-otter".into()),
            ..Default::default()
        };
        assert_eq!(session_label(&root, "sakaki", "root"), "sakaki/root/brave-otter (…8948)");

        let child = SessionRecord {
            session_id: "sess-0000-1234".into(),
            petname: Some("calm-thorn".into()),
            ..Default::default()
        };
        assert_eq!(session_label(&child, "sakaki", "child"), "sakaki/child/calm-thorn (…1234)");

        // Legacy: no petname minted — degrade to the full raw id, never a
        // truncated fake.
        let legacy = SessionRecord {
            session_id: "sess-legacy-full-id".into(),
            petname: None,
            ..Default::default()
        };
        assert_eq!(
            session_label(&legacy, "sakaki", "root"),
            "sakaki/root/sess-legacy-full-id"
        );
    }
}
