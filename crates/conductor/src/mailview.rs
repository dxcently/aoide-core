//! Non-consuming recent-letter view over the existing immutable mail base.

use aoide_storage::mail::{Address, Entry};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_LETTERS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailLetter {
    pub seq: u64,
    pub msgid: String,
    pub from: String,
    pub to: String,
    pub from_address: Address,
    pub to_address: Address,
    pub text: String,
    pub received_at: String,
    pub minted_at: String,
}

impl MailLetter {
    /// Structured fields are presentation metadata; envelope identity stays authoritative.
    pub fn content(&self) -> Option<aoide_storage::letter::LetterContent> {
        aoide_storage::letter::decode(&self.text)
    }

    pub fn thread_id(&self) -> Option<String> {
        self.content().and_then(|c| c.thread_id)
    }

    pub fn reply_to(&self) -> Option<String> {
        self.content().and_then(|c| c.reply_to)
    }

    pub fn subject(&self) -> Option<String> {
        self.content().map(|c| c.subject)
    }

    pub fn to_recipients(&self) -> Vec<Address> {
        self.content()
            .map(|c| c.to)
            .unwrap_or_else(|| vec![self.to_address.clone()])
    }

    pub fn cc_recipients(&self) -> Vec<Address> {
        self.content().map(|c| c.cc).unwrap_or_default()
    }

    /// Unknown versions and malformed structured text remain visible without alteration.
    pub fn body(&self) -> String {
        self.content()
            .map(|c| c.body)
            .unwrap_or_else(|| self.text.clone())
    }
}

/// Explicit letter threads, with clearly separate legacy pair correspondence.
/// Participants describe observed envelopes/content, not shared room membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub id: String,
    pub label: String,
    pub participants: Vec<String>,
    pub thread_id: Option<String>,
    pub letters: Vec<MailLetter>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct MailBoard {
    /// Newest first; identities remain the original envelope message IDs.
    pub letters: Vec<MailLetter>,
    /// A refresh error leaves the last successful snapshot available.
    pub error: Option<String>,
    pub truncated: bool,
}

impl MailBoard {
    pub fn conversations(&self) -> Vec<Conversation> {
        let decoded: Vec<_> = self
            .letters
            .iter()
            .map(|letter| (letter, letter.content()))
            .collect();
        let thread_ids: BTreeSet<_> = decoded
            .iter()
            .filter_map(|(_, c)| c.as_ref()?.thread_id.clone())
            .collect();
        let mut groups: BTreeMap<String, Conversation> = BTreeMap::new();
        for (letter, content) in &decoded {
            let thread_id = content
                .as_ref()
                .and_then(|c| c.thread_id.clone())
                .or_else(|| {
                    thread_ids
                        .contains(&letter.msgid)
                        .then(|| letter.msgid.clone())
                });
            let mut endpoints = [
                (&letter.from_address.node, &letter.from_address.name),
                (&letter.to_address.node, &letter.to_address.name),
            ];
            endpoints.sort();
            let id = thread_id
                .as_ref()
                .map(|id| format!("thread:{id}"))
                .unwrap_or_else(|| {
                    format!(
                        "legacy:{}",
                        serde_json::to_string(&endpoints).expect("string pairs serialize")
                    )
                });
            let group = groups.entry(id.clone()).or_insert_with(|| Conversation {
                id,
                thread_id,
                label: String::new(),
                participants: Vec::new(),
                letters: Vec::new(),
                updated_at: String::new(),
            });
            group.letters.push((*letter).clone());
        }
        let mut conversations: Vec<_> = groups.into_values().collect();
        for conversation in &mut conversations {
            conversation
                .letters
                .sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.msgid.cmp(&b.msgid)));
            let mut participants = BTreeSet::new();
            for letter in &conversation.letters {
                participants.insert((
                    letter.from_address.node.clone(),
                    letter.from_address.name.clone(),
                ));
                participants.insert((
                    letter.to_address.node.clone(),
                    letter.to_address.name.clone(),
                ));
                if let Some(content) = letter.content() {
                    for recipient in content.to.into_iter().chain(content.cc) {
                        participants.insert((recipient.node, recipient.name));
                    }
                    if conversation.label.is_empty() && !content.subject.trim().is_empty() {
                        conversation.label = content.subject;
                    }
                }
            }
            conversation.participants = participants
                .into_iter()
                .map(|(node, name)| format!("{name}@{node}"))
                .collect();
            if conversation.thread_id.is_none() {
                let first = &conversation.letters[0];
                let mut endpoints = [first.from.clone(), first.to.clone()];
                endpoints.sort();
                conversation.label = if endpoints[0] == endpoints[1] {
                    format!("Legacy · {}", endpoints[0])
                } else {
                    format!("Legacy · {} ↔ {}", endpoints[0], endpoints[1])
                };
            } else if conversation.label.is_empty() {
                conversation.label = "(no subject)".into();
            }
            if let Some(last) = conversation.letters.last() {
                conversation.updated_at = last.received_at.clone();
            }
        }
        // Local sequence is authoritative even when remote clocks disagree.
        conversations.sort_by(|a, b| {
            b.letters
                .last()
                .map(|l| l.seq)
                .cmp(&a.letters.last().map(|l| l.seq))
                .then_with(|| a.id.cmp(&b.id))
        });
        conversations
    }

    pub fn load() -> Self {
        let mut board = Self::default();
        board.refresh();
        board
    }

    pub fn refresh(&mut self) {
        self.refresh_from(&aoide_storage::mail::base_path());
    }

    fn refresh_from(&mut self, path: &Path) {
        match read_snapshot(path) {
            Ok((letters, truncated)) => {
                self.letters = letters;
                self.truncated = truncated;
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}

fn read_snapshot(path: &Path) -> Result<(Vec<MailLetter>, bool), String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
        Err(e) => return Err(format!("Cannot read mail: {e}")),
    };
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let start = size.saturating_sub(MAX_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(size - start)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    // Only complete JSONL records belong to this snapshot; never repair the writer's tail.
    let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let begin = if start > 0 {
        bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(end, |i| i + 1)
    } else {
        0
    };
    let mut letters = Vec::new();
    let mut truncated = start > 0;
    for line in bytes[begin..end]
        .split(|b| *b == b'\n')
        .rev()
        .filter(|l| !l.is_empty())
    {
        let entry: Entry = serde_json::from_slice(line)
            .map_err(|e| format!("Cannot decode mail snapshot: {e}"))?;
        if entry.kind != "letter" {
            continue;
        }
        if letters.len() == MAX_LETTERS {
            truncated = true;
            break;
        }
        let header = entry.envelope.header;
        letters.push(MailLetter {
            seq: entry.seq,
            msgid: entry.envelope.msgid,
            from: format!("{}@{}", header.from.name, header.from.node),
            to: format!("{}@{}", header.to.name, header.to.node),
            from_address: header.from,
            to_address: header.to,
            text: entry.envelope.text,
            received_at: entry.received_at,
            minted_at: header.minted_at,
        });
    }
    Ok((letters, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aoide-mailview-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn base(&self) -> std::path::PathBuf {
            self.0.join("base.jsonl")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn entry(seq: u64, kind: &str) -> String {
        serde_json::json!({"seq":seq,"receivedAt":"now","type":kind,"via":"self",
            "envelope":{"header":{"version":"0","from":{"node":"a","name":"sender"},
            "to":{"node":"b","name":"reader"},"type":kind,"mintedAt":"then","originMesh":""},
            "text":"hello\n世界","sig":"fixture","msgid":format!("id-{seq}")}})
        .to_string()
            + "\n"
    }

    fn letter(seq: u64, from: (&str, &str), to: (&str, &str)) -> MailLetter {
        MailLetter {
            seq,
            msgid: format!("id-{seq}"),
            from: format!("{}@{}", from.1, from.0),
            to: format!("{}@{}", to.1, to.0),
            from_address: Address {
                node: from.0.into(),
                name: from.1.into(),
            },
            to_address: Address {
                node: to.0.into(),
                name: to.1.into(),
            },
            text: "original".into(),
            received_at: format!("time-{seq}"),
            minted_at: "remote time".into(),
        }
    }

    #[test]
    fn structured_fields_preserve_signed_text_and_envelope_grouping() {
        let mut message = letter(1, ("a", "sender"), ("b", "reader"));
        let content = aoide_storage::letter::LetterContent {
            subject: "Review 世界".into(),
            thread_id: None,
            reply_to: None,
            to: vec![Address {
                node: "c".into(),
                name: "other".into(),
            }],
            cc: vec![Address {
                node: "d".into(),
                name: "copy".into(),
            }],
            body: "first\nsecond\r\n".into(),
        };
        let original = content.encode().unwrap();
        message.text = original.clone();
        assert_eq!(message.subject(), Some(content.subject.clone()));
        assert_eq!(message.to_recipients(), content.to);
        assert_eq!(message.cc_recipients(), content.cc);
        assert_eq!(message.body(), content.body);
        assert_eq!(message.text, original);
        assert_eq!(message.msgid, "id-1");
        let board = MailBoard {
            letters: vec![message, letter(2, ("b", "reader"), ("a", "sender"))],
            ..Default::default()
        };
        let groups = board.conversations();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].participants,
            ["sender@a", "reader@b", "other@c", "copy@d"]
        );
    }

    #[test]
    fn legacy_and_malformed_structured_letters_fall_back_without_invented_subjects() {
        for raw in [
            "plain\n世界",
            "Subject: literal\n\nbody",
            "AOIDE-LETTER/2\n{}",
            "AOIDE-LETTER/1\n{bad",
            "AOIDE-LETTER/1\n{}",
        ] {
            let mut message = letter(1, ("a", "sender"), ("b", "reader"));
            message.text = raw.into();
            assert_eq!(message.content(), None);
            assert_eq!(message.subject(), None);
            assert_eq!(message.to_recipients(), vec![message.to_address.clone()]);
            assert!(message.cc_recipients().is_empty());
            assert_eq!(message.body(), raw);
            assert_eq!(message.text, raw);
        }
    }

    fn threaded(
        mut message: MailLetter,
        thread: &str,
        subject: &str,
        cc: Vec<Address>,
    ) -> MailLetter {
        message.text = aoide_storage::letter::LetterContent {
            subject: subject.into(),
            to: vec![message.to_address.clone()],
            cc,
            body: "unchanged body".into(),
            thread_id: Some(thread.into()),
            reply_to: None,
        }
        .encode()
        .unwrap();
        message
    }

    #[test]
    fn explicit_threads_survive_new_participants_and_keep_same_people_separate() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let board = MailBoard {
            letters: vec![
                threaded(
                    letter(3, ("c", "three"), ("a", "one")),
                    &first,
                    "Re: First",
                    vec![],
                ),
                threaded(
                    letter(1, ("a", "one"), ("b", "two")),
                    &first,
                    "First",
                    vec![Address {
                        node: "c".into(),
                        name: "three".into(),
                    }],
                ),
                threaded(
                    letter(4, ("a", "one"), ("b", "two")),
                    &second,
                    "Separate",
                    vec![],
                ),
                threaded(
                    letter(2, ("b", "two"), ("d", "four")),
                    &first,
                    "Re: First",
                    vec![],
                ),
            ],
            ..Default::default()
        };
        let groups = board.conversations();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].thread_id.as_deref(), Some(second.as_str()));
        let group = &groups[1];
        assert_eq!(group.label, "First");
        assert_eq!(group.participants, ["one@a", "two@b", "three@c", "four@d"]);
        assert_eq!(
            group.letters.iter().map(|l| l.seq).collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }

    #[test]
    fn legacy_reply_anchor_moves_only_the_exact_original_into_its_thread() {
        let mut original = letter(1, ("a", "one"), ("b", "two"));
        original.msgid = "c".repeat(64);
        let reply = threaded(
            letter(3, ("b", "two"), ("a", "one")),
            &original.msgid,
            "Re: Original",
            vec![],
        );
        let board = MailBoard {
            letters: vec![
                reply,
                letter(2, ("a", "one"), ("b", "two")),
                original.clone(),
            ],
            ..Default::default()
        };
        let groups = board.conversations();
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].thread_id.as_deref(),
            Some(original.msgid.as_str())
        );
        assert_eq!(
            groups[0].letters.iter().map(|l| l.seq).collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(groups[0].letters[0].text, "original");
        assert!(groups[1].label.starts_with("Legacy · "));
        assert_eq!(groups[1].letters.len(), 1);
        assert_eq!(groups[1].letters[0].seq, 2);
    }

    #[test]
    fn conversations_group_both_directions_and_order_without_changing_identity() {
        let mut board = MailBoard::default();
        board.letters = vec![
            letter(4, ("a", "one"), ("b", "two")),
            letter(2, ("b", "two"), ("a", "one")),
            letter(3, ("c", "three"), ("c", "three")),
            letter(1, ("a", "one"), ("c", "three")),
        ];
        let groups = board.conversations();
        assert_eq!(groups.len(), 3);
        assert_eq!(
            groups[0].letters.iter().map(|l| l.seq).collect::<Vec<_>>(),
            [2, 4]
        );
        assert_eq!(groups[0].letters[0].msgid, "id-2");
        assert_eq!(groups[0].updated_at, "time-4");
        assert_eq!(groups[1].participants, ["three@c"]);
        board.letters.reverse();
        assert_eq!(groups, board.conversations());
    }

    #[test]
    fn conversation_identity_does_not_use_ambiguous_display_delimiters() {
        let mut board = MailBoard::default();
        board.letters = vec![
            letter(1, ("node", "name@part"), ("other", "peer")),
            letter(2, ("part@node", "name"), ("other", "peer")),
        ];
        assert_eq!(board.letters[0].from, board.letters[1].from);
        let groups = board.conversations();
        assert_eq!(groups.len(), 2);
        assert_ne!(groups[0].id, groups[1].id);
    }

    #[test]
    fn reads_recent_letters_without_consuming_or_repairing() {
        let fixture = Fixture::new();
        let body = entry(1, "letter") + &entry(2, "receipt") + &entry(3, "letter") + "{torn";
        std::fs::write(fixture.base(), &body).unwrap();
        let cursor = fixture.0.join("cursors.json");
        std::fs::write(&cursor, "untouched").unwrap();
        let (letters, truncated) = read_snapshot(&fixture.base()).unwrap();
        assert_eq!(letters.iter().map(|l| l.seq).collect::<Vec<_>>(), [3, 1]);
        assert_eq!(letters[0].from, "sender@a");
        assert_eq!(letters[0].text, "hello\n世界");
        assert!(!truncated);
        assert_eq!(std::fs::read_to_string(fixture.base()).unwrap(), body);
        assert_eq!(std::fs::read_to_string(cursor).unwrap(), "untouched");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
    }

    #[test]
    fn bounded_and_failed_refresh_preserves_previous_snapshot() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.base(),
            (0..205).map(|i| entry(i, "letter")).collect::<String>(),
        )
        .unwrap();
        let mut board = MailBoard::default();
        board.refresh_from(&fixture.base());
        assert_eq!(board.letters.len(), 200);
        assert_eq!(board.letters[0].seq, 204);
        assert!(board.truncated);
        std::fs::write(fixture.base(), "invalid\n").unwrap();
        board.refresh_from(&fixture.base());
        assert!(board.error.is_some());
        assert_eq!(board.letters.len(), 200);
    }

    #[test]
    fn byte_window_skips_partial_first_record_and_missing_base_is_empty() {
        let fixture = Fixture::new();
        assert!(read_snapshot(&fixture.base()).unwrap().0.is_empty());
        let body = "x".repeat(MAX_BYTES as usize) + "\n" + &entry(9, "letter");
        std::fs::write(fixture.base(), body).unwrap();
        let (letters, truncated) = read_snapshot(&fixture.base()).unwrap();
        assert!(truncated);
        assert_eq!(letters.len(), 1);
        assert_eq!(letters[0].msgid, "id-9");
    }
}
