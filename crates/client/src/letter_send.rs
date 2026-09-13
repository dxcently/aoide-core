//! Structured content fanout; transport and filing remain the scalar handler's job.
use aoide_protocol::{
    output::{Outcome, Status},
    Invocation,
};
use aoide_storage::{
    letter::{deduplicate_recipients, LetterContent},
    mail::Address,
};
use serde_json::json;

fn addresses(raw: &str, local: &str) -> Result<Vec<Address>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    raw.split(',')
        .map(|part| {
            let (node, name) = part
                .trim()
                .split_once('/')
                .ok_or("Recipients must be node/mailbox, separated by commas")?;
            if !aoide_storage::node_store::valid_node_name(node)
                || !aoide_storage::node_store::valid_node_name(name)
            {
                return Err("Recipient node and mailbox must match ^[a-z0-9][a-z0-9-]*$".into());
            }
            Ok(Address {
                node: if node == "self" {
                    local.into()
                } else {
                    node.into()
                },
                name: name.into(),
            })
        })
        .collect()
}

pub(crate) fn send(inv: &Invocation, mut scalar: impl FnMut(&Invocation) -> Outcome) -> Outcome {
    let local = aoide_storage::display::local_host_name();
    let prepare = || -> Result<LetterContent, String> {
        let to = addresses(
            inv.flags.get("to").map(String::as_str).unwrap_or(""),
            &local,
        )?;
        let cc = addresses(
            inv.flags.get("cc").map(String::as_str).unwrap_or(""),
            &local,
        )?;
        let (to, cc) = deduplicate_recipients(&to, &cc);
        let content = LetterContent {
            subject: inv.flags.get("subject").cloned().unwrap_or_default(),
            to,
            cc,
            body: inv.args.join(" "),
            thread_id: inv.flags.get("thread").cloned(),
            reply_to: inv.flags.get("reply-to").cloned(),
        };
        content.validate()?;
        if inv.args.is_empty() {
            return Err("A letter needs message text".into());
        }
        let nodes = aoide_storage::node_store::load_nodes();
        for address in content.to.iter().chain(&content.cc) {
            if address.node != local && !nodes.iter().any(|n| n.name == address.node && n.verified)
            {
                return Err(format!(
                    "Recipient {}/{} requires a registered, paired node",
                    address.node, address.name
                ));
            }
        }
        Ok(content)
    };
    let mut content = match prepare() {
        Ok(v) => v,
        Err(e) => return Outcome::usage("mail.send", e),
    };
    if content.thread_id.is_none() {
        content.thread_id = Some(aoide_storage::pairing::random_hex(32));
    }
    let encoded = match content.encode() {
        Ok(v) => v,
        Err(e) => return Outcome::usage("mail.send", e),
    };
    let mut results = Vec::new();
    let mut changes = Vec::new();
    let mut accepted = 0;
    for (role, address) in content
        .to
        .iter()
        .map(|a| ("to", a))
        .chain(content.cc.iter().map(|a| ("cc", a)))
    {
        let mut flags = inv.flags.clone();
        flags.remove("subject");
        flags.remove("cc");
        flags.remove("thread");
        flags.remove("reply-to");
        flags.insert(
            "to".into(),
            format!(
                "{}/{}",
                if address.node == local {
                    "self"
                } else {
                    &address.node
                },
                address.name
            ),
        );
        let single = Invocation {
            path: inv.path.clone(),
            flags,
            args: vec![encoded.clone()],
            door: inv.door,
        };
        let out = scalar(&single);
        let ok = out.status == Status::Ok;
        if ok {
            accepted += 1;
        }
        let data = out.data.unwrap_or_default();
        let msgid = data
            .get("msgid")
            .or_else(|| data.pointer("/envelope/msgid"))
            .cloned();
        results.push(json!({"address": address, "role": role, "accepted": ok, "status": if ok { if address.node == local { "filed" } else { "spooled" } } else { "failed" }, "msgid": msgid, "delivery": data.get("delivery"), "ring": data.get("ring"), "error": if ok { None } else { Some(out.message) }}));
        changes.extend(out.changed);
    }
    let complete = accepted == results.len();
    let message = format!("{accepted}/{} recipient copies filed or spooled; inspect recipient delivery status before retrying", results.len());
    let outcome = if complete {
        Outcome::ok("mail.send", message)
    } else {
        Outcome::error("mail.send", message)
    };
    outcome.changed(changes).with_data(json!({"complete": complete, "accepted": accepted, "recipients": results, "subject": content.subject, "threadId": content.thread_id, "replyTo": content.reply_to}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_aliases_normalize_before_dedup_and_bad_addresses_fail() {
        let to = addresses("self/agent, host/agent", "host").unwrap();
        assert_eq!(deduplicate_recipients(&to, &[]).0.len(), 1);
        assert!(addresses("host/agent,", "host").is_err());
        assert!(addresses("host/a/b", "host").is_err());
    }
    #[test]
    fn fanout_validates_before_writes_and_reports_partial_without_retry() {
        let mut inv = Invocation {
            path: vec!["mail".into(), "send".into()],
            args: vec!["body".into()],
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        };
        inv.flags.insert("to".into(), "self/one".into());
        inv.flags.insert("cc".into(), "self/two,self/one".into());
        inv.flags.insert("subject".into(), "subject".into());
        let mut calls = 0;
        let out = send(&inv, |single| {
            calls += 1;
            assert!(!single.flags.contains_key("cc"));
            let body = aoide_storage::letter::decode(&single.args[0]).unwrap();
            assert_eq!(body.to.len(), 1);
            assert_eq!(body.cc.len(), 1);
            if calls == 1 {
                Outcome::ok("mail.send", "filed").with_data(json!({"envelope":{"msgid":"one"}}))
            } else {
                Outcome::error("mail.send", "disk full")
            }
        });
        assert_eq!(calls, 2);
        assert_eq!(out.status, Status::Error);
        let data = out.data.unwrap();
        assert_eq!(data["accepted"], 1);
        assert_eq!(data["recipients"][0]["msgid"], "one");
        assert_eq!(data["recipients"][1]["error"], "disk full");
        inv.flags.insert("cc".into(), "not an address".into());
        assert_eq!(
            send(&inv, |_| panic!("must validate before any write")).status,
            Status::Usage
        );
    }
    #[test]
    fn thread_is_shared_by_copies_fresh_per_send_and_reply_ids_are_preserved() {
        let mut inv = Invocation {
            path: vec!["mail".into(), "send".into()],
            args: vec!["body".into()],
            flags: Default::default(),
            door: aoide_protocol::Door::Cli,
        };
        inv.flags.insert("to".into(), "self/one".into());
        inv.flags.insert("cc".into(), "self/two".into());
        let mut threads = Vec::new();
        let out = send(&inv, |single| {
            let content = aoide_storage::letter::decode(&single.args[0]).unwrap();
            threads.push(content.thread_id.unwrap());
            Outcome::ok("mail.send", "filed")
        });
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0], threads[1]);
        assert_eq!(out.data.unwrap()["threadId"], threads[0]);
        let next = send(&inv, |_| Outcome::ok("mail.send", "filed"));
        assert_ne!(next.data.unwrap()["threadId"], threads[0]);
        inv.flags.insert("thread".into(), threads[0].clone());
        inv.flags.insert("reply-to".into(), "a".repeat(64));
        assert_eq!(
            send(&inv, |single| {
                assert!(!single.flags.contains_key("thread"));
                assert!(!single.flags.contains_key("reply-to"));
                let content = aoide_storage::letter::decode(&single.args[0]).unwrap();
                assert_eq!(content.thread_id.as_ref(), Some(&threads[0]));
                assert_eq!(content.reply_to, Some("a".repeat(64)));
                Outcome::ok("mail.send", "filed")
            })
            .status,
            Status::Ok
        );
        inv.flags.insert("thread".into(), "invalid".into());
        assert_eq!(
            send(&inv, |_| panic!("invalid thread must not file")).status,
            Status::Usage
        );
        inv.flags.remove("thread");
        assert_eq!(
            send(&inv, |_| panic!("reply needs thread")).status,
            Status::Usage
        );
    }
}
