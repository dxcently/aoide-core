//! `graph pending list|approve|deny` — the pending queue's OTHER half.
//!
//! `state/stage/pending.json` is where [`super::send::session_send`] parks a
//! held injection when the gate doesn't authorise immediate delivery (no
//! `--yes`, no autogate match) — and where the A2A door parks the same kind
//! of held inject when its own admission check doesn't clear it
//! (`crates/server/src/a2a.rs`, the token-gated path). Until this module,
//! nothing in the tree ever read that file back: it was a write-only dead
//! drop, holding entries forever, invisibly. This is the read/approve/deny
//! surface every other surface (TUI, QML, web) can render later — CLI-only,
//! no TUI/QML/auto-approval/allowlist here (YAGNI; those are later phases).
//!
//! `approve` does NOT open a second injection path. It re-synthesizes the
//! exact `aoide graph send --id <id> --yes -- <text>` invocation the held
//! entry represents and calls [`super::send::session_send`] directly,
//! in-process — the SAME one gated injection door `graph permit`'s
//! `type_verdict` already goes through (`permit.rs`). `deny` never calls it
//! at all.
//!
//! Resolving either way REMOVES the entry from `pending.json` (under the
//! stage lock) rather than flipping a persisted "resolved" flag — the
//! resolution record is the audit line (`graph.pending.approve` /
//! `graph.pending.deny`), exactly where every other outcome in this door
//! already lives. Nothing here keeps a resolved-entry archive nobody asked
//! for.
//!
//! Addressing: `pending.json`'s `PendingSend` carries no id of its own (only
//! `sessionId`/`text`/`submit`/`queuedAt`/`from` — see
//! [`super::send::PendingSend`]), so `list`'s `id` is the entry's POSITION in
//! the array. Positions shift the
//! moment any entry resolves, so `approve`/`deny` always re-read the file
//! fresh under the lock rather than trusting a stale list; a caller scripting
//! multiple resolutions in one breath should re-list between them.
//!
//! Malformed entries (the schema's real-world failure mode: a stale
//! hand-edited or half-written array element — a bare string instead of an
//! object, or an object with no `sessionId`) are listed best-effort rather
//! than losing the whole queue to one bad line, and `approve`/`deny` on one
//! fail cleanly (a structured error, never a panic) without touching it —
//! the entry stays exactly where it was for a human to inspect by hand.

use super::common::{require_args, stage_error};
use super::model::{
    load_stage, resolved_parent, sessions_path, write_stage, SessionRecord, SessionsFile,
};
use super::send::pending_path;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

/// Is this raw `pending` array element too broken to resolve? The one field
/// every entry [`super::send::record_pending`] ever wrote is a non-empty
/// `sessionId` — anything without one (not an object at all, or an object
/// missing it) cannot be addressed to a session, approved, or denied.
fn is_malformed(v: &Value) -> bool {
    !v.as_object()
        .and_then(|o| o.get("sessionId"))
        .and_then(Value::as_str)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

/// A one-line, length-bounded preview of a pending entry's text — mirrors
/// [`super::send::one_line_title`]'s shape (not reused directly: that helper
/// is private to `send.rs` and this is a display-only concern, not the
/// auto-rename logic it exists for).
fn preview(text: &str) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    const MAX: usize = 60;
    if first.chars().count() > MAX {
        let mut t: String = first.chars().take(MAX - 1).collect();
        t.push('…');
        t
    } else {
        first.to_string()
    }
}

/// Read `pending.json`'s `pending` array as raw JSON — not the strict
/// [`super::send::PendingFile`] — so ONE malformed element can't fail
/// deserializing the whole `Vec<PendingSend>` and blind `list` to every
/// entry after it. A missing file is an empty queue (same tolerance as every
/// other stage file); a corrupt (unparseable) `pending.json` itself is still
/// a clean error — that is a broken FILE, not a broken entry.
fn load_pending_array() -> Result<Vec<Value>, String> {
    let raw: Value = load_stage(&pending_path())?;
    Ok(raw
        .get("pending")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// Render a session id for the human line via the canonical display grammar
/// (petnames plan P3): `<host>/<role>/<petname> (…<tail4>)`, degrading to
/// `<host>/<role>/<sessionId>` for a legacy/petname-less record. When the id
/// no longer resolves to any record in the current roster (the target was
/// pruned/reaped since the entry was queued), falls back to the bare raw id
/// — there is no record left to derive a role from, and a line inventing one
/// would be a lie.
fn grammar_label(
    id: &str,
    by_id: &BTreeMap<&str, &SessionRecord>,
    ids: &HashSet<&str>,
    host: &str,
) -> String {
    match by_id.get(id) {
        Some(rec) => {
            let role = if resolved_parent(rec, ids).is_some() { "child" } else { "root" };
            aoide_storage::display::session_label(rec, host, role)
        }
        None => id.to_string(),
    }
}

/// Render a sender id for the human line's TERSE `(from …)` tag — petname+
/// tail only (never host/role — matches `send.rs`'s composer-prefix grammar,
/// not the fuller tree-line one `grammar_label` above renders), falling back
/// to the raw sender id when it does not resolve to a live petnamed record.
fn from_label(id: &str, by_id: &BTreeMap<&str, &SessionRecord>) -> String {
    match by_id.get(id).and_then(|r| r.petname.as_deref()) {
        Some(petname) => format!("{petname} (…{})", aoide_storage::display::short_tail(id)),
        None => id.to_string(),
    }
}

/// One JSON view of a pending entry for `list`'s `data.pending`, and the text
/// line for its human render. `from` is the sender attribution
/// [`super::send::resolve_sender`] resolved at queue time — `None`/absent for
/// an unattributed send AND for a LEGACY entry written before this field
/// existed (serde default on read, see [`super::send::PendingSend`]).
///
/// `by_id`/`ids`/`host` are the CURRENT session roster, loaded once by the
/// caller ([`pending_list`]) and threaded through every entry — the JSON
/// `sessionId`/`from` stay the entry's own canonical raw ids verbatim
/// (machine contract unchanged); only the human LINE renders through the
/// display grammar.
fn entry_view(
    index: usize,
    v: &Value,
    by_id: &BTreeMap<&str, &SessionRecord>,
    ids: &HashSet<&str>,
    host: &str,
) -> (Value, String) {
    let malformed = is_malformed(v);
    if malformed {
        let json = json!({
            "id": index.to_string(),
            "sessionId": "",
            "text": v.to_string(),
            "submit": false,
            "queuedAt": "",
            "from": Value::Null,
            "state": "malformed",
        });
        let line = format!("[{index}] <malformed entry — cannot resolve; edit state/stage/pending.json by hand>");
        return (json, line);
    }
    let o = v.as_object().expect("checked non-malformed above");
    let session_id = o.get("sessionId").and_then(Value::as_str).unwrap_or("").to_string();
    let text = o.get("text").and_then(Value::as_str).unwrap_or("").to_string();
    let submit = o.get("submit").and_then(Value::as_bool).unwrap_or(false);
    let queued_at = o.get("queuedAt").and_then(Value::as_str).unwrap_or("").to_string();
    let from = o
        .get("from")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let json = json!({
        "id": index.to_string(),
        "sessionId": session_id,
        "text": text,
        "submit": submit,
        "queuedAt": queued_at,
        "from": from,
        "state": "pending",
    });
    let line = format!(
        "[{index}] {} ← {}{}{} ({queued_at})",
        grammar_label(&session_id, by_id, ids, host),
        preview(&text),
        if submit { " [submit]" } else { "" },
        from.as_deref()
            .map(|f| format!(" (from {})", from_label(f, by_id)))
            .unwrap_or_default(),
    );
    (json, line)
}

/// `graph pending list [--json]` — enumerate every held entry in
/// `pending.json`. Never errors on an empty or missing queue.
pub fn pending_list(_inv: &Invocation) -> Outcome {
    let cmd = "graph.pending.list";
    let arr = match load_pending_array() {
        Ok(a) => a,
        Err(e) => return stage_error(cmd, e),
    };
    // The current session roster, loaded ONCE for this whole list — every
    // entry's human line renders its target/sender through the SAME
    // snapshot (and the SAME once-resolved host), matching the render
    // pass's "host resolved once per render" rule in `doc.rs`.
    let sessions: Vec<SessionRecord> = load_stage::<SessionsFile>(&sessions_path())
        .map(|f| f.sessions)
        .unwrap_or_default();
    let by_id: BTreeMap<&str, &SessionRecord> =
        sessions.iter().map(|s| (s.session_id.as_str(), s)).collect();
    let ids: HashSet<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
    let host = aoide_storage::display::local_host_name();

    let mut data = Vec::with_capacity(arr.len());
    let mut lines = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let (j, l) = entry_view(i, v, &by_id, &ids, &host);
        data.push(j);
        lines.push(l);
    }
    let n = arr.len();
    let body = if n == 0 {
        "state/stage/pending.json is empty".to_string()
    } else {
        lines.join("\n")
    };
    Outcome::ok(cmd, format!("{n} pending\n{body}")).with_data(json!({ "pending": data }))
}

/// Remove and return the raw entry at `index`, under the stage lock — but
/// ONLY when it resolves to a real session (see [`is_malformed`]); a broken
/// entry is left exactly where it was rather than destroyed by a failed
/// resolve attempt. A missing file or an out-of-range index is the same
/// clean "not found" error — there is nothing there to take either way.
fn take_pending_entry(index: usize) -> Result<Value, String> {
    aoide_storage::fs::with_stage_lock(move || {
        let mut raw: Value = load_stage(&pending_path())?;
        let arr = raw
            .get_mut("pending")
            .and_then(Value::as_array_mut)
            .filter(|a| index < a.len())
            .ok_or_else(|| format!("no pending entry at index {index}"))?;
        if is_malformed(&arr[index]) {
            return Err(format!(
                "pending entry {index} is malformed — cannot resolve automatically; edit state/stage/pending.json by hand"
            ));
        }
        let removed = arr.remove(index);
        write_stage(&pending_path(), &raw)?;
        Ok(removed)
    })
}

/// One audit line per pending-resolution outcome, same shape as
/// [`super::send::session_send`]'s own `audit_send` — the injected/dropped
/// text rides as `untrusted_data`, never re-interpreted as a command.
fn audit_pending(inv: &Invocation, command: &str, status: &str, message: &str, text: &str) {
    let log = inv
        .flags
        .get("audit-log")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(aoide_protocol::default_audit_log);
    let _ = aoide_protocol::append_audit(
        &log,
        &aoide_protocol::AuditRecord {
            ts: super::conduct::unix_ts(),
            door: inv.door,
            class: aoide_protocol::EventClass::Audit,
            command: command.to_string(),
            status: status.to_string(),
            message: message.to_string(),
            untrusted_data: Some(text.to_string()),
        },
    );
}

/// Parse the `<id>` positional as a `pending list` index; a clean usage error
/// (never a panic) for anything else.
fn parse_id(cmd: &str, raw: &str) -> Result<usize, Outcome> {
    raw.trim().parse::<usize>().map_err(|_| {
        Outcome::usage(
            cmd,
            format!(
                "`{raw}` is not a pending id — ids are the position shown by `graph pending list` (e.g. 0)"
            ),
        )
        .with_data(json!({ "reason": "bad-id", "id": raw }))
    })
}

/// `graph pending approve <id> [--json]` — approve one held entry: re-drive
/// it through [`super::send::session_send`] with `--yes` (the one injection
/// door, in-process, no shell-out — see the module doc), then remove it from
/// the queue. The entry is taken OFF the queue before injection is attempted
/// (matching `graph send`'s own "every outcome is audited, nothing pending
/// forever" posture) — if delivery then fails (the target session died while
/// queued, say), that failure is reported plainly rather than silently
/// re-queued; the human re-sends by hand if the target is still reachable.
pub fn pending_approve(inv: &Invocation) -> Outcome {
    let cmd = "graph.pending.approve";
    let args = match require_args(inv, &["id"]) {
        Ok(a) => a,
        Err(o) => return o,
    };
    let index = match parse_id(cmd, &args[0]) {
        Ok(i) => i,
        Err(o) => return o,
    };
    let removed = match take_pending_entry(index) {
        Ok(v) => v,
        Err(e) => {
            audit_pending(inv, cmd, "error", &e, "");
            return Outcome::error(cmd, e)
                .with_data(json!({ "reason": "pending-entry-unresolvable", "id": index.to_string() }));
        }
    };
    let o = removed.as_object().expect("take_pending_entry only returns well-formed entries");
    let session_id = o.get("sessionId").and_then(Value::as_str).unwrap_or("").to_string();
    let text = o.get("text").and_then(Value::as_str).unwrap_or("").to_string();
    let submit = o.get("submit").and_then(Value::as_bool).unwrap_or(false);
    let from = o
        .get("from")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut flags = BTreeMap::new();
    flags.insert("id".to_string(), session_id.clone());
    flags.insert("yes".to_string(), "true".to_string());
    if submit {
        flags.insert("submit".to_string(), "true".to_string());
    }
    // Carry the ORIGINAL entry's attribution through as `--from` — ALWAYS,
    // even when the entry had none. `resolve_sender`'s tri-state rule makes
    // this the only correct move: a PRESENT `--from` (the entry's sender, or
    // `""` when it had none) is used as-is and the env is never consulted;
    // an ABSENT `--from` would instead fall through to the approver's own
    // live `AOIDE_SESSION_ID` (an orchestrating conducted session always has
    // one) and misattribute an anonymously-queued send to whoever happened
    // to approve it. `--from ""` keeps that entry anonymous through
    // delivery, exactly as it was queued.
    flags.insert("from".to_string(), from.clone().unwrap_or_default());
    if let Some(log) = inv.flags.get("audit-log") {
        flags.insert("audit-log".to_string(), log.clone());
    }
    // The one injection door, in-process — same pattern as
    // `permit.rs::type_verdict`. `args: vec![text]` (a single element) round
    // -trips the exact original text through `session_send`'s own
    // `inv.args.join(" ")`, whitespace and all.
    let inner = super::send::session_send(&Invocation {
        path: vec!["graph".to_string(), "send".to_string()],
        args: vec![text.clone()],
        flags,
        door: inv.door,
    });

    let audit_status = if inner.status == Status::Ok { "delivered" } else { "error" };
    audit_pending(
        inv,
        cmd,
        audit_status,
        &format!("approve [{index}] {session_id}: {}", inner.message),
        &text,
    );

    if inner.status != Status::Ok {
        return Outcome::error(
            cmd,
            format!(
                "pending entry {index} left the queue but delivery to `{session_id}` failed: {}",
                inner.message
            ),
        )
        .with_data(json!({
            "id": index.to_string(),
            "sessionId": session_id,
            "injected": false,
            "reason": "delivery-failed",
            "sendOutcome": inner.data,
        }));
    }
    Outcome::ok(cmd, format!("pending entry {index} approved → delivered to `{session_id}`"))
        .changed(vec![format!("pending[{index}] for {session_id}: approved and injected")])
        .with_data(json!({
            "id": index.to_string(),
            "sessionId": session_id,
            "injected": true,
            "sendOutcome": inner.data,
        }))
}

/// `graph pending deny <id> [--json]` — reject one held entry: remove it from
/// the queue, inject nothing, one audit line.
pub fn pending_deny(inv: &Invocation) -> Outcome {
    let cmd = "graph.pending.deny";
    let args = match require_args(inv, &["id"]) {
        Ok(a) => a,
        Err(o) => return o,
    };
    let index = match parse_id(cmd, &args[0]) {
        Ok(i) => i,
        Err(o) => return o,
    };
    let removed = match take_pending_entry(index) {
        Ok(v) => v,
        Err(e) => {
            audit_pending(inv, cmd, "error", &e, "");
            return Outcome::error(cmd, e)
                .with_data(json!({ "reason": "pending-entry-unresolvable", "id": index.to_string() }));
        }
    };
    let o = removed.as_object().expect("take_pending_entry only returns well-formed entries");
    let session_id = o.get("sessionId").and_then(Value::as_str).unwrap_or("").to_string();
    let text = o.get("text").and_then(Value::as_str).unwrap_or("").to_string();

    audit_pending(inv, cmd, "denied", &format!("deny [{index}] {session_id}"), &text);
    Outcome::ok(cmd, format!("pending entry {index} for `{session_id}` denied — nothing injected"))
        .changed(vec![format!("pending[{index}] for {session_id}: denied")])
        .with_data(json!({ "id": index.to_string(), "sessionId": session_id, "injected": false }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::conduct::conduct_socket_path;
    use crate::graph::model::{sessions_path, SessionsFile};
    use crate::graph::send::session_send;
    use crate::graph::session_store::do_session_start;
    use crate::graph::testutil::*;
    use std::os::unix::net::UnixListener;

    fn pending_invocation(path: &[&str], args: &[&str]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: BTreeMap::new(),
            door: aoide_protocol::Door::Cli,
        }
    }

    fn setup(tag: &str) -> std::path::PathBuf {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        // Tests running under a REAL conducted session (this one included)
        // inherit a real AOIDE_SESSION_ID from the ambient environment; now
        // that `pending_approve`'s re-drive resolves sender attribution, an
        // unguarded env would leak that ambient id into `list`/`approve`
        // assertions. Callers that need a specific sender set it themselves
        // AFTER `setup` and must include "AOIDE_SESSION_ID" in their own
        // `EnvVars::save` so it is restored.
        std::env::remove_var("AOIDE_SESSION_ID");
        root
    }

    #[test]
    fn list_reads_real_and_malformed_entries_without_dying() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG", "AOIDE_CONDUCT_AUTOGATE", "AOIDE_SESSION_ID"]);
        let root = setup("pnd-ls");

        std::fs::write(
            pending_path(),
            r#"{"schemaVersion":"0","pending":[
                {"sessionId":"s1","text":"do the thing","submit":true,"queuedAt":"2026-08-13T14:01:10Z"},
                "SHOULD_NOT_RUN_UNAUTH",
                {"text":"no session id at all"}
            ]}"#,
        )
        .unwrap();

        let out = pending_list(&pending_invocation(&["graph", "pending", "list"], &[]));
        assert_eq!(out.status, Status::Ok, "a malformed entry must not fail the whole list");
        let data = out.data.unwrap();
        let arr = data["pending"].as_array().unwrap();
        assert_eq!(arr.len(), 3, "every entry is listed, real or not");
        assert_eq!(arr[0]["sessionId"], "s1");
        assert_eq!(arr[0]["state"], "pending");
        assert_eq!(arr[1]["state"], "malformed", "a bare string entry is flagged, not fatal");
        assert_eq!(arr[2]["state"], "malformed", "an object with no sessionId is unresolvable too");
        assert!(out.message.contains("3 pending"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_human_line_renders_the_display_grammar_while_the_json_stays_raw() {
        // Petnames plan P3: `list`'s human line renders the target through
        // the canonical grammar (host/role/petname/tail) and the sender
        // through the terse petname+tail tag — but `data.pending[]`'s
        // `sessionId`/`from` are the machine contract and must stay the
        // entry's raw canonical ids, untouched.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pnd-grammar");

        let sender_id = "grammar-sender";
        do_session_start(sender_id, Some("claude"), Some("/w"), None, None, None, None, None, None);

        let target = "grammar-target";
        let socket = conduct_socket_path(target);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            target,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // Held pending: no --yes, no autogate.
        std::env::set_var("AOIDE_SESSION_ID", sender_id);
        let queued = session_send(&send_invocation(&["do", "the", "thing"], &[("id", target), ("submit", "true")]));
        assert_eq!(queued.data.as_ref().unwrap()["state"], "pending");

        // Pull the SAME petnames the mint actually chose (non-deterministic
        // roll) rather than hand-guessing a literal.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let target_petname = s
            .sessions
            .iter()
            .find(|r| r.session_id == target)
            .and_then(|r| r.petname.clone())
            .expect("every minted session carries a petname (P2)");
        let sender_petname = s
            .sessions
            .iter()
            .find(|r| r.session_id == sender_id)
            .and_then(|r| r.petname.clone())
            .expect("every minted session carries a petname (P2)");
        let host = aoide_storage::display::local_host_name();

        let out = pending_list(&pending_invocation(&["graph", "pending", "list"], &[]));
        assert_eq!(out.status, Status::Ok);
        let data = out.data.unwrap();
        let arr = data["pending"].as_array().unwrap();
        // The JSON contract: raw canonical ids, verbatim.
        assert_eq!(arr[0]["sessionId"], target, "JSON sessionId stays the raw canonical id");
        assert_eq!(arr[0]["from"], sender_id, "JSON from stays the raw canonical id");
        // The human line: full grammar for the target (a root — no parent),
        // terse petname+tail for the sender.
        let expected_target = format!(
            "{host}/root/{target_petname} (…{})",
            aoide_storage::display::short_tail(target)
        );
        let expected_from = format!(
            "(from {sender_petname} (…{}))",
            aoide_storage::display::short_tail(sender_id)
        );
        assert!(
            out.message.contains(&expected_target),
            "target renders via the display grammar: {}",
            out.message
        );
        assert!(
            out.message.contains(&expected_from),
            "sender renders via the terse petname+tail tag: {}",
            out.message
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn approve_routes_through_session_send_and_removes_the_entry() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pnd-ap");

        let id = "apt1";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        std::fs::write(
            pending_path(),
            format!(
                r#"{{"schemaVersion":"0","pending":[{{"sessionId":"{id}","text":"hello world","submit":true,"queuedAt":"2026-08-13T14:01:10Z"}}]}}"#
            ),
        )
        .unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["0"]));
        let got = acc.join().unwrap();

        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["injected"], true);
        // The exact text (with its embedded space) rode through unmangled, +
        // the newline `submit` demands — proves the SAME injection door ran.
        assert_eq!(String::from_utf8(got).unwrap(), "hello world\n");

        // The entry is gone from the queue.
        let arr = load_pending_array().unwrap();
        assert!(arr.is_empty(), "a resolved entry leaves the queue");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn approving_a_pending_entry_files_it_into_the_inbox_via_the_shared_delivery_seam() {
        // Messaging plan P-C6: the inbox append lives ONLY in `deliver_local`
        // (send.rs) — `pending_approve`'s re-drive goes through the SAME
        // `session_send` door, so a previously-held entry lands in the
        // inbox naturally the moment it is actually delivered, never at
        // queue time.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pnd-inbox");
        let state = root.join("state");
        std::env::set_var("AOIDE_STATE_DIR", &state);

        let id = "inbox-approve-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        std::fs::write(
            pending_path(),
            format!(
                r#"{{"schemaVersion":"0","pending":[{{"sessionId":"{id}","text":"hello inbox","submit":true,"queuedAt":"2026-08-13T14:01:10Z","from":"queuer-a"}}]}}"#
            ),
        )
        .unwrap();

        // Nothing in the inbox yet — the entry is only PENDING.
        assert!(aoide_storage::inbox::load().unwrap().entries.is_empty());

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let out = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["0"]));
        let _ = acc.join().unwrap();
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);

        let file = aoide_storage::inbox::load().unwrap();
        assert_eq!(file.entries.len(), 1, "approval's re-drive filed the message");
        assert_eq!(file.entries[0].from, "queuer-a", "the ORIGINAL queuer, not the approver");
        assert_eq!(file.entries[0].target, id);
        assert_eq!(file.entries[0].text, "hello inbox");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pending_round_trip_keeps_the_original_queuer_as_sender_through_approve() {
        // Queue under sender A, approve under sender B → the delivered bytes
        // must name A (the original queuer), never B (the approver) — the
        // whole point of carrying `from` through the queue.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pnd-rt");

        let id = "rt-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // Queue under sender A (no --yes, no autogate → held pending).
        std::env::set_var("AOIDE_SESSION_ID", "sender-a");
        let queued = session_send(&send_invocation(&["do", "the", "thing"], &[("id", id), ("submit", "true")]));
        assert_eq!(queued.data.as_ref().unwrap()["state"], "pending");

        // `from` is visible in `list` BEFORE approve.
        let listed = pending_list(&pending_invocation(&["graph", "pending", "list"], &[]));
        let arr = listed.data.unwrap()["pending"].as_array().unwrap().clone();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["from"], "sender-a", "the queuer is visible before approval");

        // Approve under a DIFFERENT sender B.
        std::env::set_var("AOIDE_SESSION_ID", "sender-b");
        listener.set_nonblocking(false).unwrap();
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let approved = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["0"]));
        let got = acc.join().unwrap();
        assert_eq!(approved.status, Status::Ok, "msg: {}", approved.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "from sender-a: do the thing\n",
            "the delivered bytes name the ORIGINAL queuer, not the approver"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn approving_an_anonymously_queued_entry_never_wears_the_approvers_name() {
        // Regression: an entry queued with NO sender (env cleared at queue
        // time) must NOT inherit the approver's own live AOIDE_SESSION_ID —
        // an orchestrating conducted session always has one, so an unguarded
        // re-drive would silently misattribute an anonymous send to whoever
        // happened to approve it.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pnd-anon");

        let id = "anon-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // Queue with NO sender at all (env cleared — `setup` already does
        // this, reasserted here for clarity).
        std::env::remove_var("AOIDE_SESSION_ID");
        let queued = session_send(&send_invocation(&["do", "the", "thing"], &[("id", id), ("submit", "true")]));
        assert_eq!(queued.data.as_ref().unwrap()["state"], "pending");

        let listed = pending_list(&pending_invocation(&["graph", "pending", "list"], &[]));
        let arr = listed.data.unwrap()["pending"].as_array().unwrap().clone();
        assert_eq!(arr[0]["from"], Value::Null, "queued with no attribution");

        // Approve under a REAL, non-empty sender.
        std::env::set_var("AOIDE_SESSION_ID", "approver-x");
        listener.set_nonblocking(false).unwrap();
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let approved = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["0"]));
        let got = acc.join().unwrap();
        assert_eq!(approved.status, Status::Ok, "msg: {}", approved.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "do the thing\n",
            "no prefix at all — the approver's own session id must never leak in"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_legacy_pending_entry_with_no_from_field_still_lists_and_approves_cleanly() {
        // An entry written before this field existed (serde default on read)
        // must not fail to list or approve.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        std::env::remove_var("AOIDE_SESSION_ID"); // no ambient attribution — legacy path only.
        let root = setup("pnd-legacy");

        let id = "legacy-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // Hand-written, NO `from` key at all — exactly the pre-P6 shape.
        std::fs::write(
            pending_path(),
            format!(
                r#"{{"schemaVersion":"0","pending":[{{"sessionId":"{id}","text":"legacy send","submit":false,"queuedAt":"2026-08-13T14:01:10Z"}}]}}"#
            ),
        )
        .unwrap();

        let listed = pending_list(&pending_invocation(&["graph", "pending", "list"], &[]));
        assert_eq!(listed.status, Status::Ok);
        let arr = listed.data.unwrap()["pending"].as_array().unwrap().clone();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["from"], Value::Null, "no attribution on a legacy entry");

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let approved = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["0"]));
        let got = acc.join().unwrap();
        assert_eq!(approved.status, Status::Ok, "msg: {}", approved.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "legacy send",
            "no provenance prefix for a legacy entry with no sender to attribute"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn deny_removes_without_touching_the_socket() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("pnd-dn");

        let id = "dnt1";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        std::fs::write(
            pending_path(),
            format!(
                r#"{{"schemaVersion":"0","pending":[{{"sessionId":"{id}","text":"SHOULD_NOT_RUN","submit":false,"queuedAt":"2026-08-13T14:01:10Z"}}]}}"#
            ),
        )
        .unwrap();

        let out = pending_deny(&pending_invocation(&["graph", "pending", "deny"], &["0"]));
        assert_eq!(out.status, Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["injected"], false);

        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "deny must never write to the socket"
        );
        let arr = load_pending_array().unwrap();
        assert!(arr.is_empty(), "a denied entry leaves the queue too");

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s.sessions.iter().find(|r| r.session_id == id).unwrap().title.is_none(),
            "deny never auto-renames — nothing was ever delivered"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn approve_and_deny_on_a_malformed_or_missing_id_fail_cleanly() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG", "AOIDE_CONDUCT_AUTOGATE", "AOIDE_SESSION_ID"]);
        let root = setup("pnd-mf");

        std::fs::write(
            pending_path(),
            r#"{"schemaVersion":"0","pending":["SHOULD_NOT_RUN_UNAUTH"]}"#,
        )
        .unwrap();

        let out = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["0"]));
        assert_eq!(out.status, Status::Error, "a malformed entry cannot be approved");
        assert_eq!(out.data.unwrap()["reason"], "pending-entry-unresolvable");
        // Left exactly where it was — a failed resolve must not destroy it.
        assert_eq!(load_pending_array().unwrap().len(), 1);

        let out = pending_deny(&pending_invocation(&["graph", "pending", "deny"], &["0"]));
        assert_eq!(out.status, Status::Error, "a malformed entry cannot be denied either");
        assert_eq!(load_pending_array().unwrap().len(), 1, "still there");

        // An out-of-range index is the same clean error, not a panic.
        let out = pending_approve(&pending_invocation(&["graph", "pending", "approve"], &["9"]));
        assert_eq!(out.status, Status::Error);

        // A non-numeric id is a usage error.
        let out = pending_deny(&pending_invocation(&["graph", "pending", "deny"], &["not-a-number"]));
        assert_eq!(out.status, Status::Usage);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_on_a_missing_queue_is_an_empty_ok_no_op() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let root = setup("pnd-ok");
        let out = pending_list(&pending_invocation(&["graph", "pending", "list"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.data.unwrap()["pending"].as_array().unwrap().len(), 0);
        assert!(out.message.contains("0 pending"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
