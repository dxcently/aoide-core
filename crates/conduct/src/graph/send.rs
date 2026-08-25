//! `graph send` — the gated injection door — and the hook door (`graph
//! session hook`) that maps Claude-Code hook payloads onto the session/
//! sub-agent verbs. The one place untrusted agent-bound text and untrusted
//! hook JSON both land, so every outcome is audited and a hook payload never
//! propagates as anything but data.
//!
//! `graph send` has two ways to name a target (messaging plan P-C3):
//! `--id <id>` (the original, unchanged) or `--to <target>` (resolved via
//! `aoide_storage::addr::resolve`, mutually exclusive with `--id` — see
//! [`session_send`]). A LOCAL `--to` match re-drives the exact `--id` path
//! (`deliver_local`); a REMOTE match (`peer/<query>`, resolved against that
//! peer's CACHED graph — never a live pull) delivers over A2A
//! `message/send` instead (`deliver_remote`) and runs no LOCAL gate at all,
//! since the receiving peer's own `message_send` Inject arm is where that
//! gate actually lives — see `deliver_remote`'s doc comment.

use super::common::{require_flag, stage_error};
use super::doc::restage_graph;
use super::model::{
    load_stage, resolved_parent, sessions_path, write_stage, SessionRecord, SessionsFile,
    STAGE_GRAPH_VERSION,
};
use super::session_store::{
    do_session_end, do_session_phase, do_session_phase_if, do_session_start, do_subagent_end,
    do_subagent_rekey, do_subagent_spawn, ensure_session_ceiling, now_iso_utc,
    refresh_subagent_says, refresh_transcript_fields, set_owner_activity, stamp_hook_ancestry,
};
use super::window::{discover_window, ensure_session_window, pid_ancestry, windowless_by_lineage_from_parent};
use aoide_protocol::agents::{agent_profile, known_agents, AgentProfile, HookClass, CLAUDE_PROFILE};
use aoide_protocol::Invocation;
use aoide_protocol::output::Outcome;
use aoide_storage::addr::{self, LocalCandidate, Resolution};
use aoide_storage::fs::{stage_dir, with_stage_lock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::os::unix::net::UnixStream;
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

// ── `graph send`: the gated injection door ──────────────────────────────────

/// A pending (unapproved) injection, staged for the conductor to surface for a
/// one-key approve/deny. Written atomically to `song/stage/pending.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingSend {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub submit: bool,
    #[serde(rename = "queuedAt", default)]
    pub queued_at: String,
    /// The sender attribution [`resolve_sender`] resolved at queue time (see
    /// its doc — attribution, not security). `skip_serializing_if` keeps an
    /// unattributed entry's JSON byte-identical to before this field existed;
    /// `default` on read means a LEGACY entry written before this field
    /// existed deserializes with `from: None`, not a parse failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// `pending.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub pending: Vec<PendingSend>,
}

/// `pub`, not `pub(in crate::graph)`: `graph/pending.rs` (the read/approve/
/// deny surface over this queue) needs the same path `record_pending`
/// writes, and as of P-D3 (`docs/architecture/AOIDED.md`'s "L1" section)
/// so does `aoide-server`'s #69 hand-edit watcher, which folds
/// `pending.json` into the same watched-file roster as `sessions.json`/
/// `hooks.json`/`projects.json`/`graph.json`/`herald.json` — reached via
/// `aoide_conduct::graph::pending_path()` rather than a second `stage_dir()
/// .join("pending.json")` literal elsewhere (this crate's own "no
/// cross-crate copying" convention, widen-don't-fork).
pub fn pending_path() -> PathBuf {
    stage_dir().join("pending.json")
}

/// The gate decision for a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendGate {
    /// Explicit `--yes` on this send.
    Yes,
    /// The global orchestration-mode switch authorised it (no human in the loop).
    Autogate,
    /// The sender is the target's parent — an orchestrator freely commanding a
    /// child it spawned (the "freely orchestrated" default). No human in the loop.
    AutogateParent,
    /// The sender and the target are SIBLINGS — same parent, and that parent is
    /// itself still live — talking to each other without going through it. See
    /// [`sibling_autogate_enabled`] for the User's decision and the opt-out.
    AutogateSibling,
    /// No authorisation — held pending for approval.
    Pending,
}
impl SendGate {
    fn delivers(self) -> bool {
        !matches!(self, SendGate::Pending)
    }
    fn label(self) -> &'static str {
        match self {
            SendGate::Yes => "yes",
            SendGate::Autogate => "autogate",
            SendGate::AutogateParent => "autogate-parent",
            SendGate::AutogateSibling => "autogate-sibling",
            SendGate::Pending => "pending",
        }
    }
}

/// Global autogate switch: `AOIDE_CONDUCT_AUTOGATE` in {1,true,yes,all} declares
/// an orchestration-mode where every send delivers without a human (still
/// audited) — the box-wide "freely orchestrated" toggle.
fn autogate_env() -> bool {
    matches!(
        std::env::var("AOIDE_CONDUCT_AUTOGATE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("all")
    )
}

/// The parent-autogate rule (pure, unit-tested): the sender may freely command a
/// child it spawned. True when the target session's `parentSessionId` equals the
/// SENDER's own `AOIDE_SESSION_ID` — both present and non-empty. A cross-tree or
/// unrelated send (no id, empty id, or a mismatch) is NOT autogated and stays
/// pending. This is what lets an orchestrator steer the children it conducted
/// without a prompt while every other send remains gated.
fn sender_is_parent(sender_session: Option<&str>, target_parent: Option<&str>) -> bool {
    match (sender_session, target_parent) {
        (Some(s), Some(p)) => !s.is_empty() && s == p,
        _ => false,
    }
}

/// The sibling-autogate rule (pure, unit-tested): the sender and the target
/// may freely talk to each other when they are SIBLINGS — both parented under
/// the SAME session, and that shared parent is itself still live (not
/// `done`). A dead/absent parent, a cross-tree pair, or either side unparented
/// stays gated. `parent_live` is resolved by the caller against the already-
/// loaded sessions file (no I/O here).
///
/// Deliberately blind to whether sender == target: a self-send trivially
/// satisfies `a == b` here too (same record, same parent field read twice),
/// so the caller MUST refuse that case before this predicate ever runs — see
/// the `is_self_send` guard in [`session_send`]. Folding that guard in here
/// would hide it behind a parameter that looks like just another parent
/// string.
fn siblings_share_live_parent(
    sender_parent: Option<&str>,
    target_parent: Option<&str>,
    parent_live: bool,
) -> bool {
    match (sender_parent, target_parent) {
        (Some(a), Some(b)) => !a.is_empty() && a == b && parent_live,
        _ => false,
    }
}

/// The sibling-autogate switch. **The User's decision, 2026-08-20: sibling
/// delivery is ON BY DEFAULT.** Opt out per-box with
/// `AOIDE_CONDUCT_SIBLING_AUTOGATE` set to one of `{0,false,no}`; absent or
/// any other value leaves it enabled. One-line flip to default-off: change the
/// wildcard arm below from `true` to `false`.
fn sibling_autogate_enabled() -> bool {
    match std::env::var("AOIDE_CONDUCT_SIBLING_AUTOGATE").ok().as_deref() {
        Some("0") | Some("false") | Some("no") => false,
        _ => true, // one-line flip to default-off: change this arm to `false`.
    }
}

/// Resolve the gate: `--yes`, then the global autogate switch, then the
/// parent-of-target rule, then the sibling rule, else pending.
fn send_gate(yes: bool, sender_is_parent: bool, is_sibling: bool) -> SendGate {
    if yes {
        SendGate::Yes
    } else if autogate_env() {
        SendGate::Autogate
    } else if sender_is_parent {
        SendGate::AutogateParent
    } else if is_sibling && sibling_autogate_enabled() {
        SendGate::AutogateSibling
    } else {
        SendGate::Pending
    }
}

/// Does this injected text NAME the node? A `graph send` steer is a task, so it
/// renames; a bare KEYSTROKE answer is not. `graph permit` types a single digit
/// to answer a permission prompt (and a human answering a numbered prompt by
/// hand types the same thing), and letting that overwrite the node's title with
/// `1` would erase the one label the dock and the graph tree identify the
/// session by. A title is words: text carrying no letter at all is an answer.
fn names_the_node(text: &str) -> bool {
    text.chars().any(char::is_alphabetic)
}

/// Sanitize a resolved sender string for use in the single-line provenance
/// prefix: every `\n`/`\r` collapses to a single space. Both `--from` (raw
/// argv) and `AOIDE_SESSION_ID` (raw env) may legally contain a newline —
/// neither the shell nor the OS forbids it — but the prefix built from this
/// value is a promise to the delivery path: exactly one line, ever. An
/// unsanitized sender would smuggle an extra `\n` into the payload ahead of
/// the real text, submitting a bogus half-line into the target's TUI before
/// the actual message arrives — exactly the corruption [`provenance_prefix`]
/// exists to prevent.
fn sanitize_sender(raw: &str) -> String {
    raw.replace(['\n', '\r'], " ")
}

/// The sender attribution for THIS invocation — a TRI-STATE read of `--from`,
/// falling back to `AOIDE_SESSION_ID` only when `--from` is ABSENT:
///
/// - `--from` **absent** → fall back to the `AOIDE_SESSION_ID` env (the
///   conducting session's own id, exported by `conduct`/`wrap`/`spawn` into
///   every child's env); an empty/unset env is `None` (no attribution).
/// - `--from` **present and non-empty** → that sender, sanitized (see
///   [`sanitize_sender`]) — the env is never consulted.
/// - `--from` **present but empty** (`--from ""`) → explicit "no
///   attribution": `None`, and the env fallback is deliberately SKIPPED. This
///   is the case [`super::pending::pending_approve`] relies on: it always
///   sets `--from` on its re-drive (the original entry's sender when `Some`,
///   `""` when the entry carried none), so an anonymously-queued send stays
///   anonymous through approval instead of silently inheriting the
///   approver's own live `AOIDE_SESSION_ID`.
///
/// **ATTRIBUTION, NOT SECURITY.** Neither source is proof of identity: `--from`
/// is a plain CLI flag any same-user process can set to whatever string it
/// likes, and `AOIDE_SESSION_ID` is an ordinary env var any same-user process
/// can export before calling `graph send` — both are trivially spoofable by
/// anyone who can already run `aoide` as this user. This exists so a
/// receiving agent and the audit log can see who CLAIMS to have sent a
/// message, not to gate delivery on that claim (the gate in [`send_gate`] is
/// unaffected by this). The wider door is the control socket itself: whoever
/// can write to it can already impersonate the target's own keystrokes with
/// no attribution at all — this label is strictly additive information, never
/// a trust boundary.
fn resolve_sender(inv: &Invocation) -> Option<String> {
    match inv.flags.get("from") {
        Some(f) if f.is_empty() => None, // explicit anonymous — env fallback skipped.
        Some(f) => Some(sanitize_sender(f)),
        None => std::env::var("AOIDE_SESSION_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| sanitize_sender(&s)),
    }
}

/// A single-line sender-provenance prefix (`from <sender>: `) for a delivered
/// payload, or `None` when there is nothing to attribute or `text` isn't a
/// real message. `None` when `sender` is `None`, or when `!names_the_node
/// (text)` — [`names_the_node`]'s "does this carry a letter" check is exactly
/// the right test here too: a bare keystroke/verdict payload (`graph
/// permit`'s digit, `3\n`) is not an authored message, it's an answer typed
/// into a prompt, and prefixing it would corrupt the exact bytes the target's
/// TUI is waiting to read as a keystroke.
///
/// The returned string carries NO embedded newline — the caller prepends it
/// directly to the front of the payload, which (since the prefix itself is
/// newline-free) lands it on the payload's first line only; an injected
/// newline here would submit a half-line into a TUI composer ahead of the
/// real text. This relies on `sender` already being sanitized (every caller
/// goes through [`resolve_sender`], which does exactly that) — this function
/// does not re-sanitize.
fn provenance_prefix(sender: Option<&str>, text: &str) -> Option<String> {
    let sender = sender?;
    if !names_the_node(text) {
        return None;
    }
    Some(format!("from {sender}: "))
}

/// Map a resolved+sanitized sender id to its TERSE provenance DISPLAY form —
/// `<petname> (…<tail4>)` (petnames plan P3's grammar, minus host/role: the
/// composer prefix stays deliberately narrower than the full `graph view`/
/// pending-list grammar) — when `sender` resolves against `sessions` (the
/// caller's ALREADY-LOADED roster, no second read) to a record carrying a
/// minted petname. Falls back to `sender` unchanged for an unknown sender or
/// a legacy/petname-less one — `sanitize_sender` already governs the string
/// that reaches here, and this never re-sanitizes.
///
/// DISPLAY ONLY: [`record_pending`]'s `from`, the audit line
/// ([`audit_send`]), and `approve --from` (`pending.rs`) all keep the raw
/// sender id — this resolves fresh, off whatever the CURRENT roster says, at
/// the moment of DELIVERY (not memoized into the queue at hold time, so a
/// petname minted/changed between queueing and approval still shows right).
fn display_sender<'a>(sender: &'a str, sessions: &[SessionRecord]) -> std::borrow::Cow<'a, str> {
    match sessions
        .iter()
        .find(|s| s.session_id == sender)
        .and_then(|s| s.petname.as_deref())
    {
        Some(petname) => std::borrow::Cow::Owned(format!(
            "{petname} (…{})",
            aoide_storage::display::short_tail(sender)
        )),
        None => std::borrow::Cow::Borrowed(sender),
    }
}

/// A one-line, length-bounded form of the injected text — the auto-rename title.
fn one_line_title(text: &str) -> String {
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

fn record_pending(id: &str, text: &str, submit: bool, from: Option<&str>) -> Result<(), String> {
    with_stage_lock(|| {
        let mut file: PendingFile = load_stage(&pending_path())?;
        file.schema_version = STAGE_GRAPH_VERSION.to_string();
        file.pending.push(PendingSend {
            session_id: id.to_string(),
            text: text.to_string(),
            submit,
            queued_at: now_iso_utc(),
            from: from.map(str::to_string),
        });
        write_stage(&pending_path(), &file)
    })
}

/// Auto-rename: write `title` onto the session record and re-stage the graph so
/// the node relabels. A missing id is a silent no-op (the send still succeeded).
fn set_session_title(id: &str, title: &str) -> Result<(), String> {
    with_stage_lock(|| {
        let mut file: SessionsFile = load_stage(&sessions_path())?;
        let mut found = false;
        for s in file.sessions.iter_mut() {
            if s.session_id == id {
                s.title = Some(title.to_string());
                found = true;
            }
        }
        if !found {
            return Ok(());
        }
        if file.schema_version.is_empty() {
            file.schema_version = STAGE_GRAPH_VERSION.to_string();
        }
        write_stage(&sessions_path(), &file)?;
        restage_graph().map(|_| ())
    })
}

/// Name a session from its FIRST user prompt — set the `title` slot only when it
/// is still empty, so the opening prompt names the session and later prompts do
/// not rename it (a deliberate `graph send` steer still overwrites via
/// [`set_session_title`] — that IS a rename). Under the stage lock (this runs on
/// every UserPromptSubmit hook, concurrent with conduct ticks). No-op for an
/// unregistered id. Re-stages only when it wrote.
fn set_session_name_if_unset(id: &str, name: &str) {
    if name.is_empty() {
        return;
    }
    with_stage_lock(|| {
        let mut file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut changed = false;
        for s in file.sessions.iter_mut() {
            if s.session_id == id && s.title.as_deref().unwrap_or("").is_empty() {
                s.title = Some(name.to_string());
                changed = true;
            }
        }
        if changed {
            if file.schema_version.is_empty() {
                file.schema_version = STAGE_GRAPH_VERSION.to_string();
            }
            if write_stage(&sessions_path(), &file).is_ok() {
                let _ = restage_graph();
            }
        }
    });
}

/// One audit line per send outcome, through aoided's audit path. The injected
/// text rides as `untrusted_data` (never the message) — forwarded agent-bound
/// text is data, never re-interpreted as a command (the house rule). The
/// resolved [`resolve_sender`] attribution (when present) is folded into the
/// audit MESSAGE — never into `untrusted_data`, which stays exactly the
/// injected text — so the audit trail names who claimed to send it.
fn audit_send(inv: &Invocation, status: &str, message: &str, text: &str) {
    let log = inv
        .flags
        .get("audit-log")
        .map(PathBuf::from)
        .unwrap_or_else(aoide_protocol::default_audit_log);
    let message = match resolve_sender(inv) {
        Some(sender) => format!("{message} (from {sender})"),
        None => message.to_string(),
    };
    let _ = aoide_protocol::append_audit(
        &log,
        &aoide_protocol::AuditRecord {
            ts: super::conduct::unix_ts(),
            door: inv.door,
            class: aoide_protocol::EventClass::Audit,
            command: "graph.send".to_string(),
            status: status.to_string(),
            message,
            untrusted_data: Some(text.to_string()),
        },
    );
}

/// `aoide graph send (--id <id> | --to <target>) [--submit] [--yes] -- <text
/// …>` — the one injection door, with two ways to name the target (messaging
/// plan P-C3 added `--to`; mutually exclusive with `--id`, checked before
/// either resolves).
///
/// **`--id <id>`** resolves the target's control socket from sessions.json
/// directly; errors cleanly (exit 1) if the id is unknown or not conductable.
/// Gate: WITHOUT `--yes` and no autogate match, the send is recorded PENDING
/// (atomic stage write) and NOT delivered; WITH `--yes` (or an autogate
/// match — global env, sender-is-target's-parent, or
/// sender-and-target-are-siblings-under-a-live-parent, see
/// [`sibling_autogate_enabled`]) it connects to the socket, writes `<text>`
/// (+ the TARGET's own submit keystroke on `--submit` — `\n` for most
/// harnesses, `\r` for kimi, resolved from the target session's agent profile
/// at delivery time via [`super::permit::profile_for_agent`], never a fixed
/// byte), auto-renames the node to a one-line form of the text (unless the
/// text is a bare keystroke answer — see [`names_the_node`]), and returns
/// delivered. A delivered payload that names the node also carries a `from
/// <sender>: ` provenance prefix on its first line when a sender resolves
/// (see [`resolve_sender`] / [`provenance_prefix`] — attribution, not
/// authentication); the title, the keystroke check, and the audit
/// `untrusted_data` all still see the unprefixed text. Every outcome writes
/// an audit line, the sender folded into its message.
///
/// **`--to <target>`** resolves `target` via [`aoide_storage::addr::resolve`]
/// against this box's current local sessions + registered peers (see
/// [`session_send_to`]):
/// - a LOCAL match re-drives the exact `--id` path above, unchanged (same
///   gate, pending queue, provenance, audit) — `--to brave-otter` behaves
///   identically to `--id <that session's id>`.
/// - a REMOTE match (`peer/<query>`) delivers over A2A `message/send`
///   instead of a local socket write — see [`session_send_to`]'s doc for the
///   full remote gating discussion (short version: **remote gating is the
///   RECEIVING peer's job**, done inside its own `message_send` Inject arm;
///   this door's `--yes`/pending/autogate machinery above is a LOCAL-socket
///   concept and does not apply to a remote delivery, which always attempts
///   the network send — exactly like the existing `a2a agent send`/`peer
///   pull` verbs already do unconditionally).
///
/// With NEITHER flag, this is a usage error (same as before `--to` existed —
/// `require_flag` below is untouched).
pub fn session_send(inv: &Invocation) -> Outcome {
    let cmd = "graph.send";
    let to = inv
        .flags
        .get("to")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let id_present = inv.flags.get("id").map(|s| !s.trim().is_empty()).unwrap_or(false);
    if to.is_some() && id_present {
        return Outcome::usage(
            cmd,
            "usage: aoide graph send (--id <id> | --to <target>) [--submit] [--yes] -- <text …> \
             — --id and --to are mutually exclusive",
        );
    }
    if let Some(target) = to {
        return session_send_to(inv, &target);
    }
    let id = match require_flag(inv, "id") {
        Ok(v) => v,
        Err(o) => return o,
    };
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph send --id <id> [--submit] [--yes] -- <text …>",
        );
    }
    deliver_local(inv, &id)
}

/// The exact body `--id` has always run, factored out so [`session_send_to`]'s
/// LOCAL resolution branch re-drives it unmodified rather than reimplementing
/// any piece of the gate/pending/provenance/audit path — the phase's SACRED
/// invariant. `id` is re-owned into a `String` immediately so every line
/// below is byte-identical to the pre-P-C3 function body (no `&id`/`id`
/// reference-vs-owned churn to review).
fn deliver_local(inv: &Invocation, id: &str) -> Outcome {
    let cmd = "graph.send";
    // Accept the exact `session:<id>` form `graph view --json` emits for a
    // node id, so a copy-pasted id round-trips through `--id` — mirrors
    // `graph focus`'s identical `session:` stripping (window.rs). Only this
    // known prefix is special-cased; anything else passes through untouched
    // and still falls into the `unknown session` error below, same as
    // before this fix. `--to`'s LOCAL branch already hands in a bare,
    // resolver-produced id (`aoide_storage::addr::resolve`, itself now
    // prefix-tolerant too), so this is a no-op on that path.
    let id = id.strip_prefix("session:").unwrap_or(id).to_string();
    let text = inv.args.join(" ");
    let submit = inv.flag_present("submit");
    let yes = inv.flag_present("yes");

    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(rec) = file.sessions.iter().find(|s| s.session_id == id) else {
        let out = Outcome::error(cmd, format!("unknown session `{id}`"))
            .with_data(json!({ "reason": "session-not-found", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    };
    let is_conductable = rec.conductable == Some(true);
    let socket = rec.socket.clone().filter(|s| !s.is_empty());
    let target_parent = rec.parent_session_id.clone();
    if !is_conductable || socket.is_none() {
        let out = Outcome::error(
            cmd,
            format!("session `{id}` is not conductable (no control socket)"),
        )
        .with_data(json!({ "reason": "not-conductable", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    }
    let socket = socket.unwrap();

    // The gate. The sender's own session id (from the env `aoide conduct` exports)
    // vs the target's parent decides the parent-autogate rule. The sibling rule
    // resolves the SENDER's own record from this SAME already-loaded file (no
    // second read) to find ITS parent, and checks that parent is still live.
    let sender = std::env::var("AOIDE_SESSION_ID").ok();
    let is_parent = sender_is_parent(sender.as_deref(), target_parent.as_deref());
    let sender_parent: Option<String> = sender
        .as_deref()
        .and_then(|sid| file.sessions.iter().find(|s| s.session_id == sid))
        .and_then(|r| r.parent_session_id.clone());
    let parent_live = target_parent
        .as_deref()
        .filter(|p| !p.is_empty())
        .and_then(|p| file.sessions.iter().find(|s| s.session_id == p))
        .map(|r| aoide_protocol::canonical_state(&r.state) != "done")
        .unwrap_or(false);
    // A self-send (sender id == target id) vacuously satisfies the predicate —
    // a session is trivially its OWN sibling (same record, same parent field on
    // both sides of the comparison) — but it is not a sibling relationship at
    // all, it is a session talking to itself. `AOIDE_SESSION_ID` is exported
    // into every conducted child's own env, so an unguarded predicate here
    // would let a prompt-injected `graph send --id "$AOIDE_SESSION_ID" --submit
    // -- <text>` self-deliver text straight back into its own input stream,
    // bypassing approval entirely — a gate WIDENING, not a convenience. Excluded
    // before the predicate ever runs.
    let is_self_send = sender.as_deref() == Some(id.as_str());
    let is_sibling = !is_self_send
        && siblings_share_live_parent(sender_parent.as_deref(), target_parent.as_deref(), parent_live);
    let gate = send_gate(yes, is_parent, is_sibling);
    // The provenance attribution — `--from` or `AOIDE_SESSION_ID` (see
    // [`resolve_sender`]) — is resolved once here, from the ORIGINAL
    // invocation, and reused for both the pending record and (below) the
    // delivered payload's prefix, so a queued-then-approved send still names
    // whoever queued it, not whoever approved it.
    let attributed_sender = resolve_sender(inv);
    if !gate.delivers() {
        if let Err(e) = record_pending(&id, &text, submit, attributed_sender.as_deref()) {
            return stage_error(cmd, e);
        }
        let out = Outcome::ok(
            cmd,
            format!("send to `{id}` held pending approval (no --yes / autogate)"),
        )
        .changed(vec![format!("pending send queued for {id}")])
        .with_data(json!({
            "id": id,
            "state": "pending",
            "delivered": false,
            "submit": submit,
            "gate": gate.label(),
        }));
        audit_send(inv, "pending", &out.message, &text);
        return out;
    }

    // Deliver: connect + write the payload (+ the target's own submit
    // keystroke on --submit, decided from the ORIGINAL text before any
    // prefix). Resolved from `rec.agent` through the SAME profile lookup
    // `graph permit` uses (`profile_for_agent`, promoted `pub(in
    // crate::graph)` in permit.rs) — an unregistered/empty agent falls back
    // to claude's `\n`, exactly as that lookup already does; no second
    // resolver. The provenance prefix (see [`provenance_prefix`]) is then
    // prepended to the payload as a whole — since the prefix itself is
    // newline-free, that lands it on the payload's first line only, never
    // disturbing a later line or the trailing submit keystroke. The title
    // (`one_line_title`), the `names_the_node` check, and the audit
    // `untrusted_data` below all keep reading the ORIGINAL `text`, never this
    // prefixed payload.
    let mut payload = text.clone();
    if submit {
        payload.push_str(super::permit::profile_for_agent(&rec.agent).submit_key);
    }
    // Display-only: the prefix names the sender by petname+tail when the
    // ALREADY-LOADED roster (`file.sessions`) resolves one, never the raw id
    // — `attributed_sender` itself (the raw id) is what `record_pending` and
    // `audit_send` still see, unaffected by this mapping.
    let prefix_sender = attributed_sender
        .as_deref()
        .map(|s| display_sender(s, &file.sessions));
    if let Some(prefix) = provenance_prefix(prefix_sender.as_deref(), &text) {
        payload = format!("{prefix}{payload}");
    }
    match UnixStream::connect(&socket) {
        Ok(mut stream) => {
            use std::io::Write as _;
            if let Err(e) = stream
                .write_all(payload.as_bytes())
                .and_then(|_| stream.flush())
            {
                let out = Outcome::error(cmd, format!("failed to inject into `{id}`: {e}"))
                    .with_data(json!({ "reason": "socket-write-failed", "id": id, "socket": socket }));
                audit_send(inv, "error", &out.message, &text);
                return out;
            }
        }
        Err(e) => {
            let out = Outcome::error(cmd, format!("control socket for `{id}` unreachable: {e}"))
                .with_data(json!({ "reason": "socket-unreachable", "id": id, "socket": socket }));
            audit_send(inv, "error", &out.message, &text);
            return out;
        }
    }

    // File this delivered message into the durable per-host inbox
    // (messaging plan P-C6, `state/inbox.json`) — this is the ONE seam that
    // covers every route a message takes to land here: a direct `--id`
    // send, a `--to <local target>` (re-drives this exact function), a
    // `pending approve` re-drive, AND the A2A server's `do_inject`
    // (`crates/server/src/a2a.rs`) — `do_inject` builds a `graph send --id`
    // invocation and calls `session_send` too, which for a same-box
    // `contextId` can only ever reach THIS branch (it never sets `--to`).
    // See `aoide_storage::inbox`'s module doc for the full reasoning and
    // why `do_inject` does not file a second entry of its own.
    //
    // `from` is `attributed_sender` — the SAME resolved sender the audit
    // line and the provenance prefix above already computed, empty string
    // for an anonymous/unresolved sender (never `None` — the inbox's `from`
    // is a plain `String`, not optional). `text` is the ORIGINAL message,
    // not `payload` (which carries the provenance prefix and/or submit
    // keystroke actually written to the socket).
    //
    // Best-effort by design: an inbox write failing must never turn an
    // ALREADY-DELIVERED message into a reported failure — any error is
    // folded into `changed` below, the returned status stays `Ok`.
    let inbox_note = match aoide_storage::inbox::receive(
        attributed_sender.as_deref().unwrap_or(""),
        &id,
        &text,
        None,
    ) {
        Ok(()) => None,
        Err(e) => Some(format!("(inbox filing failed: {e})")),
    };

    // Auto-rename the node to a one-line form of the delivered task — unless
    // the text is a keystroke answer rather than a task (see [`names_the_node`]).
    let renamed = names_the_node(&text);
    let title = if renamed {
        one_line_title(&text)
    } else {
        String::new()
    };
    let mut changed = vec![format!("injected {} byte(s) into {id}", payload.len())];
    if let Some(note) = inbox_note {
        changed.push(note);
    }
    if renamed {
        match set_session_title(&id, &title) {
            Ok(()) => changed.push(format!("session {id}: title → {title}")),
            Err(e) => changed.push(format!("(title update failed: {e})")), // delivery already happened.
        }
    }

    let out = Outcome::ok(cmd, format!("delivered to `{id}` ({})", gate.label()))
        .changed(changed)
        .with_data(json!({
            "id": id,
            "state": "delivered",
            "delivered": true,
            "submit": submit,
            "title": title,
            "gate": gate.label(),
        }));
    audit_send(inv, "delivered", &out.message, &text);
    out
}

// ── `--to <target>`: local-or-remote resolution (messaging plan P-C3) ───────

/// `--to <target>` resolution: turns `target` into either a LOCAL session id
/// (re-drives [`deliver_local`] unchanged — same gate/pending/provenance/
/// audit) or a REMOTE peer+session (delivered over A2A `message/send`, see
/// [`deliver_remote`]). Ambiguity is always a hard error at every tier —
/// send is a delivering action, never narrows or guesses (mirrors
/// `aoide_storage::addr`'s own "ambiguity is an error, never first-match"
/// rule in its home context, restated here for send specifically).
fn session_send_to(inv: &Invocation, target: &str) -> Outcome {
    let cmd = "graph.send";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide graph send --to <target> [--submit] [--yes] -- <text …>",
        );
    }
    let text = inv.args.join(" ");

    let file: SessionsFile = match load_stage(&sessions_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let host = aoide_storage::display::local_host_name();
    let ids: HashSet<&str> = file.sessions.iter().map(|s| s.session_id.as_str()).collect();
    let candidates: Vec<LocalCandidate<'_>> = file
        .sessions
        .iter()
        .map(|s| {
            let role = if resolved_parent(s, &ids).is_some() { "child" } else { "root" };
            LocalCandidate { session_id: &s.session_id, petname: s.petname.as_deref(), role }
        })
        .collect();
    let peers = aoide_storage::peer_store::load_peers();
    let peer_names: Vec<&str> = peers.iter().map(|p| p.name.as_str()).collect();

    match addr::resolve(target, &host, &candidates, &peer_names) {
        Resolution::Local(id) => deliver_local(inv, &id),
        Resolution::Remote { peer, query } => match peers.iter().find(|p| p.name == peer) {
            Some(p) => deliver_remote(inv, p, &query),
            // `addr::resolve` only ever names a peer it was HANDED in
            // `peer_names` above (built from this SAME `peers` slice), so a
            // miss here is unreachable in practice — a defensive clean error
            // rather than an unwrap/panic.
            None => {
                let out = Outcome::error(cmd, format!("peer `{peer}` vanished mid-resolution"))
                    .with_data(json!({ "reason": "peer-not-found", "peer": peer }));
                audit_send(inv, "error", &out.message, &text);
                out
            }
        },
        Resolution::Ambiguous(ids) => {
            let out = Outcome::error(
                cmd,
                format!(
                    "`{target}` is ambiguous — {} local session(s) match: {}",
                    ids.len(),
                    ids.join(", ")
                ),
            )
            .with_data(json!({ "reason": "ambiguous", "target": target, "candidates": ids }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
        Resolution::NotFound => {
            // addr.rs's documented "bare known-peer-name" decision: a
            // slash-free token that names a registered peer but matches no
            // local session is `NotFound`, not `Remote` (there is no
            // `<rest>` to defer without a slash) — hint the `peer/<rest>`
            // form the user probably meant instead of leaving them guessing.
            let hint = if !target.contains('/') && peer_names.contains(&target) {
                format!(
                    " (`{target}` names a known peer, not a local session — did you mean `{target}/<session>`?)"
                )
            } else {
                String::new()
            };
            let out = Outcome::error(cmd, format!("no session matches `{target}`{hint}"))
                .with_data(json!({ "reason": "not-found", "target": target }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
    }
}

/// Extract every `kind:"session"` node from a peer's CACHED graph document
/// as (sessionId, petname, role) triples — role derived from the SAME
/// document's own `spawned` edges. A `send`-local twin of
/// `who.rs::sessions_from_graph`'s extraction: not reused directly, since
/// that function returns `who`'s own display-only `SessionView`, a shape
/// this door has no use for — this needs only what [`LocalCandidate`] and an
/// error-message label need.
fn peer_cached_sessions(graph: &Value) -> Vec<(String, Option<String>, &'static str)> {
    let empty: Vec<Value> = Vec::new();
    let nodes = graph.get("nodes").and_then(Value::as_array).unwrap_or(&empty);
    let edges = graph.get("edges").and_then(Value::as_array).unwrap_or(&empty);
    nodes
        .iter()
        .filter(|n| n["kind"] == "session")
        .map(|n| {
            let full_id = n["id"].as_str().unwrap_or("");
            let session_id = full_id.strip_prefix("session:").unwrap_or(full_id).to_string();
            let role = if edges.iter().any(|e| e["kind"] == "spawned" && e["to"] == full_id) {
                "child"
            } else {
                "root"
            };
            let petname = n["petname"].as_str().map(String::from);
            (session_id, petname, role)
        })
        .collect()
}

/// Resolve `query` (the remainder after `peer/` — see `aoide_storage::addr`'s
/// tier-5 doc) against `peer`'s cached session set. Tries `query` AS TYPED
/// first — this covers the common, DOCUMENTED case (`addr.rs`'s own module
/// doc example: `Remote { peer: "yomi-strix", query: "brave-otter" }`, a
/// bare petname) via tiers 1–3 (exact remote id, id tail4, bare petname) —
/// and only on a miss retries the RECONSTRUCTED `<peer>/<query>` form, so a
/// `role/petname` remainder (what tier 5 stripped the host segment OFF of —
/// `addr.rs`'s "multi-segment rest… passes it through verbatim" test case)
/// still resolves via tier 4 against the peer's own name standing in as
/// `host`. `peers: &[]` on BOTH attempts: a remote-of-remote is not a shape
/// this phase resolves, so tier 5 can never fire here — see
/// [`deliver_remote`]'s `Resolution::Remote` arm.
fn resolve_remote_query(peer: &str, query: &str, candidates: &[LocalCandidate<'_>]) -> Resolution {
    match addr::resolve(query, peer, candidates, &[]) {
        Resolution::NotFound => addr::resolve(&format!("{peer}/{query}"), peer, candidates, &[]),
        other => other,
    }
}

/// A peer session's display label for an error message — mirrors
/// `who.rs::sessions_from_graph`'s label construction
/// (`display::session_label` with the peer's own name standing in as
/// `host`), so an ambiguous/not-found `--to` error names candidates the same
/// way `aoide who` would already be showing them.
fn peer_session_label(peer: &str, session_id: &str, petname: Option<&str>, role: &str) -> String {
    let rec = aoide_storage::records::SessionRecord {
        session_id: session_id.to_string(),
        petname: petname.map(String::from),
        ..Default::default()
    };
    aoide_storage::display::session_label(&rec, peer, role)
}

/// Which of `--submit`/`--yes` the caller actually passed on THIS
/// invocation — both are accepted-but-unused for a `--to` remote send (see
/// [`deliver_remote`]'s doc), so this is purely for surfacing that fact back
/// to the caller, never for a gating decision. Order matches flag
/// declaration order in `commands/graph.rs`.
fn ignored_remote_flags(inv: &Invocation) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if inv.flag_present("submit") {
        flags.push("submit");
    }
    if inv.flag_present("yes") {
        flags.push("yes");
    }
    flags
}

/// Deliver `text` to ONE remote session on `peer`, resolved from `query`
/// against `peer`'s CACHED graph (`state/peer-cache/<peer>.json`) — a live
/// pull is deliberately NOT performed here (the plan's own call: the cache
/// is the addressing source for `send`; `who` is the probe verb). No cache
/// at all (peer never pulled) is a clean error pointing at `peer pull`,
/// never a silent auto-pull — a send should be predictable, not trigger a
/// network fetch the user didn't ask for.
///
/// **GATING**: unlike [`deliver_local`], this function runs NO gate at all —
/// `--yes`/pending/autogate (`send_gate`, `record_pending`) are a
/// LOCAL-SOCKET concept: they decide whether THIS process writes to a
/// socket it owns. A remote send is always ATTEMPTED over the network,
/// exactly like `a2a agent send`/`peer pull` already do unconditionally.
/// The RECEIVING peer's own `message_send` Inject arm
/// (`aoide-server::a2a::message_send` → `do_inject`) is where the real gate
/// lives: it decides deliver-now vs. hold-pending off ITS OWN peer-trust
/// config (`should_deliver_now`/autogate — CONTRACTS.md §6), unconditionally
/// forcing `submit=true` on its side regardless of what this caller's
/// `--submit` flag says. So `--submit`/`--yes` are ACCEPTED but UNUSED
/// here — there is nothing on this side left for them to gate — and NOT
/// silently: [`ignored_remote_flags`] collects whichever of them was
/// actually passed and both delivery-attempt arms below fold a note into
/// the returned `Outcome` (`message` + `data.ignoredFlags`) so a caller who
/// habitually passes them sees they did nothing, rather than guessing.
///
/// No title auto-rename, no local provenance prefix: both are operations on
/// OUR OWN `sessions.json` graph node — a remote peer's graph is a
/// projection this box doesn't own (`who.rs`'s own invariant, restated here
/// for the same reason). Authenticated cross-host provenance is #51's
/// scope, not this phase's (messaging plan, "Verified facts").
fn deliver_remote(inv: &Invocation, peer: &aoide_storage::peer_store::Peer, query: &str) -> Outcome {
    let cmd = "graph.send";
    let text = inv.args.join(" ");
    // `--submit`/`--yes` are accepted-but-unused for a remote send (see this
    // function's own doc) — a caller who habitually passes them gets no
    // hint they did nothing unless the Outcome says so. Collected once,
    // folded into BOTH arms of the delivery attempt below (success and
    // failure): the flags were equally inert either way, not just on a
    // success.
    let ignored = ignored_remote_flags(inv);
    let ignored_note = if ignored.is_empty() {
        String::new()
    } else {
        format!(
            " (--{} ignored — gating a remote send is the receiving peer's job)",
            ignored.join(", --")
        )
    };

    let cache = aoide_storage::peer_store::load_peer_cache(&peer.name);
    let Some(graph) = cache.and_then(|c| c.graph) else {
        let out = Outcome::error(
            cmd,
            format!(
                "peer `{}` has no cached graph — run `aoide peer pull {}` first",
                peer.name, peer.name
            ),
        )
        .with_data(json!({ "reason": "peer-never-pulled", "peer": peer.name }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    };

    let sess = peer_cached_sessions(&graph);
    let candidates: Vec<LocalCandidate<'_>> = sess
        .iter()
        .map(|(id, pet, role)| LocalCandidate { session_id: id, petname: pet.as_deref(), role })
        .collect();

    match resolve_remote_query(&peer.name, query, &candidates) {
        Resolution::Local(remote_id) => {
            match aoide_client::commands::send_message_to_peer(peer, &text, &remote_id) {
                Ok(response) => {
                    let out = Outcome::ok(
                        cmd,
                        format!("delivered to `{remote_id}` on peer `{}`{ignored_note}", peer.name),
                    )
                    .changed(vec![format!("sent to {}/{remote_id}", peer.name)])
                    .with_data(json!({
                        "peer": peer.name,
                        "remoteSessionId": remote_id,
                        "delivered": true,
                        "response": response,
                        "ignoredFlags": ignored,
                    }));
                    audit_send(inv, "delivered", &out.message, &text);
                    out
                }
                Err(e) => {
                    let out = Outcome::error(
                        cmd,
                        format!("delivering to `{remote_id}` on peer `{}`: {e}{ignored_note}", peer.name),
                    )
                    .with_data(json!({
                        "reason": "peer-send-failed", "peer": peer.name, "remoteSessionId": remote_id,
                        "ignoredFlags": ignored,
                    }));
                    audit_send(inv, "error", &out.message, &text);
                    out
                }
            }
        }
        Resolution::Ambiguous(ids) => {
            let labels: Vec<String> = ids
                .iter()
                .filter_map(|id| {
                    sess.iter().find(|(sid, _, _)| sid == id).map(|(sid, pet, role)| {
                        peer_session_label(&peer.name, sid, pet.as_deref(), role)
                    })
                })
                .collect();
            let out = Outcome::error(
                cmd,
                format!(
                    "`{query}` is ambiguous on peer `{}` — {} session(s) match: {}",
                    peer.name,
                    ids.len(),
                    labels.join(", ")
                ),
            )
            .with_data(json!({ "reason": "ambiguous", "peer": peer.name, "query": query, "candidates": ids }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
        Resolution::NotFound => {
            let labels: Vec<String> = sess
                .iter()
                .map(|(id, pet, role)| peer_session_label(&peer.name, id, pet.as_deref(), role))
                .collect();
            let hint = if labels.is_empty() {
                format!(" (peer `{}` has no cached sessions)", peer.name)
            } else {
                format!(" — available on `{}`: {}", peer.name, labels.join(", "))
            };
            let out = Outcome::error(
                cmd,
                format!("no session on peer `{}` matches `{query}`{hint}", peer.name),
            )
            .with_data(json!({ "reason": "not-found", "peer": peer.name, "query": query }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
        Resolution::Remote { .. } => {
            // Unreachable: `resolve_remote_query` always passes `peers: &[]`
            // to `addr::resolve`, so tier 5 (the only source of `Remote`)
            // never fires. A clean error, not a panic/unwrap, in case that
            // invariant ever drifts.
            let out = Outcome::error(
                cmd,
                format!("`{query}` resolved to a nested peer reference, which is not supported"),
            )
            .with_data(json!({ "reason": "nested-remote-unsupported", "peer": peer.name, "query": query }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
    }
}

/// A Task sub-agent to create: its node id (`sub:<tool_use_id>`), a human name
/// (the Task description or subagent type), and the subagent type.
#[derive(Debug)]
struct SubSpawn {
    sub_id: String,
    name: String,
    agent_type: String,
}

/// The action a Claude-Code hook payload maps to (or nothing, for events we
/// deliberately ignore — the door is a no-op for everything unmapped).
#[derive(Debug)]
enum HookAction {
    Start { id: String, cwd: Option<String> },
    /// Set the live phase; `name` carries the first user prompt on
    /// UserPromptSubmit (used to name the session set-once), `None` otherwise.
    Phase {
        id: String,
        phase: String,
        name: Option<String>,
    },
    /// A tool started (PreToolUse). `owner` is the session, or `sub:<parent_
    /// tool_use_id>` when the tool ran inside a Task sub-agent (so a sub-agent's
    /// tool churn updates the sub-node, not its parent). `spawn` is Some when the
    /// tool IS a Task — create that child node.
    ToolStart {
        session: String,
        owner: String,
        activity: Option<String>,
        spawn: Option<SubSpawn>,
    },
    /// A tool finished (PostToolUse). `end_sub` closes the Task's child node.
    ToolEnd {
        session: String,
        owner: String,
        end_sub: Option<String>,
    },
    /// PostToolUse for an ASYNC `Agent` dispatch (`tool_response.isAsync == true`):
    /// the launch returned in single-digit ms but the background sub-agent runs
    /// on. Do NOT tear the node down; RE-KEY it from `sub:<tool_use_id>` to
    /// `sub:<agent_id>` (the only id the later SubagentStart/Stop carry) and clear
    /// the owner's foreground activity like a normal tool boundary.
    SubRekey {
        session: String,
        owner: String,
        from_sub_id: String,
        to_sub_id: String,
    },
    /// SubagentStart backstop: ensure the child node exists. `create` is true for
    /// the classic path (keyed by the Task's tool_use_id via `parent_tool_use_id`)
    /// so a missed PreToolUse(Task) is still recovered; it is false for the async
    /// `Agent` fallback (keyed by `agent_id`), which only confirms the re-keyed
    /// node and must never create a duplicate.
    SubEnsure {
        sub_id: String,
        session: String,
        agent_type: String,
        create: bool,
    },
    /// SubagentStop backstop: close the child node.
    SubEnd {
        sub_id: String,
    },
    /// Conditional phase: set `phase` ONLY if the session is still `working`,
    /// else a no-op. Guards the ambiguous idle Notification — a "waiting for your
    /// input" ping only means `awaiting` when the turn is still mid-flight (an
    /// unanswered AskUserQuestion); a settled `idle`/`done` session must not be
    /// flipped by the ~60s idle heartbeat.
    PhaseIfRunning { id: String, phase: String },
    End { id: String },
}

/// Map ONE hook payload (`session_id`, `hook_event_name`, optional `cwd`) to a
/// session-registration action, or `None` when the event is unknown/missing or
/// the `session_id` is absent/empty. Pure over the decoded JSON so the mapping
/// is unit-testable without touching stdin or the stage. The event vocabulary
/// itself lives in the agent's profile (`hook_event_map`); this collapses the
/// semantic classes onto the session verbs.
fn map_hook(profile: &AgentProfile, payload: &Value) -> Option<HookAction> {
    let id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let event = payload.get("hook_event_name").and_then(Value::as_str)?;
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    // Is `tool` a sub-agent-dispatch tool for this harness (claude: Task/Agent)?
    let is_subagent_tool = |tool: &str| profile.subagent_tools.contains(&tool);
    match (profile.hook_event_map)(event) {
        HookClass::SessionStart => Some(HookAction::Start { id: id.to_string(), cwd }),
        // A new prompt: the turn is live → `working`, and the prompt text names
        // the session (set-once, downstream).
        HookClass::PromptSubmit => {
            let name = payload
                .get("user_prompt")
                .and_then(Value::as_str)
                .map(one_line_title)
                .filter(|s| !s.is_empty());
            Some(HookAction::Phase {
                id: id.to_string(),
                phase: "working".to_string(),
                name,
            })
        }
        // A tool call. Route it to its OWNER — the session, or the sub-node
        // `sub:<parent_tool_use_id>` when the tool ran inside a Task sub-agent
        // (nesting + activity routing). The Task tool itself spawns/closes a
        // child node; any other tool sets the owner working with the tool as its
        // current `activity`. Both are part of the awaiting-clearing set.
        HookClass::PreToolUse => {
            let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
            let tuid = payload.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
            let owner = match payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                Some(p) => format!("sub:{p}"),
                None => id.to_string(),
            };
            if is_subagent_tool(tool) && !tuid.is_empty() {
                let input = payload.get("tool_input");
                let field = |k: &str| {
                    input
                        .and_then(|i| i.get(k))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                };
                let stype = field("subagent_type");
                let desc = field("description");
                let name = one_line_title(if desc.is_empty() { stype } else { desc });
                Some(HookAction::ToolStart {
                    session: id.to_string(),
                    owner,
                    activity: if name.is_empty() { None } else { Some(name.clone()) },
                    spawn: Some(SubSpawn {
                        sub_id: format!("sub:{tuid}"),
                        name,
                        agent_type: stype.to_string(),
                    }),
                })
            } else {
                Some(HookAction::ToolStart {
                    session: id.to_string(),
                    owner,
                    activity: if tool.is_empty() { None } else { Some(tool.to_string()) },
                    spawn: None,
                })
            }
        }
        HookClass::PostToolUse => {
            let tool = payload.get("tool_name").and_then(Value::as_str).unwrap_or("");
            let tuid = payload.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
            let owner = match payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                Some(p) => format!("sub:{p}"),
                None => id.to_string(),
            };
            // Async `Agent` dispatch: PostToolUse fires the instant the LAUNCH
            // returns (`tool_response.isAsync == true`), NOT when the background
            // agent finishes — so tearing the node down here would kill it within
            // ~4ms of creating it. Instead re-key `sub:<tuid>` → `sub:<agentId>`
            // (this payload's own `tool_response.agentId`, the only place both ids
            // co-occur) so the later SubagentStop can find it. A classic Task (or a
            // synchronous Agent with no `isAsync`) really IS done here — end it.
            let resp = payload.get("tool_response");
            let async_agent_id = if is_subagent_tool(tool)
                && !tuid.is_empty()
                && resp
                    .and_then(|r| r.get("isAsync"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                resp.and_then(|r| r.get("agentId"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            } else {
                None
            };
            if let Some(aid) = async_agent_id {
                Some(HookAction::SubRekey {
                    session: id.to_string(),
                    owner,
                    from_sub_id: format!("sub:{tuid}"),
                    to_sub_id: format!("sub:{aid}"),
                })
            } else {
                let end_sub = if is_subagent_tool(tool) && !tuid.is_empty() {
                    Some(format!("sub:{tuid}"))
                } else {
                    None
                };
                Some(HookAction::ToolEnd {
                    session: id.to_string(),
                    owner,
                    end_sub,
                })
            }
        }
        // The turn ended and it is the user's move again — but a finished turn is
        // NOT "needs input" (that would make the anxious state the resting face of
        // the whole roster). `awaiting` is reserved strictly for the Notification
        // signals below, so Stop settles to `stopped`: alive, at the prompt, and
        // RECENTLY so. It is not `done` (the session did not end — only the turn),
        // and not `idle` (that is the COLD rest a `stopped` session decays into an
        // hour later, in the reaper's `decay_stopped_sessions` pass).
        HookClass::Stop => Some(HookAction::Phase {
            id: id.to_string(),
            phase: "stopped".to_string(),
            name: None,
        }),
        // The needs-input signal. Prefer the structured `notification_type`
        // (idle_prompt / permission_prompt, confirmed present in the CLI); fall
        // back to the brittle English `message` for older payloads. A permission
        // prompt is an unambiguous mid-turn blocker → `awaiting` at once. The ~60s
        // idle ping is ambiguous — only a still-`working` turn (an unseen
        // AskUserQuestion) becomes `awaiting`; a settled idle/done session is left
        // untouched. Anything else is a no-op. The vocabulary lives in the
        // profile; the unconditional permission tier wins across BOTH sources.
        HookClass::Notification => {
            let ntype = payload
                .get("notification_type")
                .and_then(Value::as_str)
                .unwrap_or("");
            let msg = payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let by_type = (profile.hook_event_map)(&format!("ntype:{ntype}"));
            let by_msg = (profile.hook_event_map)(&format!("msg:{msg}"));
            if matches!(by_type, HookClass::Awaiting) || matches!(by_msg, HookClass::Awaiting) {
                Some(HookAction::Phase {
                    id: id.to_string(),
                    phase: "awaiting".to_string(),
                    name: None,
                })
            } else if matches!(by_type, HookClass::AwaitingIfRunning)
                || matches!(by_msg, HookClass::AwaitingIfRunning)
            {
                Some(HookAction::PhaseIfRunning {
                    id: id.to_string(),
                    phase: "awaiting".to_string(),
                })
            } else {
                None
            }
        }
        // Sub-agent lifecycle backstops. The classic path keys on the spawning
        // Task's tool_use_id (carried as `parent_tool_use_id`) — it converges on
        // the same node the PreToolUse/PostToolUse(Task) path manages, whichever
        // fires. This harness's async `Agent` dispatch carries NEITHER
        // tool_use_id NOR parent_tool_use_id here — only `agent_id` — so we fall
        // back to it, keyed `sub:<agent_id>`, which is exactly what the async
        // PostToolUse re-keyed the node to. The classic path may create a node
        // (backstop for a missed PreToolUse); the agent_id fallback only confirms
        // the re-keyed node (never creates a duplicate).
        HookClass::SubagentStart => {
            let via_parent = payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let key = via_parent.or_else(|| {
                payload
                    .get("agent_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            });
            key.map(|k| HookAction::SubEnsure {
                sub_id: format!("sub:{k}"),
                session: id.to_string(),
                agent_type: payload
                    .get("agent_type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                create: via_parent.is_some(),
            })
        }
        HookClass::SubagentStop => {
            let key = payload
                .get("parent_tool_use_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    payload
                        .get("agent_id")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                });
            key.map(|k| HookAction::SubEnd {
                sub_id: format!("sub:{k}"),
            })
        }
        HookClass::SessionEnd => Some(HookAction::End { id: id.to_string() }),
        // A DEDICATED needs-input event (kimi: `PermissionRequest`) — the same
        // unconditional `awaiting` a permission Notification yields. Claude's
        // map can never produce this class at the top level (its Awaiting only
        // answers prefixed notification-detail queries), so claude is unchanged.
        HookClass::Awaiting => Some(HookAction::Phase {
            id: id.to_string(),
            phase: "awaiting".to_string(),
            name: None,
        }),
        // Unknown events (and the conditional idle class, which only the
        // Notification arm acts on) map to nothing.
        _ => None,
    }
}

/// Drive one hook payload (already read as a string) through the claude
/// profile — the test-facing wrapper (production resolves the profile from
/// `--agent` via [`hook_profile_for`] and calls [`hook_for_profile`]).
#[cfg(test)]
fn hook_from_str(buf: &str) -> Outcome {
    let profile = agent_profile(CLAUDE_PROFILE.name).expect("the claude profile is registered");
    hook_for_profile(profile, buf)
}

/// A hook payload's self-reported `pid` — the harness process's OWN pid, when
/// the harness can know it (pi's extension runs INSIDE the pi process and
/// reports `process.pid`). This is the liveness anchor the reaper's `/proc`
/// signal needs for a harness that can die inside a still-open terminal: the
/// door's ancestry walk can only ever find the TERMINAL's owning pid, which
/// outlives the agent, so a killed agent (no SessionEnd, terminal alive) was
/// invisible to every reaper signal. A payload pid flips that: the record's
/// `pid` dies when the agent dies, whatever the terminal does. Accepts a JSON
/// number or a numeric string; anything else is ignored (claude/kimi payloads
/// never carry it).
fn payload_pid(payload: &Value) -> Option<u32> {
    let raw = payload.get("pid")?;
    raw.as_u64()
        .or_else(|| {
            raw.as_str()
                .and_then(|s| s.trim().parse::<u64>().ok())
        })
        .and_then(|p| u32::try_from(p).ok())
}

/// A hook payload's self-reported `context_ceiling` — the active model's
/// context-window size in tokens, straight from the harness's own model
/// catalog (pi's extension reads `ctx.getContextUsage().contextWindow`).
/// This outranks the aoide catalog: a custom/provider model the catalog has
/// never heard of gets the RIGHT meter instead of the conservative default.
/// Accepts a JSON number or a numeric string; zero/absent is ignored (never a
/// signal to clear — an unknown window simply doesn't overwrite).
fn payload_ceiling(payload: &Value) -> Option<u64> {
    let raw = payload.get("context_ceiling")?;
    let n = raw
        .as_u64()
        .or_else(|| raw.as_str().and_then(|s| s.trim().parse::<u64>().ok()))?;
    (n > 0).then_some(n)
}

/// Up to 8 ancestor pids of THIS hook-firing process, self-first — the
/// `hookAncestry` a fresh hook session stamps ONCE at registration (task
/// #89), consumed later by a `wrap`/`conduct`/`spawn` registration's own
/// ancestry walk (`window::ancestry_parent`) to find its true launching
/// agent.
fn my_hook_ancestry() -> Vec<i32> {
    pid_ancestry(std::process::id() as i32).into_iter().take(8).collect()
}

/// The profile-parametrized core of [`hook_from_str`].
///
/// Split from `session_hook` so the whole path — parse, map, execute — is
/// testable without a real stdin. Empty/malformed input or an unmapped event is
/// an ok no-op; a mapped action runs the matching core but its outcome is ALWAYS
/// folded into an ok envelope: this door runs inside interactive-session hooks
/// and must never exit non-zero (a stage hiccup must not break the session).
/// Self-heal for the hook door: a live session whose store record was ended
/// or pruned mid-process (an errant SessionEnd payload, a conversation switch
/// that fired End, a store reset, a reap during a hook-silent restart window)
/// re-registers on its NEXT real event — harnesses fire SessionStart only at
/// launch, so without this the session is permanently invisible to the graph
/// until the harness restarts. Mirror of the `Start` arm's registration
/// (window discovery + `AOIDE_SESSION_ID` env-parent threading), inserting a
/// fresh idle record; no-op when the id already exists. `sub:` ids are never
/// implicit-started — they exist only as children of a registered parent.
///
/// An EXISTING record gets one refresh: when the payload self-reports a `pid`
/// (pi), the stored pid is rewritten to it if it differs. This is the
/// self-heal for the liveness anchor — a record born before the payload-pid
/// seam (pid = terminal) converges to the harness's real pid on its very next
/// hook, so a later agent death becomes reapable without a re-registration.
fn hook_ensure_session(profile: &AgentProfile, payload: &Value, id: &str) {
    if id.starts_with("sub:") {
        return;
    }
    let reported = payload_pid(payload);
    let existing = load_stage::<SessionsFile>(&sessions_path()).ok();
    let exists = existing
        .as_ref()
        .map(|f| f.sessions.iter().any(|s| s.session_id == id))
        .unwrap_or(false);
    if exists {
        if let Some(pid) = reported {
            // The write takes the SAME stage lock every other stage writer
            // holds (do_session_phase, refresh_transcript_fields, the reaper):
            // an unlocked read-modify-write here raced the locked writers and
            // clobbered their fresh contextTokens/contextCeiling/say updates
            // with this process's stale snapshot (observed: a live session's
            // ceiling flip-flopping between 1M and null as the two writers
            // interleaved).
            aoide_storage::fs::with_stage_lock(|| {
                let mut file: SessionsFile = match load_stage(&sessions_path()) {
                    Ok(f) => f,
                    Err(_) => return,
                };
                if let Some(s) = file
                    .sessions
                    .iter_mut()
                    .find(|s| s.session_id == id && s.pid != Some(pid))
                {
                    s.pid = Some(pid);
                    if file.schema_version.is_empty() {
                        file.schema_version = STAGE_GRAPH_VERSION.to_string();
                    }
                    let _ = write_stage(&sessions_path(), &file);
                    let _ = restage_graph();
                }
            });
        }
        return;
    }
    let cwd = payload.get("cwd").and_then(Value::as_str).map(str::to_string);
    let env_parent = std::env::var("AOIDE_SESSION_ID")
        .ok()
        .filter(|p| !p.is_empty() && *p != id);
    // Windowless by construction (task #89): a hook session whose
    // (about-to-be-set) parent's own lineage runs through an unwindowed
    // conducted wrap must never discover a window at all — that walk would
    // find the ENCLOSING terminal's window, not this session's own (it has
    // none), which is exactly what made the same-window eviction treat two
    // unrelated agents as stale twins.
    let windowless = existing
        .as_ref()
        .map(|f| windowless_by_lineage_from_parent(env_parent.as_deref(), &f.sessions))
        .unwrap_or(false);
    let (window, discovered) = if windowless {
        (None, None)
    } else {
        match discover_window() {
            Some((addr, pid, _workspace)) => (Some(addr), Some(pid)),
            None => (None, None),
        }
    };
    // The harness's own pid wins over the discovered terminal pid — see
    // [`payload_pid`].
    let pid = reported.or(discovered);
    let _ = do_session_start(
        &id,
        Some(profile.name),
        cwd.as_deref(),
        window.as_deref(),
        env_parent.as_deref(),
        None,
        None,
        None,
        pid,
    );
    stamp_hook_ancestry(id, &my_hook_ancestry());
}

fn hook_for_profile(profile: &'static AgentProfile, buf: &str) -> Outcome {
    let cmd = "graph.session.hook";
    let noop = |reason: &str| {
        Outcome::ok(cmd, format!("no-op ({reason})"))
            .with_data(json!({ "action": "none", "reason": reason }))
    };
    let mut payload: Value = match serde_json::from_str(buf.trim()) {
        Ok(v) => v,
        Err(_) => return noop("empty-or-malformed-stdin"),
    };
    // Map harness-native field names onto the canonical contract before
    // mapping (identity for claude; kimi's prompt array, tool_call_id, and
    // agent_name land on user_prompt / tool_use_id / agent_type).
    (profile.normalize_payload)(&mut payload);
    let Some(action) = map_hook(profile, &payload) else {
        return noop("unmapped-or-missing-event");
    };
    let inner = match action {
        HookAction::Start { id, cwd } => {
            // A claude launched INSIDE a conducted session inherits its parent's
            // `AOIDE_SESSION_ID` in the hook process env — thread it as the
            // parent so a claude-conducting-claude (or a claude-in-a-shell) nests
            // in the graph. The hook door inherits the launcher's env.
            let env_parent = std::env::var("AOIDE_SESSION_ID")
                .ok()
                .filter(|p| !p.is_empty() && *p != id);
            // Windowless by construction (task #89): this (about-to-be-set)
            // parent's own lineage running through an unwindowed conducted
            // wrap means THIS session has no window either — skip discovery
            // outright rather than pid-ancestry-walking to the ENCLOSING
            // terminal's window (the exact same-window collision that made
            // the eviction pass treat two unrelated agents as stale twins).
            let windowless = load_stage::<SessionsFile>(&sessions_path())
                .ok()
                .map(|f| windowless_by_lineage_from_parent(env_parent.as_deref(), &f.sessions))
                .unwrap_or(false);
            // Best-effort: the hook is a subprocess of the agent's terminal, so
            // discover that window (+ its owning pid) now and register it — this
            // is what makes a hook-only Claude session `graph focus`-jumpable.
            // Workspace is stamped later by the shellbridge window-event listener
            // (resolve_pending_session_windows), which is authoritative and keeps
            // it fresh across moves — do_session_start carries only window + pid.
            let (window, discovered) = if windowless {
                (None, None)
            } else {
                match discover_window() {
                    Some((addr, pid, _workspace)) => (Some(addr), Some(pid)),
                    None => (None, None),
                }
            };
            // The harness's own pid wins over the discovered terminal pid (see
            // [`payload_pid`]) — pi reports `process.pid`, so a pi that dies
            // inside a still-open terminal still trips the reaper's `/proc`
            // signal.
            let pid = payload_pid(&payload).or(discovered);
            let out = do_session_start(
                &id,
                Some(profile.name),
                cwd.as_deref(),
                window.as_deref(),
                env_parent.as_deref(),
                None,
                None,
                None,
                pid,
            );
            stamp_hook_ancestry(&id, &my_hook_ancestry());
            // A FRESH id is inserted `idle` by `upsert_session`. A RESUME (same id,
            // SessionStart source=resume/compact/clear) deliberately preserves the
            // stored state — a working/awaiting session must not be reset — but a
            // session resumed out of `stopped` is by definition "not yet active"
            // again, which is `idle`. Fold exactly that one case, conditionally, so
            // both stage files agree (hooks.json still holds the Stop phase, and
            // `merged_sessions` overlays it — leaving it would resurrect `stopped`).
            do_session_phase_if(&id, "idle", "stopped");
            out
        }
        HookAction::Phase { id, phase, name } => {
            // Self-heal: a live session whose store record was ended or pruned
            // mid-process (an errant SessionEnd payload, a conversation switch,
            // a store reset, a reap during a hook-silent restart window) comes
            // back on its NEXT event — harnesses fire SessionStart only at
            // launch, so without this the session is permanently invisible until
            // the harness restarts. Same registration path as Start (window +
            // env-parent threading), fresh idle.
            hook_ensure_session(profile, &payload, &id);
            // Backfill a still-empty windowAddress on any later hook — covers a
            // session that registered before the window mapped (or before this
            // discovery shipped), so it becomes jumpable without a restart.
            ensure_session_window(&id);
            let out = do_session_phase(&id, &phase);
            // The first user prompt names the session (set-once).
            if let Some(n) = name {
                set_session_name_if_unset(&id, &n);
            }
            // `awaiting` reached THIS arm means an unconditional blocker — a
            // permission prompt (claude's `notification_type: permission_prompt`,
            // kimi's PermissionRequest); the ambiguous idle ping takes
            // PhaseIfRunning instead and never summons. Raise the herald's
            // approve/deny card, detached, after the phase is on disk so the
            // card's own still-awaiting guard reads the state it was raised for.
            // Best-effort throughout: a notification problem never fails a hook.
            if phase == "awaiting" {
                // The harness's OWN human-readable line ("Claude needs your
                // permission to use Bash") rides along as the card's context
                // tier — passed through verbatim as untrusted display data,
                // never parsed for the tool name (that English-sniffing is
                // exactly what `notification_type` exists to replace).
                super::permit::spawn_summons(
                    &id,
                    payload.get("message").and_then(Value::as_str),
                );
            }
            out
        }
        HookAction::PhaseIfRunning { id, phase } => {
            hook_ensure_session(profile, &payload, &id);
            ensure_session_window(&id);
            do_session_phase_if(&id, &phase, "working")
        }
        HookAction::ToolStart {
            session,
            owner,
            activity,
            spawn,
        } => {
            hook_ensure_session(profile, &payload, &session);
            ensure_session_window(&session);
            // Spawn the child FIRST so it exists before its parent's activity
            // points at it, then mark the owner working + its current activity.
            if let Some(sp) = spawn {
                do_subagent_spawn(&sp.sub_id, &owner, &sp.name, &sp.agent_type, true);
            }
            set_owner_activity(&owner, "working", activity.as_deref());
            Outcome::ok("graph.session.hook", format!("tool start → {owner}"))
        }
        HookAction::ToolEnd {
            session,
            owner,
            end_sub,
        } => {
            hook_ensure_session(profile, &payload, &session);
            ensure_session_window(&session);
            if let Some(sub) = end_sub {
                do_subagent_end(&sub);
            }
            // The tool finished; the owner is still in its turn (working) but no
            // longer running that tool — clear its `activity`.
            set_owner_activity(&owner, "working", None);
            Outcome::ok("graph.session.hook", format!("tool end → {owner}"))
        }
        HookAction::SubRekey {
            session,
            owner,
            from_sub_id,
            to_sub_id,
        } => {
            hook_ensure_session(profile, &payload, &session);
            ensure_session_window(&session);
            do_subagent_rekey(&from_sub_id, &to_sub_id);
            // The launch returned; the parent is no longer running that tool in
            // the foreground (its sub-agent runs on in the background) — clear the
            // activity, exactly as a normal tool boundary would.
            set_owner_activity(&owner, "working", None);
            Outcome::ok(
                "graph.session.hook",
                format!("subagent rekey {from_sub_id} → {to_sub_id}"),
            )
        }
        HookAction::SubEnsure {
            sub_id,
            session,
            agent_type,
            create,
        } => {
            hook_ensure_session(profile, &payload, &session);
            do_subagent_spawn(&sub_id, &session, &agent_type, &agent_type, create);
            Outcome::ok("graph.session.hook", format!("subagent {sub_id}"))
        }
        HookAction::SubEnd { sub_id } => {
            do_subagent_end(&sub_id);
            Outcome::ok("graph.session.hook", format!("subagent end {sub_id}"))
        }
        HookAction::End { id } => do_session_end(&id),
    };
    // Publish a harness-reported context-window ceiling onto the record
    // IMMEDIATELY (every hook carries it — pi's extension reads the active
    // model's window on every payload). Covers SessionStart and the
    // high-frequency PreToolUse too, where the transcript refresh below never
    // runs; that refresh prefers this same value over the aoide catalog, so
    // the two writers can never disagree.
    if let Some(ceiling) = payload_ceiling(&payload) {
        if let Some(sid) = payload
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            ensure_session_ceiling(sid, ceiling);
        }
    }
    // After applying the action, refresh the session's transcript `say` at the
    // boundaries where fresh prose has just landed: the turn end (Stop), a tool
    // boundary (PostToolUse), a new prompt (UserPromptSubmit), or an input-needed
    // ping (Notification). Skips the high-frequency PreToolUse (its prose is
    // captured at the matching PostToolUse) and the lifecycle-only events. Only
    // the TOP-LEVEL session speaks — a sub-agent tool call carries
    // `parent_tool_use_id`, and must not overwrite its parent's say.
    if let (Some(sid), Some(evt)) = (
        payload
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty()),
        payload.get("hook_event_name").and_then(Value::as_str),
    ) {
        let is_sub = payload
            .get("parent_tool_use_id")
            .and_then(Value::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let cwd = payload.get("cwd").and_then(Value::as_str);
        let say_boundary = matches!(
            (profile.hook_event_map)(evt),
            HookClass::Stop | HookClass::PostToolUse | HookClass::PromptSubmit | HookClass::Notification
        );
        if !is_sub && say_boundary {
            refresh_transcript_fields(
                profile,
                sid,
                cwd,
                payload.get("transcript_path").and_then(Value::as_str),
                payload_ceiling(&payload),
            );
        }
        // A background Task keeps running after the parent's turn settles, so
        // catch its words on every one of the parent's own hooks (not just the
        // set above) — cheap: a no-op unless the session currently has a live
        // sub-node. Deferred/direct children only (see `refresh_subagent_says`).
        if !is_sub {
            refresh_subagent_says(profile, sid, cwd);
        }
    }
    // Fold the inner outcome into an ok envelope — exit 0, no matter what.
    Outcome::ok(cmd, inner.message)
        .changed(inner.changed)
        .with_data(json!({
            "action": "applied",
            "innerStatus": format!("{:?}", inner.status),
            "innerData": inner.data,
        }))
}

/// Resolve the agent profile for a hook invocation: `--agent <name>` selects
/// it (default claude, until harnesses self-report); an unknown name is a
/// structured error naming the registered agents.
fn hook_profile_for(inv: &Invocation) -> Result<&'static AgentProfile, Outcome> {
    let name = inv
        .flags
        .get("agent")
        .map(String::as_str)
        .unwrap_or(CLAUDE_PROFILE.name);
    agent_profile(name).ok_or_else(|| {
        Outcome::error(
            "graph.session.hook",
            format!("unknown agent `{name}` (known: {})", known_agents().join(", ")),
        )
        .with_data(json!({ "reason": "unknown-agent", "agent": name, "known": known_agents() }))
    })
}

/// `graph session hook [--agent <name>]` — the hook door for agent harnesses.
/// Reads ONE JSON object from stdin and maps it (through the selected agent
/// profile) to the session verbs. Never exits non-zero for a payload problem
/// (see [`hook_for_profile`]); a bogus `--agent` is a plain CLI error.
pub fn session_hook(inv: &Invocation) -> Outcome {
    use std::io::Read;
    let profile = match hook_profile_for(inv) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let mut buf = String::new();
    let _ = std::io::stdin().lock().read_to_string(&mut buf);
    hook_for_profile(profile, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::common::load_inputs;
    use crate::graph::conduct::conduct_socket_path;
    use crate::graph::doc::prune_done;
    use crate::graph::model::{hooks_path, merged_sessions, HooksFile, SessionRecord};
    use crate::graph::testutil::*;

    #[test]
    fn parent_autogate_decision_is_exact_and_guarded() {
        // The sender IS the target's parent → autogated (freely orchestrated).
        assert!(sender_is_parent(Some("orch"), Some("orch")));
        // Mismatched ids (cross-tree / unrelated) → NOT autogated.
        assert!(!sender_is_parent(Some("orch"), Some("other")));
        // A missing sender or a parentless target → NOT autogated.
        assert!(!sender_is_parent(None, Some("orch")));
        assert!(!sender_is_parent(Some("orch"), None));
        // Empty ids never match (a blank env var is not a parent claim).
        assert!(!sender_is_parent(Some(""), Some("")));
        assert!(!sender_is_parent(Some(""), Some("orch")));

        // The gate resolves in priority order: --yes ▸ global env ▸ parent ▸ pending.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_CONDUCT_AUTOGATE"]);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        assert_eq!(send_gate(true, false, false), SendGate::Yes); // --yes wins outright
        assert_eq!(send_gate(false, true, false), SendGate::AutogateParent);
        assert_eq!(send_gate(false, false, false), SendGate::Pending);
        assert!(SendGate::AutogateParent.delivers());
        assert_eq!(SendGate::AutogateParent.label(), "autogate-parent");
        std::env::set_var("AOIDE_CONDUCT_AUTOGATE", "1");
        // The global switch outranks the parent rule (both deliver; label differs).
        assert_eq!(send_gate(false, true, false), SendGate::Autogate);
        assert_eq!(send_gate(false, false, false), SendGate::Autogate);
    }
    #[test]
    fn sibling_autogate_decision_is_exact_and_guarded() {
        // Equal, non-empty parents, parent live → sibling autogate.
        assert!(siblings_share_live_parent(Some("orch"), Some("orch"), true));
        // Equal parent id, but that parent is done (or absent, parent_live=false) → not.
        assert!(!siblings_share_live_parent(Some("orch"), Some("orch"), false));
        // One side missing → not.
        assert!(!siblings_share_live_parent(None, Some("orch"), true));
        assert!(!siblings_share_live_parent(Some("orch"), None, true));
        // Both missing → not.
        assert!(!siblings_share_live_parent(None, None, true));
        // Empty-string parents never match (a blank id is not a parent claim).
        assert!(!siblings_share_live_parent(Some(""), Some(""), true));
        // Different parents (cross-tree) → not, whatever `parent_live` says.
        assert!(!siblings_share_live_parent(Some("orch"), Some("other"), true));

        // The env opt-out: absent/anything-else → enabled; {0,false,no} → disabled.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_CONDUCT_SIBLING_AUTOGATE"]);
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE");
        assert!(sibling_autogate_enabled());
        for off in ["0", "false", "no"] {
            std::env::set_var("AOIDE_CONDUCT_SIBLING_AUTOGATE", off);
            assert!(!sibling_autogate_enabled(), "{off} should disable it");
        }
        std::env::set_var("AOIDE_CONDUCT_SIBLING_AUTOGATE", "whatever");
        assert!(sibling_autogate_enabled());

        // The gate: --yes ▸ global env ▸ parent-of-target ▸ sibling ▸ pending.
        let _env2 = EnvVars::save(&["AOIDE_CONDUCT_AUTOGATE"]);
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE");
        assert_eq!(send_gate(false, false, true), SendGate::AutogateSibling);
        assert_eq!(SendGate::AutogateSibling.label(), "autogate-sibling");
        assert!(SendGate::AutogateSibling.delivers());
        // Parent-of-target still outranks sibling when both are true.
        assert_eq!(send_gate(false, true, true), SendGate::AutogateParent);
        // The opt-out env falls the sibling arm through to pending.
        std::env::set_var("AOIDE_CONDUCT_SIBLING_AUTOGATE", "0");
        assert_eq!(send_gate(false, false, true), SendGate::Pending);
    }
    #[test]
    fn send_yes_delivers_and_autorenames_the_title() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-yes");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no standing autogate.
        // No sender attribution in scope here — a real ambient AOIDE_SESSION_ID
        // (this test may itself be running inside a conducted session) would
        // otherwise leak a provenance prefix into the plain-delivery assertion
        // below.
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "send-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        // A stand-in listener plays the conducted process.
        let listener = UnixListener::bind(&socket).unwrap();

        // Register a conductable session pointing at that socket.
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

        // Accept + read the injected payload to EOF in a thread.
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["hello", "world"],
            &[("id", id), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "yes");
        // --submit appended a newline.
        assert_eq!(String::from_utf8(got).unwrap(), "hello world\n");

        // Title auto-renamed on the record + restaged graph node.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|r| r.session_id == id).unwrap().title.as_deref(),
            Some("hello world")
        );

        // An audit line for the delivery was written.
        let log = std::fs::read_to_string(root.join("log")).unwrap_or_default();
        assert!(
            log.contains("graph.send") && log.contains("delivered"),
            "audit log carries the delivered send: {log}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_id_accepts_the_session_prefix_graph_view_emits() {
        // `graph view --json` emits node ids as `session:<id>` (doc.rs's
        // `render`); an agent copying that field verbatim into `--id`
        // must resolve to the exact same session a bare `--id` would.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-prefixed-id");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "send-prefixed-target";
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

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        // The exact id `graph view --json` would emit for this session.
        let prefixed = format!("session:{id}");
        let out = session_send(&send_invocation(
            &["hi", "there"],
            &[("id", prefixed.as_str()), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        // The resolved id reported back is the BARE id — `graph view`'s own
        // emitted contract is untouched, but the resolved target is the same
        // session a bare `--id` would have hit.
        assert_eq!(out.data.as_ref().unwrap()["id"], id);
        assert_eq!(String::from_utf8(got).unwrap(), "hi there\n");

        // An id carrying an UNKNOWN prefix is not special-cased — it still
        // errors as an unknown session, exactly as an unrecognised id always
        // has.
        let out = session_send(&send_invocation(
            &["hi"],
            &[("id", "peerish:send-prefixed-target"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "session-not-found");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_delivered_local_send_is_filed_into_the_inbox() {
        // Messaging plan P-C6: `deliver_local`'s success path is the one
        // seam that files a delivered message into `state/inbox.json` — see
        // `aoide_storage::inbox`'s module doc for why the A2A door's
        // `do_inject` does not need (and must not add) a second append.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-inbox");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::set_var("AOIDE_SESSION_ID", "orchestrator-1");

        let id = "send-inbox-target";
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

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let out = session_send(&send_invocation(&["do", "the", "thing"], &[("id", id), ("yes", "true")]));
        let _ = acc.join().unwrap();
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);

        let file = aoide_storage::inbox::load().unwrap();
        assert_eq!(file.entries.len(), 1, "one delivered message, one inbox entry");
        let e = &file.entries[0];
        assert_eq!(e.from, "orchestrator-1");
        assert_eq!(e.target, id);
        assert_eq!(e.text, "do the thing", "the RAW text, not the prefixed wire payload");
        assert!(!e.read);
        assert!(e.context.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_send_left_pending_is_not_filed_into_the_inbox_until_approved() {
        // Only a SUCCESSFUL delivery files — a held-pending send must not
        // appear in the inbox at all yet.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-inbox-pending");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "send-inbox-pending-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
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

        // No --yes, no autogate → held pending, never touches the socket.
        let out = session_send(&send_invocation(&["do", "the", "thing"], &[("id", id)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");

        let file = aoide_storage::inbox::load().unwrap();
        assert!(file.entries.is_empty(), "a pending (undelivered) send never reaches the inbox");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_keystroke_answer_is_delivered_but_never_renames_the_node() {
        // `graph permit` types a bare verdict digit through this door; a title
        // of `1` would erase the only label the dock identifies the session by.
        assert!(names_the_node("hello world"));
        assert!(names_the_node("fix the auth test"));
        assert!(names_the_node("見て")); // any script's letters name a node
        assert!(!names_the_node("1"));
        assert!(!names_the_node("3\n"));
        assert!(!names_the_node("  2  "));
        assert!(!names_the_node("")); // an empty send names nothing either

        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-key");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        // No sender attribution in scope — this test is about the
        // names_the_node/title distinction, not provenance; guard against a
        // real ambient AOIDE_SESSION_ID leaking a prefix into the steer's
        // plain-text delivery assertion below.
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "key-t";
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
        // A real steer names the node first, so the test can prove the digit
        // leaves that name STANDING rather than merely never setting one.
        let acc = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (mut conn, _) = listener.accept().unwrap();
                use std::io::Read as _;
                let mut buf = Vec::new();
                let _ = conn.read_to_end(&mut buf);
                seen.push(String::from_utf8_lossy(&buf).into_owned());
            }
            seen
        });
        let steer = session_send(&send_invocation(
            &["fix", "the", "reaper"],
            &[("id", id), ("yes", "true")],
        ));
        assert_eq!(steer.status, aoide_protocol::output::Status::Ok);

        // Now the verdict keystroke: delivered, no newline, no rename.
        let out = session_send(&send_invocation(&["3"], &[("id", id), ("yes", "true")]));
        let seen = acc.join().unwrap();
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["title"], "", "no title was written");
        assert_eq!(seen, vec!["fix the reaper".to_string(), "3".to_string()]);
        assert!(
            !out.changed.iter().any(|c| c.contains("title")),
            "the keystroke reports no rename: {:?}",
            out.changed
        );

        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|r| r.session_id == id).unwrap().title.as_deref(),
            Some("fix the reaper"),
            "the steer's name survived the verdict keystroke"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn provenance_prefix_table() {
        // No sender → no prefix, whatever the text.
        assert_eq!(provenance_prefix(None, "hello world"), None);
        // A keystroke/verdict payload (no letters) is never prefixed, even
        // with a sender resolved — this is the regression that matters most:
        // `graph permit`'s bare digit must reach the socket byte-identical.
        assert_eq!(provenance_prefix(Some("orch"), "1"), None);
        assert_eq!(provenance_prefix(Some("orch"), "3\n"), None);
        assert_eq!(provenance_prefix(Some("orch"), "  2  "), None);
        assert_eq!(provenance_prefix(Some("orch"), ""), None);
        // Normal text with a sender → prefixed, single line, no trailing
        // newline of its own.
        assert_eq!(
            provenance_prefix(Some("orch"), "fix the auth test"),
            Some("from orch: ".to_string())
        );
        // Multi-line text: the prefix itself never grows a newline (the
        // caller prepends it to the whole payload, landing it on line one
        // only — proven end-to-end by the delivery test below).
        let p = provenance_prefix(Some("orch"), "line one\nline two").unwrap();
        assert!(!p.contains('\n'), "the prefix itself carries no newline: {p:?}");
        assert_eq!(p, "from orch: ");
    }
    #[test]
    fn resolve_sender_is_tri_state_absent_present_or_explicitly_anonymous() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_SESSION_ID"]);

        // Neither source present → None.
        std::env::remove_var("AOIDE_SESSION_ID");
        assert_eq!(resolve_sender(&send_invocation(&["hi"], &[("id", "x")])), None);

        // `--from` ABSENT → falls through to the env.
        std::env::set_var("AOIDE_SESSION_ID", "env-sid");
        assert_eq!(
            resolve_sender(&send_invocation(&["hi"], &[("id", "x")])),
            Some("env-sid".to_string())
        );

        // `--from` PRESENT and non-empty wins over the env — env never consulted.
        assert_eq!(
            resolve_sender(&send_invocation(&["hi"], &[("id", "x"), ("from", "flag-sid")])),
            Some("flag-sid".to_string())
        );

        // `--from` PRESENT but EMPTY is explicit "no attribution" — the env
        // fallback is SKIPPED (not consulted), even though it's set to a real
        // sender. This is the case `pending_approve` relies on to keep an
        // anonymously-queued entry anonymous through approval (see
        // `graph::pending::tests::pending_round_trip_...`).
        assert_eq!(resolve_sender(&send_invocation(&["hi"], &[("id", "x"), ("from", "")])), None);

        // An empty env with `--from` ABSENT → None too.
        std::env::set_var("AOIDE_SESSION_ID", "");
        assert_eq!(resolve_sender(&send_invocation(&["hi"], &[("id", "x")])), None);
    }
    #[test]
    fn resolve_sender_sanitizes_embedded_newlines_from_either_source() {
        // `--from` and `AOIDE_SESSION_ID` are both raw argv/env data — a
        // newline is legal in either — but the provenance prefix built from
        // this value crosses into a TUI's input stream, where an unsanitized
        // newline would submit a bogus extra line ahead of the real text.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_SESSION_ID"]);

        std::env::remove_var("AOIDE_SESSION_ID");
        assert_eq!(
            resolve_sender(&send_invocation(&["hi"], &[("id", "x"), ("from", "evil\nsender")])),
            Some("evil sender".to_string())
        );
        assert_eq!(
            resolve_sender(&send_invocation(&["hi"], &[("id", "x"), ("from", "cr\rlf\r\nboth")])),
            Some("cr lf  both".to_string())
        );

        std::env::set_var("AOIDE_SESSION_ID", "env\nsender");
        assert_eq!(
            resolve_sender(&send_invocation(&["hi"], &[("id", "x")])),
            Some("env sender".to_string())
        );
    }
    #[test]
    fn delivered_payload_carries_the_provenance_prefix_but_the_title_does_not() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-provenance");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::set_var("AOIDE_SESSION_ID", "the-sender");

        let id = "prov-target";
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

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["fix", "the", "reaper"],
            &[("id", id), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "from the-sender: fix the reaper\n",
            "the delivered bytes carry the provenance prefix"
        );

        // The auto-rename title is the UNPREFIXED text — the sender label
        // must never leak into the node's name.
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|r| r.session_id == id).unwrap().title.as_deref(),
            Some("fix the reaper"),
            "the title carries no provenance prefix"
        );
        assert_eq!(out.data.as_ref().unwrap()["title"], "fix the reaper");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_permit_shaped_keystroke_is_delivered_with_no_prefix_even_with_a_sender() {
        // The regression that matters most: `graph permit`'s bare-digit
        // verdict (or a hand-typed answer of the same shape) must reach the
        // socket as EXACTLY the digit + newline — a provenance prefix here
        // would corrupt the keystroke the target's TUI is waiting to read.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-permit-shaped");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::set_var("AOIDE_SESSION_ID", "the-approver");

        let id = "permit-shaped-target";
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

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["2"],
            &[("id", id), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "2\n",
            "a permit-shaped keystroke delivers with NO provenance prefix"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_from_flag_with_an_embedded_newline_never_smuggles_an_extra_submitted_line() {
        // Regression: `--from` is raw argv — a newline is legal in it — but an
        // unsanitized sender would inject a second, EARLY-SUBMITTED line into
        // the target's TUI ahead of the real text. The delivered bytes must
        // carry EXACTLY the one newline `--submit` asked for.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-from-newline");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "from-newline-target";
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

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["ship", "it"],
            &[("id", id), ("submit", "true"), ("yes", "true"), ("from", "evil\nsender")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let delivered = String::from_utf8(got).unwrap();
        assert_eq!(
            delivered.matches('\n').count(),
            1,
            "exactly one newline (the --submit one), never an early-submitted line: {delivered:?}"
        );
        assert_eq!(
            delivered, "from evil sender: ship it\n",
            "the embedded newline in --from collapsed to a space, prefix stays single-line"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_yes_to_a_kimi_target_submits_with_carriage_return_not_newline() {
        // Kimi's TUI submits on `\r`, not `\n` (KIMI_PROFILE::submit_key) —
        // the delivered payload must carry exactly that byte, resolved from
        // the TARGET's own registered agent, not a fixed `\n` at the call
        // site.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("s-kimi");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "kimi-t";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("kimi"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["hello", "world"],
            &[("id", id), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let delivered = String::from_utf8(got).unwrap();
        assert_eq!(delivered, "hello world\r");
        assert_eq!(delivered.matches('\r').count(), 1);
        assert_eq!(delivered.matches('\n').count(), 0, "no newline for a kimi target");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_yes_to_an_unregistered_agent_defaults_to_newline_submit() {
        // An unregistered ("shell") or empty agent string falls back to the
        // claude profile's `\n` — the same fallback `profile_for_agent`
        // already applies for `graph permit`.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        for (tag, agent) in [("sh", Some("shell")), ("mt", Some(""))] {
            let root = unique_stage(&format!("s-unk-{tag}"));
            let stage = root.join("stage");
            std::fs::create_dir_all(&stage).unwrap();
            std::env::set_var("AOIDE_STAGE_DIR", &stage);
            std::env::set_var("XDG_RUNTIME_DIR", &root);
            std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
            std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
            std::env::remove_var("AOIDE_SESSION_ID");

            let id = "unk-t";
            let socket = conduct_socket_path(id);
            std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
            let listener = UnixListener::bind(&socket).unwrap();
            do_session_start(
                id,
                agent,
                Some("/w"),
                None,
                None,
                Some(true),
                Some(socket.to_str().unwrap()),
                None,
                None,
            );

            let acc = std::thread::spawn(move || {
                let (mut conn, _) = listener.accept().unwrap();
                use std::io::Read as _;
                let mut buf = Vec::new();
                let _ = conn.read_to_end(&mut buf);
                buf
            });

            let out = session_send(&send_invocation(
                &["hello", "world"],
                &[("id", id), ("submit", "true"), ("yes", "true")],
            ));
            let got = acc.join().unwrap();

            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
            assert_eq!(
                String::from_utf8(got).unwrap(),
                "hello world\n",
                "agent {tag:?} defaults to the claude fallback's newline submit"
            );

            let _ = std::fs::remove_dir_all(&root);
        }
    }
    #[test]
    fn a_from_flag_with_an_embedded_carriage_return_never_smuggles_an_extra_submitted_line_for_a_kimi_target(
    ) {
        // Twin of `a_from_flag_with_an_embedded_newline_never_smuggles_an_
        // extra_submitted_line`, against a kimi target: `sanitize_sender`
        // already collapses an embedded `\r` in `--from` to a space, and the
        // ONE `\r` in the delivered payload must be the trailing submit
        // keystroke — never one smuggled in early by an unsanitized sender.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("s-kimi-cr");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "kimi-cr-t";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("kimi"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["ship", "it"],
            &[("id", id), ("submit", "true"), ("yes", "true"), ("from", "evil\rsender")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let delivered = String::from_utf8(got).unwrap();
        assert_eq!(
            delivered.matches('\r').count(),
            1,
            "exactly one \\r (the trailing kimi submit), never an early-smuggled one: {delivered:?}"
        );
        assert!(delivered.ends_with('\r'), "the one \\r sits at the very end: {delivered:?}");
        assert_eq!(
            delivered, "from evil sender: ship it\r",
            "the embedded \\r in --from collapsed to a space, prefix stays single-line"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn provenance_prefix_names_a_petnamed_sender_by_petname_and_tail() {
        // Petnames plan P3: the composer prefix is TERSE — `from <petname>
        // (…<tail4>): `, never host/role — and resolves the sender against
        // the ALREADY-LOADED roster at delivery time, not the raw session id
        // `resolve_sender` produced. Every session minted since P2 carries a
        // petname automatically, so a registered sender always hits this path.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-provenance-petname");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");

        let sender_id = "petname-sender";
        std::env::remove_var("AOIDE_SESSION_ID");
        do_session_start(sender_id, Some("claude"), Some("/w"), None, None, None, None, None, None);
        std::env::set_var("AOIDE_SESSION_ID", sender_id);

        let target = "petname-target";
        let socket = conduct_socket_path(target);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
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

        // Read back the petname `do_session_start` minted for the sender —
        // pinned off the SAME storage helper the prefix build uses, not a
        // hand-guessed literal (the mint is non-deterministic by design).
        let sessions: SessionsFile = load_stage(&sessions_path()).unwrap();
        let sender_rec = sessions.sessions.iter().find(|s| s.session_id == sender_id).unwrap();
        let petname = sender_rec.petname.clone().expect("every minted session carries a petname (P2)");
        let expected_prefix = format!(
            "from {petname} (…{}): ",
            aoide_storage::display::short_tail(sender_id)
        );

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["ship", "it"],
            &[("id", target), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            format!("{expected_prefix}ship it\n"),
            "the delivered prefix names the sender by petname+tail, not the raw session id"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn provenance_prefix_falls_back_to_the_raw_sender_id_when_unresolvable() {
        // A sender that resolves to nothing in the current roster (never
        // registered, or already pruned/reaped since it sent) degrades to
        // the raw id — the same fallback a legacy/petname-less record would
        // hit, exercised here via the far more common real-world case: an
        // unknown sender.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-provenance-fallback");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::set_var("AOIDE_SESSION_ID", "ghost-sender");

        let target = "fallback-target";
        let socket = conduct_socket_path(target);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
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

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["ship", "it"],
            &[("id", target), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "from ghost-sender: ship it\n",
            "an unresolvable sender falls back to the raw id, exactly as before this change"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_without_yes_is_held_pending_not_delivered() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
        ]);

        let root = unique_stage("send-pending");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");

        let id = "pend-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap(); // so we can assert nothing connected.

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

        let out = session_send(&send_invocation(&["do", "a", "thing"], &[("id", id)]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        // Nothing connected to the listener.
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a held-pending send delivers nothing"
        );

        // Recorded in pending.json.
        let pf: PendingFile = load_stage(&pending_path()).unwrap();
        assert!(
            pf.pending
                .iter()
                .any(|p| p.session_id == id && p.text == "do a thing"),
            "the send is recorded pending"
        );

        // Title NOT changed (delivery never happened).
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions.iter().find(|r| r.session_id == id).unwrap().title.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_delivers_when_sender_is_the_targets_parent() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-parent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no global autogate.
        // The SENDER is the orchestrator session `orch`.
        std::env::set_var("AOIDE_SESSION_ID", "orch");

        let id = "child-of-orch";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        // Register a conductable CHILD whose parent is the sender (`orch`).
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"),
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        // No --yes: delivery is authorised purely by the parent relationship.
        let out = session_send(&send_invocation(&["go"], &[("id", id), ("submit", "true")]));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "autogate-parent");
        // The gate's sender (`AOIDE_SESSION_ID=orch`) doubles as the
        // provenance attribution — the delivered bytes carry the prefix.
        assert_eq!(String::from_utf8(got).unwrap(), "from orch: go\n");

        // An UNRELATED sender (different session) to the same child stays pending.
        std::env::set_var("AOIDE_SESSION_ID", "stranger");
        let out = session_send(&send_invocation(&["hi"], &[("id", id)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_delivers_between_siblings_of_a_live_parent() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_CONDUCT_SIBLING_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-sibling");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no global autogate.
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // default: enabled.

        // A live parent `orch`, and two of its children: `sib-a` (the sender,
        // NOT conductable — it never receives) and `sib-b` (the conductable
        // TARGET). Neither is the other's parent — only their shared, live
        // parent makes this a sibling send.
        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, None);
        do_session_start(
            "sib-a", Some("claude"), Some("/w"), None, Some("orch"), None, None, None, None,
        );
        let target = "sib-b";
        let socket = conduct_socket_path(target);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            target,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"),
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // (a) sender and target share a live parent, no --yes, no env autogate,
        // sender is NOT the target's parent → DELIVERED, sibling label.
        std::env::set_var("AOIDE_SESSION_ID", "sib-a");
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let out = session_send(&send_invocation(&["hey", "sib"], &[("id", target)]));
        let got = acc.join().unwrap();
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "autogate-sibling");
        // `AOIDE_SESSION_ID=sib-a` doubles as the gate's sender AND the
        // provenance attribution (see [`resolve_sender`]) — the delivered
        // bytes carry the sibling's prefix, DISPLAY-mapped to its
        // auto-minted petname+tail (petnames plan P3; every session mints
        // one on registration since P2, so `sib-a` — a real registered
        // sender — always hits that path). Pulled off the roster rather
        // than hand-guessed since the mint is non-deterministic.
        let sessions: SessionsFile = load_stage(&sessions_path()).unwrap();
        let sender_petname = sessions
            .sessions
            .iter()
            .find(|s| s.session_id == "sib-a")
            .and_then(|s| s.petname.clone())
            .expect("every minted session carries a petname (P2)");
        assert_eq!(
            String::from_utf8(got).unwrap(),
            format!(
                "from {sender_petname} (…{}): hey sib",
                aoide_storage::display::short_tail("sib-a")
            )
        );

        // (b) same pair, but the opt-out env is set → held pending, not delivered.
        std::env::set_var("AOIDE_CONDUCT_SIBLING_AUTOGATE", "0");
        let out = session_send(&send_invocation(&["hey", "again"], &[("id", target)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // back to enabled.

        // (c) a cross-tree sender (a different parent than the target's) → pending.
        do_session_start(
            "cross-sender", Some("claude"), Some("/w"), None, Some("other-parent"), None, None,
            None, None,
        );
        std::env::set_var("AOIDE_SESSION_ID", "cross-sender");
        let out = session_send(&send_invocation(&["nope"], &[("id", target)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        // (d) an orphan sender (no AOIDE_SESSION_ID at all) → pending.
        std::env::remove_var("AOIDE_SESSION_ID");
        let out = session_send(&send_invocation(&["nope"], &[("id", target)]));
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_to_self_never_autodelivers_via_the_sibling_arm() {
        // Regression for a real gate-widening: `AOIDE_SESSION_ID` is exported
        // into every conducted child's own env, so a prompt-injected `graph
        // send --id "$AOIDE_SESSION_ID" --submit -- <text>` finds ITS OWN
        // record as sender — sender_parent == target_parent trivially (same
        // record, same field, read twice) and the shared parent is live in the
        // normal case. Without the `is_self_send` guard this self-delivers
        // text straight back into the session's own input stream, bypassing
        // approval. It must queue, exactly like any other ungated send.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_CONDUCT_SIBLING_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-self");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // default: enabled.

        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, None);
        let id = "self-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap(); // prove nothing connects.
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"), // a live parent — the predicate WOULD fire if unguarded.
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // The sender IS the target — the exact shape a self-injecting prompt
        // would produce (`--id "$AOIDE_SESSION_ID"`).
        std::env::set_var("AOIDE_SESSION_ID", id);
        let out = session_send(&send_invocation(&["do", "a", "thing"], &[("id", id)]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a self-send delivers nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn global_autogate_env_outranks_the_sibling_label_even_when_both_apply() {
        // Precedence lock-in: when the global switch is on AND the sibling
        // predicate is true, the label must be the global arm's ("autogate"),
        // never "autogate-sibling" — a future refactor that reorders the `if`
        // chain in `send_gate` should trip this, not silently relabel deliveries.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_CONDUCT_AUTOGATE"]);
        std::env::set_var("AOIDE_CONDUCT_AUTOGATE", "1");
        let gate = send_gate(false, false, true);
        assert_eq!(gate, SendGate::Autogate);
        assert_eq!(gate.label(), "autogate");
    }
    #[test]
    fn sibling_send_queues_when_the_shared_parent_record_is_done() {
        // Integration-level: the pure predicate's `parent_live=false` arm is
        // already unit-tested; this proves the RESOLUTION through a real
        // SessionsFile record actually feeds it — a parent whose on-disk state
        // is `done` must gate the sibling send, not just the bool parameter.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_CONDUCT_SIBLING_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-sibling-done-parent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // default: enabled.

        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, None);
        do_session_start(
            "sib-a", Some("claude"), Some("/w"), None, Some("orch"), None, None, None, None,
        );
        let target = "sib-b";
        let socket = conduct_socket_path(target);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        do_session_start(
            target,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"),
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );
        // The shared parent ends — its on-disk sessions.json record flips to
        // `done` (sib-a/sib-b are not `kind: subagent`, so they survive intact).
        do_session_end("orch");

        std::env::set_var("AOIDE_SESSION_ID", "sib-a");
        let out = session_send(&send_invocation(&["nope"], &[("id", target)]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a dead-parent sibling send delivers nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_unknown_or_unconductable_is_a_clean_error() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("send-err");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        // Unknown id.
        let out = session_send(&send_invocation(&["hi"], &[("id", "ghost"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "session-not-found");

        // Registered but not conductable (a plain wrap/hook session).
        do_session_start("plain", Some("claude"), None, None, None, None, None, None, None);
        let out = session_send(&send_invocation(&["hi"], &[("id", "plain"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-conductable");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `--to` resolution (messaging plan P-C3) ───────────────────────────

    fn test_peer(name: &str, url: &str) -> aoide_storage::peer_store::Peer {
        aoide_storage::peer_store::Peer {
            name: name.to_string(),
            url: url.to_string(),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            added_at: "2026-08-21T00:00:00Z".to_string(),
        }
    }

    fn test_cache(name: &str, graph: Value) -> aoide_storage::peer_store::PeerCacheEntry {
        aoide_storage::peer_store::PeerCacheEntry {
            schema_version: "0".to_string(),
            name: name.to_string(),
            instance: None,
            graph: Some(graph),
            fetched_at: Some("2026-08-21T00:00:00Z".to_string()),
            stale: false,
            last_error: None,
        }
    }

    /// `(sessionId, petname, role)` triples → a minimal cached-graph
    /// document `peer_cached_sessions` can extract back out of — a `role:
    /// "child"` entry gets a synthetic `spawned` edge so the role-derivation
    /// half of the extraction is exercised too, mirroring `who.rs`'s own
    /// `peer_graph` test fixture.
    fn peer_graph_json(sessions: &[(&str, Option<&str>, &str)]) -> Value {
        let nodes: Vec<Value> = sessions
            .iter()
            .map(|(id, petname, _role)| {
                let mut n = json!({
                    "id": format!("session:{id}"), "kind": "session",
                    "state": "working", "cwd": "/x", "agent": "claude",
                });
                if let Some(p) = petname {
                    n["petname"] = json!(p);
                }
                n
            })
            .collect();
        let edges: Vec<Value> = sessions
            .iter()
            .filter(|(_, _, role)| *role == "child")
            .map(|(id, _, _)| json!({ "from": "session:parent", "to": format!("session:{id}"), "kind": "spawned" }))
            .collect();
        json!({ "schemaVersion": "0", "nodes": nodes, "edges": edges })
    }

    #[test]
    fn resolve_remote_query_table() {
        // Pure, no I/O — mirrors `aoide_storage::addr`'s own table-driven
        // style, scoped to what this function adds on top of `addr::resolve`
        // itself: trying `query` exactly as typed first (tiers 1-3), and
        // only on a miss retrying the reconstructed `<peer>/<query>` form
        // (tier 4, the `role/petname` remainder tier 5 stripped the host off
        // of).
        struct Case {
            name: &'static str,
            query: &'static str,
            candidates: Vec<(&'static str, Option<&'static str>, &'static str)>,
            expected: Resolution,
        }
        let peer = "yomi-strix";
        let cases = vec![
            Case {
                name: "exact remote id, tried as typed",
                query: "sess-aaaa-1111",
                candidates: vec![("sess-aaaa-1111", Some("brave-otter"), "root")],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "id tail4, tried as typed",
                query: "1111",
                candidates: vec![("sess-aaaa-1111", Some("brave-otter"), "root")],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "bare petname, tried as typed (the documented common case)",
                query: "brave-otter",
                candidates: vec![("sess-aaaa-1111", Some("brave-otter"), "root")],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "role/petname compound falls back to the reconstructed <peer>/<query> form",
                query: "root/brave-otter",
                candidates: vec![("sess-aaaa-1111", Some("brave-otter"), "root")],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "petname collision on the peer's own cache is ambiguous",
                query: "brave-otter",
                candidates: vec![
                    ("sess-aaaa-1111", Some("brave-otter"), "root"),
                    ("sess-bbbb-2222", Some("brave-otter"), "child"),
                ],
                expected: Resolution::Ambiguous(vec!["sess-aaaa-1111".into(), "sess-bbbb-2222".into()]),
            },
            Case {
                name: "no match in either attempt",
                query: "ghost-name",
                candidates: vec![("sess-aaaa-1111", Some("brave-otter"), "root")],
                expected: Resolution::NotFound,
            },
        ];
        for c in cases {
            let candidates: Vec<LocalCandidate<'_>> = c
                .candidates
                .iter()
                .map(|(id, pet, role)| LocalCandidate { session_id: id, petname: *pet, role })
                .collect();
            let got = resolve_remote_query(peer, c.query, &candidates);
            assert_eq!(got, c.expected, "case failed: {}", c.name);
        }
    }

    #[test]
    fn to_and_id_together_is_a_usage_error() {
        let out = session_send(&send_invocation(&["hi"], &[("id", "x"), ("to", "y"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("mutually exclusive"), "msg: {}", out.message);
    }

    #[test]
    fn to_local_petname_redrives_the_exact_id_path() {
        // Same assertions `send_yes_delivers_and_autorenames_the_title` makes
        // for `--id`, driven through `--to` instead — proving resolution
        // funnels into `deliver_local` unmodified, not a parallel
        // reimplementation of the gate/delivery/rename path.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("to-local");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "to-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();

        do_session_start(
            id, Some("claude"), Some("/w"), None, None, Some(true), Some(socket.to_str().unwrap()), None, None,
        );
        // Mint a petname directly on the stage record — the send path
        // resolves against whatever `sessions.json` says, not through the
        // real minting machinery (not this phase's concern).
        {
            let mut f: SessionsFile = load_stage(&sessions_path()).unwrap();
            f.sessions.iter_mut().find(|s| s.session_id == id).unwrap().petname =
                Some("brave-otter".to_string());
            write_stage(&sessions_path(), &f).unwrap();
        }

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        let out = session_send(&send_invocation(
            &["hello", "world"],
            &[("to", "brave-otter"), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["id"], id);
        assert_eq!(String::from_utf8(got).unwrap(), "hello world\n");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_local_ambiguous_petname_is_a_hard_error_never_first_match() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-ambiguous");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        let mut a = session("dup-a", "/x", "working", "1", None);
        a.petname = Some("brave-otter".to_string());
        let mut b = session("dup-b", "/x", "idle", "2", None);
        b.petname = Some("brave-otter".to_string());
        let sf = SessionsFile { schema_version: "0".to_string(), sessions: vec![a, b] };
        write_stage(&sessions_path(), &sf).unwrap();

        let out = session_send(&send_invocation(&["hi"], &[("to", "brave-otter"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "ambiguous");
        assert_eq!(out.data.as_ref().unwrap()["candidates"].as_array().unwrap().len(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_unknown_bare_peer_name_hints_the_slash_form() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-bare-peer");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::peer_store::save_peers(&[test_peer("yomi-strix", "http://127.0.0.1:9/")]).unwrap();

        // A slash-free query naming a KNOWN peer but no local session is
        // `NotFound` (`addr.rs`'s documented bare-known-peer-name decision,
        // never a whole-peer `Remote`) — the error should hint the
        // `peer/<rest>` form instead of leaving the user guessing.
        let out = session_send(&send_invocation(&["hi"], &[("to", "yomi-strix"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-found");
        assert!(out.message.contains("did you mean"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_unknown_target_not_found_with_no_hint_when_it_matches_no_known_peer_either() {
        // The plain branch of `Resolution::NotFound`: `target` names neither
        // a local session nor a known peer at all (no registered peers, and
        // not slash-shaped), so the "did you mean `peer/<rest>`?" hint must
        // NOT fire — a bare, unrecognized token gets the plain message.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-plain-notfound");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        // No peers registered at all, no local sessions either.

        let out = session_send(&send_invocation(&["hi"], &[("to", "ghost-target"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-found");
        assert_eq!(out.message, "no session matches `ghost-target`", "msg: {}", out.message);
        assert!(!out.message.contains("did you mean"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ignored_remote_flags_table() {
        // Pure — the flags a caller passed on a `--to` invocation, in
        // declaration order, with neither/one/both present.
        assert_eq!(ignored_remote_flags(&send_invocation(&["hi"], &[])), Vec::<&str>::new());
        assert_eq!(
            ignored_remote_flags(&send_invocation(&["hi"], &[("submit", "true")])),
            vec!["submit"]
        );
        assert_eq!(
            ignored_remote_flags(&send_invocation(&["hi"], &[("yes", "true")])),
            vec!["yes"]
        );
        assert_eq!(
            ignored_remote_flags(&send_invocation(&["hi"], &[("submit", "true"), ("yes", "true")])),
            vec!["submit", "yes"]
        );
    }

    #[test]
    fn to_remote_with_no_cache_points_at_peer_pull() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-no-cache");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::peer_store::save_peers(&[test_peer("yomi-strix", "http://127.0.0.1:9/")]).unwrap();

        // Peer registered but NEVER pulled — no `state/peer-cache/…` file at
        // all. Never an auto-pull: a clean error pointing at `peer pull`.
        let out = session_send(&send_invocation(
            &["hi"],
            &[("to", "yomi-strix/brave-otter"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "peer-never-pulled");
        assert!(out.message.contains("peer pull"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_remote_resolves_against_the_cache_and_attempts_delivery() {
        // No mock HTTP server: `peer.url` names a closed loopback port so
        // the underlying curl POST fails FAST and deterministically. This
        // proves resolution reached exactly ONE remote session and the door
        // actually attempted the network delivery (the part THIS phase
        // owns) — not that the delivery succeeds, which is `aoide-client`'s
        // own transport, untouched here beyond threading `context_id`.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-deliver");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::peer_store::save_peers(&[test_peer("yomi-strix", "http://127.0.0.1:9/")]).unwrap();
        aoide_storage::peer_store::save_peer_cache(&test_cache(
            "yomi-strix",
            peer_graph_json(&[("sess-remote-1", Some("misty-comet"), "root")]),
        ))
        .unwrap();

        // `--submit`/`--yes` both passed too — accepted-but-unused for a
        // remote send; the Outcome must say so rather than leaving a caller
        // who habitually passes them guessing (review nit).
        let out = session_send(&send_invocation(
            &["hi", "there"],
            &[("to", "yomi-strix/misty-comet"), ("yes", "true"), ("submit", "true")],
        ));
        assert_eq!(
            out.status,
            aoide_protocol::output::Status::Error,
            "the closed loopback port refuses the POST: {}",
            out.message
        );
        assert_eq!(out.data.as_ref().unwrap()["reason"], "peer-send-failed");
        assert_eq!(out.data.as_ref().unwrap()["remoteSessionId"], "sess-remote-1");
        assert_eq!(
            out.data.as_ref().unwrap()["ignoredFlags"],
            json!(["submit", "yes"]),
        );
        assert!(
            out.message.contains("--submit, --yes ignored"),
            "msg: {}", out.message
        );

        let log = std::fs::read_to_string(root.join("log")).unwrap_or_default();
        assert!(log.contains("graph.send"), "audit line written even on a failed remote delivery: {log}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_remote_ambiguous_in_the_cache_lists_peer_session_labels() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-ambiguous");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::peer_store::save_peers(&[test_peer("yomi-strix", "http://127.0.0.1:9/")]).unwrap();
        aoide_storage::peer_store::save_peer_cache(&test_cache(
            "yomi-strix",
            peer_graph_json(&[
                ("sess-remote-1", Some("misty-comet"), "root"),
                ("sess-remote-2", Some("misty-comet"), "child"),
            ]),
        ))
        .unwrap();

        let out = session_send(&send_invocation(
            &["hi"],
            &[("to", "yomi-strix/misty-comet"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "ambiguous");
        assert_eq!(out.data.as_ref().unwrap()["candidates"].as_array().unwrap().len(), 2);
        assert!(out.message.contains("misty-comet"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_remote_not_found_in_the_cache_lists_available_sessions() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-notfound");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::peer_store::save_peers(&[test_peer("yomi-strix", "http://127.0.0.1:9/")]).unwrap();
        aoide_storage::peer_store::save_peer_cache(&test_cache(
            "yomi-strix",
            peer_graph_json(&[("sess-remote-1", Some("misty-comet"), "root")]),
        ))
        .unwrap();

        let out = session_send(&send_invocation(
            &["hi"],
            &[("to", "yomi-strix/ghost-name"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-found");
        assert!(out.message.contains("misty-comet"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hook_event_mapping_covers_the_lifecycle_and_ignores_the_rest() {
        let start = map_hook(
            &CLAUDE_PROFILE,
            &json!({ "session_id": "s", "hook_event_name": "SessionStart", "cwd": "/w" }),
        )
        .unwrap();
        assert!(matches!(start, HookAction::Start { cwd: Some(_), .. }));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "UserPromptSubmit" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "working"
        ));
        // A non-Task tool → ToolStart on the session (owner), tool as activity.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash" }))
                .unwrap(),
            HookAction::ToolStart { ref owner, ref activity, spawn: None, .. }
                if owner == "s" && activity.as_deref() == Some("Bash")
        ));
        // PostToolUse → ToolEnd on the same owner (part of the awaiting-clearing set).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Bash" }))
                .unwrap(),
            HookAction::ToolEnd { ref owner, end_sub: None, .. } if owner == "s"
        ));
        // A Task tool → ToolStart carrying a SubSpawn (the child node to create),
        // keyed by its tool_use_id, named from the description.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Task",
                "tool_use_id": "tuABC",
                "tool_input": { "description": "explore the auth module", "subagent_type": "Explore" }
            })).unwrap(),
            HookAction::ToolStart { spawn: Some(ref sp), .. }
                if sp.sub_id == "sub:tuABC" && sp.name == "explore the auth module" && sp.agent_type == "Explore"
        ));
        // A tool fired INSIDE a sub-agent (parent_tool_use_id present) routes to
        // the sub-node, not the session — the nesting/activity-routing rule.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Grep",
                "parent_tool_use_id": "tuABC"
            })).unwrap(),
            HookAction::ToolStart { ref owner, .. } if owner == "sub:tuABC"
        ));
        // PostToolUse(Task) closes the child; SubagentStop is the backstop.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Task",
                "tool_use_id": "tuABC"
            })).unwrap(),
            HookAction::ToolEnd { end_sub: Some(ref e), .. } if e == "sub:tuABC"
        ));
        // This harness's own dispatch tool is named `Agent`, not `Task`. It must
        // spawn/close the sub-node identically — same tool_input field names
        // (`description`, `subagent_type`), so the child is named the same way.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                "tool_use_id": "tuAG",
                "tool_input": { "description": "explore the auth module", "subagent_type": "Explore" }
            })).unwrap(),
            HookAction::ToolStart { spawn: Some(ref sp), .. }
                if sp.sub_id == "sub:tuAG" && sp.name == "explore the auth module" && sp.agent_type == "Explore"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                "tool_use_id": "tuAG"
            })).unwrap(),
            HookAction::ToolEnd { end_sub: Some(ref e), .. } if e == "sub:tuAG"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStop", "parent_tool_use_id": "tuABC"
            })).unwrap(),
            HookAction::SubEnd { ref sub_id } if sub_id == "sub:tuABC"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStart",
                "parent_tool_use_id": "tuABC", "agent_type": "Explore"
            })).unwrap(),
            HookAction::SubEnsure { ref sub_id, ref agent_type, create, .. }
                if sub_id == "sub:tuABC" && agent_type == "Explore" && create
        ));
        // ASYNC `Agent` dispatch: its PostToolUse fires at LAUNCH
        // (`tool_response.isAsync == true`), NOT at completion. It must NOT end the
        // node — it re-keys `sub:<tool_use_id>` → `sub:<agentId>` (the only place
        // both ids co-occur) so the later SubagentStop can find it.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                "tool_use_id": "tuAsync",
                "tool_response": { "isAsync": true, "status": "async_launched", "agentId": "agz1" }
            })).unwrap(),
            HookAction::SubRekey { ref from_sub_id, ref to_sub_id, .. }
                if from_sub_id == "sub:tuAsync" && to_sub_id == "sub:agz1"
        ));
        // The async lifecycle events carry ONLY `agent_id` (no parent_tool_use_id):
        // SubagentStart falls back to it as an enrich-only ensure (create=false);
        // SubagentStop falls back to it to close the re-keyed node.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStart",
                "agent_id": "agz1", "agent_type": "general-purpose"
            })).unwrap(),
            HookAction::SubEnsure { ref sub_id, create, .. }
                if sub_id == "sub:agz1" && !create
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s", "hook_event_name": "SubagentStop", "agent_id": "agz1"
            })).unwrap(),
            HookAction::SubEnd { ref sub_id } if sub_id == "sub:agz1"
        ));
        // Stop settles the turn to `stopped` — a finished turn is not "needs
        // input" (not `awaiting`), not a finished SESSION (not `done`), and not
        // yet cold (`idle` is where the reaper ages it an hour later).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "Stop" })).unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "stopped"
        ));
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "SessionEnd" })).unwrap(),
            HookAction::End { .. }
        ));
        // Notification with a permission message → an unconditional `awaiting`.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "Claude needs your permission to use Bash"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "awaiting"
        ));
        // The structured notification_type is honoured too (permission_prompt).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "notification_type": "permission_prompt"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "awaiting"
        ));
        // The ambiguous idle ping → the CONDITIONAL variant (guarded downstream).
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "Claude is waiting for your input"
            }))
            .unwrap(),
            HookAction::PhaseIfRunning { ref phase, .. } if phase == "awaiting"
        ));
        // …and via notification_type idle_prompt.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "notification_type": "idle_prompt"
            }))
            .unwrap(),
            HookAction::PhaseIfRunning { ref phase, .. } if phase == "awaiting"
        ));
        // "permission" match is case-insensitive.
        assert!(matches!(
            map_hook(&CLAUDE_PROFILE, &json!({
                "session_id": "s",
                "hook_event_name": "Notification",
                "message": "PERMISSION required"
            }))
            .unwrap(),
            HookAction::Phase { ref phase, .. } if phase == "awaiting"
        ));
        // A Notification with an unrecognised or absent message → no action.
        assert!(map_hook(
            &CLAUDE_PROFILE,
            &json!({ "session_id": "s", "hook_event_name": "Notification", "message": "hello" })
        )
        .is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "Notification" })).is_none());
        // Unknown event, missing event, and empty/absent session_id → no action.
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s", "hook_event_name": "Zzz" })).is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "s" })).is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "hook_event_name": "SessionStart" })).is_none());
        assert!(map_hook(&CLAUDE_PROFILE, &json!({ "session_id": "", "hook_event_name": "SessionStart" })).is_none());
    }
    #[test]
    fn hook_garbage_stdin_is_an_ok_noop_never_nonzero() {
        // Every one of these is empty/garbage/unmapped: an ok no-op that touches
        // no stage file (so the live stage is safe even without an override).
        for bad in [
            "",
            "   ",
            "not json at all",
            "{",
            "[]",
            "42",
            "\"a string\"",
            r#"{ "session_id": "x" }"#,                       // no event
            r#"{ "hook_event_name": "SessionStart" }"#,        // no id
            r#"{ "session_id": "x", "hook_event_name": "Zzz" }"#, // unmapped
        ] {
            let out = hook_from_str(bad);
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "input: {bad:?}");
            assert_eq!(out.render(false).1, aoide_protocol::output::exit::OK);
            assert_eq!(out.data.unwrap()["action"], "none", "input: {bad:?}");
        }
    }
    #[test]
    fn hook_lifecycle_start_running_waiting_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        // SessionStart registers the session (agent claude, cwd from payload).
        let out = hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "extra": 9 }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "claude");
        assert_eq!(s.sessions[0].cwd, "/proj");

        // A FRESH registration is at rest and cold: `idle`, never `stopped`.
        assert_eq!(s.sessions[0].state, "idle");

        // PreToolUse → working, Stop → stopped (latest hook phase wins). The
        // canonical live state now lands on sessions.json too (the widget file).
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "PreToolUse" }"#);
        let s_working: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_working.sessions[0].state, "working");
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "Stop" }"#);
        let (_, ss, hh) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss.sessions, &hh.hooks)[0].state, "stopped");
        let s_stopped: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_stopped.sessions[0].state, "stopped");

        // A RESUME (SessionStart on the SAME id) folds that `stopped` back to
        // `idle` — resumed and not yet active — in BOTH files, so the merge agrees.
        hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "source": "resume" }"#,
        );
        let s_resumed: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_resumed.sessions.len(), 1, "a resume never duplicates");
        assert_eq!(s_resumed.sessions[0].state, "idle");
        let (_, ss_r, hh_r) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss_r.sessions, &hh_r.hooks)[0].state, "idle");

        // A resume must still NOT reset a live turn: back to working, resume again.
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "PreToolUse" }"#);
        hook_from_str(
            r#"{ "session_id": "h1", "hook_event_name": "SessionStart", "cwd": "/proj", "source": "resume" }"#,
        );
        let s_live: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s_live.sessions[0].state, "working");
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "Stop" }"#);

        // SessionEnd → done in both files.
        hook_from_str(r#"{ "session_id": "h1", "hook_event_name": "SessionEnd" }"#);
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s2.sessions[0].state, "done");
        let h2: HooksFile = load_stage(&hooks_path()).unwrap();
        assert_eq!(h2.hooks.iter().find(|h| h.session_id == "h1").unwrap().phase, "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn hook_notification_blocks_and_the_clearing_set_lifts_it() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("sess-blocked");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let live_phase = |id: &str| -> String {
            let h: HooksFile = load_stage(&hooks_path()).unwrap();
            h.hooks
                .iter()
                .find(|r| r.session_id == id)
                .map(|r| r.phase.clone())
                .unwrap_or_default()
        };

        // Register, then drive to a live turn.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "PreToolUse" }"#);
        assert_eq!(live_phase("b1"), "working");

        // A permission Notification → awaiting, unconditionally.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude needs your permission to use Bash" }"#,
        );
        assert_eq!(live_phase("b1"), "awaiting");

        // PostToolUse (the approval → tool-ran edge) lifts the fermata → working.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "PostToolUse" }"#);
        assert_eq!(live_phase("b1"), "working");

        // The ambiguous idle ping, mid-turn (working), is a real mid-turn
        // question → awaiting.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude is waiting for your input" }"#,
        );
        assert_eq!(live_phase("b1"), "awaiting");

        // Stop settles the turn → stopped.
        hook_from_str(r#"{ "session_id": "b1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_phase("b1"), "stopped");

        // The SAME idle ping on a SETTLED (stopped) session is a no-op — the ~60s
        // heartbeat must NOT flip a quietly-finished turn to awaiting.
        let out = hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "Claude is waiting for your input" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(live_phase("b1"), "stopped");

        // A garbage/absent-message Notification is an ok no-op (action:none), and
        // never touches the phase.
        let noop = hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification", "message": "hi" }"#,
        );
        assert_eq!(noop.data.unwrap()["action"], "none");
        assert_eq!(live_phase("b1"), "stopped");

        // awaiting flows through the merge opaquely as the node state.
        hook_from_str(
            r#"{ "session_id": "b1", "hook_event_name": "Notification",
                 "message": "permission needed" }"#,
        );
        let (_, ss, hh) = load_inputs("test").unwrap();
        assert_eq!(merged_sessions(&ss.sessions, &hh.hooks)[0].state, "awaiting");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn first_user_prompt_names_the_session_set_once() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("name");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        hook_from_str(r#"{ "session_id": "n1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        // First prompt names the session.
        hook_from_str(
            r#"{ "session_id": "n1", "hook_event_name": "UserPromptSubmit",
                 "prompt": "fix the flaky auth test\nand rerun CI" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].title.as_deref(), Some("fix the flaky auth test"));

        // A LATER prompt must NOT rename it (set-once).
        hook_from_str(
            r#"{ "session_id": "n1", "hook_event_name": "UserPromptSubmit",
                 "prompt": "now do something else entirely" }"#,
        );
        let s2: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s2.sessions[0].title.as_deref(),
            Some("fix the flaky auth test"),
            "the first prompt names the session; later prompts don't rename it"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn subagent_task_builds_nests_and_collapses_the_tree() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("subagent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        // A claude session runs, then spawns a Task sub-agent.
        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "UserPromptSubmit", "prompt": "audit the repo" }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Task",
                 "tool_use_id": "t1",
                 "tool_input": { "description": "map the bridge", "subagent_type": "Explore" } }"#,
        );
        let ss = load();
        let sub = find(&ss, "sub:t1").expect("the Task sub-node is created");
        assert_eq!(sub.parent_session_id.as_deref(), Some("a"));
        assert_eq!(sub.kind.as_deref(), Some("subagent"));
        assert_eq!(sub.state, "working");
        assert_eq!(sub.title.as_deref(), Some("map the bridge"));
        assert_eq!(sub.agent, "Explore");
        // The parent's activity reflects what its child is doing.
        assert_eq!(find(&ss, "a").unwrap().activity.as_deref(), Some("map the bridge"));

        // A tool fired INSIDE the sub-agent routes to the sub-node, not the session.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Grep",
                 "parent_tool_use_id": "t1" }"#,
        );
        assert_eq!(find(&load(), "sub:t1").unwrap().activity.as_deref(), Some("Grep"));

        // The Task returns → the sub-node is removed (the tree collapses).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Task",
                 "tool_use_id": "t1" }"#,
        );
        assert!(
            find(&load(), "sub:t1").is_none(),
            "the sub-node is removed when its Task returns"
        );

        // SessionEnd cascades: a still-open sub-node is cleaned with its session.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Task",
                 "tool_use_id": "t2", "tool_input": { "subagent_type": "Plan" } }"#,
        );
        assert!(find(&load(), "sub:t2").is_some());
        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionEnd" }"#);
        let end = load();
        assert!(
            find(&end, "sub:t2").is_none(),
            "SessionEnd removes the sub-agent subtree"
        );
        assert_eq!(find(&end, "a").unwrap().state, "done");

        // The `Agent` tool (this harness's dispatch name) drives the tree the
        // same way `Task` does: spawn a sub-node on PreToolUse, collapse it on
        // PostToolUse — identical tool_input field names.
        hook_from_str(r#"{ "session_id": "b", "hook_event_name": "SessionStart", "cwd": "/p" }"#);
        hook_from_str(
            r#"{ "session_id": "b", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "g1",
                 "tool_input": { "description": "map the bridge", "subagent_type": "Explore" } }"#,
        );
        let ss = load();
        let sub = find(&ss, "sub:g1").expect("the Agent sub-node is created");
        assert_eq!(sub.parent_session_id.as_deref(), Some("b"));
        assert_eq!(sub.kind.as_deref(), Some("subagent"));
        assert_eq!(sub.state, "working");
        assert_eq!(sub.title.as_deref(), Some("map the bridge"));
        assert_eq!(sub.agent, "Explore");
        assert_eq!(find(&ss, "b").unwrap().activity.as_deref(), Some("map the bridge"));
        hook_from_str(
            r#"{ "session_id": "b", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "g1" }"#,
        );
        assert!(
            find(&load(), "sub:g1").is_none(),
            "the sub-node is removed when its Agent dispatch returns"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn async_agent_dispatch_survives_launch_and_dies_on_subagent_stop() {
        // The live-captured async `Agent` lifecycle (the reason the earlier fix
        // did nothing on the box): PreToolUse spawns `sub:<tool_use_id>`, but the
        // Agent's PostToolUse fires ~4ms later at LAUNCH (isAsync), NOT at
        // completion — so it must NOT tear the node down. It re-keys the node to
        // `sub:<agentId>`, and only the much-later SubagentStop (agent_id only)
        // ends it.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("async-agent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionStart", "cwd": "/p" }"#);

        // 1) PreToolUse → the node is born under the tool_use_id.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "toolu_X",
                 "tool_input": { "description": "diagnostic probe", "subagent_type": "general-purpose" } }"#,
        );
        let sub = find(&load(), "sub:toolu_X").expect("PreToolUse spawns the node under tool_use_id");
        assert_eq!(sub.parent_session_id.as_deref(), Some("a"));
        assert_eq!(sub.title.as_deref(), Some("diagnostic probe"));

        // 2) SubagentStart (agent_id only, fires BEFORE PostToolUse) is enrich-only:
        // the re-key has not landed, so it is a harmless no-op — it must NOT create
        // a second, bare `sub:<agentId>` node.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStart",
                 "agent_id": "agentX", "agent_type": "general-purpose" }"#,
        );
        assert!(
            find(&load(), "sub:agentX").is_none(),
            "SubagentStart must not create a node before the re-key lands"
        );
        assert!(find(&load(), "sub:toolu_X").is_some(), "the original node still stands");

        // 3) PostToolUse (isAsync) re-keys in place: same node, new id, every field
        // preserved. It must NOT be removed (the ~4ms teardown bug).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "toolu_X",
                 "tool_response": { "isAsync": true, "status": "async_launched", "agentId": "agentX" } }"#,
        );
        let ss = load();
        assert!(
            find(&ss, "sub:toolu_X").is_none(),
            "the tool_use_id key is gone (renamed, not removed)"
        );
        let renamed = find(&ss, "sub:agentX").expect("the node is now reachable by agent_id");
        assert_eq!(renamed.parent_session_id.as_deref(), Some("a"), "parent preserved");
        assert_eq!(renamed.title.as_deref(), Some("diagnostic probe"), "title preserved");
        assert_eq!(renamed.kind.as_deref(), Some("subagent"), "kind preserved");
        assert_eq!(renamed.state, "working", "state preserved (NOT torn down)");

        // 4) A late SubagentStart on the re-keyed node just confirms it (no dup).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStart",
                 "agent_id": "agentX", "agent_type": "general-purpose" }"#,
        );
        assert_eq!(
            load().sessions.iter().filter(|s| s.session_id == "sub:agentX").count(),
            1,
            "the confirming SubagentStart never duplicates the node"
        );

        // 5) SubagentStop (agent_id only, the REAL completion) closes the node.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStop", "agent_id": "agentX" }"#,
        );
        assert!(
            find(&load(), "sub:agentX").is_none(),
            "SubagentStop ends the re-keyed node — the tree collapses at real completion"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn two_concurrent_async_agents_never_cross_attribute() {
        // Two Agent dispatches in ONE turn (parallel). They share a prompt_id, so
        // it is NOT a reliable correlator — the tool_use_id ↔ agent_id link is
        // established per-dispatch by each call's OWN PostToolUse. Prove each node
        // re-keys to its own agent_id with zero cross-contamination, and each
        // SubagentStop ends only its own node.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("async-concurrent");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        hook_from_str(r#"{ "session_id": "a", "hook_event_name": "SessionStart", "cwd": "/p" }"#);

        // Both PreToolUse events (same prompt_id, distinct tool_use_ids).
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidA", "prompt_id": "P",
                 "tool_input": { "description": "task A", "subagent_type": "Explore" } }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PreToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidB", "prompt_id": "P",
                 "tool_input": { "description": "task B", "subagent_type": "Plan" } }"#,
        );
        assert!(find(&load(), "sub:tuidA").is_some());
        assert!(find(&load(), "sub:tuidB").is_some());

        // Each PostToolUse pairs its OWN tool_use_id with its OWN agentId. Deliver
        // them interleaved with the SubagentStarts to stress the ordering.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStart",
                 "agent_id": "aidA", "agent_type": "Explore" }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidB",
                 "tool_response": { "isAsync": true, "agentId": "aidB" } }"#,
        );
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "PostToolUse", "tool_name": "Agent",
                 "tool_use_id": "tuidA",
                 "tool_response": { "isAsync": true, "agentId": "aidA" } }"#,
        );

        // Each node re-keyed to ITS OWN agent_id, carrying ITS OWN title — no swap.
        let ss = load();
        assert!(find(&ss, "sub:tuidA").is_none() && find(&ss, "sub:tuidB").is_none());
        let a = find(&ss, "sub:aidA").expect("dispatch A reachable by aidA");
        let b = find(&ss, "sub:aidB").expect("dispatch B reachable by aidB");
        assert_eq!(a.title.as_deref(), Some("task A"), "A kept its own title");
        assert_eq!(b.title.as_deref(), Some("task B"), "B kept its own title");
        assert_eq!(a.agent, "Explore");
        assert_eq!(b.agent, "Plan");

        // SubagentStop for A ends ONLY A; B survives until its own stop.
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStop", "agent_id": "aidA" }"#,
        );
        let ss = load();
        assert!(find(&ss, "sub:aidA").is_none(), "A's stop removes A");
        assert!(find(&ss, "sub:aidB").is_some(), "B is untouched by A's stop");
        hook_from_str(
            r#"{ "session_id": "a", "hook_event_name": "SubagentStop", "agent_id": "aidB" }"#,
        );
        assert!(find(&load(), "sub:aidB").is_none(), "B's stop removes B");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn kimi_hook_lifecycle_start_prompt_permission_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("kimi-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let live_state = || -> String {
            let s: SessionsFile = load_stage(&sessions_path()).unwrap();
            s.sessions[0].state.clone()
        };

        // SessionStart registers the session — agent recorded as kimi.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "SessionStart", "cwd": "/proj" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "kimi");
        assert_eq!(s.sessions[0].cwd, "/proj");
        assert_eq!(s.sessions[0].state, "idle");

        // UserPromptSubmit → working.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "UserPromptSubmit", "user_prompt": "do the thing" }"#,
        );
        assert_eq!(live_state(), "working");

        // PermissionRequest → awaiting (kimi's dedicated needs-input event).
        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "PermissionRequest" }"#);
        assert_eq!(live_state(), "awaiting");

        // Kimi-only observational events are ok no-ops that never move the phase.
        for evt in ["Interrupt", "PreCompact", "PostCompact", "PermissionResult", "StopFailure", "PostToolUseFailure"] {
            let out = hook_for_profile(
                kimi,
                &format!(r#"{{ "session_id": "k1", "hook_event_name": "{evt}" }}"#),
            );
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "event: {evt}");
            assert_eq!(out.data.unwrap()["action"], "none", "event: {evt}");
        }
        assert_eq!(live_state(), "awaiting", "observational events never move the phase");

        // A kimi Notification carries background-task status, NOT a permission
        // prompt — no vocab, no awaiting.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "Notification", "notification_type": "task.completed" }"#,
        );
        assert_eq!(out.data.unwrap()["action"], "none");
        assert_eq!(live_state(), "awaiting");

        // Stop settles the turn; SessionEnd ends the session.
        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_state(), "stopped");
        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "SessionEnd" }"#);
        assert_eq!(live_state(), "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn kimi_hook_normalizes_native_fields_and_drives_the_subagent_lifecycle() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("kimi-norm");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let load = || -> SessionsFile { load_stage(&sessions_path()).unwrap() };
        let find = |ss: &SessionsFile, id: &str| ss.sessions.iter().find(|s| s.session_id == id).cloned();

        hook_for_profile(kimi, r#"{ "session_id": "k1", "hook_event_name": "SessionStart", "cwd": "/p" }"#);

        // UserPromptSubmit with kimi's content-block ARRAY names the session
        // (set-once) and moves it to working.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "UserPromptSubmit",
                 "prompt": [{"type":"text","text":"fix the flaky auth test"}] }"#,
        );
        let s = load();
        assert_eq!(s.sessions[0].title.as_deref(), Some("fix the flaky auth test"));
        assert_eq!(s.sessions[0].state, "working");
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "UserPromptSubmit",
                 "prompt": [{"type":"text","text":"renamed? no"}] }"#,
        );
        assert_eq!(
            load().sessions[0].title.as_deref(),
            Some("fix the flaky auth test"),
            "set-once survives normalization"
        );

        // PreToolUse(Agent) with kimi's tool_call_id spawns the child node —
        // this is kimi's ONLY sub-spawn path (its SubagentStart carries no ids).
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "PreToolUse",
                 "tool_name": "Agent", "tool_call_id": "tool_VvbM0",
                 "tool_input": { "description": "probe the repo", "prompt": "…" } }"#,
        );
        let s = load();
        let sub = find(&s, "sub:tool_VvbM0").expect("PreToolUse(Agent) spawns sub:<tool_call_id>");
        assert_eq!(sub.title.as_deref(), Some("probe the repo"));

        // Kimi's SubagentStart (agent_name only, no tool/agent id) is an ok
        // no-op: it must neither error nor mint a second node.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "SubagentStart",
                 "agent_name": "coder", "prompt": "do the child thing" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert_eq!(out.data.unwrap()["action"], "none");
        assert_eq!(
            load().sessions.iter().filter(|x| x.session_id.starts_with("sub:")).count(),
            1,
            "no id-less SubagentStart duplicate"
        );

        // PostToolUse(Agent) closes the node: kimi's Agent is SYNCHRONOUS
        // (status: completed in tool_output) and 0.31.1's SubagentStop is
        // unreliable/never fired — the tool boundary IS the close path.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "k1", "hook_event_name": "PostToolUse",
                 "tool_name": "Agent", "tool_call_id": "tool_VvbM0",
                 "tool_input": { "description": "probe the repo", "prompt": "…" },
                 "tool_output": "agent_id: agent-0\nstatus: completed\n\n[summary]\ndone" }"#,
        );
        assert!(find(&load(), "sub:tool_VvbM0").is_none(), "PostToolUse(Agent) closed the sub node");
        assert_eq!(load().sessions[0].state, "working", "the parent's turn runs on");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn pi_hook_lifecycle_start_prompt_tools_stop_end() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("pi-hook");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let pi = agent_profile("pi").unwrap();
        let live_state = || -> String {
            let s: SessionsFile = load_stage(&sessions_path()).unwrap();
            s.sessions[0].state.clone()
        };

        // SessionStart registers the session — agent recorded as pi, idle.
        let out = hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "SessionStart", "cwd": "/proj" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "pi");
        assert_eq!(s.sessions[0].cwd, "/proj");
        assert_eq!(s.sessions[0].state, "idle");

        // UserPromptSubmit names the session (set-once) and → working.
        hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "UserPromptSubmit", "user_prompt": "do the thing" }"#,
        );
        assert_eq!(live_state(), "working");
        assert_eq!(
            load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions[0].title.as_deref(),
            Some("do the thing")
        );

        // PreToolUse sets the tool as activity; PostToolUse clears it — with
        // pi's empty subagent_tools, no sub-node is ever spawned.
        hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "PreToolUse", "tool_name": "bash", "tool_use_id": "call_1" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].activity.as_deref(), Some("bash"));
        assert_eq!(
            s.sessions.iter().filter(|x| x.session_id.starts_with("sub:")).count(),
            0,
            "pi never spawns sub-nodes"
        );
        assert_eq!(live_state(), "working");
        hook_for_profile(
            pi,
            r#"{ "session_id": "p1", "hook_event_name": "PostToolUse", "tool_name": "bash", "tool_use_id": "call_1" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(s.sessions[0].activity.is_none(), "activity cleared at the tool end");
        assert_eq!(live_state(), "working");

        // pi events with no pi vocabulary are ok no-ops (never an error).
        for evt in ["Notification", "SubagentStart", "SubagentStop", "PermissionRequest"] {
            let out = hook_for_profile(
                pi,
                &format!(r#"{{ "session_id": "p1", "hook_event_name": "{evt}" }}"#),
            );
            assert_eq!(out.status, aoide_protocol::output::Status::Ok, "event: {evt}");
            assert_eq!(out.data.unwrap()["action"], "none", "event: {evt}");
        }
        assert_eq!(live_state(), "working", "no-op events never move the phase");

        // Stop settles the turn; SessionEnd ends the session.
        hook_for_profile(pi, r#"{ "session_id": "p1", "hook_event_name": "Stop" }"#);
        assert_eq!(live_state(), "stopped");
        hook_for_profile(pi, r#"{ "session_id": "p1", "hook_event_name": "SessionEnd" }"#);
        assert_eq!(live_state(), "done");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn pi_payload_pid_anchors_liveness_to_the_agent_process() {
        // THE pi regression: the door's ancestry walk can only discover the
        // TERMINAL's owning pid, which outlives a pi killed inside a
        // still-open terminal — the record then carries no signal that dies
        // with the agent, and the reaper can never reap it. The pi extension
        // self-reports `process.pid`; the door must store THAT as the
        // session's pid (at Start AND as a refresh on any later hook), so the
        // reaper's /proc signal fires when the agent dies, terminal or not.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("pi-pid");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let pi = agent_profile("pi").unwrap();

        // SessionStart with a self-reported pid: the record anchors on it (the
        // discovered terminal window is still stamped; the payload only
        // overrides the pid).
        hook_for_profile(
            pi,
            r#"{ "session_id": "p9", "hook_event_name": "SessionStart", "cwd": "/proj", "pid": 4242 }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions[0].pid, Some(4242));

        // Refresh: a record born with a terminal pid converges to the reported
        // pid on its next hook — the self-heal for pre-seam records, so a live
        // pi session becomes reapable without waiting for a fresh registration.
        // (A numeric-string pid is accepted too; pi's `process.pid` is a
        // number, this just pins the tolerant parse.)
        let mut f: SessionsFile = load_stage(&sessions_path()).unwrap();
        f.sessions.push(SessionRecord {
            session_id: "old".into(),
            agent: "pi".into(),
            state: "idle".into(),
            pid: Some(7),
            ..Default::default()
        });
        write_stage(&sessions_path(), &f).unwrap();
        hook_for_profile(
            pi,
            r#"{ "session_id": "old", "hook_event_name": "UserPromptSubmit", "user_prompt": "hi", "pid": "5150" }"#,
        );
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|x| x.session_id == "old").unwrap().pid,
            Some(5150)
        );

        // A payload WITHOUT pid (claude/kimi) never rewrites the stored pid.
        hook_for_profile(pi, r#"{ "session_id": "old", "hook_event_name": "Stop" }"#);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(
            s.sessions.iter().find(|x| x.session_id == "old").unwrap().pid,
            Some(5150)
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn pi_payload_ceiling_publishes_and_outranks_the_catalog() {
        // pi's extension reports its active model's `contextWindow` on every
        // hook payload. The door must publish it immediately (SessionStart
        // included) and the transcript refresh must PREFER it over the aoide
        // catalog — a custom/provider model the catalog has never heard of
        // gets the right meter instead of the conservative default.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("pi-ceil");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let pi = agent_profile("pi").unwrap();
        let ceil = |f: &SessionsFile| {
            f.sessions
                .iter()
                .find(|s| s.session_id == "pc1")
                .and_then(|s| s.context_ceiling)
        };

        // SessionStart carries the harness-reported window — published at once.
        hook_for_profile(
            pi,
            r#"{ "session_id": "pc1", "hook_event_name": "SessionStart", "cwd": "/proj", "context_ceiling": 1500000 }"#,
        );
        assert_eq!(ceil(&load_stage(&sessions_path()).unwrap()), Some(1_500_000));

        // A hook WITHOUT the field never clears the stored ceiling.
        hook_for_profile(
            pi,
            r#"{ "session_id": "pc1", "hook_event_name": "PreToolUse", "tool_name": "bash" }"#,
        );
        assert_eq!(ceil(&load_stage(&sessions_path()).unwrap()), Some(1_500_000));

        // The transcript refresh (say_boundary) prefers the reported ceiling:
        // the fixture's model resolves to 200k in the aoide catalog, but the
        // payload's 1.5M must win.
        let tx = std::path::Path::new(&stage).join("pc1.jsonl");
        std::fs::write(
            &tx,
            [
                r#"{"type":"model_change","provider":"claude","modelId":"claude-haiku-4-5"}"#,
                r#"{"type":"message","message":{"role":"assistant","content":[{"type":"text","text":"hi"}],"provider":"claude","model":"claude-haiku-4-5","usage":{"input":10,"output":5,"cacheRead":1,"cacheWrite":0}}}"#,
            ]
            .join("\n"),
        )
        .unwrap();
        let pay = format!(
            r#"{{ "session_id": "pc1", "hook_event_name": "PostToolUse", "tool_name": "bash", "cwd": "/proj", "transcript_path": "{}", "context_ceiling": 1500000 }}"#,
            tx.display()
        );
        hook_for_profile(pi, &pay);
        let f: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(ceil(&f), Some(1_500_000));
        assert_eq!(
            f.sessions
                .iter()
                .find(|s| s.session_id == "pc1")
                .unwrap()
                .model
                .as_deref(),
            Some("claude/claude-haiku-4-5"),
            "the refresh ran and read the fixture"
        );

        // WITHOUT the field, the same refresh falls back to the aoide catalog
        // (claude-haiku-4-5 → 200k).
        let pay = format!(
            r#"{{ "session_id": "pc1", "hook_event_name": "PostToolUse", "tool_name": "bash", "cwd": "/proj", "transcript_path": "{}" }}"#,
            tx.display()
        );
        hook_for_profile(pi, &pay);
        assert_eq!(ceil(&load_stage(&sessions_path()).unwrap()), Some(200_000));

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn hook_self_heals_a_pruned_session_on_its_next_event() {
        // The kimi regression: a live session got a SessionEnd payload (the
        // process never exited), was pruned as `done`, and no further event
        // could ever re-register it — SessionStart fires only at harness
        // launch. The door must treat the first event for an unknown id as an
        // implicit start.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("hook-heal");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let pay = |name: &str, extra: serde_json::Value| {
            let mut m = serde_json::Map::new();
            m.insert("hook_event_name".into(), name.into());
            m.insert("session_id".into(), "ghost-1".into());
            m.insert("cwd".into(), "/proj".into());
            for (k, v) in extra.as_object().unwrap() {
                m.insert(k.clone(), v.clone());
            }
            serde_json::Value::Object(m).to_string()
        };

        // SessionStart -> SessionEnd -> prune: the store record is GONE.
        hook_for_profile(kimi, &pay("SessionStart", json!({})));
        hook_for_profile(kimi, &pay("SessionEnd", json!({})));
        let mut f: SessionsFile = load_stage(&sessions_path()).unwrap();
        let mut h: HooksFile = load_stage(&hooks_path()).unwrap();
        let (kept, kept_h, _removed, _cleared) = prune_done(f.sessions, h.hooks);
        f.sessions = kept;
        h.hooks = kept_h;
        write_stage(&sessions_path(), &f).unwrap();
        write_stage(&hooks_path(), &h).unwrap();
        assert!(
            load_stage::<SessionsFile>(&sessions_path()).unwrap().sessions.is_empty(),
            "precondition: the session record is gone"
        );

        // The next real event (a prompt) re-registers it, working + named.
        let out =
            hook_for_profile(kimi, &pay("UserPromptSubmit", json!({ "user_prompt": "revive" })));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert_eq!(s.sessions.len(), 1);
        assert_eq!(s.sessions[0].agent, "kimi");
        assert_eq!(s.sessions[0].state, "working");
        assert_eq!(s.sessions[0].title.as_deref(), Some("revive"));
        assert_eq!(s.sessions[0].cwd, "/proj");

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }
    #[test]
    fn hook_end_for_an_unknown_session_stays_a_noop() {
        // SessionEnd must NOT create a session — ending something that never
        // existed is a no-op, not an implicit start.
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("hook-end-noop");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let payload = json!({
            "hook_event_name": "SessionEnd",
            "session_id": "ghost-2",
            "cwd": "/proj",
        })
        .to_string();
        let out = hook_for_profile(kimi, &payload);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(
            s.sessions.is_empty(),
            "SessionEnd for an unknown id never creates a session"
        );

        match saved {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn hook_agent_flag_selects_the_profile_or_errors() {
        // No flag → the claude default.
        let inv = flag_invocation(&["graph", "session", "hook"], &[]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "claude");
        // --agent kimi → the kimi profile.
        let inv = flag_invocation(&["graph", "session", "hook"], &[("agent", "kimi")]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "kimi");
        // --agent pi → the pi profile.
        let inv = flag_invocation(&["graph", "session", "hook"], &[("agent", "pi")]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "pi");
        // --agent bogus → a structured error (exit 1, reason + the known list).
        let inv = flag_invocation(&["graph", "session", "hook"], &[("agent", "bogus")]);
        let out = match hook_profile_for(&inv) {
            Err(o) => o,
            Ok(p) => panic!("bogus agent resolved to {}", p.name),
        };
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.render(false).1, aoide_protocol::output::exit::ERROR);
        let data = out.data.unwrap();
        assert_eq!(data["reason"], "unknown-agent");
        assert_eq!(data["agent"], "bogus");
        assert_eq!(data["known"], json!(["claude", "kimi", "pi"]));
    }
}
