//! `send` — the gated injection door — and the hook door (`session hook`)
//! that maps Claude-Code hook payloads onto the session/
//! sub-agent commands. The one place untrusted agent-bound text and untrusted
//! hook JSON both land, so every outcome is audited and a hook payload never
//! propagates as anything but data.
//!
//! **The gate's sender identity (LANE IDENTITY P-ID2, `docs/architecture/
//! CONTRACTS.md`'s identity section).** `sender_is_parent`/
//! `siblings_share_live_parent` key on a KERNEL-ATTESTED sender session —
//! never `AOIDE_SESSION_ID` (removed from every gate predicate; it remains
//! only as ATTRIBUTION, `resolve_sender`'s own doc). `deliver_local`
//! resolves that identity by walking THIS `aoide send` process's OWN real
//! `/proc` ancestry (`std::process::id()` — as unforgeable a kernel fact as
//! a peercred read of the same real process would be, since neither can
//! lie about the SAME real pid) to find a session whose sealed
//! `(pid, pidStarttime)` matches an ancestor AND whose seal verifies
//! against the daemon's LIVE public key (`real_attested_sender`'s own
//! doc — never cached, never read from a file). **Why the gate did NOT
//! move onto the per-session socket's accept side wholesale**, even though
//! that IS where `SO_PEERCRED` gets read (`graph/conduct.rs`): the socket
//! carries raw injected BYTES with no envelope, so `--yes`/the global
//! autogate switch (argv/env-only signals) cannot be told apart from an
//! ordinary send at the receiving end without inventing a wire protocol,
//! which this phase does not do. Peercred earns its keep at the accept
//! side for a narrower, complementary property instead: refusing a
//! connection that originates from within the TARGET's own session
//! subtree, unconditionally — the un-bypassable replacement for the OLD
//! client-side self-send guard this file used to carry (removed; see
//! `deliver_local`'s own comment on exactly why removing it is sound).
//!
//! `send` has two ways to name a target (messaging plan P-C3):
//! `--id <id>` (the original, unchanged) or `--to <target>` (resolved via
//! `aoide_storage::addr::resolve`, mutually exclusive with `--id` — see
//! [`session_send`]). A LOCAL `--to` match re-drives the exact `--id` path
//! (`deliver_local`); a REMOTE match (`node/<query>`, resolved against that
//! node's CACHED graph — never a live pull) delivers over A2A
//! `message/send` instead (`deliver_remote`) and runs no LOCAL gate at all,
//! since the receiving node's own `message_send` Inject arm is where that
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
    refresh_subagent_says, refresh_transcript_fields, set_owner_activity, stamp_attested_parent,
    stamp_harness_session_id, stamp_hook_ancestry, stored_phase,
};
use super::window::{discover_window, ensure_session_window, pid_ancestry, windowless_by_lineage_from_parent};
use aoide_protocol::agents::{agent_profile, known_agents, AgentProfile, HookClass, CLAUDE_PROFILE};
use aoide_protocol::{Door, Invocation};
use aoide_protocol::output::Outcome;
use aoide_storage::addr::{self, LocalCandidate, Resolution};
use aoide_storage::fs::{conducting_stage_dir, with_stage_lock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::os::unix::net::UnixStream;
#[cfg(test)]
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// The gap between the text payload write and the trailing submit-keystroke
/// write in [`deliver_local_with`] (task #124, live-diagnosed on kimi
/// 0.31.1). Kimi's TUI input parser paste-coalesces a `\r` that arrives in
/// the same event batch as preceding text into a composer NEWLINE rather
/// than Enter — the prompt sits unsubmitted; a `\r` arriving as its own
/// LATER read submits correctly. `conduct_multiplex`'s injection relay
/// (`graph/conduct.rs`) does one `read()`-then-pty-`write()` per `poll()`
/// wakeup, so two socket writes this far apart DO land as two distinct pty
/// writes — the relay needs no change. The value itself is empirically
/// pinned, not guessed: a live windowed kimi session on this box reproduced
/// the exact newline-not-submit failure at 120ms (proving the gap must
/// clear more than one syscall-level scheduling tick — kimi's own
/// paste-coalescing window is apparently tied to its input/render tick, not
/// to wall-clock micro-timing) and submitted cleanly, twice, at 300ms —
/// see the task #124 commit body for the screenshot-verified trace. Applied
/// UNIVERSALLY, every profile, one code path: a separately-written `\n` is
/// semantically identical to today's concatenated one for claude/pi, so
/// this is a delay, not a behavior change, for either. Zeroed under
/// `cfg(test)` so the unit suite doesn't pay it — a real delay is only
/// meaningful against a real pty reader; [`write_delivery`]'s own tests
/// pass a real, explicit delay when they need to observe the boundary.
// `pub(in crate::graph)`: the ring (`graph/doorbell.rs`, P-M5a-2) is a
// SECOND production caller of `write_delivery`, alongside `deliver_local_with`
// below — both raw-inject, both want the exact same submit-keystroke gap.
#[cfg(not(test))]
pub(in crate::graph) const SUBMIT_KEYSTROKE_DELAY: std::time::Duration = std::time::Duration::from_millis(300);
#[cfg(test)]
pub(in crate::graph) const SUBMIT_KEYSTROKE_DELAY: std::time::Duration = std::time::Duration::from_millis(0);

// ── `send`: the gated injection door ──────────────────────────────────

/// A pending (unapproved) injection, staged for the conductor to surface for a
/// one-key approve/deny. Written atomically to `state/stage/pending.json`.
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
/// `aoide_conduct::graph::pending_path()` rather than a second
/// `conducting_stage_dir().join("pending.json")` literal elsewhere (this
/// crate's own "no cross-crate copying" convention, widen-don't-fork).
///
/// `state/stage/pending.json` (command-defrag S1, 2026-08-27) — core
/// conducting state, moved off `song/stage/` (lyra's tree).
pub fn pending_path() -> PathBuf {
    conducting_stage_dir().join("pending.json")
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
/// satisfies `a == b` here too (same record, same parent field read twice)
/// — the client-side guard that used to refuse this case before the
/// predicate ran is GONE (LANE IDENTITY P-ID2; `deliver_local`'s own
/// comment on exactly why removing it is sound). This predicate can
/// therefore legitimately compute `true` for a genuinely self-attested
/// sender; the protection against a session injecting into its OWN pty
/// moved to the RECEIVING socket instead (`graph/conduct.rs`'s accept
/// loop, kernel-attested and un-bypassable, unlike the old guard here).
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

/// Does this injected text NAME the node? A `send` steer is a task, so it
/// renames; a bare KEYSTROKE answer is not. `session permit` types a single digit
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
/// can export before calling `send` — both are trivially spoofable by
/// anyone who can already run `aoide` as this user. This exists so a
/// receiving agent and the audit log can see who CLAIMS to have sent a
/// message, never to gate delivery on that claim — [`deliver_local`]'s gate
/// resolves a SEPARATE, kernel-attested sender identity for that (LANE
/// IDENTITY P-ID2, module doc); this function's output never reaches
/// `send_gate`'s inputs. **The still-wider door, unclosed by this phase:**
/// the per-session control socket (`graph/conduct.rs`) forwards bytes from
/// ANY connection its accept loop does not specifically refuse (P-ID2 adds
/// exactly one such refusal — a connection from within the TARGET's own
/// session subtree, `conduct.rs`'s own doc) — a genuinely unrelated
/// same-uid process connecting directly (bypassing `aoide send`
/// altogether) still injects with no gate and no attribution at all. This
/// label remains strictly additive display information, never a trust
/// boundary, for exactly that reason.
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
/// composer prefix stays deliberately narrower than the full bare `graph`/
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
/// not rename it (a deliberate `send` steer still overwrites via
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
            command: "send".to_string(),
            status: status.to_string(),
            message,
            untrusted_data: Some(text.to_string()),
        },
    );
}

/// `aoide send (--id <id> | --to <target>) [--submit] [--yes] -- <text
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
/// authentication) — but only when the target is an AGENT session
/// (`rec.agent` is neither `"shell"` nor empty, #116); a SHELL target's
/// delivered bytes are always verbatim, since a prefix would corrupt the
/// command line the shell reads, the same "delivered bytes arrive
/// verbatim" discipline `resurrect`'s restore delivery already holds. The
/// title, the keystroke check, and the audit `untrusted_data` all still
/// see the unprefixed text either way. Every outcome writes an audit
/// line, the sender folded into its message — the audit trail always
/// records who claimed to send it, regardless of whether the delivered
/// bytes carried a prefix.
///
/// **`--to <target>`** resolves `target` via [`aoide_storage::addr::resolve`]
/// against this box's current local sessions + registered nodes (see
/// [`session_send_to`]):
/// - a LOCAL match re-drives the exact `--id` path above, unchanged (same
///   gate, pending queue, provenance, audit) — `--to brave-otter` behaves
///   identically to `--id <that session's id>`.
/// - a REMOTE match (`node/<query>`) delivers over A2A `message/send`
///   instead of a local socket write — see [`session_send_to`]'s doc for the
///   full remote gating discussion (short version: **remote gating is the
///   RECEIVING node's job**, done inside its own `message_send` Inject arm;
///   this door's `--yes`/pending/autogate machinery above is a LOCAL-socket
///   concept and does not apply to a remote delivery, which always attempts
///   the network send — exactly like the existing `node pull` command
///   already does unconditionally).
///
/// With NEITHER flag, this is a usage error (same as before `--to` existed —
/// `require_flag` below is untouched).
pub fn session_send(inv: &Invocation) -> Outcome {
    let cmd = "send";
    let to = inv
        .flags
        .get("to")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let id_present = inv.flags.get("id").map(|s| !s.trim().is_empty()).unwrap_or(false);
    if to.is_some() && id_present {
        return Outcome::usage(
            cmd,
            "usage: aoide send (--id <id> | --to <target>) [--submit] [--yes] -- <text …> \
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
            "usage: aoide send --id <id> [--submit] [--yes] -- <text …>",
        );
    }
    deliver_local(inv, &id)
}

/// The REAL kernel-attested sender resolution [`deliver_local`] uses in
/// production (LANE IDENTITY P-ID2, module doc): fetches the daemon's
/// CURRENT public key over a fresh, ~100ms-bounded `ping` round trip
/// (`aoide_client::daemon::daemon_seal_pubkey_hex` — never cached, never
/// read from a file; that function's own doc explains why) and, if that
/// succeeds, walks THIS process's own real `/proc` ancestry via
/// [`crate::graph::identity::attested_sender`] to find a verified sealed session
/// among it. An unreachable daemon makes EVERY sender unidentified, not a
/// benign fallback: the credential's whole security property rests on a
/// LIVE daemon (OQ1-A, process liveness) — nothing to authenticate against
/// otherwise.
fn real_attested_sender(sessions: &[SessionRecord]) -> Option<String> {
    let pubkey = aoide_client::daemon::daemon_seal_pubkey_hex()?;
    crate::graph::identity::attested_sender(std::process::id() as i32, sessions, |rec| {
        crate::graph::identity::verify_seal_over(rec, &pubkey)
    })
}

/// The REAL attested-wrap resolution [`hook_ensure_session`] uses in
/// production (P-QOL-C §1): the same live daemon-key fetch
/// [`real_attested_sender`] makes, delegated to
/// [`crate::graph::identity::attested_wrap`] (the conducted-ancestor-only
/// walk) instead of `attested_sender`'s any-sealed-ancestor one, walked from
/// `hook_pid` — the HOOK process's own real pid (carried across the daemon
/// hop by [`HOOK_PID_FLAG`]), never this process's own `std::process::id()`
/// when running daemon-side. An unreachable daemon or an unreadable roster
/// makes every hook unattested (`None`), never a benign fallback — same
/// fail-closed posture as `real_attested_sender`.
fn real_attested_wrap(hook_pid: i32) -> Option<String> {
    let pubkey = aoide_client::daemon::daemon_seal_pubkey_hex()?;
    let sessions: SessionsFile = load_stage(&sessions_path()).ok()?;
    crate::graph::identity::attested_wrap(hook_pid, &sessions.sessions, |rec| {
        crate::graph::identity::verify_seal_over(rec, &pubkey)
    })
}

/// The exact body `--id` has always run, factored out so [`session_send_to`]'s
/// LOCAL resolution branch re-drives it unmodified rather than reimplementing
/// any piece of the gate/pending/provenance/audit path — the phase's SACRED
/// invariant. `id` is re-owned into a `String` immediately so every line
/// below is byte-identical to the pre-P-C3 function body (no `&id`/`id`
/// reference-vs-owned churn to review).
fn deliver_local(inv: &Invocation, id: &str) -> Outcome {
    deliver_local_with(inv, id, real_attested_sender)
}

/// Write `payload` to `stream`, then — when `submit` is set — a SEPARATE,
/// LATER write of `submit_key` alone, sleeping `delay` in between (task
/// #124; see [`SUBMIT_KEYSTROKE_DELAY`]'s doc comment for why this must be
/// two writes, never one concatenated write). `delay` is a parameter, not a
/// hardcoded read of the constant, so a test can pass a real, observable gap
/// directly — [`deliver_local_with`] is the one production caller, and it
/// always passes [`SUBMIT_KEYSTROKE_DELAY`].
///
/// `pub(in crate::graph)`: the ring (`graph/doorbell.rs`, P-M5a-2) is the
/// second production caller — raw injection into a target wrap's socket,
/// no gate, no provenance prefix, exactly this function's own contract.
pub(in crate::graph) fn write_delivery(
    stream: &mut UnixStream,
    payload: &[u8],
    submit: bool,
    submit_key: &str,
    delay: std::time::Duration,
) -> std::io::Result<()> {
    use std::io::Write as _;
    stream.write_all(payload)?;
    stream.flush()?;
    if submit {
        std::thread::sleep(delay);
        stream.write_all(submit_key.as_bytes())?;
        stream.flush()?;
    }
    Ok(())
}

/// [`deliver_local`]'s actual body, parameterized over the sender-identity
/// resolver (LANE IDENTITY P-ID2) so the gate/pending/provenance/audit path
/// stays exhaustively table-testable WITHOUT a live daemon: production
/// wires [`real_attested_sender`]; tests inject a fixed resolver (or the
/// real `attested_sender`/`verify_seal_over` pair against a test keypair,
/// proving the actual cryptographic machinery, not a stub) — see `mod
/// tests` below.
fn deliver_local_with(
    inv: &Invocation,
    id: &str,
    resolve_sender_id: impl Fn(&[SessionRecord]) -> Option<String>,
) -> Outcome {
    let cmd = "send";
    // Accept the exact `session:<id>` form `graph --json` emits for a
    // node id, so a copy-pasted id round-trips through `--id` — mirrors
    // `focus_session`'s identical `session:` stripping (window.rs). Only this
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
    let is_conductable = super::doc::is_conductable_now(rec);
    let socket = rec.socket.clone().filter(|s| !s.is_empty());
    let target_parent = rec.parent_session_id.clone();
    if !is_conductable {
        let message = match (rec.conductable == Some(true), socket.as_deref()) {
            (true, Some(path)) => {
                format!("session `{id}` is not conductable (control socket file `{path}` is gone)")
            }
            _ => format!("session `{id}` is not conductable (no control socket)"),
        };
        let out = Outcome::error(cmd, message)
            .with_data(json!({ "reason": "not-conductable", "id": id }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    }
    let socket = socket.unwrap();

    // The gate (LANE IDENTITY P-ID2, G1/G2 close). `--yes` and the global
    // autogate switch outrank identity entirely in `send_gate`'s own
    // precedence, so the kernel-attested sender resolution — a live daemon
    // round trip, `real_attested_sender`'s own doc — only runs when it can
    // actually change the outcome; skipping it otherwise is both a real
    // cost saving and correct (identity is irrelevant to those two arms).
    // Once resolved, the sender's own session id feeds the SAME
    // parent/sibling predicates as before — only WHERE that id comes from
    // changed: `resolve_sender_id` (module doc), never `AOIDE_SESSION_ID`.
    // The old client-side self-send guard is GONE (send.rs's own former
    // ~566): it existed because the env var could be forged to equal the
    // sender's own id, trivially satisfying "shares a live parent with
    // itself." A kernel-attested id cannot be forged the same way, but a
    // session genuinely running `aoide send --id <its-own-real-id>` from
    // within itself still resolves truthfully to itself — the protection
    // against THAT moved to the RECEIVING end instead
    // (`graph/conduct.rs`'s accept loop refuses any connection whose
    // peercred-derived ancestry roots back to the target's OWN session,
    // unconditionally, un-bypassably — stronger than the old guard, which
    // only ever covered well-behaved callers of `aoide send`).
    let (is_parent, is_sibling) = if yes || autogate_env() {
        (false, false) // never examined — send_gate's own precedence short-circuits first.
    } else {
        let sender = resolve_sender_id(&file.sessions);
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
        let is_sibling =
            siblings_share_live_parent(sender_parent.as_deref(), target_parent.as_deref(), parent_live);
        (is_parent, is_sibling)
    };
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

    // Deliver: connect + write the payload, THEN — on --submit — a SEPARATE
    // later write of the target's own submit keystroke (see
    // SUBMIT_KEYSTROKE_DELAY below for why this is two socket writes, never
    // one concatenated write). Resolved from `rec.agent` through the SAME
    // profile lookup `session permit` uses (`profile_for_agent`, promoted
    // `pub(in crate::graph)` in permit.rs) — an unregistered/empty agent
    // falls back to claude's `\n`, exactly as that lookup already does; no
    // second resolver. The provenance prefix (see [`provenance_prefix`]) is
    // then prepended to the payload as a whole — since the prefix itself is
    // newline-free, that lands it on the payload's first line only, never
    // disturbing a later line. The title (`one_line_title`), the
    // `names_the_node` check, and the audit `untrusted_data` below all keep
    // reading the ORIGINAL `text`, never this prefixed payload.
    let submit_key = super::permit::profile_for_agent(&rec.agent).submit_key;
    let mut payload = text.clone();
    // Display-only: the prefix names the sender by petname+tail when the
    // ALREADY-LOADED roster (`file.sessions`) resolves one, never the raw id
    // — `attributed_sender` itself (the raw id) is what `record_pending` and
    // `audit_send` still see, unaffected by this mapping.
    //
    // A send ATTRIBUTED TO THE TARGET ITSELF (`--from <target-id>`, or a
    // genuine env self-send) is never prefixed: "from yourself:" attributes
    // nothing, and the one caller that legitimately produces this shape —
    // `resurrect`'s restore delivery, putting a session's own prior
    // bytes back at its own prompt — needs those bytes verbatim (a prefixed
    // re-exec is a shell syntax error; a prefixed preload is a line no human
    // typed). Note this keys off the ATTRIBUTED sender, never the gate's
    // own kernel-attested sender identity (LANE IDENTITY P-ID2) — restore
    // is delivered from another session's env, which is exactly why it was
    // mis-prefixed. Not a gate
    // widening: attribution was already caller-asserted (`--from ""` is the
    // documented explicit-anonymous form that also skips the prefix), and
    // the audit line still records the attributed sender either way.
    //
    // A send to a SHELL target (#116) is likewise never prefixed, for the
    // SAME "the delivered bytes must arrive verbatim" reasoning restore
    // delivery already established (this discipline's precedent). A shell
    // has no concept of an attribution comment on its input — `rec.agent`
    // being `"shell"` (a plain terminal, `window.rs`'s auto-registration)
    // or empty (an unregistered/legacy record, the same fallback
    // `profile_for_agent` already treats as shell-shaped) means whatever
    // reaches the socket is read as a COMMAND LINE, not a message a human
    // or agent reads — `from <sender>: rm -rf /tmp/x` is not the command
    // `rm -rf /tmp/x`, corrupting it exactly like an unprefixed restore
    // would have. An AGENT target (any other `rec.agent`) still gets the
    // prefix: a prompt is not a command line, and the agent benefits from
    // seeing who sent it. Either way the audit line ([`audit_send`])
    // records the attributed sender regardless — this only ever changes
    // what rides in the bytes written to the socket.
    let attributed_to_target = attributed_sender.as_deref() == Some(id.as_str());
    let is_shell_target = matches!(rec.agent.as_str(), "" | "shell");
    let prefix_sender = attributed_sender
        .as_deref()
        .filter(|_| !attributed_to_target && !is_shell_target)
        .map(|s| display_sender(s, &file.sessions));
    if let Some(prefix) = provenance_prefix(prefix_sender.as_deref(), &text) {
        payload = format!("{prefix}{payload}");
    }
    match UnixStream::connect(&socket) {
        Ok(mut stream) => {
            if let Err(e) =
                write_delivery(&mut stream, payload.as_bytes(), submit, submit_key, SUBMIT_KEYSTROKE_DELAY)
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

    // File this delivered message into the mailbase as a receipt (messaging
    // plan P-M1, `docs/architecture/MAIL.md`, `state/mail/base.jsonl`) —
    // this is the ONE seam that covers every route a message takes to land
    // here: a direct `--id` send, a `--to <local target>` (re-drives this
    // exact function), a `pending approve` re-drive, AND the A2A server's
    // `do_inject` (`crates/server/src/a2a.rs`) — `do_inject` builds a
    // `send --id` invocation and calls `session_send` too, which for a
    // same-box `contextId` can only ever reach THIS branch (it never sets
    // `--to`). See `aoide_storage::mail`'s module doc for the full
    // reasoning and why `do_inject` does not file a second entry of its
    // own.
    //
    // `from` is `attributed_sender` — the SAME resolved sender the audit
    // line and the provenance prefix above already computed, empty string
    // for an anonymous/unresolved sender (`file_receipt`'s `from` is a
    // plain `&str`, not optional). `text` is the ORIGINAL message, not
    // `payload` (which carries the provenance prefix and/or submit
    // keystroke actually written to the socket). `to_name` is `id`: a
    // receipt's `to` is the session it was delivered to, not a mailbox
    // name a human reads by — MAIL.md's ruling that context is dropped,
    // not carried (a receipt is filed and forgotten, never read back by
    // `mail read`).
    //
    // Best-effort by design: a mailbase write failing must never turn an
    // ALREADY-DELIVERED message into a reported failure — any error is
    // folded into `changed` below, the returned status stays `Ok`.
    let mail_note = match aoide_storage::mail::file_receipt(
        attributed_sender.as_deref().unwrap_or(""),
        &id,
        &text,
    ) {
        Ok(()) => None,
        Err(e) => Some(format!("(mail filing failed: {e})")),
    };

    // Auto-rename the node to a one-line form of the delivered task — unless
    // the text is a keystroke answer rather than a task (see [`names_the_node`]).
    let renamed = names_the_node(&text);
    let title = if renamed {
        one_line_title(&text)
    } else {
        String::new()
    };
    let total_bytes = payload.len() + if submit { submit_key.len() } else { 0 };
    let mut changed = vec![format!("injected {total_bytes} byte(s) into {id}")];
    if let Some(note) = mail_note {
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
/// audit) or a REMOTE node+session (delivered over A2A `message/send`, see
/// [`deliver_remote`]). Ambiguity is always a hard error at every tier —
/// send is a delivering action, never narrows or guesses (mirrors
/// `aoide_storage::addr`'s own "ambiguity is an error, never first-match"
/// rule in its home context, restated here for send specifically).
fn session_send_to(inv: &Invocation, target: &str) -> Outcome {
    let cmd = "send";
    if inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "usage: aoide send --to <target> [--submit] [--yes] -- <text …>",
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
    let nodes = aoide_storage::node_store::load_nodes();
    let node_names: Vec<&str> = nodes.iter().map(|p| p.name.as_str()).collect();
    // P-D5's hub option, wired at its own ROUTING consumer (P-D6 rider,
    // `docs/architecture/AOIDED.md`'s "The hub option": "address resolution
    // prefers the hub as the default remote target when a --to query
    // matches no local session and names no explicit node") — every OTHER
    // tier (exact id, tail4, petname, host/role/petname, an explicit
    // `node/<rest>` prefix) still wins outright; the hub only ever fills in
    // for an otherwise-`NotFound` query. `who.rs`'s own `apply_filter` is a
    // LISTING/display filter, not a route, and deliberately keeps the plain
    // `addr::resolve` — the design doc names exactly two hub-preference
    // consumers (this `--to` resolution and the mail relay),
    // neither of which is `who`'s display semantics.
    let hub = nodes.iter().find(|p| p.hub).map(|p| p.name.as_str());

    match addr::resolve_with_hub(target, &host, &candidates, &node_names, hub) {
        Resolution::Local(id) => deliver_local(inv, &id),
        Resolution::Remote { node, query } => match nodes.iter().find(|p| p.name == node) {
            Some(p) => deliver_remote(inv, p, &query),
            // `addr::resolve` only ever names a node it was HANDED in
            // `node_names` above (built from this SAME `nodes` slice), so a
            // miss here is unreachable in practice — a defensive clean error
            // rather than an unwrap/panic.
            None => {
                let out = Outcome::error(cmd, format!("node `{node}` vanished mid-resolution"))
                    .with_data(json!({ "reason": "node-not-found", "node": node }));
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
            // addr.rs's documented "bare known-node-name" decision: a
            // slash-free token that names a registered node but matches no
            // local session is `NotFound`, not `Remote` (there is no
            // `<rest>` to defer without a slash) — hint the `node/<rest>`
            // form the user probably meant instead of leaving them guessing.
            let hint = if !target.contains('/') && node_names.contains(&target) {
                format!(
                    " (`{target}` names a known node, not a local session — did you mean `{target}/<session>`?)"
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

/// Extract every `kind:"session"` node from a node's CACHED graph document
/// as (sessionId, petname, role) triples — role derived from the SAME
/// document's own `spawned` edges. A `send`-local twin of
/// `who.rs::sessions_from_graph`'s extraction: not reused directly, since
/// that function returns `who`'s own display-only `SessionView`, a shape
/// this door has no use for — this needs only what [`LocalCandidate`] and an
/// error-message label need.
fn node_cached_sessions(graph: &Value) -> Vec<(String, Option<String>, &'static str)> {
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

/// Resolve `query` (the remainder after `node/` — see `aoide_storage::addr`'s
/// tier-5 doc) against `node`'s cached session set. Tries `query` AS TYPED
/// first — this covers the common, DOCUMENTED case (`addr.rs`'s own module
/// doc example: `Remote { node: "yomi-strix", query: "brave-otter" }`, a
/// bare petname) via tiers 1–3 (exact remote id, id tail4, bare petname) —
/// and only on a miss retries the RECONSTRUCTED `<node>/<query>` form, so a
/// `role/petname` remainder (what tier 5 stripped the host segment OFF of —
/// `addr.rs`'s "multi-segment rest… passes it through verbatim" test case)
/// still resolves via tier 4 against the node's own name standing in as
/// `host`. `nodes: &[]` on BOTH attempts: a remote-of-remote is not a shape
/// this phase resolves, so tier 5 can never fire here — see
/// [`deliver_remote`]'s `Resolution::Remote` arm.
fn resolve_remote_query(node: &str, query: &str, candidates: &[LocalCandidate<'_>]) -> Resolution {
    match addr::resolve(query, node, candidates, &[]) {
        Resolution::NotFound => addr::resolve(&format!("{node}/{query}"), node, candidates, &[]),
        other => other,
    }
}

/// A node session's display label for an error message — mirrors
/// `who.rs::sessions_from_graph`'s label construction
/// (`display::session_label` with the node's own name standing in as
/// `host`), so an ambiguous/not-found `--to` error names candidates the same
/// way `aoide session --hosts` would already be showing them.
fn node_session_label(node: &str, session_id: &str, petname: Option<&str>, role: &str) -> String {
    let rec = aoide_storage::records::SessionRecord {
        session_id: session_id.to_string(),
        petname: petname.map(String::from),
        ..Default::default()
    };
    aoide_storage::display::session_label(&rec, node, role)
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

/// Deliver `text` to ONE remote session on `node`, resolved from `query`
/// against `node`'s CACHED graph (`state/node-cache/<node>.json`) — a live
/// pull is deliberately NOT performed here (the plan's own call: the cache
/// is the addressing source for `send`; `session --hosts` is the probe
/// command). No cache
/// at all (node never pulled) is a clean error pointing at `node pull`,
/// never a silent auto-pull — a send should be predictable, not trigger a
/// network fetch the user didn't ask for.
///
/// **GATING**: unlike [`deliver_local`], this function runs NO gate at all —
/// `--yes`/pending/autogate (`send_gate`, `record_pending`) are a
/// LOCAL-SOCKET concept: they decide whether THIS process writes to a
/// socket it owns. A remote send is always ATTEMPTED over the network,
/// exactly like `node pull` already does unconditionally.
/// The RECEIVING node's own `message_send` Inject arm
/// (`aoide-server::a2a::message_send` → `do_inject`) is where the real gate
/// lives: it decides deliver-now vs. hold-pending off ITS OWN node-trust
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
/// OUR OWN `sessions.json` graph node — a remote node's graph is a
/// projection this box doesn't own (`who.rs`'s own invariant, restated here
/// for the same reason). Authenticated cross-host provenance is #51's
/// scope, not this phase's (messaging plan, "Verified facts").
fn deliver_remote(inv: &Invocation, node: &aoide_storage::node_store::Node, query: &str) -> Outcome {
    let cmd = "send";
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
            " (--{} ignored — gating a remote send is the receiving node's job)",
            ignored.join(", --")
        )
    };

    let cache = aoide_storage::node_store::load_node_cache(&node.name);
    let Some(graph) = cache.and_then(|c| c.graph) else {
        let out = Outcome::error(
            cmd,
            format!(
                "node `{}` has no cached graph — run `aoide node pull {}` first",
                node.name, node.name
            ),
        )
        .with_data(json!({ "reason": "node-never-pulled", "node": node.name }));
        audit_send(inv, "error", &out.message, &text);
        return out;
    };

    let sess = node_cached_sessions(&graph);
    let candidates: Vec<LocalCandidate<'_>> = sess
        .iter()
        .map(|(id, pet, role)| LocalCandidate { session_id: id, petname: pet.as_deref(), role })
        .collect();

    match resolve_remote_query(&node.name, query, &candidates) {
        Resolution::Local(remote_id) => {
            match aoide_client::commands::send_message_to_node(node, &text, &remote_id) {
                Ok(response) => {
                    let out = Outcome::ok(
                        cmd,
                        format!("delivered to `{remote_id}` on node `{}`{ignored_note}", node.name),
                    )
                    .changed(vec![format!("sent to {}/{remote_id}", node.name)])
                    .with_data(json!({
                        "node": node.name,
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
                        format!("delivering to `{remote_id}` on node `{}`: {e}{ignored_note}", node.name),
                    )
                    .with_data(json!({
                        "reason": "node-send-failed", "node": node.name, "remoteSessionId": remote_id,
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
                        node_session_label(&node.name, sid, pet.as_deref(), role)
                    })
                })
                .collect();
            let out = Outcome::error(
                cmd,
                format!(
                    "`{query}` is ambiguous on node `{}` — {} session(s) match: {}",
                    node.name,
                    ids.len(),
                    labels.join(", ")
                ),
            )
            .with_data(json!({ "reason": "ambiguous", "node": node.name, "query": query, "candidates": ids }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
        Resolution::NotFound => {
            let labels: Vec<String> = sess
                .iter()
                .map(|(id, pet, role)| node_session_label(&node.name, id, pet.as_deref(), role))
                .collect();
            let hint = if labels.is_empty() {
                format!(" (node `{}` has no cached sessions)", node.name)
            } else {
                format!(" — available on `{}`: {}", node.name, labels.join(", "))
            };
            let out = Outcome::error(
                cmd,
                format!("no session on node `{}` matches `{query}`{hint}", node.name),
            )
            .with_data(json!({ "reason": "not-found", "node": node.name, "query": query }));
            audit_send(inv, "error", &out.message, &text);
            out
        }
        Resolution::Remote { .. } => {
            // Unreachable: `resolve_remote_query` always passes `nodes: &[]`
            // to `addr::resolve`, so tier 5 (the only source of `Remote`)
            // never fires. A clean error, not a panic/unwrap, in case that
            // invariant ever drifts.
            let out = Outcome::error(
                cmd,
                format!("`{query}` resolved to a nested node reference, which is not supported"),
            )
            .with_data(json!({ "reason": "nested-remote-unsupported", "node": node.name, "query": query }));
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
/// semantic classes onto the session commands.
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
///
/// Attested re-parenting (P-QOL-C §1): BEFORE the exists/fresh split, walk
/// `hook_pid`'s real `/proc` ancestry for a verified conducted wrap
/// ([`real_attested_wrap`]) and, when found, re-stamp `parentSessionId` onto
/// it (`stamp_attested_parent`, change-only). This is what fixes an EXISTING
/// record: the exists branch below only ever refreshed `pid` and returned,
/// so a record born under an earlier wrap (a harness id that survives
/// `--resume`) never re-parented onto its CURRENT one — kernel process
/// evidence now runs on every hook, not just at birth. No daemon or no
/// resolvable ancestor → `None` → nothing touched, no error (fail-closed,
/// never a guess from cwd/title/workspace).
fn hook_ensure_session(profile: &AgentProfile, payload: &Value, id: &str, hook_pid: i32) {
    if id.starts_with("sub:") {
        return;
    }
    let attested = real_attested_wrap(hook_pid);
    if let Some(w) = attested.as_deref() {
        stamp_attested_parent(id, w);
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
    // Attested beats env — kernel truth over an ordinary same-user variable
    // a subprocess could set on itself. Same value feeds windowless
    // discovery below AND `do_session_start`: one resolution, no double
    // write (the fresh record doesn't exist yet, so `stamp_attested_parent`
    // above was a no-op; `do_session_start` is what actually stamps it).
    let parent = attested.as_deref().or(env_parent.as_deref());
    // Windowless by construction (task #89): a hook session whose
    // (about-to-be-set) parent's own lineage runs through an unwindowed
    // conducted wrap must never discover a window at all — that walk would
    // find the ENCLOSING terminal's window, not this session's own (it has
    // none), which is exactly what made the same-window eviction treat two
    // unrelated agents as stale twins.
    let windowless = existing
        .as_ref()
        .map(|f| windowless_by_lineage_from_parent(parent, &f.sessions))
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
        parent,
        None,
        None,
        None,
        pid,
    );
    stamp_hook_ancestry(id, &my_hook_ancestry());
}

/// Test-only convenience wrapper: every existing test in this module drives
/// `HookAction` handling through here rather than [`session_hook`]'s own
/// door gate, so it always allows the replay — the shape this function held
/// before P-M5a-2c split the gate out. `#[cfg(test)]` because production now
/// has no caller of this arity: [`session_hook`] calls
/// [`hook_for_profile_gated`] directly with the real `may_ring` value.
#[cfg(test)]
fn hook_for_profile(profile: &'static AgentProfile, buf: &str) -> Outcome {
    hook_for_profile_gated(profile, buf, true, std::process::id() as i32)
}

/// `may_ring` gates ONLY the Stop-hook ring replay inside `HookAction::
/// Phase`'s `phase == "stopped"` arm (P-M5a-2c: a ring executes only under
/// `Door::Daemon` — the daemon is the policy and audit boundary for every
/// ring). Every other action, and every other line of this function, is
/// unaffected by it. [`session_hook`] is the one production caller, passing
/// `inv.door == Door::Daemon` straight through — never a global, a
/// thread-local, or an env var. `hook_pid` (P-QOL-C §1) is threaded straight
/// through to every [`hook_ensure_session`] call site below, unexamined
/// here — see [`HOOK_PID_FLAG`]'s doc for why it cannot be re-derived from
/// `std::process::id()` on the daemon-routed path.
fn hook_for_profile_gated(
    profile: &'static AgentProfile,
    buf: &str,
    may_ring: bool,
    hook_pid: i32,
) -> Outcome {
    let cmd = "session.hook";
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
        // Even an event this door has no graph ACTION for (kimi's
        // PreCompact/StopFailure, a Notification whose detail classifies as
        // neither awaiting tier, …) still carries the harness's own raw
        // `session_id` whenever the payload does — capture it here too
        // (P-D7), not only on the mapped path below: a silent no-op for a
        // session that hasn't registered yet (nothing to stamp onto), a
        // same-value refresh for one that already has.
        if let Some(sid) = payload
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            stamp_harness_session_id(sid, sid);
        }
        return noop("unmapped-or-missing-event");
    };
    // The check lane (task #139 phase 2): "Stop records, the next
    // context-reaching event speaks." SessionStart (below, `HookAction::
    // Start`) drains any pending note and, when settled, runs the lane fresh;
    // `phase == "working"` (the one string only `UserPromptSubmit` produces
    // — see `map_hook`) drains it too, the normal case since a prompt
    // follows every Stop; `phase == "stopped"` (the one string only Stop
    // produces) runs the lane and stores the delta as pending WITHOUT
    // assigning it here — Stop's own stdout never reaches the model
    // (`checklane`'s module doc), so it has nothing to say to this Outcome.
    // Folded onto the final Outcome's message after the match so every OTHER
    // event stays exactly as chatty as it was.
    let mut lane_note: Option<String> = None;
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
            // is what makes a hook-only Claude session focus-jumpable.
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
            // The check lane's own settled/mid-turn split (task #139 phase
            // 2): read the STORED phase before either mutating call below
            // touches it — `do_session_phase_if` just past this block is the
            // only thing in this arm that can change `id`'s hooks.json phase
            // — so `mid_turn` reflects the phase as it stood when THIS event
            // fired, never one this same event already moved. `working` is
            // the one canonical phase a turn in flight produces; anything
            // else (a fresh id, `idle`, `stopped`, `done`) is a settled
            // boundary.
            let mid_turn = stored_phase(&id) == "working";
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
            // The check lane's own SessionStart trigger. Settled: run the
            // lane, drain any pending note, flag an already-red or
            // already-.nix-carrying tree. Mid-turn: no lane run, just replay
            // the stored baseline's own message (`checklane`'s module doc —
            // this is the half that closes the compaction-laundering bug).
            // Best-effort (`None` on a missing `cwd`, a disabled lane, or an
            // unloadable config) — never fails this hook.
            if let Some(cwd_str) = cwd.as_deref() {
                lane_note =
                    aoide_upkeep::checklane::on_session_start(&id, Path::new(cwd_str), mid_turn);
            }
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
            hook_ensure_session(profile, &payload, &id, hook_pid);
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
            // The check lane's own PromptSubmit trigger — `phase == "working"`
            // is the one string only `UserPromptSubmit` produces in this arm
            // (`map_hook`; PreToolUse routes through `ToolStart`, idle pings
            // through `PhaseIfRunning`), so this is a clean "new prompt" gate.
            // Drains whatever `on_stop` persisted last turn — no config load,
            // no subprocess, no `cwd` needed (`checklane`'s module doc).
            if phase == "working" {
                lane_note = aoide_upkeep::checklane::on_prompt_submit(&id);
            }
            // The check lane's own Stop trigger — `phase == "stopped"` is the
            // one string `HookClass::Stop` alone produces (`map_hook`), so
            // this never fires on a mere `working`/`awaiting` transition.
            // Re-runs the lane and persists the DELTA against the baseline
            // `on_session_start` recorded as this session's PENDING note, off
            // the raw payload's OWN `cwd` (not a stage lookup — every hook
            // payload carries it) — never assigned to `lane_note`: Stop's own
            // stdout never reaches the model, so there is nothing for this
            // Outcome to carry (`checklane`'s module doc). Best-effort, same
            // as the SessionStart arm: a no-op on a missing `cwd`, a disabled
            // lane, or an unloadable config.
            if phase == "stopped" {
                if let Some(cwd_str) = payload.get("cwd").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    aoide_upkeep::checklane::on_stop(&id, Path::new(cwd_str));
                }
                // The doorbell's Stop-hook replay trigger (P-M5a-2, MAIL.md
                // "Delivery and the doorbell", trigger (b)): the reader that
                // just went idle asks "what should ring me now" across every
                // mailbox it is armed under, rather than waiting for the next
                // letter to arrive. `id` here is the hook-fed AGENT CHILD,
                // never the wrap itself — a ring targets and injects into the
                // WRAP's own socket, and `armed_names_for_reader` keys on the
                // reader id `enrol_reader`/the petname fallback always enrol
                // (the wrap id), so this walks the child's own
                // `parentSessionId` and replays on the WRAP's behalf. No
                // parent (a bare terminal's own hook-fed session, never
                // conducted) means nothing to replay. Best-effort throughout,
                // exactly like the check lane above: a ring failure here must
                // never change this hook's own outcome, and a session-store
                // read that comes back empty is silently a no-op.
                // Gated on `may_ring` (P-M5a-2c): a ring executes only under
                // `Door::Daemon`, so this hook's local no-daemon fallback
                // must never replay — the latch stays armed for the next
                // daemon-handled trigger instead.
                if may_ring {
                    if let Ok(file) = load_stage::<SessionsFile>(&sessions_path()) {
                        if let Some(parent) = file
                            .sessions
                            .iter()
                            .find(|s| s.session_id == id)
                            .and_then(|s| s.parent_session_id.clone())
                        {
                            if let Ok(armed) = aoide_storage::mail::armed_names_for_reader(&parent) {
                                for (name, _) in armed {
                                    let _ = super::ring(&name, None);
                                }
                            }
                        }
                    }
                }
            }
            out
        }
        HookAction::PhaseIfRunning { id, phase } => {
            hook_ensure_session(profile, &payload, &id, hook_pid);
            ensure_session_window(&id);
            do_session_phase_if(&id, &phase, "working")
        }
        HookAction::ToolStart {
            session,
            owner,
            activity,
            spawn,
        } => {
            hook_ensure_session(profile, &payload, &session, hook_pid);
            ensure_session_window(&session);
            // Spawn the child FIRST so it exists before its parent's activity
            // points at it, then mark the owner working + its current activity.
            if let Some(sp) = spawn {
                do_subagent_spawn(&sp.sub_id, &owner, &sp.name, &sp.agent_type, true);
            }
            set_owner_activity(&owner, "working", activity.as_deref());
            Outcome::ok("session.hook", format!("tool start → {owner}"))
        }
        HookAction::ToolEnd {
            session,
            owner,
            end_sub,
        } => {
            hook_ensure_session(profile, &payload, &session, hook_pid);
            ensure_session_window(&session);
            if let Some(sub) = end_sub {
                do_subagent_end(&sub);
            }
            // The tool finished; the owner is still in its turn (working) but no
            // longer running that tool — clear its `activity`.
            set_owner_activity(&owner, "working", None);
            Outcome::ok("session.hook", format!("tool end → {owner}"))
        }
        HookAction::SubRekey {
            session,
            owner,
            from_sub_id,
            to_sub_id,
        } => {
            hook_ensure_session(profile, &payload, &session, hook_pid);
            ensure_session_window(&session);
            do_subagent_rekey(&from_sub_id, &to_sub_id);
            // The launch returned; the parent is no longer running that tool in
            // the foreground (its sub-agent runs on in the background) — clear the
            // activity, exactly as a normal tool boundary would.
            set_owner_activity(&owner, "working", None);
            Outcome::ok(
                "session.hook",
                format!("subagent rekey {from_sub_id} → {to_sub_id}"),
            )
        }
        HookAction::SubEnsure {
            sub_id,
            session,
            agent_type,
            create,
        } => {
            hook_ensure_session(profile, &payload, &session, hook_pid);
            do_subagent_spawn(&sub_id, &session, &agent_type, &agent_type, create);
            Outcome::ok("session.hook", format!("subagent {sub_id}"))
        }
        HookAction::SubEnd { sub_id } => {
            do_subagent_end(&sub_id);
            Outcome::ok("session.hook", format!("subagent end {sub_id}"))
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
    // Stamp `harnessSessionId` — the raw hook payload's OWN `session_id` —
    // onto the record NOW that the action above has registered/self-healed
    // it (`do_session_start`/`hook_ensure_session` have already run for this
    // event's `id`), so this covers a session's very first SessionStart, not
    // just later events (P-D7). Stamped regardless of whether it equals the
    // record's own `sessionId` — see `SessionRecord::harness_session_id`'s
    // doc comment for why a same-valued stamp is still meaningful.
    if let Some(sid) = payload
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        stamp_harness_session_id(sid, sid);
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
    // The check lane's note (if SessionStart or the PromptSubmit drain
    // produced one — Stop itself never does, see the `phase == "stopped"`
    // gate above) rides on the SAME message, separated by an em dash: this is
    // the one text channel that actually reaches the harness
    // (`hooks::door_command`'s claude wrapper stopped swallowing stdout for
    // exactly this reason), so the note has nowhere else to go.
    let note_for_data = lane_note.clone();
    let message = match lane_note {
        Some(note) => format!("{} — {note}", inner.message),
        None => inner.message,
    };
    Outcome::ok(cmd, message)
        .changed(inner.changed)
        .with_data(json!({
            "action": "applied",
            "innerStatus": format!("{:?}", inner.status),
            "innerData": inner.data,
            "checkLane": note_for_data,
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
            "session.hook",
            format!("unknown agent `{name}` (known: {})", known_agents().join(", ")),
        )
        .with_data(json!({ "reason": "unknown-agent", "agent": name, "known": known_agents() }))
    })
}

/// Internal-only flag key `session_hook`'s own P-D6 routing stamps onto a
/// SYNTHETIC invocation before calling `daemon_dispatch` — never set by a
/// real CLI/MCP/A2A caller, and never registered in this command's own
/// `flags:` list (`commands/graph.rs`), so it carries no schema surface.
/// The daemon `dispatch` wire (`{"op":"dispatch","path":...,"args":...,
/// "flags":...}`) has no channel for forwarding stdin bytes, and this door
/// is the one session-write command whose payload arrives THAT way rather than
/// through `path`/`args`/`flags` — smuggling the already-read payload
/// through the existing `flags` map avoids inventing new wire framing
/// (out of scope this phase, per the phase brief) while still making this
/// command routable: the DAEMON side sees this key present (its own
/// `invocation_from_dispatch_request` copies `flags` verbatim off the wire)
/// and reads the payload from there instead of its own process's stdin,
/// which is never the calling hook's own pipe.
const STDIN_PAYLOAD_FLAG: &str = "__daemon-stdin-payload";

/// Internal-only flag key carrying the HOOK process's own real pid across the
/// same daemon hop `STDIN_PAYLOAD_FLAG` rides (P-QOL-C §1) — never set by a
/// real CLI/MCP/A2A caller, never registered in `commands/graph.rs`'s
/// `flags:` list, no schema surface. `std::process::id()` read daemon-side
/// (inside `hook_ensure_session`'s attested-wrap walk) is `aoided`'s OWN
/// pid, not the hook's — useless as ancestry evidence (its parent is
/// `systemd --user`, not the agent's terminal tree). The hook process is
/// blocked on the daemon's reply while this rides along, so its `/proc`
/// entry is still live when the daemon walks it.
const HOOK_PID_FLAG: &str = "__daemon-hook-pid";

/// `session hook [--agent <name>]` — the hook door for agent harnesses.
/// Reads ONE JSON object from stdin and maps it (through the selected agent
/// profile) to the session commands. Never exits non-zero for a payload problem
/// (see [`hook_for_profile_gated`]); a bogus `--agent` is a plain CLI error.
///
/// P-D6 routing (`docs/architecture/AOIDED.md`'s "L4"): stdin is read FIRST,
/// always, from THIS process's own pipe — a routed call cannot read it a
/// second time on the daemon's side, so the already-read bytes ride along
/// on [`STDIN_PAYLOAD_FLAG`] instead of the wire growing a new field. The
/// daemon-side invocation (flag present) skips both the routing attempt AND
/// the real stdin read, using the forwarded payload directly.
pub fn session_hook(inv: &Invocation) -> Outcome {
    use std::io::Read;
    let profile = match hook_profile_for(inv) {
        Ok(p) => p,
        Err(o) => return o,
    };
    // P-M5a-2c: the Stop-hook ring replay executes only under `Door::
    // Daemon` — the daemon is the policy and audit boundary for every ring,
    // the same ruling `doorbell.rs`'s own module doc states. `invocation_
    // from_dispatch_request` (`aoide-server`'s `daemon.rs`) builds a
    // `Door::Daemon` invocation LITERALLY, never off the wire, so this is
    // trustworthy on both branches below: the STDIN_PAYLOAD_FLAG branch is
    // exactly that routed invocation, and the local-fallback branch's `inv`
    // is whatever door the ORIGINAL caller actually used.
    let may_ring = inv.door == Door::Daemon;
    if let Some(payload) = inv.flags.get(STDIN_PAYLOAD_FLAG) {
        // Daemon side: `std::process::id()` here is `aoided`'s own pid, not
        // the hook's — use the pid the hook stamped onto the routed
        // invocation before the hop, falling back to this process's pid on
        // an absent or unparsable flag (never a hard failure of the hook).
        let hook_pid = inv
            .flags
            .get(HOOK_PID_FLAG)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or_else(|| std::process::id() as i32);
        return hook_for_profile_gated(profile, payload, may_ring, hook_pid);
    }
    let mut buf = String::new();
    let _ = std::io::stdin().lock().read_to_string(&mut buf);
    let routed = Invocation {
        path: inv.path.clone(),
        args: inv.args.clone(),
        flags: {
            let mut f = inv.flags.clone();
            f.insert(STDIN_PAYLOAD_FLAG.to_string(), buf.clone());
            f.insert(HOOK_PID_FLAG.to_string(), std::process::id().to_string());
            f
        },
        door: inv.door,
    };
    if let Some(outcome) = aoide_client::daemon::daemon_dispatch(&routed) {
        return outcome;
    }
    // Local, no-daemon fallback: THIS process is the hook itself.
    hook_for_profile_gated(profile, &buf, may_ring, std::process::id() as i32)
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
            log.contains("send") && log.contains("delivered"),
            "audit log carries the delivered send: {log}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_id_accepts_the_session_prefix_graph_view_emits() {
        // `graph --json` emits node ids as `session:<id>` (doc.rs's
        // `render`); an agent copying that field verbatim into `--id`
        // must resolve to the exact same session a bare `--id` would.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

        // The exact id `graph --json` would emit for this session.
        let prefixed = format!("session:{id}");
        let out = session_send(&send_invocation(
            &["hi", "there"],
            &[("id", prefixed.as_str()), ("submit", "true"), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        // The resolved id reported back is the BARE id — bare `graph`'s own
        // emitted contract is untouched, but the resolved target is the same
        // session a bare `--id` would have hit.
        assert_eq!(out.data.as_ref().unwrap()["id"], id);
        assert_eq!(String::from_utf8(got).unwrap(), "hi there\n");

        // An id carrying an UNKNOWN prefix is not special-cased — it still
        // errors as an unknown session, exactly as an unrecognised id always
        // has.
        let out = session_send(&send_invocation(
            &["hi"],
            &[("id", "nodeish:send-prefixed-target"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "session-not-found");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_delivered_local_send_is_filed_into_the_mailbase() {
        // Messaging plan P-M1: `deliver_local`'s success path is the one
        // seam that files a delivered message into `state/mail/base.jsonl`
        // as a receipt — see `aoide_storage::mail`'s module doc for why the
        // A2A door's `do_inject` does not need (and must not add) a second
        // append.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-mail");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::set_var("AOIDE_SESSION_ID", "orchestrator-1");

        let id = "send-mail-target";
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

        let entries = aoide_storage::mail::read_base().unwrap();
        assert_eq!(entries.len(), 1, "one delivered message, one mailbase entry");
        let e = &entries[0];
        assert_eq!(e.kind, aoide_storage::mail::ENTRY_TYPE_RECEIPT);
        assert_eq!(e.envelope.header.from.name, "orchestrator-1");
        assert_eq!(e.envelope.header.to.name, id);
        assert_eq!(e.envelope.text, "do the thing", "the RAW text, not the prefixed wire payload");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_send_left_pending_is_not_filed_into_the_mailbase_until_approved() {
        // Only a SUCCESSFUL delivery files — a held-pending send must not
        // appear in the mailbase at all yet.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-mail-pending");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_SESSION_ID");

        let id = "send-mail-pending-target";
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

        let entries = aoide_storage::mail::read_base().unwrap();
        assert!(entries.is_empty(), "a pending (undelivered) send never reaches the mailbase");

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_keystroke_answer_is_delivered_but_never_renames_the_node() {
        // `session permit` types a bare verdict digit through this door; a title
        // of `1` would erase the only label the dock identifies the session by.
        assert!(names_the_node("hello world"));
        assert!(names_the_node("fix the auth test"));
        assert!(names_the_node("見て")); // any script's letters name a node
        assert!(!names_the_node("1"));
        assert!(!names_the_node("3\n"));
        assert!(!names_the_node("  2  "));
        assert!(!names_the_node("")); // an empty send names nothing either

        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        // `session permit`'s bare digit must reach the socket byte-identical.
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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

    /// #116: a send to a SHELL target from a DIFFERENT session (so the
    /// `attributed_to_target`/self-attribution exemption above does NOT
    /// apply — this is the general case, not the restore special case) is
    /// STILL delivered with no provenance prefix. Before this fix, this
    /// exact shape delivered `from the-sender: fix the reaper\n` to a shell
    /// socket — a prefix a shell reads as the start of a command line, not
    /// attribution text, corrupting whatever command the sender meant to
    /// run. Same fixture as `delivered_payload_carries_the_provenance_
    /// prefix_but_the_title_does_not` immediately above, with the ONE
    /// difference load-bearing here: the target's `agent` is `"shell"`
    /// instead of `"claude"`.
    #[test]
    fn send_to_a_shell_target_from_another_session_is_delivered_verbatim_no_provenance_prefix() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-shell-verbatim");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::set_var("AOIDE_SESSION_ID", "the-sender");

        let id = "shell-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("shell"),
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
            "fix the reaper\n",
            "a shell target's delivered bytes carry NO provenance prefix, from anyone"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A send ATTRIBUTED TO THE TARGET ITSELF (`--from <target-id>`) delivers
    /// its bytes verbatim — no provenance prefix. This is `resurrect`'s
    /// restore-delivery shape: the session's own prior bytes going back to
    /// its own prompt. Pinned against the live P-C7 finding, where the
    /// restored re-exec arrived as `from quiet-birch (…1892): /run/…/sleep
    /// 900` and bash threw a syntax error instead of restoring anything.
    #[test]
    fn a_send_attributed_to_the_target_itself_is_delivered_unprefixed() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-self-attr");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        // The delivering process is some OTHER session — exactly restore's
        // shape: the daemon (or the resurrecting operator's shell) delivers,
        // but the bytes belong to the target. `--from` must beat this env.
        std::env::set_var("AOIDE_SESSION_ID", "the-resurrector");

        let id = "self-attr-target";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        do_session_start(
            id,
            Some("shell"),
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
            &["echo", "hello"],
            &[("id", id), ("from", id), ("yes", "true")],
        ));
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "echo hello",
            "self-attributed bytes arrive verbatim — no prefix, no submit key"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_permit_shaped_keystroke_is_delivered_with_no_prefix_even_with_a_sender() {
        // The regression that matters most: `session permit`'s bare-digit
        // verdict (or a hand-typed answer of the same shape) must reach the
        // socket as EXACTLY the digit + newline — a provenance prefix here
        // would corrupt the keystroke the target's TUI is waiting to read.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    fn write_delivery_performs_two_ordered_writes_when_submit_is_set() {
        // Task #124: kimi's TUI paste-coalesces a submit keystroke that
        // arrives in the SAME pty write as preceding text into a composer
        // newline, never Enter — so the fix is two SEPARATE socket writes
        // (text, then the submit key alone), not one concatenated write.
        // Back-to-back writes with NO gap can still coalesce in the kernel's
        // socket buffer before a blocked reader wakes (a stream socket
        // carries no message boundaries of its own) — which is exactly why
        // `delay` is a real, non-zero, injected value here rather than
        // `SUBMIT_KEYSTROKE_DELAY`'s own zeroed `cfg(test)` value: this test
        // needs to actually observe two separate `read()`s land, not merely
        // call `write_delivery` twice. The acceptor's two independent
        // `read()` calls (never `read_to_end`) are what makes a regression
        // back to one concatenated write visible: it would hand the whole
        // payload to the FIRST `read()`, leaving the second empty.
        let root = unique_stage("write-delivery-two-writes");
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join("s.sock");
        let listener = UnixListener::bind(&socket).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut first = [0u8; 256];
            let n1 = conn.read(&mut first).unwrap();
            let mut second = [0u8; 256];
            let n2 = conn.read(&mut second).unwrap();
            (first[..n1].to_vec(), second[..n2].to_vec())
        });

        let mut stream = UnixStream::connect(&socket).unwrap();
        write_delivery(
            &mut stream,
            b"hello world",
            true,
            "\r",
            std::time::Duration::from_millis(30),
        )
        .unwrap();
        let (first, second) = acc.join().unwrap();

        assert_eq!(
            String::from_utf8(first).unwrap(),
            "hello world",
            "the first socket write is the text payload alone, no submit key riding along"
        );
        assert_eq!(
            String::from_utf8(second).unwrap(),
            "\r",
            "the submit key arrives as its OWN later write — kimi's profile, not a fixed \\n"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn write_delivery_is_one_write_when_submit_is_not_set() {
        // The non-submit path is untouched: no `submit_key` write happens at
        // all, so an acceptor's `read_to_end` (blocking until the sender's
        // `UnixStream` drops and closes its half of the connection) sees
        // exactly the text and nothing trails it.
        let root = unique_stage("write-delivery-one-write");
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join("s.sock");
        let listener = UnixListener::bind(&socket).unwrap();

        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });

        {
            let mut stream = UnixStream::connect(&socket).unwrap();
            write_delivery(&mut stream, b"hello world", false, "\r", std::time::Duration::ZERO)
                .unwrap();
        } // drop closes the stream, unblocking the acceptor's read_to_end.
        let got = acc.join().unwrap();

        assert_eq!(
            String::from_utf8(got).unwrap(),
            "hello world",
            "no --submit means no submit-key write at all, text arrives unaccompanied"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_yes_to_an_unregistered_agent_defaults_to_newline_submit() {
        // An unregistered ("shell") or empty agent string falls back to the
        // claude profile's `\n` — the same fallback `profile_for_agent`
        // already applies for `session permit`.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    // ── LANE IDENTITY P-ID2: the kernel-attested gate ───────────────────────

    /// Seal an ALREADY-REGISTERED session record (`do_session_start`'s own
    /// `pid` param) with a REAL signature under `kp`, over its own live
    /// `pid` — mirrors exactly what `stamp_seal` writes in production
    /// (`server::daemon::mint_seal`/`seal_freshly_registered_session`).
    /// `pid` must be a real, live pid so `pid_starttime` resolves — every
    /// caller below passes `std::process::id()`, since `attested_sender`
    /// walks the CALLING TEST PROCESS's own real ancestry. `origin` is
    /// STAMPED onto the record first (`stamp_origin`, never just baked
    /// into the signed identity) — `verify_seal_over` reads `originClass`
    /// straight off the record's OWN `origin` field, so sealing over a
    /// value the record doesn't actually carry would mismatch the
    /// canonical string and silently fail verification (the exact bug
    /// this comment exists to keep from regressing: an earlier revision
    /// sealed over a caller-supplied string no `stamp_origin` call ever
    /// wrote, which verified against nothing and hung every caller's
    /// `accept()` join waiting for a delivery that could never happen).
    fn seal_test_session(id: &str, pid: i32, origin: &str, kp: &aoide_storage::identity::Keypair) {
        if !origin.is_empty() {
            crate::graph::session_store::stamp_origin(id, origin);
        }
        let starttime =
            crate::graph::window::pid_starttime(pid).expect("test pid must be a real, live pid");
        let issued_at = 1_700_000_000;
        let identity = aoide_storage::sealed_id::SealedIdentity {
            session_id: id.to_string(),
            pid,
            pid_starttime: starttime,
            origin_class: origin.to_string(),
            issued_at,
        };
        let seal_hex = aoide_storage::sealed_id::mint_seal(kp, &identity);
        crate::graph::session_store::stamp_seal(id, &seal_hex, issued_at);
    }

    /// The REAL `attested_sender`/`verify_seal_over` pipeline (module doc
    /// on why this is not a stub) pinned to a fixed test keypair — every
    /// "genuine" gate test below wires this in place of
    /// `real_attested_sender`'s live daemon ping, exercising the actual
    /// cryptographic verification without needing a running `aoided`.
    fn test_resolver(pubkey_hex: String) -> impl Fn(&[SessionRecord]) -> Option<String> {
        move |sessions| {
            crate::graph::identity::attested_sender(std::process::id() as i32, sessions, |rec| {
                crate::graph::identity::verify_seal_over(rec, &pubkey_hex)
            })
        }
    }

    #[test]
    fn send_delivers_when_sender_is_the_targets_parent() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG", "AOIDE_CONDUCT_AUTOGATE"]);

        let root = unique_stage("send-parent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no global autogate.

        let me = std::process::id() as i32;
        let kp = aoide_storage::identity::mint_ephemeral().unwrap();
        // The SENDER is the orchestrator session `orch` — sealed over THIS
        // TEST PROCESS's own real pid, since `attested_sender` walks the
        // calling process's own ancestry (self included).
        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, Some(me as u32));
        seal_test_session("orch", me, "local", &kp);

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

        // No --yes: delivery is authorised purely by the parent relationship,
        // resolved via the REAL sealed-ancestry pipeline.
        let out = deliver_local_with(
            &send_invocation(&["go"], &[("id", id), ("submit", "true")]),
            id,
            test_resolver(kp.info().pubkey_hex.clone()),
        );
        let got = acc.join().unwrap();

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "autogate-parent");
        // The attested sender (`orch`) doubles as the provenance attribution
        // ONLY when `--from`/`AOIDE_SESSION_ID` also names it — attribution
        // stays a SEPARATE axis from the gate (module doc); with neither set
        // here, no prefix is added.
        assert_eq!(String::from_utf8(got).unwrap(), "go\n");

        // An UNIDENTIFIED caller (the resolver finds no seal in its
        // ancestry at all — P-ID2's "no seal in ancestry" case, e.g. a
        // bare shell running `aoide send` with no conducted session above
        // it) stays pending, even for the SAME target `orch` genuinely
        // parents. An injected `None` resolver stands in — the crypto
        // `test_resolver` would keep finding `orch` regardless of what
        // OTHER unsealed sessions exist, since it walks THIS test
        // process's own real, unchanging ancestry; identity resolution
        // itself is exhaustively covered by `graph::identity`'s own tests.
        let out = deliver_local_with(
            &send_invocation(&["hi"], &[("id", id)]),
            id,
            |_sessions| None,
        );
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_delivers_between_siblings_of_a_live_parent() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_CONDUCT_SIBLING_AUTOGATE",
        ]);

        let root = unique_stage("send-sibling");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE"); // no global autogate.
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // default: enabled.

        let me = std::process::id() as i32;
        let kp = aoide_storage::identity::mint_ephemeral().unwrap();

        // A live parent `orch`, and two of its children: `sib-a` (the sender,
        // sealed over THIS test process's own pid, NOT conductable — it
        // never receives) and `sib-b` (the conductable TARGET). Neither is
        // the other's parent — only their shared, live parent makes this a
        // sibling send.
        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, None);
        do_session_start(
            "sib-a", Some("claude"), Some("/w"), None, Some("orch"), None, None, None, Some(me as u32),
        );
        seal_test_session("sib-a", me, "local", &kp);
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
        let acc = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
            buf
        });
        let out = deliver_local_with(
            &send_invocation(&["hey", "sib"], &[("id", target)]),
            target,
            test_resolver(kp.info().pubkey_hex.clone()),
        );
        let got = acc.join().unwrap();
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);
        assert_eq!(out.data.as_ref().unwrap()["gate"], "autogate-sibling");
        // No attribution set (`--from`/`AOIDE_SESSION_ID`) → no prefix, even
        // though the gate's sealed sender resolved successfully — attribution
        // and the gate are separate axes (module doc).
        assert_eq!(String::from_utf8(got).unwrap(), "hey sib");

        // (b) same pair, but the opt-out env is set → held pending, not delivered.
        std::env::set_var("AOIDE_CONDUCT_SIBLING_AUTOGATE", "0");
        let out = deliver_local_with(
            &send_invocation(&["hey", "again"], &[("id", target)]),
            target,
            test_resolver(kp.info().pubkey_hex.clone()),
        );
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // back to enabled.

        // (c) a cross-tree sender — the resolver truthfully attests to a
        // REAL, sealed session whose parent differs from the target's own
        // → pending: `siblings_share_live_parent` refuses it on the
        // parent-mismatch, not on identity. An INJECTED resolver stands in
        // here (not the crypto `test_resolver`, which would keep finding
        // `sib-a` — this test process's own real ancestry doesn't change
        // just because an unrelated record exists) — the identity
        // resolution itself is already exhaustively covered by
        // `graph::identity`'s own table tests; this proves the GATE
        // correctly refuses a genuinely different sender once resolved.
        do_session_start(
            "cross-sender", Some("claude"), Some("/w"), None, Some("other-parent"), None, None,
            None, None,
        );
        let out = deliver_local_with(
            &send_invocation(&["nope"], &[("id", target)]),
            target,
            |_sessions| Some("cross-sender".to_string()),
        );
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        // (d) an unidentified caller (the resolver finds nothing at all —
        // the P-ID2 "no seal in ancestry" case) → pending.
        let out = deliver_local_with(
            &send_invocation(&["nope"], &[("id", target)]),
            target,
            |_sessions| None,
        );
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);

        let _ = std::fs::remove_dir_all(&root);
    }
    /// LANE IDENTITY P-ID2: the OLD client-side `is_self_send` guard is
    /// gone (`send.rs`'s own module doc on where the protection moved).
    /// This pins the NEW split honestly: the GATE alone, fed a resolver
    /// that (truthfully) attests the sender AS the target itself, computes
    /// `autogate-sibling` and proceeds to connect+write — exactly what a
    /// genuinely-self-identified sender's gate arithmetic produces. The
    /// actual block now lives at the RECEIVING socket, proven by
    /// `conduct.rs`'s own `accept_refuses_a_connection_from_within_its_own_
    /// session_subtree` integration test — this test exists so a reader
    /// sees the responsibility named here, not silently missing.
    #[test]
    fn send_to_self_gate_arithmetic_would_deliver_the_block_now_lives_at_the_socket() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_CONDUCT_SIBLING_AUTOGATE",
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
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"), // a live parent — the sibling predicate DOES fire.
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

        // The resolver truthfully attests the sender AS the target itself —
        // exactly what a genuinely self-connecting process's kernel identity
        // would resolve to.
        let out = deliver_local_with(
            &send_invocation(&["do", "a", "thing"], &[("id", id)]),
            id,
            |_sessions| Some(id.to_string()),
        );
        acc.join().unwrap(); // the stand-in listener accepts unconditionally — this test is
                              // about the GATE's own arithmetic, not the real receiver's block.

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(
            out.data.as_ref().unwrap()["gate"],
            "autogate-sibling",
            "the gate itself no longer special-cases a self-attested sender — the guard moved"
        );
        assert_eq!(out.data.as_ref().unwrap()["delivered"], true);

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn global_autogate_env_outranks_the_sibling_label_even_when_both_apply() {
        // Precedence lock-in: when the global switch is on AND the sibling
        // predicate is true, the label must be the global arm's ("autogate"),
        // never "autogate-sibling" — a future refactor that reorders the `if`
        // chain in `send_gate` should trip this, not silently relabel deliveries.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_CONDUCT_SIBLING_AUTOGATE",
        ]);

        let root = unique_stage("send-sibling-done-parent");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        std::env::remove_var("AOIDE_CONDUCT_SIBLING_AUTOGATE"); // default: enabled.

        let me = std::process::id() as i32;
        let kp = aoide_storage::identity::mint_ephemeral().unwrap();

        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, None);
        do_session_start(
            "sib-a", Some("claude"), Some("/w"), None, Some("orch"), None, None, None, Some(me as u32),
        );
        seal_test_session("sib-a", me, "local", &kp);
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

        let out = deliver_local_with(
            &send_invocation(&["nope"], &[("id", target)]),
            target,
            test_resolver(kp.info().pubkey_hex),
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a dead-parent sibling send delivers nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    /// The G1 close, end to end, through the REAL production entry point
    /// (`session_send` → `deliver_local` → `real_attested_sender`, NOT the
    /// test-injected resolver every other test above uses): a forged
    /// `AOIDE_SESSION_ID` naming a genuine, live parent no longer flips
    /// pending → deliver, because the gate never reads it at all. No daemon
    /// is listening in this test environment, so `real_attested_sender`'s
    /// own live `ping` round trip returns `None` — the honest, fail-closed
    /// consequence of "the credential's security rests on a live daemon"
    /// (module doc), not a special case carved out for the test.
    #[test]
    fn send_ignores_a_forged_aoide_session_id_env_the_real_production_path() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_CONDUCT_AUTOGATE",
            "AOIDE_DAEMON_SOCKET",
            "AOIDE_SESSION_ID",
        ]);

        let root = unique_stage("send-forged-env");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        std::env::remove_var("AOIDE_CONDUCT_AUTOGATE");
        // No daemon listening on this socket — `daemon_seal_pubkey_hex`
        // must fail closed (`None`), never fall back to trusting the env.
        std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("no-such-daemon.sock"));

        do_session_start("orch", Some("claude"), Some("/w"), None, None, None, None, None, None);
        let id = "child-of-orch";
        let socket = conduct_socket_path(id);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap(); // prove nothing connects.
        do_session_start(
            id,
            Some("claude"),
            Some("/w"),
            None,
            Some("orch"), // a genuine, live parent — the exact shape the forgery targets.
            Some(true),
            Some(socket.to_str().unwrap()),
            None,
            None,
        );

        // Forge the env to claim the real parent's identity — no seal
        // backs this claim.
        std::env::set_var("AOIDE_SESSION_ID", "orch");
        let out = session_send(&send_invocation(&["go"], &[("id", id), ("submit", "true")]));

        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["state"], "pending", "a forged env must never flip pending → deliver");
        assert_eq!(out.data.as_ref().unwrap()["delivered"], false);
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a forged-env send delivers nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn send_unknown_or_unconductable_is_a_clean_error() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    #[test]
    fn send_to_a_wrap_whose_socket_file_is_gone_is_not_conductable() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("send-socket-gone");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        // `conductable: true` and a stored socket path — but nothing ever
        // bound that path, the shellbridge-rebuild scenario `is_conductable_now`
        // exists to catch.
        let never_bound = root.join("never-bound.sock");
        do_session_start(
            "gone",
            Some("claude"),
            Some("/w"),
            None,
            None,
            Some(true),
            Some(never_bound.to_str().unwrap()),
            None,
            None,
        );

        let out = session_send(&send_invocation(&["hi"], &[("id", "gone"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-conductable");
        assert!(out.message.contains("is gone"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── `--to` resolution (messaging plan P-C3) ───────────────────────────

    fn test_node(name: &str, url: &str) -> aoide_storage::node_store::Node {
        aoide_storage::node_store::Node {
            name: name.to_string(),
            url: url.to_string(),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-08-21T00:00:00Z".to_string(),
        }
    }

    fn test_cache(name: &str, graph: Value) -> aoide_storage::node_store::NodeCacheEntry {
        aoide_storage::node_store::NodeCacheEntry {
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
    /// document `node_cached_sessions` can extract back out of — a `role:
    /// "child"` entry gets a synthetic `spawned` edge so the role-derivation
    /// half of the extraction is exercised too, mirroring `who.rs`'s own
    /// `node_graph` test fixture.
    fn node_graph_json(sessions: &[(&str, Option<&str>, &str)]) -> Value {
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
        // only on a miss retrying the reconstructed `<node>/<query>` form
        // (tier 4, the `role/petname` remainder tier 5 stripped the host off
        // of).
        struct Case {
            name: &'static str,
            query: &'static str,
            candidates: Vec<(&'static str, Option<&'static str>, &'static str)>,
            expected: Resolution,
        }
        let node = "yomi-strix";
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
                name: "role/petname compound falls back to the reconstructed <node>/<query> form",
                query: "root/brave-otter",
                candidates: vec![("sess-aaaa-1111", Some("brave-otter"), "root")],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "petname collision on the node's own cache is ambiguous",
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
            let got = resolve_remote_query(node, c.query, &candidates);
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    fn to_unknown_bare_node_name_hints_the_slash_form() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-bare-node");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::node_store::save_nodes(&[test_node("yomi-strix", "http://127.0.0.1:9/")]).unwrap();

        // A slash-free query naming a KNOWN node but no local session is
        // `NotFound` (`addr.rs`'s documented bare-known-node-name decision,
        // never a whole-node `Remote`) — the error should hint the
        // `node/<rest>` form instead of leaving the user guessing.
        let out = session_send(&send_invocation(&["hi"], &[("to", "yomi-strix"), ("yes", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "not-found");
        assert!(out.message.contains("did you mean"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_unknown_target_not_found_with_no_hint_when_it_matches_no_known_node_either() {
        // The plain branch of `Resolution::NotFound`: `target` names neither
        // a local session nor a known node at all (no registered nodes, and
        // not slash-shaped), so the "did you mean `node/<rest>`?" hint must
        // NOT fire — a bare, unrecognized token gets the plain message.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-plain-notfound");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        // No nodes registered at all, no local sessions either.

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
    fn to_remote_with_no_cache_points_at_node_pull() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-no-cache");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::node_store::save_nodes(&[test_node("yomi-strix", "http://127.0.0.1:9/")]).unwrap();

        // Node registered but NEVER pulled — no `state/node-cache/…` file at
        // all. Never an auto-pull: a clean error pointing at `node pull`.
        let out = session_send(&send_invocation(
            &["hi"],
            &[("to", "yomi-strix/brave-otter"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "node-never-pulled");
        assert!(out.message.contains("node pull"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// P-D6 rider (`docs/architecture/AOIDED.md`'s "The hub option"): a
    /// `--to` query that matches no local session and names no node at all
    /// (no local candidates, no `node/` prefix, not even a bare known-node
    /// name) falls through every tier of `addr::resolve` to `NotFound` —
    /// with a hub node registered, `resolve_with_hub` fills that `NotFound`
    /// in as `Remote { node: <hub>, .. }` rather than leaving it an error.
    /// Proven unit-level with no live network, exactly as the phase's own
    /// test list asks: two nodes are registered, only one `hub: true`, and
    /// the assertion is that resolution reached THAT node specifically (its
    /// name shows up in the deterministic, network-free `node-never-pulled`
    /// error — same proof-shape `to_remote_with_no_cache_points_at_node_pull`
    /// already uses right above) — not the non-hub node, and not a plain
    /// "not-found" error.
    #[test]
    fn send_to_an_unmatched_target_routes_via_the_hub_node() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-hub-fallback");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        let mut hub_node = test_node("beacon-hub", "http://127.0.0.1:9/");
        hub_node.hub = true;
        aoide_storage::node_store::save_nodes(&[test_node("yomi-strix", "http://127.0.0.1:9/"), hub_node]).unwrap();

        // No local sessions, and the target names neither node — every tier
        // of plain `addr::resolve` misses, so ONLY the hub preference can
        // explain the outcome naming `beacon-hub`.
        let out = session_send(&send_invocation(
            &["hi"],
            &[("to", "nothing-else-matches-this"), ("yes", "true")],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);
        assert_eq!(out.data.as_ref().unwrap()["reason"], "node-never-pulled");
        assert_eq!(out.data.as_ref().unwrap()["node"], "beacon-hub", "{out:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_remote_resolves_against_the_cache_and_attempts_delivery() {
        // No mock HTTP server: `node.url` names a closed loopback port so
        // the underlying curl POST fails FAST and deterministically. This
        // proves resolution reached exactly ONE remote session and the door
        // actually attempted the network delivery (the part THIS phase
        // owns) — not that the delivery succeeds, which is `aoide-client`'s
        // own transport, untouched here beyond threading `context_id`.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-deliver");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::node_store::save_nodes(&[test_node("yomi-strix", "http://127.0.0.1:9/")]).unwrap();
        aoide_storage::node_store::save_node_cache(&test_cache(
            "yomi-strix",
            node_graph_json(&[("sess-remote-1", Some("misty-comet"), "root")]),
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
        assert_eq!(out.data.as_ref().unwrap()["reason"], "node-send-failed");
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
        assert!(log.contains("send"), "audit line written even on a failed remote delivery: {log}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_remote_ambiguous_in_the_cache_lists_node_session_labels() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-ambiguous");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::node_store::save_nodes(&[test_node("yomi-strix", "http://127.0.0.1:9/")]).unwrap();
        aoide_storage::node_store::save_node_cache(&test_cache(
            "yomi-strix",
            node_graph_json(&[
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_AUDIT_LOG"]);

        let root = unique_stage("to-remote-notfound");
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::node_store::save_nodes(&[test_node("yomi-strix", "http://127.0.0.1:9/")]).unwrap();
        aoide_storage::node_store::save_node_cache(&test_cache(
            "yomi-strix",
            node_graph_json(&[("sess-remote-1", Some("misty-comet"), "root")]),
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    fn check_lane_note_flows_from_a_configured_verify_command_through_the_hook_outcome() {
        // Task #139: proves the WIRING — that `aoide_upkeep::checklane`'s note
        // actually reaches the `Outcome` `session hook` returns — not the
        // lane's own logic (covered exhaustively in `aoide-upkeep`'s own
        // tests). Isolates BOTH the conduct stage (`AOIDE_STAGE_DIR`, the
        // usual convention here) AND the config root (`AOIDE_ROOT`) — the
        // check lane reads `aoide_storage::config`, which every OTHER test in
        // this module never touches and must not start touching by accident.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_ROOT", "AOIDE_CONFIG", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        std::env::remove_var("AOIDE_CONFIG");
        let stage = unique_stage("check-lane-wiring-stage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let config_root = unique_stage("check-lane-wiring-config");
        std::env::set_var("AOIDE_ROOT", &config_root);
        aoide_storage::config::set("upkeep.verifyCommand", "false").unwrap();

        // A real git repo the lane can actually scan (unlike this file's other
        // hook tests, which use a fictional, nonexistent `cwd` since they
        // never exercise anything that reads the tree).
        let tree = unique_stage("check-lane-wiring-tree");
        let run_git = |args: &[&str]| {
            let status =
                std::process::Command::new("git").arg("-C").arg(&tree).args(args).status().unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        run_git(&["init", "-q"]);
        run_git(&["config", "user.email", "test@example.invalid"]);
        run_git(&["config", "user.name", "test"]);
        std::fs::write(tree.join("README.md"), "x\n").unwrap();
        run_git(&["add", "README.md"]);
        run_git(&["commit", "-q", "-m", "init"]);

        // SessionStart: the configured command is `false`, so the baseline is
        // red — the Outcome's own message carries the note, joined onto
        // whatever `do_session_start` already said.
        let out = hook_from_str(&format!(
            r#"{{ "session_id": "wire1", "hook_event_name": "SessionStart", "cwd": "{}" }}"#,
            tree.display()
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        assert!(out.message.contains("already red"), "{}", out.message);
        assert!(out.message.contains("inherited"), "{}", out.message);
        let data = out.data.unwrap();
        assert!(
            data["checkLane"].as_str().unwrap().contains("already red"),
            "{data}"
        );

        // Stop: silent to the harness UNCONDITIONALLY now — even with nothing
        // changed since the baseline, `on_stop` never assigns `lane_note`
        // (task #139 phase 2), so the message and `checkLane` read exactly
        // as they would with the lane off.
        let out2 = hook_from_str(&format!(
            r#"{{ "session_id": "wire1", "hook_event_name": "Stop", "cwd": "{}" }}"#,
            tree.display()
        ));
        assert!(!out2.message.contains("check lane"), "{}", out2.message);
        assert!(out2.data.unwrap()["checkLane"].is_null());

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&config_root);
        let _ = std::fs::remove_dir_all(&tree);
    }
    #[test]
    fn check_lane_delta_at_stop_stays_silent_until_the_next_prompt_delivers_it_once() {
        // Task #139 phase 2: the delivery sequence itself. `Stop` computes a
        // REAL delta (a fresh untracked `.nix` file) and must stay silent to
        // the harness regardless — the note only surfaces at the next
        // `UserPromptSubmit`, and only once.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_ROOT", "AOIDE_CONFIG", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        std::env::remove_var("AOIDE_CONFIG");
        let stage = unique_stage("check-lane-delivery-stage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let config_root = unique_stage("check-lane-delivery-config");
        std::env::set_var("AOIDE_ROOT", &config_root);
        aoide_storage::config::set("upkeep.verifyCommand", "true").unwrap();

        let tree = unique_stage("check-lane-delivery-tree");
        let run_git = |args: &[&str]| {
            let status =
                std::process::Command::new("git").arg("-C").arg(&tree).args(args).status().unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        run_git(&["init", "-q"]);
        run_git(&["config", "user.email", "test@example.invalid"]);
        run_git(&["config", "user.name", "test"]);
        std::fs::write(tree.join("README.md"), "x\n").unwrap();
        run_git(&["add", "README.md"]);
        run_git(&["commit", "-q", "-m", "init"]);

        // Settled start: green baseline, nothing to flag.
        let start = hook_from_str(&format!(
            r#"{{ "session_id": "wire2", "hook_event_name": "SessionStart", "cwd": "{}" }}"#,
            tree.display()
        ));
        assert!(!start.message.contains("check lane"), "{}", start.message);

        // A prompt with nothing pending: silent.
        let prompt_silent = hook_from_str(
            r#"{ "session_id": "wire2", "hook_event_name": "UserPromptSubmit", "user_prompt": "go" }"#,
        );
        assert!(!prompt_silent.message.contains("check lane"), "{}", prompt_silent.message);

        // The agent drops a fresh, untracked `.nix` file mid-turn.
        std::fs::write(tree.join("new-module.nix"), "{ }\n").unwrap();

        // Stop: computes the delta but stays silent to the harness — no
        // `check lane` text, no `checkLane` data.
        let stop = hook_from_str(&format!(
            r#"{{ "session_id": "wire2", "hook_event_name": "Stop", "cwd": "{}" }}"#,
            tree.display()
        ));
        assert!(!stop.message.contains("check lane"), "{}", stop.message);
        assert!(stop.data.unwrap()["checkLane"].is_null());

        // The NEXT prompt drains it — the Outcome's own message carries the
        // note, naming the file, and `checkLane` carries it separately.
        let delivered = hook_from_str(
            r#"{ "session_id": "wire2", "hook_event_name": "UserPromptSubmit", "user_prompt": "continue" }"#,
        );
        assert!(delivered.message.contains("new-module.nix"), "{}", delivered.message);
        let data = delivered.data.unwrap();
        assert!(
            data["checkLane"].as_str().unwrap().contains("new-module.nix"),
            "{data}"
        );

        // A further prompt with nothing new pending: silent — drained exactly
        // once, never re-delivered.
        let prompt_again = hook_from_str(
            r#"{ "session_id": "wire2", "hook_event_name": "UserPromptSubmit", "user_prompt": "once more" }"#,
        );
        assert!(!prompt_again.message.contains("check lane"), "{}", prompt_again.message);

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&config_root);
        let _ = std::fs::remove_dir_all(&tree);
    }
    #[test]
    fn a_mid_turn_session_start_runs_no_lane_and_writes_no_baseline() {
        // Task #139 phase 2: the settled/mid-turn split. A `SessionStart`
        // firing while the stored phase is `working` (an auto-compact
        // mid-turn) must not touch the baseline file at all — proven here by
        // flipping the configured verify command between the settled start
        // and the mid-turn one: if the mid-turn arm ran the lane fresh, the
        // flip would flow straight into a different message and a rewritten
        // file. Neither happens.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_ROOT", "AOIDE_CONFIG", "AOIDE_SESSION_ID"]);
        std::env::remove_var("AOIDE_SESSION_ID");
        std::env::remove_var("AOIDE_CONFIG");
        let stage = unique_stage("check-lane-midturn-stage");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let config_root = unique_stage("check-lane-midturn-config");
        std::env::set_var("AOIDE_ROOT", &config_root);
        aoide_storage::config::set("upkeep.verifyCommand", "false").unwrap();

        let tree = unique_stage("check-lane-midturn-tree");
        std::fs::create_dir_all(&tree).unwrap();

        // Settled start: baseline is red, flagged and inherited.
        let start = hook_from_str(&format!(
            r#"{{ "session_id": "wire3", "hook_event_name": "SessionStart", "cwd": "{}" }}"#,
            tree.display()
        ));
        assert!(start.message.contains("already red"), "{}", start.message);

        // A real prompt moves the stored phase to `working` — a turn is now
        // in flight (this also drains the empty pending note; a no-op).
        hook_from_str(
            r#"{ "session_id": "wire3", "hook_event_name": "UserPromptSubmit", "user_prompt": "go" }"#,
        );

        let lane_file = aoide_storage::fs::state_dir().join("checklane").join("wire3.json");
        let bytes_before = std::fs::read(&lane_file).unwrap();

        // Flip the command green — a fresh lane run would see this and go
        // quiet; the recorded baseline must not.
        aoide_storage::config::set("upkeep.verifyCommand", "true").unwrap();

        // An auto-compact fires SessionStart mid-turn (stored phase is still
        // `working`).
        let midturn = hook_from_str(&format!(
            r#"{{ "session_id": "wire3", "hook_event_name": "SessionStart", "cwd": "{}" }}"#,
            tree.display()
        ));
        assert!(
            midturn.message.contains("already red"),
            "mid-turn must replay the STORED (red) baseline, not a fresh (now-green) run: {}",
            midturn.message
        );

        let bytes_after = std::fs::read(&lane_file).unwrap();
        assert_eq!(
            bytes_before, bytes_after,
            "a mid-turn SessionStart must not write the baseline file at all"
        );

        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&config_root);
        let _ = std::fs::remove_dir_all(&tree);
    }
    #[test]
    fn hook_notification_blocks_and_the_clearing_set_lifts_it() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
    fn hook_stamps_harness_session_id_from_the_raw_payload_on_every_carrying_event() {
        // P-D7: `harnessSessionId` is stamped from the raw hook payload's own
        // `session_id`, regardless of whether the event maps to a graph
        // action — both the registering SessionStart itself AND a later
        // event this door has no action for (kimi's PreCompact) must land
        // it, but an unmapped event for a session that never registered
        // must stay a silent no-op (no ghost record).
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STAGE_DIR").ok();
        let stage = unique_stage("harness-sid");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        let kimi = agent_profile("kimi").unwrap();
        let hsid = |f: &SessionsFile| {
            f.sessions
                .iter()
                .find(|s| s.session_id == "hs1")
                .and_then(|s| s.harness_session_id.clone())
        };

        // SessionStart: the record is created AND stamped in the SAME
        // event — not deferred to a later hook.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "hs1", "hook_event_name": "SessionStart", "cwd": "/proj" }"#,
        );
        assert_eq!(
            hsid(&load_stage(&sessions_path()).unwrap()).as_deref(),
            Some("hs1")
        );

        // PreCompact maps to no graph action at all for kimi (an ok
        // observational no-op — ground-truthed in agents.rs's own
        // kimi_hook_event tests) but still carries session_id, and must
        // still stamp: the mapped/unmapped split is invisible to this
        // field.
        let out = hook_for_profile(
            kimi,
            r#"{ "session_id": "hs1", "hook_event_name": "PreCompact" }"#,
        );
        assert_eq!(out.data.as_ref().unwrap()["reason"], "unmapped-or-missing-event");
        assert_eq!(
            hsid(&load_stage(&sessions_path()).unwrap()).as_deref(),
            Some("hs1")
        );

        // An unmapped event naming a session that never registered stays a
        // silent no-op — never a ghost record.
        hook_for_profile(
            kimi,
            r#"{ "session_id": "hs-never-registered", "hook_event_name": "PreCompact" }"#,
        );
        assert!(
            !load_stage::<SessionsFile>(&sessions_path())
                .unwrap()
                .sessions
                .iter()
                .any(|s| s.session_id == "hs-never-registered"),
            "an unmapped event must never register a ghost session"
        );

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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
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
        let inv = flag_invocation(&["session", "hook"], &[]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "claude");
        // --agent kimi → the kimi profile.
        let inv = flag_invocation(&["session", "hook"], &[("agent", "kimi")]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "kimi");
        // --agent pi → the pi profile.
        let inv = flag_invocation(&["session", "hook"], &[("agent", "pi")]);
        assert_eq!(hook_profile_for(&inv).unwrap().name, "pi");
        // --agent bogus → a structured error (exit 1, reason + the known list).
        let inv = flag_invocation(&["session", "hook"], &[("agent", "bogus")]);
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

    /// P-QOL-C §1's composed positive path (hook → attested wrap →
    /// re-stamp) needs a live daemon to prove end to end — out of scope for
    /// this crate's fixtures, which guarantee a DEAD daemon socket
    /// (`isolated_mail_root`'s own doc). What IS provable here, in-crate: no
    /// daemon reachable means [`real_attested_wrap`] resolves `None`, so
    /// `hook_ensure_session` touches neither `parentSessionId` nor the
    /// existing pid-refresh behavior — the fail-closed half of the seam,
    /// exercised through two real hooks (a fresh SessionStart, then a
    /// PreToolUse that hits the now-existing record's self-heal branch).
    #[test]
    fn hook_leaves_the_parent_untouched_when_no_wrap_is_attested() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env_sid = EnvVars::save(&["AOIDE_SESSION_ID"]);
        // No sender attribution in scope here — a real ambient
        // `AOIDE_SESSION_ID` (this test may itself be running inside a
        // conducted session) is exactly the ENV fallback `parent` falls
        // back to, and would otherwise leak that real session id into the
        // "no attested parent" assertions below (`send_yes_delivers_and_
        // autorenames_the_title`'s own doc comment states the same hazard).
        std::env::remove_var("AOIDE_SESSION_ID");
        let (_env, _root) = aoide_test_support::isolated_mail_root("hook-no-attested-wrap");
        let profile = agent_profile(CLAUDE_PROFILE.name).unwrap();

        let out = hook_for_profile(
            profile,
            r#"{ "session_id": "c1", "hook_event_name": "SessionStart", "cwd": "/p" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|s| s.session_id == "c1").unwrap();
        assert_eq!(rec.parent_session_id, None, "no daemon means no attested parent");
        let pid_before = rec.pid;

        // PreToolUse on the now-EXISTING record hits `hook_ensure_session`'s
        // self-heal branch — the exact path §0 identified as never
        // re-parenting. With no daemon reachable it must still be a no-op.
        let out = hook_for_profile(
            profile,
            r#"{ "session_id": "c1", "hook_event_name": "PreToolUse" }"#,
        );
        assert_eq!(out.status, aoide_protocol::output::Status::Ok);
        let s: SessionsFile = load_stage(&sessions_path()).unwrap();
        let rec = s.sessions.iter().find(|s| s.session_id == "c1").unwrap();
        assert_eq!(
            rec.parent_session_id, None,
            "an existing record's parent stays untouched with no daemon to attest against"
        );
        assert_eq!(rec.pid, pid_before, "the existing-record pid refresh is unaffected");
    }
}
