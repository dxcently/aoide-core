//! `graph *` / `conduct` — thin registrations over this crate's `graph/`
//! domain (concepts/Terminal-Commander, concepts/Conductor-Channel). Handler
//! bodies live in `graph/`; this module only wires schema metadata to the
//! already-public `crate::graph::*` functions — nothing here duplicates
//! graph-domain logic.
//!
//! Moved from the root package's `src/commands/graph.rs` (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI verbs
//! live with the domain; the root package's `commands::all()` calls
//! [`register`] at the exact historical position so `schema --json` order
//! never shifts.

use aoide_protocol::registry::{arg, cmd, flag, Registry};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["graph", "view"],
        summary: "Render the project/session DAG (Unicode tree; --json emits the graph document).",
        args: [],
        flags: [flag!("focus", "string", "Node id to highlight with ▶ (session:<id>, project:<name>, or bare id).")],
        gated: false,
        implemented: true,
        handler: crate::graph::view,
        examples: [
            "graph view",
            "graph view --focus session:<id>",
        ],
    ));
    r.insert(cmd!(
        path: ["graph", "project", "add"],
        summary: "Register or update a project anchor root in song/stage/projects.json (atomic, idempotent).",
        args: [
            arg!("name", "string", true, "Project name (its node id becomes project:<name>)."),
            arg!("path", "string", false, "Project root path (defaults to the current working directory); sessions anchor by cwd prefix (longest wins)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::project_add,
        examples: [
            "graph project add aoide ~/Aoide",
            "graph project add aoide",
        ],
    ));
    r.insert(cmd!(
        path: ["graph", "project", "remove"],
        summary: "Unregister a project anchor root (ok + no-op if absent).",
        args: [arg!("name", "string", true, "Project name to remove.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::project_remove,
    ));
    r.insert(cmd!(
        path: ["graph", "project", "list"],
        summary: "List the registered project anchor roots.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::project_list,
    ));
    r.insert(cmd!(
        path: ["graph", "link"],
        summary: "Record a spawned-by edge: set parentSessionId on the child session (cycle-checked).",
        args: [
            arg!("child", "string", true, "Session id of the spawned (child) session."),
            arg!("parent", "string", true, "Session id of the spawning (parent) session."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::link,
    ));
    r.insert(cmd!(
        path: ["graph", "session", "start"],
        summary: "Register or update a running session in song/stage/sessions.json (UPSERT; atomic; startedAt preserved on re-start).",
        args: [],
        flags: [
            flag!("id", "string", "Session id (required); its node id becomes session:<id>."),
            flag!("agent", "string", "Agent name driving the session (default claude)."),
            flag!("cwd", "string", "Working directory; the session anchors under the longest-prefix project."),
            flag!("window", "string", "Hyprland window address for `graph focus` to jump to."),
            flag!("parent", "string", "Spawning session id — records the spawned-by edge (cycle-checked)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_start,
    ));
    r.insert(cmd!(
        path: ["graph", "session", "phase"],
        summary: "Upsert the live hook phase for a session in song/stage/hooks.json (latest updatedAt wins).",
        args: [],
        flags: [
            flag!("id", "string", "Session id (required)."),
            flag!("phase", "string", "Live phase to record; folded to one canonical state: working | awaiting | stopped | idle | done."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_phase,
    ));
    r.insert(cmd!(
        path: ["graph", "session", "end"],
        summary: "Mark a session done (state=done in sessions.json, phase=done in hooks.json); ok no-op if unknown.",
        args: [],
        flags: [flag!("id", "string", "Session id to end (required).")],
        gated: false,
        implemented: true,
        handler: crate::graph::session_end,
    ));
    r.insert(cmd!(
        path: ["graph", "session", "hook"],
        summary: "Hook door for agent harnesses: read one hook JSON from stdin and map it to a session verb through the agent's profile (never exits non-zero for a payload problem).",
        args: [],
        flags: [flag!("agent", "string", "Agent harness the payload comes from: claude (default), kimi, or pi.")],
        gated: false,
        implemented: true,
        handler: crate::graph::session_hook,
    ));
    r.insert(cmd!(
        path: ["graph", "wrap"],
        summary: "Run ANY agent command as a registered session: spawn with inherited stdio, register running, wait, end. Exports AOIDE_SESSION_ID so the child can self-report phases; exit mirrors the child (0 ok, 1 otherwise; real code in data.exitCode).",
        args: [arg!("command", "string", true, "The wrapped command and its args — put them after `--` so the child's own flags pass through verbatim.")],
        flags: [
            flag!("agent", "string", "Agent name for the roster (default: the command's basename)."),
            flag!("parent", "string", "Spawning session id — records the spawned-by edge."),
            flag!("id", "string", "Session id override (default wrap-<pid>-<unixts>)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_wrap,
        examples: ["graph wrap --agent codex -- codex --model x"],
    ));
    r.insert(cmd!(
        path: ["graph", "spawn"],
        summary: "Spawn ANY agent command as a DETACHED headless conducted session that outlives this call: re-execs `conduct --headless`, waits briefly for it to register its control socket, and returns. Exports AOIDE_SESSION_ID to the child same as `conduct`/`wrap`. An optional --prompt is injected through the one gated injection door (`graph send --yes --submit`) once registration succeeds; skipped (honestly reported) if it never does.",
        args: [arg!("command", "string", true, "The wrapped command and its args — put them after `--` so the child's own flags pass through verbatim.")],
        flags: [
            flag!("agent", "string", "Agent name for the roster (default: the command's basename)."),
            flag!("parent", "string", "Spawning session id — records the spawned-by edge (passed through to `conduct`)."),
            flag!("id", "string", "Session id override (default spawn-<pid>-<unixts>)."),
            flag!("prompt", "string", "A first turn to inject once the session registers (skipped, honestly reported, if it never does)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_spawn,
        examples: ["graph spawn --agent codex -- codex --model x"],
    ));
    r.insert(cmd!(
        path: ["graph", "send"],
        summary: "Inject text into a conducted session's control socket (the one gated injection door). Held pending approval by default; --yes (or an autogate policy) delivers and auto-renames the node to a one-line form of the text — except for a bare keystroke answer (text with no letters, e.g. a permission verdict digit), which is not a task and leaves the node's name alone. Every outcome is audited.",
        args: [arg!("text", "string", true, "The text to inject — put it after `--` so its own words/flags pass through verbatim.")],
        flags: [
            flag!("id", "string", "Target session id (required); its socket is resolved from sessions.json."),
            flag!("submit", "bool", "Append a newline so the agent submits the line (Enter)."),
            flag!("yes", "bool", "Authorise delivery now (else the send is held pending approval)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_send,
        examples: [
            "graph send --id <session-id> --submit -- yes, ship it",
            "graph send --id <session-id> --yes -- 1",
        ],
    ));
    r.insert(cmd!(
        path: ["graph", "pending", "list"],
        summary: "Enumerate held `graph send` / A2A entries in song/stage/pending.json (id is the entry's position — re-list after any approve/deny, positions shift). A malformed entry (a stale hand-edited line) is listed with state `malformed` rather than failing the whole read.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::pending_list,
        examples: ["graph pending list"],
    ));
    r.insert(cmd!(
        path: ["graph", "pending", "approve"],
        summary: "Approve one held pending entry: re-drive it through the one gated injection door (`graph send`, in-process, --yes) and remove it from the queue. A malformed or out-of-range id fails cleanly, leaving the entry untouched.",
        args: [arg!("id", "string", true, "Pending entry id — its position from `graph pending list`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::pending_approve,
        examples: ["graph pending approve 0"],
    ));
    r.insert(cmd!(
        path: ["graph", "pending", "deny"],
        summary: "Reject one held pending entry: remove it from the queue and inject nothing. A malformed or out-of-range id fails cleanly, leaving the entry untouched.",
        args: [arg!("id", "string", true, "Pending entry id — its position from `graph pending list`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::pending_deny,
        examples: ["graph pending deny 0"],
    ));
    r.insert(cmd!(
        path: ["graph", "permit"],
        summary: "Publish the herald's permission SUMMONS for a session blocked on a permission prompt. The card is filed into the herald ledger (stage/herald.json) and this verb RETURNS — the Quickshell herald draws it with real approve/deny buttons, and the click routes back through the shellbridge to type the verdict in. The hook door raises it automatically when a session goes `awaiting`. Only ever raised for a conductable session whose harness has verified prompt keys, and the verdict is only typed while the session is still awaiting.",
        args: [],
        flags: [
            flag!("id", "string", "Target session id (required); its socket is resolved from sessions.json."),
            flag!("tool", "string", "Tool the permission is being asked for — the card's title tier."),
            flag!("what", "string", "One line describing the ask — the card's context tier (rendered as plain text)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_permit,
    ));
    r.insert(cmd!(
        path: ["graph", "focus"],
        summary: "Jump to a session's window via hyprctl focuswindow (Terminal-Commander session jump).",
        args: [arg!("node", "string", true, "Session id (or session:<id> node id) to focus.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::focus,
    ));
    r.insert(cmd!(
        path: ["graph", "prune"],
        summary: "Drop `done` sessions and their hook records; clear orphaned parentSessionId links.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::prune,
    ));
    r.insert(cmd!(
        path: ["graph", "reap"],
        summary: "Reap dead sessions: mark every KILLED session (window gone per hyprctl, or pid's /proc gone) done and drop it, decay every `stopped` session at rest over an hour to `idle`, then re-stage. Also collects the three ghosts no liveness signal catches — a record whose every timestamp predates this boot (a recycled pid reads as alive forever), a sub-agent whose parent has left the roster, and the control socket a killed `conduct` left in $XDG_RUNTIME_DIR (only ever one nothing is listening on). Automatic liveness sweep for SUPER+Q / SIGKILL'd terminals whose own cleanup could never run. Falls back to pid-only liveness off Hyprland; never errors on nothing-to-reap.",
        args: [],
        flags: [flag!("announce", "bool", "Always raise the desktop toast, even on a quiet pass — for the dock's reap control, where a human pressed something and is owed an answer. Unflagged, the sweep only toasts when it actually changed the roster.")],
        gated: false,
        implemented: true,
        handler: crate::reap::reap_and_announce,
        examples: [
            "graph reap",
            "graph reap --announce",
        ],
    ));
    r.insert(cmd!(
        path: ["graph", "emit"],
        summary: "Stage the resolved DAG to song/stage/graph.json for Quickshell hot-reload (atomic).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::emit,
    ));
    // ── conduct: the PTY-backed conductable wrap (concepts/Conductor-Channel) ─
    r.insert(cmd!(
        path: ["conduct"],
        summary: "Run an agent command on its own PTY as a CONDUCTABLE session: like `graph wrap` (spawn, register running, wait, end, exit mirrored, AOIDE_SESSION_ID exported) but with a controlling tty + a per-session control socket, so `graph send` can type into the running agent while its TUI runs undisturbed.",
        args: [arg!("command", "string", true, "The wrapped command and its args — put them after `--` so the child's own flags pass through verbatim.")],
        flags: [
            flag!("agent", "string", "Agent name for the roster (default: the command's basename)."),
            flag!("parent", "string", "Spawning session id — records the spawned-by edge."),
            flag!("id", "string", "Session id override (default conduct-<pid>-<unixts>)."),
            flag!("headless", "bool", "No controlling tty: never touch the real terminal (no raw-mode, no stdin shuttle), and mirror the pty's output to state/sessions/<id>.log (logPath on the record) instead of stdout."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_conduct,
    ));
}
