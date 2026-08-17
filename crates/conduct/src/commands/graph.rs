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
    ));
    r.insert(cmd!(
        path: ["graph", "project", "add"],
        summary: "Register or update a project anchor root in song/stage/projects.json (atomic, idempotent).",
        args: [
            arg!("name", "string", true, "Project name (its node id becomes project:<name>)."),
            arg!("path", "string", true, "Project root path; sessions anchor by cwd prefix (longest wins)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::project_add,
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
    ));
    r.insert(cmd!(
        path: ["graph", "permit"],
        summary: "Raise the herald's permission SUMMONS for a session blocked on a permission prompt and type the human's verdict back into it: left-click approves, middle-click (dismiss) denies. Blocks until the card is answered — the hook door spawns it detached when a session goes `awaiting`. Only ever raised for a conductable session whose harness has verified prompt keys, and only injected while the session is still awaiting.",
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
        summary: "Reap dead sessions: mark every KILLED session (window gone per hyprctl, or pid's /proc gone) done and drop it, decay every `stopped` session at rest over an hour to `idle`, then re-stage. Automatic liveness sweep for SUPER+Q / SIGKILL'd terminals whose own cleanup could never run. Falls back to pid-only liveness off Hyprland; never errors on nothing-to-reap.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::reap::reap,
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
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_conduct,
    ));
}
