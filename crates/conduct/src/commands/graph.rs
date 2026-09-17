//! `graph` / `session` / `project` / `send` / `spawn` / `resurrect` /
//! `conduct` — thin registrations over this crate's `graph/` domain
//! (concepts/Terminal-Commander, concepts/Conductor-Channel). Handler bodies
//! live in `graph/`; this module only wires schema metadata to the
//! already-public `crate::graph::*` functions — nothing here duplicates
//! graph-domain logic.
//!
//! **The graph-prefix cutover (task #101, Lane R, Phase R1).** The `graph`
//! prefix used to own the WHOLE conducting surface; it now owns only the
//! read/analysis lens — the bare render (`aoide graph`, ex-`graph view`) and
//! `graph link`. Everything that ACTS (send/spawn/resurrect) or manages
//! session/project lifecycle promoted to its own top-level family:
//! `send`/`spawn`/`resurrect` (bare, ex-`graph send`/`graph spawn`/`graph
//! resurrect`), `session start|phase|end|hook|carry|permit|pending
//! list|approve|deny|reap|prune` (ex-`graph session *`/`graph permit`/`graph
//! pending *`/`graph reap`/`graph prune`), `project add|list|remove`
//! (ex-`graph project *`). A hard cutover — no aliases, the old `graph
//! <command>` spellings are plain unknown commands now, same as a typo. Handler
//! functions and their own file layout are UNCHANGED; only the registered
//! `path:` (and the `examples:`/summary prose that quotes an invocation)
//! moved. See `pkgs/aoide/crates/AGENTS.md` on why the handler names staying
//! put is deliberate — a command's home is its domain crate's own `commands`
//! module, independent of what its registered path spells.
//!
//! Moved from the root package's `src/commands/graph.rs` (Phase 9
//! restructure, docs/architecture/PACKAGE-LAYOUT.md): a domain's CLI commands
//! live with the domain; the root package's `commands::all()` calls
//! [`register`] at the exact historical position so `schema --json` order
//! never shifts (the graph-prefix cutover renames spellings in place, at the
//! same registration slots — it does not reorder `all()`).

use aoide_protocol::registry::{arg, cmd, flag, Registry};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["graph"],
        summary: "Render the project/session DAG (Unicode tree; --json emits the graph document).",
        args: [],
        flags: [flag!("focus", "string", "Node id to highlight with ▶ (session:<id>, project:<name>, or bare id).")],
        gated: false,
        implemented: true,
        handler: crate::graph::view,
        examples: [
            "graph",
            "graph --focus session:<id>",
        ],
    ));
    r.insert(cmd!(
        path: ["project", "add"],
        summary: "Register a project anchor root in state/stage/projects.json, or ADD roots to an existing project (atomic, idempotent per root).",
        args: [
            arg!("name", "string", true, "Project name (its node id becomes project:<name>)."),
            arg!("path", "string", false, "Project root path; give one or more (defaults to the current working directory). Each is appended as a root — a name that already exists gains roots rather than losing the ones it has. Sessions anchor by cwd prefix, longest root wins."),
        ],
        flags: [
            flag!("auto-resume", "bool", "Opt this project into the daemon's boot-time auto-resume sweep (`resurrect --project <name>` on `run_loop` entry, once per boot). Only ever sets it true — hand-edit projects.json to clear it."),
            flag!("new", "bool", "Refuse if the project name already exists instead of adding roots to it."),
            flag!("host", "string", "Re-scope the path list to that REGISTERED node's own roots instead of local ones — adds it as a member and appends any given roots (idempotent per root). With no path, membership-only; never falls back to the cwd default. Refused (unknown-host, zero writes) if the node isn't registered."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::project_add,
        examples: [
            "project add aoide ~/Aoide",
            "project add aoide",
            "project add aoide ~/Aoide --auto-resume",
            "project add aoide ~/Aoide ~/Aoide-docs",
            "project add aoide ~/Aoide --new",
        ],
    ));
    r.insert(cmd!(
        path: ["project", "remove"],
        summary: "Unregister a project anchor root, or one root of a multi-root project (ok + no-op if absent).",
        args: [
            arg!("name", "string", true, "Project name to remove."),
            arg!("path", "string", false, "One root to remove instead of the whole project; removing the last root removes the project."),
        ],
        flags: [
            flag!("host", "string", "Re-scope PATH to that host's own roots: bare `--host <node>` drops the whole membership (roots included); `--host <node> <path>` drops just that one host root and leaves the membership, even at zero roots."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::project_remove,
    ));
    r.insert(cmd!(
        path: ["project", "list"],
        summary: "List the registered project anchor roots, with every root.",
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
    r.insert({
        let mut c = cmd!(
            path: ["session", "start"],
            summary: "Register or update a running session in state/stage/sessions.json (UPSERT; atomic; startedAt preserved on re-start).",
            args: [],
            flags: [
                flag!("id", "string", "Session id (required); its node id becomes session:<id>."),
                flag!("agent", "string", "Agent name driving the session (default claude)."),
                flag!("cwd", "string", "Working directory; the session anchors under the longest-prefix project."),
                flag!("window", "string", "Hyprland window address for the focus jump (`focus_session`) to use."),
                flag!("parent", "string", "Spawning session id — records the spawned-by edge (cycle-checked)."),
            ],
            gated: false,
            implemented: true,
            handler: crate::graph::session_start,
        );
        // Hook-plumbing, not an operator command — a harness's own lifecycle
        // drives it, never a human typing it directly (task #101 R1). Hidden
        // from `guide.rs`'s human listing; still enumerated by schema/MCP/A2A.
        c.internal = true;
        c
    });
    r.insert({
        let mut c = cmd!(
            path: ["session", "phase"],
            summary: "Upsert the live hook phase for a session in state/stage/hooks.json (latest updatedAt wins).",
            args: [],
            flags: [
                flag!("id", "string", "Session id (required)."),
                flag!("phase", "string", "Live phase to record; folded to one canonical state: working | awaiting | stopped | idle | done."),
            ],
            gated: false,
            implemented: true,
            handler: crate::graph::session_phase,
        );
        c.internal = true;
        c
    });
    r.insert({
        let mut c = cmd!(
            path: ["session", "end"],
            summary: "Mark a session done (state=done in sessions.json, phase=done in hooks.json); ok no-op if unknown.",
            args: [],
            flags: [flag!("id", "string", "Session id to end (required).")],
            gated: false,
            implemented: true,
            handler: crate::graph::session_end,
        );
        c.internal = true;
        c
    });
    r.insert({
        let mut c = cmd!(
            path: ["session", "hook"],
            summary: "Hook door for agent harnesses: read one hook JSON from stdin and map it to a session command through the agent's profile (never exits non-zero for a payload problem).",
            args: [],
            flags: [flag!("agent", "string", "Agent harness the payload comes from: claude (default), kimi, or pi.")],
            gated: false,
            implemented: true,
            handler: crate::graph::session_hook,
        );
        c.internal = true;
        c
    });
    r.insert(cmd!(
        path: ["spawn"],
        summary: "Spawn ANY agent command as a DETACHED conducted session that outlives this call — headless by default (re-execs `conduct --headless`), or in a real terminal with --windowed (execs $AOIDE_TERMINAL running the same conducted command) — waits briefly for it to register its control socket, and returns. Exports AOIDE_SESSION_ID to the child same as `conduct`/`wrap`. An optional --prompt is injected through the one gated injection door (`send --yes --submit`) once registration succeeds; skipped (honestly reported) if it never does.",
        args: [arg!("command", "string", true, "The wrapped command and its args — put them after `--` so the child's own flags pass through verbatim.")],
        flags: [
            flag!("agent", "string", "Agent name for the roster (default: the command's basename)."),
            flag!("parent", "string", "Spawning session id — records the spawned-by edge (passed through to `conduct`)."),
            flag!("id", "string", "Session id override (default spawn-<pid>-<unixts>)."),
            flag!("prompt", "string", "A first turn to inject once the session registers (skipped, honestly reported, if it never does)."),
            flag!("windowed", "bool", "Open a real terminal (from $AOIDE_TERMINAL, a whitespace-split argv with a `{cmd}` placeholder) instead of a detached headless child. A bare `{cmd}` splices the conducted argv as separate arguments (`kitty -e {cmd}`); a quote-wrapped `'{cmd}'` joins it shell-quoted into one word for `sh -c` templates (`foot sh -c '{cmd}'`). Taught errors when unset, or when no display is present."),
            flag!("cwd", "string", "Working directory for the spawned child (default: this process's own cwd) — for --windowed, the terminal emulator's own cwd, which its own shell inherits."),
            flag!("undying", "bool", "Mark the spawned session durable in state/undying.json once it registers (no-op if it never does) — the same mark `session grant undying on` sets, so this project's whole undying set can later be resurrected together."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_spawn,
        examples: ["spawn --agent codex -- codex --model x"],
    ));
    r.insert(cmd!(
        path: ["resurrect"],
        summary: "Revive sessions. BARE (no --project/--all/--id): walk up from cwd for the nearest .aoide/project.json and revive THAT manifest's specs directly — no projects.json registration needed. Each local-host spec (a spec whose host doesn't match this host's own name is skipped, remote summoning lands in a later phase) enriches off the newest matching state/session-ledger.jsonl entry (same cwd/agent) through the exact --id path below when one exists, else clean-spawns windowed from the spec's own command or the agent's default launch. WITH --project (resolved against projects.json by exact name; --all/--id ignore the manifest entirely): anchors ledger entries to it (longest-prefix, same rule the bare `graph` render uses), then selects — bare (no --all/--id) resumes the project's WHOLE undying set (state/undying.json, `session grant undying on|off`) minus any id already alive; --all widens to every anchored entry; --id narrows to one. Each candidate resolves through two arms: a harness with a verified resume argv spawns windowed running `<harness> --resume <id>`; a conducted TERMINAL (no harness profile, but a captured `restore` snapshot) spawns windowed running its login shell, then — once registered — either re-execs its last foreground command (`--yes --submit`, only when it was demonstrably running one, and never for a recorded `sudo …`) or preloads its last typed-but-unsubmitted line into the new prompt (`--yes`, deliberately never `--submit` — nothing runs without a human keystroke) or delivers nothing if it was idle with no typed line. Neither arm resolving is skipped with a taught message. The revived session always mints a NEW sessionId (ids are never recycled) and is stamped resumedFrom, rendered as a `resumed` graph edge; an undying old id transfers its mark onto the new one. A windowed-spawn failure (no $AOIDE_TERMINAL / no display) is folded into `failed` rather than erroring the command, so a headless host degrades gracefully.",
        args: [],
        flags: [
            flag!("project", "string", "Project name to resurrect a session for; resolved against projects.json by exact name. Omit entirely, along with --all/--id, to use bare-manifest mode instead (walk up from cwd for .aoide/project.json)."),
            flag!("all", "bool", "Resurrect every anchored, resumable ledger entry instead of just the single most recent. Requires --project; ignores any .aoide/project.json."),
            flag!("id", "string", "Resurrect one specific ledger sessionId instead of the most recent (mutually exclusive with --all; --id wins if both given). Requires --project; ignores any .aoide/project.json."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_resurrect,
        examples: [
            "resurrect",
            "resurrect --project aoide",
            "resurrect --project aoide --all",
        ],
    ));
    r.insert(cmd!(
        path: ["send"],
        summary: "Inject text into a conducted session's control socket (the one gated injection door). Held pending approval by default; --yes (or an autogate policy) delivers and auto-renames the node to a one-line form of the text — except for a bare keystroke answer (text with no letters, e.g. a permission verdict digit), which is not a task and leaves the node's name alone. Siblings (sharing a live parent) autogate each other by default too — opt out with AOIDE_CONDUCT_SIBLING_AUTOGATE={0,false,no}. Every outcome is audited. --to resolves a name (local id/tail4/petname, or node/<query> for a remote session over A2A) instead of a raw --id; mutually exclusive with --id — a remote send is always attempted (the receiving node gates its own delivery) and never queues locally.",
        args: [arg!("text", "string", true, "The text to inject — put it after `--` so its own words/flags pass through verbatim.")],
        flags: [
            flag!("id", "string", "Target session id (required unless --to is given); its socket is resolved from sessions.json."),
            flag!("submit", "bool", "Append the target harness's own submit keystroke (Enter for most agents, \\r for kimi — resolved from the target session's agent profile at delivery time). No-op for a --to remote send (the receiving node always submits its own way)."),
            flag!("yes", "bool", "Authorise delivery now (else the send is held pending approval). No-op for a --to remote send — the receiving node gates its own delivery."),
            flag!("from", "string", "Sender attribution override for the delivered provenance prefix (default: AOIDE_SESSION_ID). ATTRIBUTION ONLY, not authentication — unauthenticated and as spoofable as the env var it defaults from."),
            flag!("to", "string", "Target by name instead of --id: a local session id/tail4/petname/host-role-petname line, or node/<query> to resolve against a registered node's CACHED graph and deliver over A2A message/send. Mutually exclusive with --id."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_send,
        examples: [
            "send --id <session-id> --submit -- yes, ship it",
            "send --id <session-id> --yes -- 1",
            "send --to brave-otter --yes --submit -- status?",
            "send --to yomi-strix/brave-otter -- ping",
        ],
    ));
    r.insert(cmd!(
        path: ["session", "pending", "list"],
        summary: "Enumerate held `send` / A2A entries in state/stage/pending.json (id is the entry's position — re-list after any approve/deny, positions shift). A malformed entry (a stale hand-edited line) is listed with state `malformed` rather than failing the whole read.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::pending_list,
        examples: ["session pending list"],
    ));
    r.insert(cmd!(
        path: ["session", "trace"],
        summary: "Render a session's TRACE, one line per record — the run, step by step (docs/architecture/EIDOLON-TRACE.md: eidolon mirrors its journal as one JSON record per line and names that file from its own presence metadata; it is the one harness that does today). <id> resolves like `send --to` (id / tail4 / petname). Human form is `#<id>  <hh:mm:ss local>  <kind>  <summary>` — an assistant message shows its thinking (dimmed, cut) then its text then each `→ tool(name)`, a tool result shows its first line prefixed `!` when it errored, a settled turn shows its stop reason and tokens. --tail N shows the last N records (default 50); --follow re-reads for new lines until Ctrl-C (CLI-only); --json passes the raw trace lines through unchanged, byte for byte. A session whose harness keeps no trace (or whose presence names none) is a taught error naming which of the two it is, never an empty listing. Read-only: no stage write, no daemon, no lock.",
        args: [arg!("id", "string", true, "Session to render: a local session id, its tail4, or its petname (resolved by the same resolver `send --to` uses).")],
        flags: [
            flag!("tail", "int", "Show only the last N records (default 50). A non-numeric or zero value is a usage error, never a silently empty listing."),
            flag!("follow", "bool", "Re-read the trace every 500ms and print new records as they land; blocks until Ctrl-C. CLI-only — a follow that parks a connection makes no sense over MCP/A2A/the daemon socket."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_trace,
        examples: [
            "session trace brave-otter",
            "session trace 7d23 --tail 20",
            "session trace Aoide-7d23 --follow",
            "session trace brave-otter --json",
        ],
    ));
    r.insert(cmd!(
        path: ["session", "pending", "approve"],
        summary: "Approve one held pending entry: re-drive it through the one gated injection door (`send`, in-process, --yes) and remove it from the queue. A malformed or out-of-range id fails cleanly, leaving the entry untouched.",
        args: [arg!("id", "string", true, "Pending entry id — its position from `session pending list`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::pending_approve,
        examples: ["session pending approve 0"],
    ));
    r.insert(cmd!(
        path: ["session", "pending", "deny"],
        summary: "Reject one held pending entry: remove it from the queue and inject nothing. A malformed or out-of-range id fails cleanly, leaving the entry untouched.",
        args: [arg!("id", "string", true, "Pending entry id — its position from `session pending list`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::pending_deny,
        examples: ["session pending deny 0"],
    ));
    r.insert(cmd!(
        path: ["session", "permit"],
        summary: "Publish the herald's permission SUMMONS for a session blocked on a permission prompt. The card is filed into the herald ledger (stage/herald.json) and this command RETURNS — the Quickshell herald draws it with real approve/deny buttons, and the click routes back through the shellbridge to type the verdict in. The hook door raises it automatically when a session goes `awaiting`. Only ever raised for a conductable session whose harness has verified prompt keys, and the verdict is only typed while the session is still awaiting.",
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
        path: ["session", "prune"],
        summary: "Drop `done` sessions and their hook records; clear orphaned parentSessionId links.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::graph::prune,
    ));
    r.insert(cmd!(
        path: ["session", "reap"],
        summary: "Reap dead sessions: mark every KILLED session (window gone per hyprctl, or pid's /proc gone) done and drop it, decay every `stopped` session at rest over an hour to `idle`, then re-stage. Also collects the three ghosts no liveness signal catches — a record whose every timestamp predates this boot (a recycled pid reads as alive forever), a sub-agent whose parent has left the roster, and the control socket a killed `conduct` left in $XDG_RUNTIME_DIR (only ever one nothing is listening on). Plus the worker shells `aoide spawn` left running that no one has typed in for two days — see `--now`, which takes those on the spot. Automatic liveness sweep for SUPER+Q / SIGKILL'd terminals whose own cleanup could never run. Falls back to pid-only liveness off Hyprland; never errors on nothing-to-reap.",
        args: [],
        flags: [
            flag!("announce", "bool", "Always raise the desktop toast, even on a quiet pass — for the dock's reap control, where a human pressed something and is owed an answer. Unflagged, the sweep only toasts when it actually changed the roster."),
            flag!("now", "bool", "Take every idle worker shell `aoide spawn` left running, however recently it was touched — the unattended sweep otherwise waits out a two-day silence on the shell's pty log. Implied by a human gesture: the dock's reap control passes it, and a bare `aoide session reap` typed at a terminal picks it up. No other band moves."),
        ],
        gated: false,
        implemented: true,
        handler: crate::reap::reap_and_announce,
        examples: [
            "session reap",
            "session reap --announce",
            "session reap --now",
        ],
    ));
    // ── conduct: the PTY-backed conductable wrap (concepts/Conductor-Channel) ─
    r.insert(cmd!(
        path: ["conduct"],
        summary: "Run an agent command on its own PTY as a CONDUCTABLE session: spawn, register running, wait, end (exit mirrored, AOIDE_SESSION_ID exported), with a controlling tty + a per-session control socket, so `send` can type into the running agent while its TUI runs undisturbed.",
        args: [arg!("command", "string", true, "The wrapped command and its args — put them after `--` so the child's own flags pass through verbatim.")],
        flags: [
            flag!("agent", "string", "Agent name for the roster (default: the command's basename)."),
            flag!("parent", "string", "Spawning session id — records the spawned-by edge."),
            flag!("id", "string", "Session id override (default conduct-<pid>-<unixts>)."),
            flag!("headless", "bool", "No controlling tty: never touch the real terminal (no raw-mode, no stdin shuttle), and mirror the pty's output to state/sessions/<id>.log (logPath on the record) instead of stdout."),
            flag!("spawned", "bool", "Mark the record as created by `aoide spawn` (spawned on the record), permanently. Set by spawn's own re-exec in both launch modes; reap's abandoned-shell sweep judges only records carrying it."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_conduct,
    ));
    // ── bare `session`: the ROSTER (session-surface redesign, command-defrag
    // lane X, 2026-08-28 — supersedes both the U3 undying picker that used
    // to live here AND the standalone `aoide who` command, folded away
    // entirely). Registered here, at the END — same parent-command pattern
    // R1 established for bare `graph` (path ["graph"] alongside ["graph",
    // "link"]) — registration order matters (`crates/AGENTS.md`), and this
    // landed after every entry above it.
    r.insert(cmd!(
        path: ["session"],
        summary: "Roster listing: this box's own sessions plus every registered node, probed in parallel on every call (the retired `aoide who` command's exact probe/cache-fallback pipeline). Bare groups sessions by PROJECT (a registered projects.json name, else a .aoide/project.json manifest directory's own basename, else a trailing (no project) bucket); --hosts groups by HOST instead — this host, then each node, byte-identical to `who`'s old rendering. --json mirrors either grouping structurally.",
        args: [arg!("filter", "string", false, "Narrow what's displayed (never what's probed): a local session id/tail4/petname, a host/role/petname line, node/<rest>, or a plain substring against a node/session name.")],
        flags: [
            flag!("hosts", "bool", "Group by host instead of by project — the retired `who` command's own grouping."),
            flag!("all", "bool", "Also list `done` sessions (omitted by default)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_roster,
        examples: [
            "session",
            "session --hosts",
            "session --hosts --all",
        ],
    ));
    // ── session grant: the GRANT family (session-surface redesign,
    // command-defrag lane X) — a POSITIONAL <kind> grammar (`secrets
    // automate <name> on|off` style) replacing the old standalone `session
    // undying` command, which this absorbs and retires (hard cutover, no
    // alias). Two kinds today: `undying` (U1/U3's mark, relocated verbatim)
    // and `exempt` (task #20, the reaper's staleness safety valve — no
    // picker). Registered last — landed after every entry above it.
    r.insert(cmd!(
        path: ["session", "grant"],
        summary: "Grant (or open a picker to grant) a session capability. Bare (no <kind>) teaches the grantable set; an unknown kind is a taught refusal. `undying`: with no state, opens the interactive PICKER on a real CLI terminal — a multi-select over this box's own sessions plus every registered node's CACHED sessions (no live pulls), each row pre-checked by its current undying state, confirmed in one Enter (non-tty/non-CLI/--json steers to the scripted form below instead); with on|off, marks or unmarks a session as durable in state/undying.json directly, so a project's whole undying set can later be resurrected together — --id targets any session id directly, including one already gone from the roster. `exempt`: no picker (bare `exempt` is a taught refusal naming the scripted form); on|off vetoes the reaper's staleness judgments for a LIVE session only (never its window-gone/pid-gone/ghost/orphan signals, and never `--now`, which waives only the abandoned-shell band) — --id must name a session currently on the roster, since an exemption has nothing to mean once the record is gone. Bare and --self both resolve the target from $AOIDE_SESSION_ID for either kind.",
        args: [
            arg!("kind", "string", true, "The grant kind — `undying` or `exempt`."),
            arg!("state", "string", false, "The state to set, `on` or `off`. For `undying` only, omit to open the interactive picker instead — `exempt` has none."),
        ],
        flags: [
            flag!("self", "bool", "Target this session, resolved from $AOIDE_SESSION_ID (the default when neither --self nor --id is given)."),
            flag!("id", "string", "Target session id directly (mutually exclusive with --self). For `undying`, no roster lookup gates it, so a dead id is a valid target; for `exempt`, the id must currently be on the roster — an off-roster id is a refusal."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_grant,
        examples: [
            "session grant undying",
            "session grant undying on --self",
            "session grant undying off --id <session-id>",
            "session grant exempt on --self",
            "session grant exempt off --id <session-id>",
        ],
    ));
    r.insert(cmd!(
        path: ["session", "bind"],
        summary: "Bind a local executor to an explicit enduring agent key; idempotent, refuses a conflicting binding, requires aoided. Does not grant access or require Mneme.",
        args: [],
        flags: [
            flag!("id", "string", "Existing session id (required)."),
            flag!("agent-id", "string", "Opaque enduring key (required): lowercase letters, digits, and hyphens; starts with a letter or digit. Independent of display names and harness sessions."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::session_bind,
        examples: ["session bind --id executor-1 --agent-id 7e3f5976-98b2-44a4-827c-c687a0d9526e"],
    ));
    r.insert(cmd!(
        path: ["project", "edit"],
        summary: "Replace a project's anchor roots outright (the name is immutable; autoResume is untouched).",
        args: [
            arg!("name", "string", true, "Project name to edit; must already be registered."),
            arg!("path", "string", true, "The project's new root path; give one or more. The first becomes the project's primary root, the rest follow in order."),
        ],
        flags: [
            flag!("host", "string", "Re-scope the path list to REPLACE that host's own roots exactly, instead of the local ones — local roots and every other host stay untouched. Upserts the membership if it wasn't already one."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::project_edit,
        examples: [
            "project edit aoide ~/Aoide ~/Aoide-docs",
            "project edit aoide ~/Aoide",
        ],
    ));
}

/// `mail ring` (P-M5a-2, MAIL.md "Delivery and the doorbell") — registered
/// separately from [`register`] because its home command family (`mail`)
/// lives in the CLIENT crate's `commands.rs`, which cannot depend on this
/// crate; `aoide-cli`'s own `commands::all()` calls this alongside
/// `aoide_client::commands::register`/`aoide_client::context::register`
/// instead, at the end of that function, so the doorbell's one command
/// slots in last rather than reordering the client's own `mail` family.
pub fn register_mail_ring(r: &mut Registry) {
    r.insert(cmd!(
        path: ["mail", "ring"],
        summary: "Ring every armed reader of a mailbox that is headless and at the prompt; latched until the reader reads. Local, runs in-process.",
        args: [],
        flags: [
            flag!("for", "string", "Mailbox name to ring (required)."),
            flag!("from", "string", "The filer's own session — excluded from the ring, never rung for its own letter."),
        ],
        gated: false,
        implemented: true,
        handler: crate::graph::mail_ring,
        examples: ["mail ring --for claude-mail"],
    ));
    r.insert(cmd!(
        path: ["session", "project"],
        summary: "Assign a local session to a registered project without changing its cwd; --clear restores automatic path anchoring.",
        args: [],
        flags: [flag!("id", "string", "Exact local session id."), flag!("project", "string", "Registered project name."), flag!("clear", "bool", "Restore automatic cwd anchoring.")],
        gated: false,
        implemented: true,
        handler: crate::graph::session_project,
    ));
    r.insert(cmd!(
        path: ["session", "kill"],
        summary: "Send SIGTERM to the verified local session-owning process. Refuses shared, desktop, unsealed, stale, or unsupported targets. Does not mark completion; the reaper observes exit.",
        args: [],
        flags: [flag!("id", "string", "Exact local session id.")],
        gated: true,
        implemented: true,
        handler: crate::graph::session_kill,
    ));

}
