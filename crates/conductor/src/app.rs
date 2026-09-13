//! The conductor's core: live state, selection, and the dispatch plumbing.
//!
//! [`App`] is pi's "core" — it holds the world (projects/sessions/hooks loaded
//! from the stage tree, the audit tail, the palette) and the interaction state
//! (which panel, which row, any inline input, the last dispatched
//! [`Outcome`](aoide_protocol::output::Outcome)). It draws nothing; it hands panels the
//! data and composes their rendered lines into a [`Frame`].
//!
//! Every mutation goes back through the ONE dispatcher via [`App::dispatch`] —
//! constructing an [`Invocation`] with `Door::Cli` so the action is audited
//! identically to a typed command. Reads reuse the pure graph functions and the
//! stage-file loaders. There is no second copy of any command's logic here.
//!
//! The SESSION panel walks a flattened row model ([`App::dag_rows`]): project
//! group headers interleaved with their session subtrees, one selection index
//! over the lot. Headers are first-class rows — fold/unfold, project remove and
//! link all act on whatever the cursor is on, so the DAG is managed from within
//! the group context rather than from a separate screen. The roster also plays
//! terminal-watcher: sessions that appear between ticks are marked fresh for a
//! few beats ([`FRESH_TICKS`]) so the eye catches a new arrival.

use crate::logtail;
use aoide_conduct::graph::{self, HooksFile, ProjectsFile, SessionRecord, SessionsFile};
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Door;
use aoide_protocol::Invocation;
use aoide_storage::fs::{conducting_stage_dir, stage_dir};
use crossterm::event::{KeyCode, KeyEvent};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Instant, SystemTime};

/// Navigation follows the visible tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Graph,
    Session,
    Projects,
    Log,
    Status,
    Roster,
    Pending,
    Home,
    Mail,
    Terminals,
}

impl Panel {
    pub const ALL: [Panel; 10] = [
        Panel::Home,
        Panel::Mail,
        Panel::Session,
        Panel::Terminals,
        Panel::Roster,
        Panel::Pending,
        Panel::Projects,
        Panel::Graph,
        Panel::Log,
        Panel::Status,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Panel::Graph => "DAG",
            Panel::Session => "AGENTS",
            Panel::Projects => "PROJECTS",
            Panel::Log => "LOG",
            Panel::Status => "STATUS",
            Panel::Roster => "ROSTER",
            Panel::Pending => "PENDING",
            Panel::Home => "HOME",
            Panel::Mail => "MAIL",
            Panel::Terminals => "TERMINALS",
        }
    }
    pub fn index(self) -> usize {
        Panel::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// Exact RGB palette and Base16 tokens from stage livery, with ANSI-256
/// compatibility fields. Missing colors retain terminal fallbacks.
#[derive(Debug, Clone, Default)]
pub struct Palette {
    pub base16: [Option<(u8, u8, u8)>; 16],
    pub urgent_rgb: Option<(u8, u8, u8)>,
    pub bg_rgb: Option<(u8, u8, u8)>,
    pub fg_rgb: Option<(u8, u8, u8)>,
    pub accent_rgb: Option<(u8, u8, u8)>,
    pub bg: Option<u8>,
    pub fg: Option<u8>,
    pub accent: Option<u8>,
    pub urgent: Option<u8>,
}

/// One decoded audit-log line (the flat event feed the LOG panel tails).
#[derive(Debug, Clone)]
pub struct LogLine {
    pub raw: serde_json::Value,
    pub ts: u64,
    pub door: String,
    pub class: String,
    pub command: String,
    pub status: String,
    pub message: String,
}

/// An inline text prompt (project add, link-under-parent). When `Some`, keys go
/// to the prompt, not the global keymap.
#[derive(Debug, Clone)]
pub struct Input {
    pub label: String,
    pub buffer: String,
    /// Which multi-step field we're collecting (0 = name, 1 = path, …).
    pub step: u8,
    /// Values gathered from earlier steps.
    pub collected: Vec<String>,
    /// The action this prompt feeds.
    pub kind: InputKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputKind {
    SessionProject {
        id: String,
    },
    ProjectRoot {
        name: String,
    },
    ProjectAdd,
    ProjectRemove {
        name: String,
    },
    /// Link the named child session under the parent the prompt collects.
    Link {
        child: String,
    },
    /// Compose a message to `target` (messaging/presence plan, P-C5) — opened
    /// by `s` on a selected ROSTER session row, pre-labeled with the row's own
    /// display-grammar label. Submitting dispatches `send --to <target>
    /// --yes -- <text>` ([`App::handle_input_key`]'s `Enter` arm).
    Compose {
        target: String,
    },
}

#[derive(Debug, Clone)]
pub enum ContextTarget {
    Session(SessionRecord),
    Project(String),
    History(aoide_storage::ledger::LedgerEntry),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextAction {
    Details,
    WriteLetter,
    Open,
    AssignProject,
    Resurrect,
    AddFolder,
}
impl ContextAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Details => "Details",
            Self::WriteLetter => "Write letter",
            Self::Open => "Open / focus",
            Self::AssignProject => "Set project",
            Self::Resurrect => "Resurrect",
            Self::AddFolder => "Add folder",
        }
    }
}
#[derive(Debug, Clone)]
pub struct ContextMenu {
    pub x: u16,
    pub y: u16,
    pub title: String,
    pub target: ContextTarget,
    pub actions: Vec<ContextAction>,
    pub selected: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailMode {
    New,
    Reply,
    ReplyAll,
    Forward,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailField {
    To,
    Cc,
    Subject,
    Body,
}
#[derive(Debug, Clone)]
pub struct MailDraft {
    pub mode: MailMode,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub subject: String,
    pub body: String,
    pub original: Option<crate::mailview::MailLetter>,
    pub focus: MailField,
    pub recipient_field: MailField,
    /// UTF-8 byte boundary in the focused field.
    pub cursor: usize,
    pub error: Option<String>,
    /// A partial/uncertain submission cannot be blindly submitted again.
    pub submitted: bool,
}
impl MailDraft {
    pub fn field(&self, field: MailField) -> &str {
        match field {
            MailField::To => &self.to,
            MailField::Cc => &self.cc,
            MailField::Subject => &self.subject,
            MailField::Body => &self.body,
        }
    }
    fn field_mut(&mut self) -> &mut String {
        match self.focus {
            MailField::To => &mut self.to,
            MailField::Cc => &mut self.cc,
            MailField::Subject => &mut self.subject,
            MailField::Body => &mut self.body,
        }
    }
}

/// The group name sessions fall under when no project anchors their cwd.
pub const UNANCHORED: &str = "(unanchored)";

/// How many ticks (~500 ms each) a newly-appeared session stays marked fresh.
pub const FRESH_TICKS: u8 = 4;

/// One row of the SESSION panel's flattened DAG: a project group header or a
/// session line with its tree-branch prefix pre-walked. One `Vec<DagRow>` is the
/// single source of truth for both rendering and key handling, so the cursor
/// can never point at something the screen isn't showing.
#[derive(Debug, Clone)]
pub enum DagRow {
    Group {
        name: String,
        path: String,
        /// Sessions in the group not yet done — the "live" half of `[live/total]`.
        live: usize,
        total: usize,
        folded: bool,
    },
    Session {
        rec: SessionRecord,
        /// The tree-branch prefix (`└─ `, `│  ├─ `, …), already assembled.
        prefix: String,
    },
}

/// Sidebar navigation retains complete records; labels are presentation only.
#[derive(Debug, Clone)]
pub enum SidebarRow {
    History {
        entry: aoide_storage::ledger::LedgerEntry,
        label: String,
        depth: usize,
    },
    Project {
        name: String,
        folded: bool,
    },
    Section {
        project: String,
        terminal: bool,
        folded: bool,
        count: usize,
    },
    Past {
        project: String,
        folded: bool,
        count: usize,
    },
    Session {
        rec: SessionRecord,
        label: String,
        past: bool,
        depth: usize,
    },
}

/// mtimes of the stage files we poll, so a tick reloads only what changed.
/// Stage-files-only: the log tail's own mtime lives on [`LogTail`] itself,
/// gated separately in [`App::poll_refresh`] — a tail is a file read, not a
/// stage file, and it doesn't exist for most of an App's life (`None` while
/// closed).
#[derive(Debug, Clone, Default)]
struct StageMtimes {
    history: Option<SystemTime>,
    sessions: Option<SystemTime>,
    hooks: Option<SystemTime>,
    projects: Option<SystemTime>,
    notes: Option<SystemTime>,
    audit: Option<SystemTime>,
}

/// The open headless-log-tail overlay's state: which session, which file, the
/// last [`logtail::render_tail`]ed lines, and the file's mtime at that last
/// read (the gate [`App::poll_refresh`] checks before re-reading). Plays the
/// same "one Option, `None` == closed" modal role [`App::help_open`] plays,
/// just with a richer payload than a bare bool.
#[derive(Debug, Clone)]
pub struct LogTail {
    pub session_id: String,
    pub path: PathBuf,
    pub lines: Vec<String>,
    mtime: Option<SystemTime>,
}

/// Throttle window for the ROSTER panel's `session --hosts` dispatch
/// (messaging/presence plan, P-C4; the retired standalone `who` command's
/// own throttle, unchanged — session-surface redesign, command-defrag lane
/// X, 2026-08-28). `session --hosts` performs a LIVE network probe of every
/// registered node on each invocation (`conduct/src/graph/who.rs`'s module
/// doc — the roster core), so the pane re-dispatches at most this often —
/// never on every ~500ms UI tick.
pub const ROSTER_THROTTLE: std::time::Duration = std::time::Duration::from_secs(15);

/// One session row under a [`RosterNode`] — reshaped straight from `session
/// --hosts --json`'s `nodes[].sessions[]` (`conduct/src/graph/
/// who.rs::node_json`), never re-derived: `label`/`state` are exactly the
/// strings the roster core already computed (display-grammar label,
/// canonical state vocabulary), so `theme::state_glyph`/`state_style` — the
/// SAME glyph mapping the SESSION panel already paints — apply unchanged.
#[derive(Debug, Clone, Default)]
pub struct RosterSession {
    pub label: String,
    pub state: String,
}

/// One node (this box, or a registered node) as `session --hosts --json`
/// reports it — parsed from the cached `Outcome`'s `data.nodes[]`.
/// `presence` is one of the roster core's own three node-level classes:
/// `online` | `unreachable` | `never-pulled` (`who.rs`'s module doc,
/// "Presence model").
#[derive(Debug, Clone, Default)]
pub struct RosterNode {
    pub name: String,
    pub is_local: bool,
    pub presence: String,
    pub fetched_at: Option<String>,
    pub sessions: Vec<RosterSession>,
}

/// The ROSTER panel's cache: the last `session --hosts` [`Outcome`] plus
/// when it landed. `fetched_at: None` means "never fetched this run" —
/// always stale, so the first tick/visit fetches immediately. This is the
/// ONLY state the panel holds; there is no second copy of presence logic
/// here, only a reshape of what `session --hosts --json` already returned
/// (crate `AGENTS.md`'s "frontend only").
#[derive(Debug, Clone, Default)]
pub struct RosterCache {
    pub outcome: Option<Outcome>,
    fetched_at: Option<Instant>,
}

/// One flattened, selectable ROSTER row (P-C5 adds selection to C4's
/// read-only pane) — a node header, one of its sessions, or the cosmetic
/// "(no sessions)" filler a node with an empty session list renders. Mirrors
/// [`DagRow`]'s "one Vec is the single source of truth for both render and
/// key handling" shape, over the roster's node/session tree instead of the
/// DAG. `is_last` on `Session` is the tree-branch glyph's own lookahead
/// (`└─`/`├─`), precomputed here so the render side never re-derives it.
#[derive(Debug, Clone)]
pub enum RosterRow {
    NodeHeader {
        name: String,
        is_local: bool,
        presence: String,
        fetched_at: Option<String>,
    },
    Session {
        session: RosterSession,
        is_last: bool,
    },
    Empty,
}

/// One row of the PENDING panel — reshaped straight from `session pending
/// list --json`'s `data.pending[]` (`conduct/src/graph/pending.rs::entry_view`),
/// never re-derived: `id` is the entry's ARRAY POSITION, not a stable id (see
/// that module's doc) — `App`'s a/d handlers must always re-list immediately
/// after a resolve rather than trusting a row built before it.
#[derive(Debug, Clone, Default)]
pub struct PendingRow {
    pub id: String,
    pub session_id: String,
    pub text: String,
    pub submit: bool,
    pub queued_at: String,
    pub from: Option<String>,
    pub state: String,
}

/// The whole conductor state.
pub struct App {
    pub panel: Panel,
    pub home_sel: usize,
    pub sidebar_focused: bool,
    pub sidebar_sel: usize,
    pub sidebar_scroll: usize,
    sidebar_folded: HashSet<String>,
    sidebar_past_open: HashSet<String>,
    sidebar_section_folded: HashSet<(String, bool)>,
    pub mail: crate::mailview::MailBoard,
    pub mail_room_sel: usize,
    pub mail_room_id: Option<String>,
    pub mail_room_focus: bool,
    pub mail_sel: usize,
    pub mail_scroll: u16,
    mail_refreshed: Option<Instant>,
    pub help_open: bool,
    /// The open headless-log-tail overlay, or `None` (closed) — the same
    /// modal role [`help_open`](Self::help_open) plays, richer payload. Enter
    /// on a session whose record carries `log_path` opens this instead of
    /// focusing the session's window ([`App::cue_session`]); lib.rs's
    /// `handle_key` swallows keys while it is `Some` the same way it does for
    /// the help overlay.
    pub tail: Option<LogTail>,
    /// Selected node in the DAG (Graph) panel (indexes the preorder node list
    /// [`crate::graphview::node_order`] the layout walks).
    pub graph_sel: usize,
    pub graph_pan: Option<(usize, usize)>,
    pub graph_zoom: i8,
    pub graph_pan_mode: bool,
    pub graph_drag: Option<(u16, u16, usize, usize)>,
    /// Selected row in the SESSION panel (indexes [`App::dag_rows`]).
    pub dag_sel: usize,
    /// Selected row in the PROJECTS panel.
    pub proj_sel: usize,
    /// Live data from the stage tree.
    pub projects: Vec<graph::Project>,
    pub sessions: Vec<SessionRecord>,
    pub history: Vec<aoide_storage::ledger::LedgerEntry>,
    pub history_error: Option<String>,
    pub history_selected: Option<aoide_storage::ledger::LedgerEntry>,
    pub hooks: Vec<graph::HookRecord>,
    /// The audit tail (newest last), capped to [`LOG_CAP`].
    pub log: Vec<LogLine>,
    pub log_sel: usize,
    pub log_scroll: u16,
    pub log_error: Option<String>,
    pub palette: Palette,
    /// The last dispatched action's outcome — drives the status line.
    pub last_outcome: Option<Outcome>,
    /// Any active inline prompt.
    pub input: Option<Input>,
    pub context_menu: Option<ContextMenu>,
    pub mail_draft: Option<MailDraft>,
    pub mail_target_menu: Option<(u16, u16, Vec<(String, String)>, usize)>,
    /// Group names currently folded shut in the SESSION panel.
    pub folded: HashSet<String>,
    /// Terminal-watcher: session id → remaining fresh ticks. A session lands
    /// here when it first appears after launch and drops out a few beats later.
    pub fresh: BTreeMap<String, u8>,
    /// Every session id we have already seen (so `fresh` only marks arrivals).
    known: HashSet<String>,
    /// False until the first load — the opening roster is not "new arrivals".
    initialized: bool,
    mtimes: StageMtimes,
    /// The injected dispatcher every mutation runs through ([`App::dispatch`]
    /// calls it). Defaults to [`no_dispatch`] until [`App::load`] wires the
    /// real one in — see [`DispatchFn`]'s doc comment for why this is
    /// injected rather than reached for as a trunk global.
    dispatch_fn: DispatchFn,
    /// The ROSTER panel's cache — last `session --hosts` fetch + when.
    pub roster: RosterCache,
    /// `Some` while a background `session --hosts` dispatch is in flight — set by
    /// [`App::spawn_roster_fetch`], drained (never blocked on) by
    /// [`App::drain_roster`]. See the module doc's "Roster: throttled,
    /// backgrounded dispatch" for why this exists at all.
    roster_rx: Option<mpsc::Receiver<Outcome>>,
    /// Selected row in the ROSTER panel (indexes [`App::roster_flat_rows`]).
    pub roster_sel: usize,
    /// The PENDING panel's cache — last `session pending list` [`Outcome`]. No
    /// throttle metadata (unlike [`RosterCache`]): a local file read refreshes
    /// synchronously on the same cadence every other local pane uses (see
    /// [`App::refresh_pending`]).
    pub pending: Option<Outcome>,
    /// Selected row in the PENDING panel (indexes [`App::pending_rows`]).
    pub pending_sel: usize,
}

/// How many audit lines the LOG panel keeps in memory.
pub const LOG_CAP: usize = 500;

/// A dispatch fn pointer: matches `aoide::dispatch::dispatch`'s exact
/// signature (a plain `fn`, not a closure), so `lib.rs`'s launch site can hand
/// it in directly. Deliberately its own type rather than reusing
/// `aoide_server::mcp::DispatchFn` (structurally identical, but sharing it
/// would wire an unwanted `conductor → server` coupling once `conductor`
/// becomes its own crate) — the conductor is a FRONTEND over the trunk's
/// dispatcher, and this is the seam that lets it stop reaching for the
/// trunk's `dispatch::dispatch` / `dispatch::registry()` globals directly.
pub type DispatchFn = fn(&Invocation) -> Outcome;

/// The `dispatch_fn` fallback for an [`App`] that was never wired to a real
/// dispatcher ([`App::empty`], the `#[cfg(test)]` [`App::for_test`]): none of
/// the in-crate unit tests actually dispatch (they only render/select/
/// navigate), so this just needs to be a harmless, well-typed placeholder.
fn no_dispatch(_: &Invocation) -> Outcome {
    Outcome::usage("conductor", "dispatch not wired for this App")
}

/// The bracketed status tag shared by the global status line
/// ([`App::status_message`]) and the ROSTER pane's fetch status
/// ([`App::roster_status`]) — one mapping, not two (P-C4 review nit).
fn status_tag(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok",
        Status::Error => "err",
        Status::Usage => "usage",
        Status::NotImplemented => "n/i",
    }
}

impl App {
    fn empty() -> Self {
        App {
            panel: Panel::Home,
            home_sel: 0,
            sidebar_focused: true,
            sidebar_sel: 0,
            sidebar_scroll: 0,
            sidebar_folded: HashSet::new(),
            sidebar_past_open: HashSet::new(),
            sidebar_section_folded: HashSet::new(),
            mail: crate::mailview::MailBoard::default(),
            mail_room_sel: 0,
            mail_room_id: None,
            mail_room_focus: true,
            mail_sel: 0,
            mail_scroll: 0,
            mail_refreshed: None,
            help_open: false,
            tail: None,
            graph_sel: 0,
            graph_pan: None,
            graph_zoom: 0,
            graph_pan_mode: false,
            graph_drag: None,
            dag_sel: 0,
            proj_sel: 0,
            projects: Vec::new(),
            sessions: Vec::new(),
            history: Vec::new(),
            history_error: None,
            history_selected: None,
            hooks: Vec::new(),
            log: Vec::new(),
            log_sel: 0,
            log_scroll: 0,
            log_error: None,
            palette: Palette::default(),
            last_outcome: None,
            input: None,
            context_menu: None,
            mail_draft: None,
            mail_target_menu: None,
            folded: HashSet::new(),
            fresh: BTreeMap::new(),
            known: HashSet::new(),
            initialized: false,
            mtimes: StageMtimes::default(),
            dispatch_fn: no_dispatch,
            roster: RosterCache::default(),
            roster_rx: None,
            roster_sel: 0,
            pending: None,
            pending_sel: 0,
        }
    }

    /// Test-only constructor: an App seeded from in-memory data, no disk. Lets
    /// the panel unit tests exercise pure rendering without a stage tree.
    #[cfg(test)]
    pub fn for_test(
        projects: Vec<graph::Project>,
        sessions: Vec<SessionRecord>,
        hooks: Vec<graph::HookRecord>,
    ) -> Self {
        let mut app = App::empty();
        app.projects = projects;
        app.sessions = sessions;
        app.hooks = hooks;
        app
    }

    /// Test-only constructor: like [`App::for_test`] but also wires a real
    /// `DispatchFn` — the ROSTER throttle tests need to observe actual
    /// dispatch calls (a counting `fn`), not just render/select/navigate.
    #[cfg(test)]
    pub fn for_test_with_dispatch(dispatch: DispatchFn) -> Self {
        let mut app = App::empty();
        app.dispatch_fn = dispatch;
        app
    }

    /// Build the app from the stage tree (missing files → empty, tolerated).
    /// `dispatch` is the real dispatcher ([`App::dispatch`] threads every
    /// mutation through it) — injected here rather than reached for as a
    /// trunk global, so the conductor stays a pure frontend.
    pub fn load(dispatch: DispatchFn) -> Self {
        let mut app = App::empty();
        app.dispatch_fn = dispatch;
        app.reload_all();
        app.refresh_mail();
        app
    }

    // ── Stage-file loading (missing = empty; corrupt = kept empty) ──────────

    fn load_json<T: serde::de::DeserializeOwned + Default>(path: &std::path::Path) -> T {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn mtime(path: &std::path::Path) -> Option<SystemTime> {
        std::fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    /// The CONDUCTING stage dir (`sessions.json`/`hooks.json`/`projects.json`/
    /// `graph.json`) — `state/stage/` (command-defrag S1). Distinct from
    /// [`App::rice_stage`], which stays `song/stage/` for `livery.json`; the
    /// two coincide whenever `$AOIDE_STAGE_DIR` is set (every test fixture
    /// here does), and diverge only on the default production layout.
    fn stage() -> PathBuf {
        conducting_stage_dir()
    }
    /// The rice/paint stage dir (`livery.json`) — unchanged, `song/stage/`.
    fn rice_stage() -> PathBuf {
        stage_dir()
    }
    fn audit_path() -> PathBuf {
        aoide_protocol::default_audit_log()
    }

    fn history_mtime() -> Option<SystemTime> {
        if cfg!(test) {
            return None;
        }
        Self::mtime(&aoide_storage::ledger::session_ledger_path())
    }

    fn reload_history(&mut self) {
        // Unit fixtures inject history directly, never the operator's ambient ledger.
        if cfg!(test) {
            return;
        }
        match aoide_storage::ledger::read_ledger() {
            Ok(entries) => {
                self.history = entries;
                self.history_error = None;
            }
            Err(error) => self.history_error = Some(format!("Cannot read past sessions: {error}")),
        }
    }

    /// Reload every stage file + the audit tail and refresh recorded mtimes.
    pub fn reload_all(&mut self) {
        let dir = Self::stage();
        let p: ProjectsFile = Self::load_json(&dir.join("projects.json"));
        let s: SessionsFile = Self::load_json(&dir.join("sessions.json"));
        let h: HooksFile = Self::load_json(&dir.join("hooks.json"));
        self.projects = p.projects;
        self.sessions = s.sessions;
        self.hooks = h.hooks;
        self.palette = load_palette(&stage_notes_path(&Self::rice_stage()));
        self.reload_log();
        self.reload_history();
        // A local read through the dispatcher (P-C5) — `reload_all` runs
        // synchronously right after every mutating `App::dispatch`, so this
        // is what makes "re-list after every pending resolve" true: by the
        // time `handle_key`'s a/d handler returns, `self.pending` already
        // reflects the post-resolve queue, positions and all.
        self.refresh_pending();

        self.mtimes = StageMtimes {
            history: Self::history_mtime(),
            sessions: Self::mtime(&dir.join("sessions.json")),
            hooks: Self::mtime(&dir.join("hooks.json")),
            projects: Self::mtime(&dir.join("projects.json")),
            notes: Self::mtime(&stage_notes_path(&Self::rice_stage())),
            audit: Self::mtime(&Self::audit_path()),
        };
        self.note_new_sessions();
        self.clamp_selection();
    }

    /// Terminal-watcher bookkeeping: any session id we have never seen becomes
    /// fresh for [`FRESH_TICKS`] beats (skipped on the very first load — the
    /// opening roster is history, not news). Departed ids drop their mark.
    fn note_new_sessions(&mut self) {
        let ids: HashSet<String> = self.merged().iter().map(|s| s.session_id.clone()).collect();
        if self.initialized {
            for id in &ids {
                if !self.known.contains(id) {
                    self.fresh.insert(id.clone(), FRESH_TICKS);
                }
            }
        }
        self.fresh.retain(|id, _| ids.contains(id));
        self.known = ids;
        self.initialized = true;
    }

    /// Refresh the bounded audit snapshot without discarding it on read failure.
    fn reload_log(&mut self) {
        match crate::eventview::read_history(&Self::audit_path()) {
            Ok(lines) => {
                let selected = self.log.get(self.log_sel).map(|r| &r.raw);
                let next = selected.and_then(|raw| lines.iter().position(|r| &r.raw == raw));
                if next.is_none() {
                    self.log_scroll = 0;
                }
                self.log_sel =
                    next.unwrap_or_else(|| self.log_sel.min(lines.len().saturating_sub(1)));
                self.log = lines;
                self.log_error = None;
            }
            Err(error) => self.log_error = Some(error),
        }
    }

    /// A tick: reload any stage file / the audit log whose mtime advanced, age
    /// the fresh marks, and note any newly-arrived sessions. Returns `true`
    /// when anything changed (so the loop repaints).
    pub fn poll_refresh(&mut self) -> bool {
        let dir = Self::stage();
        let rice_dir = Self::rice_stage();
        let mut changed = false;
        if self.panel == Panel::Mail
            && self
                .mail_refreshed
                .is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(5))
        {
            self.refresh_mail();
            changed = true;
        }

        let cur = StageMtimes {
            history: Self::history_mtime(),
            sessions: Self::mtime(&dir.join("sessions.json")),
            hooks: Self::mtime(&dir.join("hooks.json")),
            projects: Self::mtime(&dir.join("projects.json")),
            notes: Self::mtime(&stage_notes_path(&rice_dir)),
            audit: Self::mtime(&Self::audit_path()),
        };

        if cur.projects != self.mtimes.projects {
            let p: ProjectsFile = Self::load_json(&dir.join("projects.json"));
            self.projects = p.projects;
            changed = true;
        }
        if cur.history != self.mtimes.history {
            self.reload_history();
            changed = true;
        }
        if cur.sessions != self.mtimes.sessions {
            let s: SessionsFile = Self::load_json(&dir.join("sessions.json"));
            self.sessions = s.sessions;
            changed = true;
        }
        if cur.hooks != self.mtimes.hooks {
            let h: HooksFile = Self::load_json(&dir.join("hooks.json"));
            self.hooks = h.hooks;
            changed = true;
        }
        if cur.notes != self.mtimes.notes {
            self.palette = load_palette(&stage_notes_path(&rice_dir));
            changed = true;
        }
        if cur.audit != self.mtimes.audit {
            self.reload_log();
            changed = true;
        }

        self.mtimes = cur;

        // The log tail (if open) re-reads on its OWN mtime gate, never
        // folded into `StageMtimes` — it isn't a stage file, and most ticks
        // it's `None` so this is a single field check, not a read. `logtail`
        // does the actual (bounded, <=64KB) IO; poll_refresh just decides
        // whether that's due.
        if let Some(t) = &mut self.tail {
            let m = Self::mtime(&t.path);
            if m != t.mtime {
                t.lines = logtail::tail_file(&t.path, logtail::TAIL_LINES);
                t.mtime = m;
                changed = true;
            }
        }

        // Age the fresh marks one beat; a mark that expires needs a repaint to
        // shed its highlight. (Decrement before detection so a session arriving
        // THIS tick keeps its full run of beats.)
        if !self.fresh.is_empty() {
            for v in self.fresh.values_mut() {
                *v = v.saturating_sub(1);
            }
            self.fresh.retain(|_, v| *v > 0);
            changed = true;
        }

        if changed {
            self.note_new_sessions();
            self.clamp_selection();
        }

        // ROSTER: independent of the stage-mtime watch above — the roster is
        // live network state, not a stage file. Deliberately outside the
        // `if changed` block: draining/spawning a roster fetch must run every
        // tick regardless of whether anything else changed.
        if self.poll_roster() {
            changed = true;
        }

        // PENDING: same "independent of the stage-mtime watch" reasoning as
        // ROSTER above, minus the throttle — see the "PENDING" section.
        if self.poll_pending() {
            changed = true;
        }

        changed
    }

    // ── ROSTER: throttled, backgrounded `session --hosts` dispatch (P-C4;
    // re-spelled from the retired standalone `who` command at the
    // session-surface redesign, command-defrag lane X, 2026-08-28 — same
    // mechanism, same `Outcome` shape, only the dispatched path/flags
    // changed) ──────────────────────────────────────────────────────────
    //
    // `session --hosts` performs a live network probe of every registered
    // node on EVERY invocation (`conduct/src/graph/who.rs`'s module doc —
    // the roster core) — up to ~2s per node, run in parallel inside the
    // roster core itself but still ~2s wall-clock in the worst case.
    // Calling it through `App::dispatch` the way every other action does
    // would block the ~500ms tick loop for that long, so this dispatch runs
    // on its OWN `std::thread` (the exact pattern the roster core's own
    // `probe_nodes` already uses one layer down) and reports back over an
    // `mpsc` channel that the tick loop only ever polls non-blockingly. This
    // is the ONE dispatch site in the crate that does not go through
    // `App::dispatch` — the roster never mutates anything, so there is no
    // stage write to `reload_all()` after, and the audit record still
    // happens (the dispatched `Invocation` still carries `Door::Cli`).

    /// Is the cached roster stale enough to re-fetch? `None` (never fetched)
    /// is always stale.
    fn roster_stale(&self) -> bool {
        match self.roster.fetched_at {
            None => true,
            Some(t) => t.elapsed() >= ROSTER_THROTTLE,
        }
    }

    /// Non-blocking: pick up a finished background `session --hosts`
    /// dispatch, if any. A fetch still running just leaves `roster_rx` in
    /// place for the next poll. Returns `true` when the cache changed (so
    /// the tick loop knows to repaint).
    fn drain_roster(&mut self) -> bool {
        let Some(rx) = &self.roster_rx else {
            return false;
        };
        match rx.try_recv() {
            Ok(outcome) => {
                self.roster.outcome = Some(outcome);
                self.roster.fetched_at = Some(Instant::now());
                self.roster_rx = None;
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
            Err(mpsc::TryRecvError::Disconnected) => {
                // The probe thread ended without sending (panicked) — drop
                // the in-flight marker so the next stale tick tries again
                // rather than wedging the pane forever.
                self.roster_rx = None;
                false
            }
        }
    }

    /// Spawn the `session --hosts` dispatch on a background thread. A no-op
    /// while a fetch is already in flight — callers (the tick, a panel
    /// switch, the manual refresh key) never need to check that themselves.
    fn spawn_roster_fetch(&mut self) {
        if self.roster_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let dispatch_fn = self.dispatch_fn;
        std::thread::spawn(move || {
            let inv = Invocation {
                path: vec!["session".to_string()],
                args: Vec::new(),
                flags: BTreeMap::from([
                    ("json".to_string(), "true".to_string()),
                    ("hosts".to_string(), "true".to_string()),
                ]),
                door: Door::Cli,
            };
            let outcome = dispatch_fn(&inv);
            // The receiver may already be gone (App dropped mid-fetch, e.g.
            // conductor quit); nothing to do about that.
            let _ = tx.send(outcome);
        });
        self.roster_rx = Some(rx);
    }

    /// Tick-driven roster refresh: drain any finished fetch, then — only when
    /// the pane is the VISIBLE panel and the cache has aged past
    /// [`ROSTER_THROTTLE`] — kick off the next one. A tick the pane isn't
    /// showing never starts a probe.
    fn poll_roster(&mut self) -> bool {
        let mut changed = self.drain_roster();
        if changed {
            // A landed fetch can SHRINK the roster (a node went unreachable,
            // a session ended) — `roster_sel` was clamped against the OLD
            // row count. `reload_all`/`poll_refresh`'s stage-mtime path
            // clamps after every reload, but a background roster fetch
            // completing is the one mutation that bypasses both (review nit): without
            // this, render's `.min()` would visibly highlight the last row
            // while `open_compose`'s raw `.get(self.roster_sel)` silently
            // no-ops `s` against a row that no longer exists at that index.
            self.clamp_selection();
        }
        if self.panel == Panel::Roster && self.roster_stale() {
            self.spawn_roster_fetch();
            changed = true; // a fresh "probing…" status is itself a repaint
        }
        changed
    }

    /// The ROSTER panel's rows, parsed from the cached `session --hosts`
    /// [`Outcome`] (never re-derived — the crate's one rule). Malformed/absent data
    /// yields an empty roster rather than panicking; [`App::roster_status`]
    /// tells the pane why.
    pub fn roster_nodes(&self) -> Vec<RosterNode> {
        let Some(data) = self.roster.outcome.as_ref().and_then(|o| o.data.as_ref()) else {
            return Vec::new();
        };
        let nodes = data
            .get("nodes")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        nodes
            .iter()
            .map(|n| {
                let sessions = n
                    .get("sessions")
                    .and_then(|v| v.as_array())
                    .map(|a| a.as_slice())
                    .unwrap_or(&[]);
                RosterNode {
                    name: n["name"].as_str().unwrap_or("").to_string(),
                    is_local: n["isLocal"].as_bool().unwrap_or(false),
                    presence: n["presence"].as_str().unwrap_or("").to_string(),
                    fetched_at: n["fetchedAt"].as_str().map(String::from),
                    sessions: sessions
                        .iter()
                        .map(|s| RosterSession {
                            label: s["label"].as_str().unwrap_or("").to_string(),
                            state: s["state"].as_str().unwrap_or("").to_string(),
                        })
                        .collect(),
                }
            })
            .collect()
    }

    /// [`App::roster_nodes`] flattened into one selectable `Vec` (P-C5 adds
    /// selection to C4's read-only pane) — the same "one row model for
    /// render + keys" shape [`App::dag_rows`] already uses over the DAG,
    /// here over the roster's node/session tree. `roster_sel` indexes this, never
    /// `roster_nodes()`'s nested shape directly.
    pub fn roster_flat_rows(&self) -> Vec<RosterRow> {
        let mut rows = Vec::new();
        for n in self.roster_nodes() {
            rows.push(RosterRow::NodeHeader {
                name: n.name,
                is_local: n.is_local,
                presence: n.presence.clone(),
                fetched_at: n.fetched_at,
            });
            let len = n.sessions.len();
            if len == 0 && n.presence != "never-pulled" {
                rows.push(RosterRow::Empty);
            }
            for (i, s) in n.sessions.into_iter().enumerate() {
                rows.push(RosterRow::Session {
                    session: s,
                    is_last: i + 1 == len,
                });
            }
        }
        rows
    }

    /// A one-line fetch status for the pane header: probing, freshly
    /// fetched, never fetched yet, or — when the roster fetch itself came
    /// back non-`Ok` — that error, in the same `[tag] command: message` shape
    /// [`App::status_message`] uses for the global status line (house
    /// style; P-C4 review nit). Without this branch a failed fetch would
    /// render as a bare "fetched Ns ago" over an empty roster, silently
    /// indistinguishable from "this box and every node really have zero
    /// sessions."
    pub fn roster_status(&self) -> String {
        let probing = self.roster_rx.is_some();
        if let Some(o) = self
            .roster
            .outcome
            .as_ref()
            .filter(|o| o.status != Status::Ok)
        {
            let first = o.message.lines().next().unwrap_or("");
            let suffix = if probing { " · probing…" } else { "" };
            return format!("[{}] {}: {first}{suffix}", status_tag(o.status), o.command);
        }
        match (self.roster.fetched_at, probing) {
            (None, true) => "probing…".to_string(),
            (None, false) => "not yet fetched — press r".to_string(),
            (Some(t), true) => format!("probing… (last fetched {}s ago)", t.elapsed().as_secs()),
            (Some(t), false) => format!("fetched {}s ago", t.elapsed().as_secs()),
        }
    }

    // ── PENDING: `session pending list` through the dispatcher (P-C5) ─────────
    //
    // Unlike ROSTER's `session --hosts`, `session pending list` is a local file read (no
    // network) — refreshing it costs one JSON parse of `state/stage/pending.json`,
    // not a ~2s-per-node probe. So there is no throttle window and no
    // background thread here: [`App::refresh_pending`] runs synchronously,
    // called from `reload_all` (which fires after every dispatch — this is
    // what makes "re-list after every resolve" true) and from
    // [`App::poll_pending`] every tick while the pane is visible.

    /// Refresh `self.pending` via the injected dispatcher — `session pending
    /// list`'s malformed-entry detection and display-grammar rendering stay
    /// in `conduct::graph::pending` (`crates/AGENTS.md`'s "no cross-crate
    /// copying"); this only reshapes the JSON it already computed.
    fn refresh_pending(&mut self) {
        let inv = Invocation {
            path: vec![
                "session".to_string(),
                "pending".to_string(),
                "list".to_string(),
            ],
            args: Vec::new(),
            flags: BTreeMap::from([("json".to_string(), "true".to_string())]),
            door: Door::Cli,
        };
        self.pending = Some((self.dispatch_fn)(&inv));
    }

    /// Tick-driven pending refresh: only while the pane is the VISIBLE panel
    /// (a tick it isn't showing never bothers). Always reports a repaint
    /// while visible — cheap enough that, unlike ROSTER, there is no
    /// staleness gate to check first.
    fn poll_pending(&mut self) -> bool {
        if self.panel == Panel::Pending {
            self.refresh_pending();
            true
        } else {
            false
        }
    }

    /// The PENDING panel's rows, parsed from the cached `session pending list`
    /// [`Outcome`] (never re-derived). `id` is each entry's ARRAY POSITION —
    /// see [`PendingRow`]'s doc — so a caller must re-fetch (which
    /// [`App::dispatch`] already does via `reload_all`) before trusting a
    /// row built from a previous fetch.
    pub fn pending_rows(&self) -> Vec<PendingRow> {
        let Some(data) = self.pending.as_ref().and_then(|o| o.data.as_ref()) else {
            return Vec::new();
        };
        let arr = data
            .get("pending")
            .and_then(|v| v.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        arr.iter()
            .map(|v| PendingRow {
                id: v["id"].as_str().unwrap_or("").to_string(),
                session_id: v["sessionId"].as_str().unwrap_or("").to_string(),
                text: v["text"].as_str().unwrap_or("").to_string(),
                submit: v["submit"].as_bool().unwrap_or(false),
                queued_at: v["queuedAt"].as_str().unwrap_or("").to_string(),
                from: v["from"].as_str().map(String::from),
                state: v["state"].as_str().unwrap_or("pending").to_string(),
            })
            .collect()
    }

    /// A one-line status for the pane header — mirrors [`App::roster_status`]'s
    /// non-`Ok` surfacing (P-C4 review nit, same rule here): a failed
    /// `session pending list` (a corrupt `pending.json` file, not a malformed
    /// individual entry — that lists fine with `state: "malformed"`) must not
    /// silently render as an empty, all-clear queue.
    pub fn pending_status(&self) -> String {
        match self.pending.as_ref() {
            Some(o) if o.status != Status::Ok => {
                let first = o.message.lines().next().unwrap_or("");
                format!("[{}] {}: {first}", status_tag(o.status), o.command)
            }
            Some(o) => o.message.lines().next().unwrap_or("").to_string(),
            None => "not yet fetched".to_string(),
        }
    }

    // ── The DAG row model (one truth for render + keys) ─────────────────────

    /// The merged sessions in the same deterministic order the DAG tree walks.
    pub fn merged(&self) -> Vec<SessionRecord> {
        graph::merged_sessions(&self.sessions, &self.hooks)
    }

    /// Project navigation is a projection of the graph's effective ownership.
    /// Past rows contain only ended records still present in the stage snapshot.
    pub fn sidebar_rows(&self) -> Vec<SidebarRow> {
        fn append(rows: &mut Vec<SidebarRow>, group: &[&SessionRecord], past: bool) {
            fn visit(
                rows: &mut Vec<SidebarRow>,
                group: &[&SessionRecord],
                rec: &SessionRecord,
                past: bool,
                depth: usize,
                seen: &mut HashSet<String>,
            ) {
                if !seen.insert(rec.session_id.clone()) {
                    return;
                }
                let title = rec
                    .title
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&rec.agent);
                let pet = rec.petname.as_deref().filter(|s| !s.is_empty());
                let short: String = rec
                    .session_id
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let label = match pet {
                    Some(p) => format!("{p} · {title} (…{short})"),
                    None => format!("{title} (…{short})"),
                };
                let label = if past {
                    format!(
                        "{} · {label}",
                        if is_terminal(rec) {
                            "terminal"
                        } else {
                            "agent"
                        }
                    )
                } else {
                    label
                };
                rows.push(SidebarRow::Session {
                    rec: rec.clone(),
                    label,
                    past,
                    depth,
                });
                for child in group
                    .iter()
                    .filter(|s| s.parent_session_id.as_deref() == Some(rec.session_id.as_str()))
                {
                    visit(rows, group, child, past, depth + 1, seen);
                }
            }
            let mut seen = HashSet::new();
            for rec in group.iter().filter(|s| {
                !group
                    .iter()
                    .any(|p| Some(p.session_id.as_str()) == s.parent_session_id.as_deref())
            }) {
                visit(rows, group, rec, past, 2, &mut seen);
            }
            // Malformed cycles remain inspectable rather than disappearing.
            for rec in group {
                visit(rows, group, rec, past, 2, &mut seen);
            }
        }
        let merged = self.merged();
        let mut names = sorted_project_names(&self.projects);
        let mut groups: BTreeMap<String, Vec<&SessionRecord>> = BTreeMap::new();
        let mut history_groups: BTreeMap<String, Vec<&aoide_storage::ledger::LedgerEntry>> =
            BTreeMap::new();
        let mut seen: HashSet<String> = merged.iter().map(|s| s.session_id.clone()).collect();
        for entry in self.history.iter().rev() {
            if !seen.insert(entry.session_id.clone()) {
                continue;
            }
            let name = entry
                .project
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let projection = SessionRecord {
                        cwd: entry.cwd.clone(),
                        ..Default::default()
                    };
                    graph::project_for(&projection, &self.projects)
                        .map(|i| self.projects[i].name.clone())
                        .unwrap_or_else(|| UNANCHORED.to_string())
                });
            if !names.contains(&name) {
                names.push(name.clone());
            }
            history_groups.entry(name).or_default().push(entry);
        }
        for rec in &merged {
            let name = graph::effective_project_for(rec, &merged, &self.projects)
                .map(|i| self.projects[i].name.clone())
                .unwrap_or_else(|| UNANCHORED.to_string());
            groups.entry(name).or_default().push(rec);
        }
        if groups.contains_key(UNANCHORED) && !names.iter().any(|n| n == UNANCHORED) {
            names.push(UNANCHORED.to_string());
        }
        let mut rows = Vec::new();
        for name in names {
            let folded = self.sidebar_folded.contains(&name);
            rows.push(SidebarRow::Project {
                name: name.clone(),
                folded,
            });
            if folded {
                continue;
            }
            let (past, live): (Vec<_>, Vec<_>) = groups
                .remove(&name)
                .unwrap_or_default()
                .into_iter()
                .partition(|s| aoide_protocol::canonical_state(&s.state) == "done");
            for terminal in [false, true] {
                let group: Vec<_> = live
                    .iter()
                    .copied()
                    .filter(|s| is_terminal(s) == terminal)
                    .collect();
                if group.is_empty() {
                    continue;
                }
                let folded = self
                    .sidebar_section_folded
                    .contains(&(name.clone(), terminal));
                rows.push(SidebarRow::Section {
                    project: name.clone(),
                    terminal,
                    folded,
                    count: group.len(),
                });
                if !folded {
                    append(&mut rows, &group, false);
                }
            }
            let history = history_groups.remove(&name).unwrap_or_default();
            if !past.is_empty() || !history.is_empty() {
                let folded = !self.sidebar_past_open.contains(&name);
                rows.push(SidebarRow::Past {
                    project: name,
                    folded,
                    count: past.len() + history.len(),
                });
                if !folded {
                    append(&mut rows, &past, true);
                    for entry in history {
                        let title = entry
                            .title
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&entry.agent);
                        let label = match entry.petname.as_deref().filter(|s| !s.is_empty()) {
                            Some(petname) => format!("{petname} · {title}"),
                            None => title.to_string(),
                        };
                        let label = format!(
                            "{} · {label}",
                            if entry.agent == "shell" {
                                "terminal"
                            } else {
                                "agent"
                            }
                        );
                        rows.push(SidebarRow::History {
                            entry: entry.clone(),
                            label,
                            depth: 2,
                        });
                    }
                }
            }
        }
        rows
    }

    /// Navigate only: selecting an ended record never resurrects or focuses it.
    pub fn sidebar_activate(&mut self, index: usize) {
        let Some(row) = self.sidebar_rows().get(index).cloned() else {
            return;
        };
        self.sidebar_sel = index;
        match row {
            SidebarRow::History { entry, .. } => {
                self.select_panel(if entry.agent == "shell" {
                    Panel::Terminals
                } else {
                    Panel::Session
                });
                self.history_selected = Some(entry);
                self.sidebar_focused = false;
            }
            SidebarRow::Project { name, .. } => {
                if let Some(i) = sorted_project_names(&self.projects)
                    .iter()
                    .position(|n| *n == name)
                {
                    self.proj_sel = i;
                    self.select_panel(Panel::Projects);
                    self.sidebar_focused = false;
                }
            }
            SidebarRow::Section {
                project, terminal, ..
            } => {
                let key = (project, terminal);
                if !self.sidebar_section_folded.remove(&key) {
                    self.sidebar_section_folded.insert(key);
                }
            }
            SidebarRow::Past { project, .. } => {
                if !self.sidebar_past_open.remove(&project) {
                    self.sidebar_past_open.insert(project);
                }
            }
            SidebarRow::Session { rec, .. } => {
                self.history_selected = None;
                self.folded.clear();
                self.select_panel(if is_terminal(&rec) {
                    Panel::Terminals
                } else {
                    Panel::Session
                });
                if let Some(i) = self.dag_rows().iter().position(|r| matches!(r, DagRow::Session { rec: s, .. } if s.session_id == rec.session_id)) {
                    self.dag_sel = i;
                    self.sidebar_focused = false;
                }
            }
        }
    }

    pub fn handle_sidebar_key(&mut self, key: KeyEvent) {
        let rows = self.sidebar_rows();
        self.sidebar_sel = self.sidebar_sel.min(rows.len().saturating_sub(1));
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.sidebar_sel = self.sidebar_sel.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.sidebar_sel = (self.sidebar_sel + 1).min(rows.len().saturating_sub(1))
            }
            KeyCode::Enter => self.sidebar_activate(self.sidebar_sel),
            KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l') => {
                let close = matches!(key.code, KeyCode::Left | KeyCode::Char('h'));
                match rows.get(self.sidebar_sel) {
                    Some(SidebarRow::Project { name, .. }) => {
                        if close {
                            self.sidebar_folded.insert(name.clone());
                        } else {
                            self.sidebar_folded.remove(name);
                        }
                    }
                    Some(SidebarRow::Section {
                        project, terminal, ..
                    }) => {
                        let key = (project.clone(), *terminal);
                        if close {
                            self.sidebar_section_folded.insert(key);
                        } else {
                            self.sidebar_section_folded.remove(&key);
                        }
                    }
                    Some(SidebarRow::Past { project, .. }) => {
                        if close {
                            self.sidebar_past_open.remove(project);
                        } else {
                            self.sidebar_past_open.insert(project.clone());
                        }
                    }
                    Some(SidebarRow::Session { past, .. }) if close => {
                        let past = *past;
                        if let Some(i) = rows[..self.sidebar_sel].iter().rposition(|r| {
                            matches!(r, SidebarRow::Project { .. })
                                || (past && matches!(r, SidebarRow::Past { .. }))
                                || (!past && matches!(r, SidebarRow::Section { .. }))
                        }) {
                            self.sidebar_sel = i;
                        }
                    }
                    Some(SidebarRow::History { .. }) if close => {
                        if let Some(i) = rows[..self.sidebar_sel]
                            .iter()
                            .rposition(|r| matches!(r, SidebarRow::Past { .. }))
                        {
                            self.sidebar_sel = i;
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        self.sidebar_sel = self
            .sidebar_sel
            .min(self.sidebar_rows().len().saturating_sub(1));
        self.sidebar_scroll = self.sidebar_scroll.min(self.sidebar_sel);
    }

    /// Flatten the DAG into selectable rows: every project (sorted by name) as
    /// a group header carrying `[live/total]`, then — unless folded — its root
    /// sessions with spawned subtrees nested beneath, tree prefixes pre-walked;
    /// unanchored sessions gather under [`UNANCHORED`] at the end. Grouping and
    /// order are borrowed from the graph pure functions (`anchor_for`, the
    /// `merged_sessions` sort), never re-derived.
    pub fn dag_rows(&self) -> Vec<DagRow> {
        let merged = self.merged();
        let mut projects = self.projects.clone();
        projects.sort_by(|a, b| a.name.cmp(&b.name));

        let visible: Vec<_> = merged
            .iter()
            .filter(|s| match self.panel {
                Panel::Session => !is_terminal(s),
                Panel::Terminals => is_terminal(s),
                _ => true,
            })
            .collect();
        let ids: HashSet<&str> = visible.iter().map(|s| s.session_id.as_str()).collect();
        let mut children: BTreeMap<&str, Vec<&SessionRecord>> = BTreeMap::new();
        let mut roots: Vec<&SessionRecord> = Vec::new();
        for s in visible {
            match s.parent_session_id.as_deref().filter(|p| ids.contains(p)) {
                Some(p) => children.entry(p).or_default().push(s),
                None => roots.push(s),
            }
        }

        let mut per_project: Vec<Vec<&SessionRecord>> = vec![Vec::new(); projects.len()];
        let mut loose: Vec<&SessionRecord> = Vec::new();
        for r in &roots {
            match graph::effective_project_for(r, &merged, &projects) {
                Some(i) => per_project[i].push(r),
                None => loose.push(r),
            }
        }

        let mut rows: Vec<DagRow> = Vec::new();
        for (i, p) in projects.iter().enumerate() {
            self.push_group(&mut rows, &p.name, &p.path, &per_project[i], &children);
        }
        if !loose.is_empty() {
            self.push_group(&mut rows, UNANCHORED, "", &loose, &children);
        }
        rows
    }

    /// One group: the header row (with live/total counted over the whole
    /// subtree) and, when unfolded, the session tree beneath it.
    fn push_group(
        &self,
        rows: &mut Vec<DagRow>,
        name: &str,
        path: &str,
        group: &[&SessionRecord],
        children: &BTreeMap<&str, Vec<&SessionRecord>>,
    ) {
        let mut count_visited: HashSet<String> = HashSet::new();
        let (live, total) = group.iter().fold((0, 0), |acc, s| {
            group_counts(s, children, &mut count_visited, acc)
        });
        let folded = self.folded.contains(name);
        rows.push(DagRow::Group {
            name: name.to_string(),
            path: path.to_string(),
            live,
            total,
            folded,
        });
        if folded {
            return;
        }
        let mut visited: HashSet<String> = HashSet::new();
        for (i, s) in group.iter().enumerate() {
            let last = i + 1 == group.len();
            let branch = if last { "└─ " } else { "├─ " };
            let deeper = if last { "   " } else { "│  " };
            push_tree(
                rows,
                s,
                branch.to_string(),
                deeper.to_string(),
                children,
                &mut visited,
            );
        }
    }

    /// The group name owning the row at `idx` — the nearest header at or above
    /// it. How a fold key on a session row finds its group.
    pub fn group_of_row(rows: &[DagRow], idx: usize) -> Option<String> {
        rows[..=idx.min(rows.len().saturating_sub(1))]
            .iter()
            .rev()
            .find_map(|r| match r {
                DagRow::Group { name, .. } => Some(name.clone()),
                _ => None,
            })
    }

    fn clamp_selection(&mut self) {
        self.sidebar_sel = self
            .sidebar_sel
            .min(self.sidebar_rows().len().saturating_sub(1));
        self.sidebar_scroll = self.sidebar_scroll.min(self.sidebar_sel);
        let n_rows = self.dag_rows().len();
        if self.dag_sel >= n_rows.max(1) {
            self.dag_sel = n_rows.saturating_sub(1);
        }
        let n_proj = self.projects.len();
        if self.proj_sel >= n_proj.max(1) {
            self.proj_sel = n_proj.saturating_sub(1);
        }
        let n_nodes = crate::graphview::node_order(self).len();
        if self.graph_sel >= n_nodes.max(1) {
            self.graph_sel = n_nodes.saturating_sub(1);
        }
        let n_roster = self.roster_flat_rows().len();
        if self.roster_sel >= n_roster.max(1) {
            self.roster_sel = n_roster.saturating_sub(1);
        }
        let n_pending = self.pending_rows().len();
        if self.pending_sel >= n_pending.max(1) {
            self.pending_sel = n_pending.saturating_sub(1);
        }
    }

    // ── Panel switching ─────────────────────────────────────────────────────

    /// Switch panels. Landing on ROSTER with a stale (or never-fetched)
    /// cache fires one immediate background fetch rather than waiting for
    /// the next ~500ms tick — the pane should not open to a blank "not yet
    /// fetched" that then sits idle for up to 15s. Landing on PENDING fires
    /// an immediate SYNCHRONOUS refresh instead (it's a local read, no
    /// background thread needed — see the "PENDING" section).
    pub fn select_panel(&mut self, p: Panel) {
        self.history_selected = None;
        if p == Panel::Mail {
            self.refresh_mail();
        }
        self.panel = p;
        if p == Panel::Roster && self.roster_stale() {
            self.spawn_roster_fetch();
        }
        if p == Panel::Pending {
            self.refresh_pending();
        }
    }
    pub fn next_panel(&mut self) {
        let i = (self.panel.index() + 1) % Panel::ALL.len();
        self.select_panel(Panel::ALL[i]);
    }
    pub fn prev_panel(&mut self) {
        let i = (self.panel.index() + Panel::ALL.len() - 1) % Panel::ALL.len();
        self.select_panel(Panel::ALL[i]);
    }

    pub fn input_active(&self) -> bool {
        self.input.is_some() || self.mail_draft.is_some()
    }

    // ── The single dispatch seam (audit for free) ───────────────────────────

    /// Run a command through the ONE dispatcher with `Door::Cli`, store the
    /// outcome for the status line, and refresh live state (an action likely
    /// wrote a stage file + an audit line). This is the ONLY way the conductor
    /// mutates anything — and it fires on the keypress itself, not on the next
    /// tick, so an action (`p` → `session prune` → a re-drawn roster) lands
    /// instantly.
    pub fn dispatch(&mut self, path: &[&str], args: &[String]) {
        self.dispatch_with_flags(path, args, BTreeMap::new());
    }

    /// Like [`App::dispatch`] but with flags — the compose flow (P-C5) needs
    /// `--to`/`--yes` on `send`, which plain positional args can't
    /// carry. Kept as a separate method rather than widening `dispatch`'s
    /// signature so the six existing flag-less call sites stay untouched.
    pub fn dispatch_with_flags(
        &mut self,
        path: &[&str],
        args: &[String],
        flags: BTreeMap<String, String>,
    ) {
        let inv = Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.to_vec(),
            flags,
            door: Door::Cli,
        };
        let outcome = (self.dispatch_fn)(&inv);
        self.last_outcome = Some(outcome);
        // The action wrote to disk; pick it up immediately rather than waiting a
        // tick, so the panel reflects the change on the very next paint.
        self.reload_all();
    }

    /// The status-line message: the last outcome's message, or a ready hint.
    pub fn status_message(&self) -> String {
        match &self.last_outcome {
            Some(o) => {
                // Collapse the message to its first line for the one-row bar.
                let first = o.message.lines().next().unwrap_or("");
                format!("[{}] {}: {first}", status_tag(o.status), o.command)
            }
            None => "ready".to_string(),
        }
    }

    // ── Enter's destination: a window to cue, or a log to tail ──────────────

    /// THE branch every Enter site shares (roster row, graph node): a
    /// headless session — `log_path` stamped, the CONTRACTS §4-exact marker
    /// only `conduct --headless` sets — has no window to focus, so Enter
    /// opens its log tail instead. Deliberately never looks at
    /// `window_address`: a spawner's window can be stamped there even for a
    /// headless child (false positive), and a pre-backfill interactive
    /// session can lack one (false negative) — `log_path` is the one field
    /// that means what we need. The windowed and neither-field cases are
    /// UNCHANGED in effect: the same no-window-address status error surfaces
    /// when neither is set. Routing changed with `graph focus`'s deletion
    /// (command-defrag lane, task #101) — the capability was never anything
    /// but a thin CLI wrapper over [`graph::focus_session`], so Enter now
    /// calls it directly instead of round-tripping through the registry
    /// dispatcher, the same way the shellbridge socket loop already calls it
    /// for a widget click (`shellbridge.rs`'s `focussession` command). The
    /// audit line this used to get for free from `dispatch` is written here
    /// by hand so the one-audit-log invariant still holds.
    fn cue_session(&mut self, rec: &SessionRecord) {
        if rec.log_path.is_some() {
            self.open_tail(rec);
        } else {
            let id = rec.session_id.clone();
            let outcome = match graph::focus_session(&id) {
                Ok(()) => Outcome::ok("graph.focus", format!("focused session `{id}`")),
                Err(e) => Outcome::error("graph.focus", format!("{id}: {}", e.message)),
            };
            let status = match outcome.status {
                Status::Ok => "ok",
                Status::Error => "error",
                Status::Usage => "usage",
                Status::NotImplemented => "not-implemented",
            };
            let _ = aoide_protocol::audit(
                &aoide_protocol::default_audit_log(),
                Door::Cli,
                aoide_protocol::EventClass::Audit,
                "graph.focus",
                status,
                &outcome.message,
            );
            self.last_outcome = Some(outcome);
            self.reload_all();
        }
    }

    /// Open the tail overlay for `rec`'s log, reading it immediately — Enter
    /// must paint content on the keypress itself, not wait for the next
    /// ~500ms tick. A no-op when `rec` has no `log_path` (defensive:
    /// [`Self::cue_session`] is the only caller and has already checked).
    pub fn open_tail(&mut self, rec: &SessionRecord) {
        let Some(path) = rec.log_path.as_ref() else {
            return;
        };
        let path = PathBuf::from(path);
        let lines = logtail::tail_file(&path, logtail::TAIL_LINES);
        let mtime = Self::mtime(&path);
        self.tail = Some(LogTail {
            session_id: rec.session_id.clone(),
            path,
            lines,
            mtime,
        });
    }

    /// Close the tail overlay. Called from lib.rs's modal-swallow block (Esc
    /// / `q` / Enter while the overlay is open).
    pub fn close_tail(&mut self) {
        self.tail = None;
    }

    // ── Key handling for the active panel / inline input ────────────────────

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.mail_draft.is_some() {
            self.handle_mail_draft_key(key);
            return;
        }
        if self.input.is_some() {
            self.handle_input_key(key);
            return;
        }
        if matches!(self.panel, Panel::Session | Panel::Terminals)
            && self.history_selected.is_some()
        {
            if key.code == KeyCode::Esc {
                self.sidebar_focused = true;
            }
            return;
        }
        match self.panel {
            Panel::Graph => self.handle_graph_key(key),
            Panel::Session | Panel::Terminals => self.handle_dag_key(key),
            Panel::Projects => self.handle_projects_key(key),
            Panel::Roster => self.handle_roster_key(key),
            Panel::Pending => self.handle_pending_key(key),
            Panel::Mail => self.handle_mail_key(key),
            Panel::Log => self.handle_log_key(key),
            Panel::Home | Panel::Status => {} // read-only panels
        }
    }

    pub fn mail_letters(&self) -> Vec<crate::mailview::MailLetter> {
        let rooms = self.mail.conversations();
        let room = self
            .mail_room_id
            .as_ref()
            .and_then(|id| rooms.iter().find(|r| &r.id == id))
            .or_else(|| rooms.first());
        room.map(|r| r.letters.clone()).unwrap_or_default()
    }

    pub fn select_mail_room(&mut self, index: usize) {
        let rooms = self.mail.conversations();
        self.mail_room_sel = index.min(rooms.len().saturating_sub(1));
        self.mail_room_id = rooms.get(self.mail_room_sel).map(|r| r.id.clone());
        self.mail_sel = rooms
            .get(self.mail_room_sel)
            .map(|r| r.letters.len().saturating_sub(1))
            .unwrap_or(0);
        self.mail_scroll = 0;
    }

    pub fn refresh_mail(&mut self) {
        let selected = self
            .mail_letters()
            .get(self.mail_sel)
            .map(|m| m.msgid.clone());
        let room = self
            .mail_room_id
            .clone()
            .or_else(|| self.mail.conversations().first().map(|r| r.id.clone()));
        self.mail.refresh();
        self.mail_refreshed = Some(Instant::now());
        let rooms = self.mail.conversations();
        if let Some(index) = room.and_then(|id| rooms.iter().position(|r| r.id == id)) {
            self.mail_room_sel = index;
            self.mail_room_id = Some(rooms[index].id.clone());
            if let Some(index) =
                selected.and_then(|id| rooms[index].letters.iter().position(|m| m.msgid == id))
            {
                self.mail_sel = index;
            } else {
                self.mail_sel = rooms[index].letters.len().saturating_sub(1);
                self.mail_scroll = 0;
            }
        } else {
            self.select_mail_room(0);
        }
    }

    fn handle_log_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.log_sel = self.log_sel.saturating_sub(1);
                self.log_scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_sel = (self.log_sel + 1).min(self.log.len().saturating_sub(1));
                self.log_scroll = 0;
            }
            KeyCode::PageUp => self.log_scroll = self.log_scroll.saturating_sub(10),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_add(10),
            KeyCode::Char('r') => self.reload_log(),
            _ => {}
        }
    }

    pub fn open_context_for_session(&mut self, rec: SessionRecord, x: u16, y: u16) {
        let mut actions = vec![ContextAction::Details];
        if !is_done(&rec.state) && self.merged().iter().any(|s| s.session_id == rec.session_id) {
            if rec.petname.as_ref().is_some_and(|name| !name.is_empty()) && !is_terminal(&rec) {
                actions.push(ContextAction::WriteLetter);
            }
            if self.sessions.iter().any(|s| s.session_id == rec.session_id) {
                actions.push(ContextAction::Open);
                actions.push(ContextAction::AssignProject);
            }
        }
        self.context_menu = Some(ContextMenu {
            x,
            y,
            title: rec.title.clone().unwrap_or_else(|| rec.agent.clone()),
            target: ContextTarget::Session(rec),
            actions,
            selected: 0,
        });
    }

    pub fn open_context_for_project(&mut self, name: String, x: u16, y: u16) {
        if !self.projects.iter().any(|p| p.name == name) {
            return;
        }
        self.context_menu = Some(ContextMenu {
            x,
            y,
            title: name.clone(),
            target: ContextTarget::Project(name),
            actions: vec![
                ContextAction::Details,
                ContextAction::WriteLetter,
                ContextAction::AddFolder,
                ContextAction::Resurrect,
            ],
            selected: 0,
        });
    }

    pub fn open_context_for_history(
        &mut self,
        entry: aoide_storage::ledger::LedgerEntry,
        x: u16,
        y: u16,
    ) {
        let mut actions = vec![ContextAction::Details];
        if self.history_project(&entry).is_some()
            && (entry.harness_session_id.is_some() || entry.restore.is_some())
        {
            actions.push(ContextAction::Resurrect);
        }
        self.context_menu = Some(ContextMenu {
            x,
            y,
            title: entry.title.clone().unwrap_or_else(|| entry.agent.clone()),
            target: ContextTarget::History(entry),
            actions,
            selected: 0,
        });
    }

    fn history_project(&self, entry: &aoide_storage::ledger::LedgerEntry) -> Option<String> {
        if let Some(name) = &entry.project {
            return self
                .projects
                .iter()
                .find(|p| &p.name == name)
                .map(|p| p.name.clone());
        }
        graph::anchor_for(&entry.cwd, &self.projects).map(|i| self.projects[i].name.clone())
    }

    pub fn run_context_action(&mut self, index: usize) {
        let Some(menu) = self.context_menu.take() else {
            return;
        };
        let Some(action) = menu.actions.get(index).copied() else {
            return;
        };
        match (menu.target, action) {
            (ContextTarget::Session(rec), ContextAction::Details) => {
                if !self.merged().iter().any(|s| s.session_id == rec.session_id) {
                    self.last_outcome = Some(Outcome::usage(
                        "session",
                        "Session is no longer in the current roster; open its historical entry.",
                    ));
                    return;
                }
                self.select_panel(if is_terminal(&rec) {
                    Panel::Terminals
                } else {
                    Panel::Session
                });
                self.folded.clear();
                if let Some(i) = self.dag_rows().iter().position(
                    |r| matches!(r,DagRow::Session{rec:r,..} if r.session_id==rec.session_id),
                ) {
                    self.dag_sel = i;
                    self.sidebar_focused = false;
                }
            }
            (ContextTarget::History(entry), ContextAction::Details) => {
                self.select_panel(if entry.agent == "shell" {
                    Panel::Terminals
                } else {
                    Panel::Session
                });
                self.history_selected = Some(entry);
                self.sidebar_focused = false;
            }
            (ContextTarget::Project(name), ContextAction::Details) => {
                self.select_panel(Panel::Projects);
                if let Some(i) = sorted_project_names(&self.projects)
                    .iter()
                    .position(|p| p == &name)
                {
                    self.proj_sel = i;
                    self.sidebar_focused = false;
                }
            }
            (ContextTarget::Session(rec), ContextAction::WriteLetter) => {
                if let Some(name) = rec.petname {
                    self.open_mail_to(format!(
                        "{}/{}",
                        aoide_storage::display::local_host_name(),
                        name
                    ));
                }
            }
            (ContextTarget::Project(name), ContextAction::WriteLetter) => {
                let merged = self.merged();
                let choices = merged
                    .iter()
                    .filter(|rec| {
                        !is_done(&rec.state)
                            && !is_terminal(rec)
                            && graph::effective_project_for(rec, &merged, &self.projects)
                                .is_some_and(|i| self.projects[i].name == name)
                    })
                    .filter_map(|rec| {
                        rec.petname.as_ref().map(|petname| {
                            (
                                format!(
                                    "{} · {petname}",
                                    rec.title.as_deref().unwrap_or(&rec.agent)
                                ),
                                format!("{}/{petname}", aoide_storage::display::local_host_name()),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                if choices.is_empty() {
                    self.last_outcome = Some(Outcome::usage(
                        "mail.send",
                        "This project has no live agent mailbox.",
                    ));
                } else {
                    self.mail_target_menu = Some((menu.x, menu.y, choices, 0));
                }
            }
            (ContextTarget::Session(rec), ContextAction::Open) => {
                if let Some(current) = self
                    .sessions
                    .iter()
                    .find(|s| s.session_id == rec.session_id && !is_done(&s.state))
                    .cloned()
                {
                    self.cue_session(&current);
                } else {
                    self.last_outcome =
                        Some(Outcome::usage("session", "Session is no longer live."));
                }
            }
            (ContextTarget::Session(rec), ContextAction::AssignProject) => {
                self.input = Some(Input {
                    label: format!(
                        "Project for {} (blank = automatic)",
                        rec.petname.as_deref().unwrap_or(&rec.session_id)
                    ),
                    buffer: rec.project.unwrap_or_default(),
                    step: 0,
                    collected: vec![],
                    kind: InputKind::SessionProject { id: rec.session_id },
                });
            }
            (ContextTarget::Project(name), ContextAction::AddFolder) => {
                self.input = Some(Input {
                    label: format!("Folder to add to {name}"),
                    buffer: String::new(),
                    step: 0,
                    collected: vec![],
                    kind: InputKind::ProjectRoot { name },
                });
            }
            (ContextTarget::Project(name), ContextAction::Resurrect) => self.dispatch_with_flags(
                &["resurrect"],
                &[],
                BTreeMap::from([("project".into(), name)]),
            ),
            (ContextTarget::History(entry), ContextAction::Resurrect) => {
                if let Some(project) = self.history_project(&entry) {
                    self.dispatch_with_flags(
                        &["resurrect"],
                        &[],
                        BTreeMap::from([
                            ("project".into(), project),
                            ("id".into(), entry.session_id),
                        ]),
                    );
                }
            }
            _ => {}
        }
    }

    pub fn open_mail_to(&mut self, recipient: String) {
        if self.mail_draft.is_some() {
            return;
        }
        self.open_mail(MailMode::New);
        if let Some(draft) = &mut self.mail_draft {
            draft.to = recipient;
            draft.focus = MailField::Subject;
            draft.cursor = 0;
        }
    }

    pub fn open_mail(&mut self, mode: MailMode) {
        if self.mail_draft.is_some() {
            return;
        }
        let original = if mode == MailMode::New {
            None
        } else {
            self.mail_letters().get(self.mail_sel).cloned()
        };
        if mode != MailMode::New && original.is_none() {
            return;
        }
        let local = aoide_storage::display::local_host_name();
        let from = format!("{local}/conductor-human");
        let mut draft = MailDraft {
            mode,
            from,
            to: String::new(),
            cc: String::new(),
            subject: String::new(),
            body: String::new(),
            original,
            focus: MailField::To,
            recipient_field: MailField::To,
            cursor: 0,
            error: None,
            submitted: false,
        };
        if let Some(letter) = &draft.original {
            let content = aoide_storage::letter::decode(&letter.text);
            let subject = content.as_ref().map(|c| c.subject.as_str()).unwrap_or("");
            let body = content
                .as_ref()
                .map(|c| c.body.as_str())
                .unwrap_or(&letter.text);
            let prefix = if mode == MailMode::Forward {
                "Fwd:"
            } else {
                "Re:"
            };
            draft.subject = if subject.to_lowercase().starts_with(&prefix.to_lowercase()) {
                subject.into()
            } else {
                format!("{prefix} {subject}").trim_end().into()
            };
            draft.body = format!(
                "\n\nOn {}, {} wrote:\n{}",
                letter.received_at,
                letter.from,
                body.lines()
                    .map(|line| format!("> {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            if mode != MailMode::Forward {
                let target = if letter.from_address.name == "conductor-human"
                    && letter.from_address.node == local
                {
                    &letter.to_address
                } else {
                    &letter.from_address
                };
                draft.to = format!("{}/{}", target.node, target.name);
                if mode == MailMode::ReplyAll {
                    let addresses = content
                        .map(|c| c.to.into_iter().chain(c.cc).collect::<Vec<_>>())
                        .unwrap_or_else(|| vec![letter.to_address.clone()]);
                    let mut seen = HashSet::from([
                        draft.to.clone(),
                        draft.from.clone(),
                        "self/conductor-human".into(),
                    ]);
                    draft.cc = addresses
                        .into_iter()
                        .map(|a| format!("{}/{}", a.node, a.name))
                        .filter(|a| seen.insert(a.clone()))
                        .collect::<Vec<_>>()
                        .join(", ");
                }
                draft.focus = MailField::Body;
            }
        }
        self.mail_draft = Some(draft);
        self.sidebar_focused = false;
    }

    pub fn focus_mail_field(&mut self, field: MailField) {
        self.sidebar_focused = false;
        if let Some(draft) = &mut self.mail_draft {
            draft.focus = field;
            if matches!(field, MailField::To | MailField::Cc) {
                draft.recipient_field = field;
            }
            draft.cursor = draft.field(field).len();
        }
    }

    pub fn add_mail_recipient(&mut self, address: &str) {
        self.sidebar_focused = false;
        let Some(draft) = &mut self.mail_draft else {
            return;
        };
        if draft.submitted {
            return;
        }
        let local = aoide_storage::display::local_host_name();
        let canonical = |value: &str| {
            value
                .trim()
                .strip_prefix("self/")
                .map(|name| format!("{local}/{name}"))
                .unwrap_or_else(|| value.trim().into())
        };
        let address = canonical(address);
        if draft
            .to
            .split(',')
            .chain(draft.cc.split(','))
            .any(|old| canonical(old) == address)
        {
            return;
        }
        let target = if draft.recipient_field == MailField::Cc {
            &mut draft.cc
        } else {
            &mut draft.to
        };
        if !target.trim().is_empty() {
            target.push_str(", ");
        }
        target.push_str(&address);
        draft.focus = draft.recipient_field;
        draft.cursor = target.len();
        draft.error = None;
    }

    pub fn send_mail_draft(&mut self) {
        let Some(mut draft) = self.mail_draft.take() else {
            return;
        };
        if draft.submitted {
            draft.error = Some(
                "Already submitted: inspect recipient results before creating another letter."
                    .into(),
            );
            self.mail_draft = Some(draft);
            return;
        }
        if draft.to.trim().is_empty() || draft.body.trim().is_empty() {
            draft.error = Some("To and Message are required.".into());
            self.mail_draft = Some(draft);
            return;
        }
        let local = aoide_storage::display::local_host_name();
        let route = |text: &str| {
            text.split(',')
                .map(str::trim)
                .map(|a| {
                    a.strip_prefix(&format!("{local}/"))
                        .map(|name| format!("self/{name}"))
                        .unwrap_or_else(|| a.into())
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut flags = BTreeMap::from([
            ("to".into(), route(&draft.to)),
            ("from".into(), "conductor-human".into()),
        ]);
        flags.insert("subject".into(), draft.subject.clone());
        if matches!(draft.mode, MailMode::Reply | MailMode::ReplyAll) {
            if let Some(original) = &draft.original {
                flags.insert(
                    "thread".into(),
                    original
                        .thread_id()
                        .unwrap_or_else(|| original.msgid.clone()),
                );
                flags.insert("reply-to".into(), original.msgid.clone());
            }
        }
        if !draft.cc.trim().is_empty() {
            flags.insert("cc".into(), route(&draft.cc));
        }
        self.dispatch_with_flags(&["mail", "send"], &[draft.body.clone()], flags);
        if let Some(outcome) = &self.last_outcome {
            if outcome.status == Status::Ok {
                self.refresh_mail();
                return;
            }
            let mut message = outcome.message.clone();
            if let Some(recipients) = outcome
                .data
                .as_ref()
                .and_then(|data| data.get("recipients"))
                .and_then(|rows| rows.as_array())
            {
                for recipient in recipients {
                    let node = recipient
                        .pointer("/address/node")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let name = recipient
                        .pointer("/address/name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let status = recipient
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let error = recipient
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    message.push_str(&format!("\n{node}/{name}: {status} {error}"));
                }
            }
            draft.error = Some(message);
            draft.submitted = outcome.data.as_ref().is_some_and(|d| {
                d.get("accepted")
                    .and_then(|n| n.as_u64())
                    .is_some_and(|n| n > 0)
                    || d.get("msgid").is_some()
            }) || !outcome.changed.is_empty();
        }
        self.mail_draft = Some(draft);
    }

    pub fn handle_mail_draft_key(&mut self, key: KeyEvent) {
        use crossterm::event::KeyModifiers;
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.send_mail_draft();
            return;
        }
        if key.code == KeyCode::Esc {
            self.mail_draft = None;
            return;
        }
        let Some(draft) = &mut self.mail_draft else {
            return;
        };
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            let fields = [
                MailField::To,
                MailField::Cc,
                MailField::Subject,
                MailField::Body,
            ];
            let i = fields.iter().position(|f| *f == draft.focus).unwrap_or(0);
            let back = key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::SHIFT);
            draft.focus = fields[(i + if back { 3 } else { 1 }) % 4];
            if matches!(draft.focus, MailField::To | MailField::Cc) {
                draft.recipient_field = draft.focus;
            }
            draft.cursor = draft.field(draft.focus).len();
            return;
        }
        let cursor = draft.cursor.min(draft.field(draft.focus).len());
        if matches!(key.code, KeyCode::Up | KeyCode::Down) && draft.focus == MailField::Body {
            let text = &draft.body;
            let start = text[..cursor].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let column = text[start..cursor].chars().count();
            let target = if key.code == KeyCode::Up {
                if start == 0 {
                    return;
                }
                let end = start - 1;
                let prev = text[..end].rfind('\n').map(|i| i + 1).unwrap_or(0);
                (prev, end)
            } else {
                let Some(end) = text[cursor..].find('\n').map(|i| cursor + i) else {
                    return;
                };
                let next = end + 1;
                (
                    next,
                    text[next..]
                        .find('\n')
                        .map(|i| next + i)
                        .unwrap_or(text.len()),
                )
            };
            draft.cursor = target.0
                + text[target.0..target.1]
                    .char_indices()
                    .nth(column)
                    .map(|(i, _)| i)
                    .unwrap_or(target.1 - target.0);
            return;
        }

        match key.code {
            KeyCode::Left => {
                draft.cursor = draft.field(draft.focus)[..cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            }
            KeyCode::Right => {
                draft.cursor = draft.field(draft.focus)[cursor..]
                    .chars()
                    .next()
                    .map(|c| cursor + c.len_utf8())
                    .unwrap_or(cursor)
            }
            KeyCode::Home => {
                draft.cursor = draft.field(draft.focus)[..cursor]
                    .rfind('\n')
                    .map(|i| i + 1)
                    .unwrap_or(0)
            }
            KeyCode::End => {
                draft.cursor = draft.field(draft.focus)[cursor..]
                    .find('\n')
                    .map(|i| cursor + i)
                    .unwrap_or(draft.field(draft.focus).len())
            }
            KeyCode::Backspace if cursor > 0 => {
                let start = draft.field(draft.focus)[..cursor]
                    .char_indices()
                    .next_back()
                    .unwrap()
                    .0;
                draft.field_mut().drain(start..cursor);
                draft.cursor = start;
            }
            KeyCode::Delete => {
                if let Some(c) = draft.field(draft.focus)[cursor..].chars().next() {
                    draft.field_mut().drain(cursor..cursor + c.len_utf8());
                }
            }
            KeyCode::Enter if draft.focus == MailField::Body => {
                draft.field_mut().insert(cursor, '\n');
                draft.cursor = cursor + 1;
            }
            KeyCode::Enter => {
                let fields = [
                    MailField::To,
                    MailField::Cc,
                    MailField::Subject,
                    MailField::Body,
                ];
                let i = fields.iter().position(|f| *f == draft.focus).unwrap();
                draft.focus = fields[(i + 1) % 4];
                if matches!(draft.focus, MailField::To | MailField::Cc) {
                    draft.recipient_field = draft.focus;
                }
                draft.cursor = draft.field(draft.focus).len();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && (draft.focus == MailField::Body || !c.is_control()) =>
            {
                draft.field_mut().insert(cursor, c);
                draft.cursor = cursor + c.len_utf8();
            }
            _ => {}
        }
    }

    fn handle_mail_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('n') => self.open_mail(MailMode::New),
            KeyCode::Char('s') => self.open_mail(MailMode::Reply),
            KeyCode::Char('a') => self.open_mail(MailMode::ReplyAll),
            KeyCode::Char('f') => self.open_mail(MailMode::Forward),
            KeyCode::Left | KeyCode::Char('h') => self.mail_room_focus = true,
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => self.mail_room_focus = false,
            KeyCode::Up | KeyCode::Char('k') => {
                if self.mail_room_focus {
                    self.select_mail_room(self.mail_room_sel.saturating_sub(1));
                } else {
                    self.mail_sel = self.mail_sel.saturating_sub(1);
                    self.mail_scroll = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.mail_room_focus {
                    self.select_mail_room(self.mail_room_sel.saturating_add(1));
                } else {
                    self.mail_sel =
                        (self.mail_sel + 1).min(self.mail_letters().len().saturating_sub(1));
                    self.mail_scroll = 0;
                }
            }
            KeyCode::PageUp => self.mail_scroll = self.mail_scroll.saturating_sub(10),
            KeyCode::PageDown => self.mail_scroll = self.mail_scroll.saturating_add(10),
            KeyCode::Char('r') => self.refresh_mail(),
            _ => {}
        }
    }

    /// Keys for the ROSTER panel (messaging/presence plan P-C4; selection +
    /// compose added P-C5): `r` forces a fetch regardless of the throttle
    /// window (unlike the tick-driven path, which only fires past
    /// [`ROSTER_THROTTLE`]) — a no-op while a fetch is already in flight
    /// ([`App::spawn_roster_fetch`]'s own guard). `j`/`k` walk
    /// [`App::roster_flat_rows`], the same flattened-row selection style
    /// [`App::handle_dag_key`] uses over the DAG. `s` opens the compose
    /// prompt on the selected session row ([`App::open_compose`]).
    fn handle_roster_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') => self.spawn_roster_fetch(),
            KeyCode::Char('j') | KeyCode::Down => {
                let n = self.roster_flat_rows().len();
                if n > 0 && self.roster_sel + 1 < n {
                    self.roster_sel += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.roster_sel = self.roster_sel.saturating_sub(1);
            }
            KeyCode::Char('s') => self.open_compose(),
            _ => {}
        }
    }

    /// `s` on a selected ROSTER session row opens the compose prompt
    /// ([`InputKind::Compose`]), pre-labeled with the row's own
    /// display-grammar label — the exact string the roster core already
    /// computed and the exact string `send --to <target>` resolves back to a
    /// session (petname, tail4, host/role/petname — whatever the roster rendered).
    /// A no-op on a node-header or empty-node row: there is no session to
    /// address, and the frontend never invents one.
    fn open_compose(&mut self) {
        let rows = self.roster_flat_rows();
        if let Some(RosterRow::Session { session, .. }) = rows.get(self.roster_sel) {
            let target = session.label.clone();
            self.input = Some(Input {
                label: format!("send to {target}"),
                buffer: String::new(),
                step: 0,
                collected: Vec::new(),
                kind: InputKind::Compose { target },
            });
        }
    }

    /// Keys for the PENDING panel (P-C5): `j`/`k` walk [`App::pending_rows`];
    /// `a`/`d` approve/deny the selected row. `Invocation.args` carries the
    /// entry's `id` — its ARRAY POSITION, not a stable id
    /// (`conduct/src/graph/pending.rs`'s module doc) — so [`App::dispatch`]'s
    /// `reload_all` -> `refresh_pending` re-list, which runs synchronously
    /// before the next paint, is not an optimization: it is what keeps a
    /// second a/d keypress in the same visit from resolving whatever now
    /// sits at a STALE selected index instead of the row on screen.
    fn handle_pending_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                let n = self.pending_rows().len();
                if n > 0 && self.pending_sel + 1 < n {
                    self.pending_sel += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.pending_sel = self.pending_sel.saturating_sub(1);
            }
            KeyCode::Char('a') => self.resolve_pending("approve"),
            KeyCode::Char('d') => self.resolve_pending("deny"),
            _ => {}
        }
    }

    /// Approve or deny the selected PENDING row, then clamp the cursor —
    /// `dispatch` has already re-listed by the time this returns (see
    /// [`App::handle_pending_key`]'s doc), so a shrunk queue never leaves
    /// `pending_sel` pointing past the end. A no-op on an empty list
    /// (nothing selected to resolve) rather than a panic; the door itself
    /// (not this frontend) is what rejects a malformed entry.
    fn resolve_pending(&mut self, command: &'static str) {
        let rows = self.pending_rows();
        let Some(row) = rows.get(self.pending_sel) else {
            return;
        };
        let id = row.id.clone();
        self.dispatch(&["session", "pending", command], &[id]);
        let n = self.pending_rows().len();
        if self.pending_sel >= n.max(1) {
            self.pending_sel = n.saturating_sub(1);
        }
    }

    /// Keys for the DAG (Graph) panel. Navigation walks the same preorder node
    /// list the layout draws, so `j`/`k` can never point at a node that isn't on
    /// screen. Enter cues the selected session's window (the same
    /// [`App::cue_session`] focus jump the roster uses); `p` prunes — the one
    /// graph-wide command — so the visual view is not read-only.
    fn handle_graph_key(&mut self, key: KeyEvent) {
        let previous_selection = self.graph_sel;
        let nodes = crate::graphview::node_order(self);
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if !nodes.is_empty() && self.graph_sel + 1 < nodes.len() {
                    self.graph_sel += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.graph_sel = self.graph_sel.saturating_sub(1);
            }
            KeyCode::Home | KeyCode::Char('g') => self.graph_sel = 0,
            KeyCode::End | KeyCode::Char('G') => {
                self.graph_sel = nodes.len().saturating_sub(1);
            }
            KeyCode::Enter => {
                if let Some(node) = nodes.get(self.graph_sel) {
                    if let Some(id) = node.session_id.clone() {
                        // Node → record via `merged()` (the same lookup the
                        // roster's rows are built from) — no graphview
                        // change, `cue_session` is the one branch.
                        let rec = self.merged().into_iter().find(|m| m.session_id == id);
                        if let Some(rec) = rec {
                            self.cue_session(&rec);
                        }
                    }
                }
            }
            KeyCode::Char('p') => self.dispatch(&["session", "prune"], &[]),
            _ => {}
        }
        if self.graph_sel != previous_selection {
            self.graph_pan = None;
        }
    }

    fn handle_dag_key(&mut self, key: KeyEvent) {
        let rows = self.dag_rows();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if !rows.is_empty() && self.dag_sel + 1 < rows.len() {
                    self.dag_sel += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.dag_sel = self.dag_sel.saturating_sub(1);
            }
            // Enter: on a session, cue it — a window to focus right now
            // (jump latency is the whole multiplexer story; Hyprland windows
            // are our panes) or, for a headless session, its log tail
            // (`cue_session` is the one branch). On a group header, toggle
            // the fold.
            KeyCode::Enter => match rows.get(self.dag_sel) {
                Some(DagRow::Session { rec, .. }) => self.cue_session(rec),
                Some(DagRow::Group { name, .. }) => self.toggle_fold(name.clone()),
                None => {}
            },
            // h / - folds the group the cursor is in (from a session row the
            // cursor climbs to the header so the fold doesn't strand it).
            KeyCode::Char('h') | KeyCode::Char('-') => {
                if let Some(name) = Self::group_of_row(&rows, self.dag_sel) {
                    self.folded.insert(name.clone());
                    self.snap_to_group(&name);
                }
            }
            // l / + unfolds the group under the cursor.
            KeyCode::Char('l') | KeyCode::Char('+') => {
                if let Some(name) = Self::group_of_row(&rows, self.dag_sel) {
                    self.folded.remove(&name);
                }
            }
            // a: register a project anchor from right here in the group view.
            KeyCode::Char('a') => self.open_project_add(),
            // d: on a group header, unregister that project (the unanchored
            // pseudo-group has nothing to remove).
            KeyCode::Char('d') => {
                if let Some(DagRow::Group { name, .. }) = rows.get(self.dag_sel) {
                    if name != UNANCHORED {
                        let name = name.clone();
                        self.open_project_remove(name);
                    }
                }
            }
            // L: link the selected session under a parent (graph link — the
            // prompt collects the parent id; the dispatcher cycle-checks).
            KeyCode::Char('L') => {
                if let Some(DagRow::Session { rec, .. }) = rows.get(self.dag_sel) {
                    self.input = Some(Input {
                        label: format!("link `{}` under parent session id", rec.session_id),
                        buffer: String::new(),
                        step: 0,
                        collected: Vec::new(),
                        kind: InputKind::Link {
                            child: rec.session_id.clone(),
                        },
                    });
                }
            }
            KeyCode::Char('p') => self.dispatch(&["session", "prune"], &[]),
            _ => {}
        }
    }

    fn toggle_fold(&mut self, name: String) {
        if !self.folded.remove(&name) {
            self.folded.insert(name);
        }
        self.clamp_selection();
    }

    /// After folding, park the cursor on the group's header (its session rows
    /// just vanished from under it).
    fn snap_to_group(&mut self, name: &str) {
        let rows = self.dag_rows();
        if let Some(i) = rows
            .iter()
            .position(|r| matches!(r, DagRow::Group { name: n, .. } if n == name))
        {
            self.dag_sel = i;
        } else {
            self.clamp_selection();
        }
    }

    fn open_project_remove(&mut self, name: String) {
        self.input = Some(Input {
            label: format!("Unregister project `{name}`; type its name to confirm"),
            buffer: String::new(),
            step: 0,
            collected: Vec::new(),
            kind: InputKind::ProjectRemove { name },
        });
    }

    fn open_project_add(&mut self) {
        self.input = Some(Input {
            label: "project name (an existing name adds a root)".to_string(),
            buffer: String::new(),
            step: 0,
            collected: Vec::new(),
            kind: InputKind::ProjectAdd,
        });
    }

    fn handle_projects_key(&mut self, key: KeyEvent) {
        let n = self.projects.len();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if n > 0 && self.proj_sel + 1 < n {
                    self.proj_sel += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.proj_sel = self.proj_sel.saturating_sub(1);
            }
            KeyCode::Char('a') => self.open_project_add(),
            KeyCode::Char('d') => {
                let sorted = sorted_project_names(&self.projects);
                if let Some(name) = sorted.get(self.proj_sel).cloned() {
                    self.open_project_remove(name);
                }
            }
            // r: resurrect the focused project's most recent resumable
            // session off the durable ledger (P-D8, `resurrect
            // --project <name>`) — the one new project-scoped action this
            // phase adds, so it lands beside `a`/`d` in the panel that is
            // already the projects list's own home. `r` is unclaimed here
            // (this panel binds only `j`/`k`/`a`/`d` today); the roster
            // panel's own `r` = refresh is a different handler/different
            // scope, so the two never collide.
            KeyCode::Char('r') => {
                let sorted = sorted_project_names(&self.projects);
                if let Some(name) = sorted.get(self.proj_sel).cloned() {
                    let mut flags = BTreeMap::new();
                    flags.insert("project".to_string(), name);
                    self.dispatch_with_flags(&["resurrect"], &[], flags);
                }
            }
            _ => {}
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent) {
        let Some(mut input) = self.input.take() else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                // Cancel — drop the prompt, no dispatch.
            }
            KeyCode::Backspace => {
                input.buffer.pop();
                self.input = Some(input);
            }
            KeyCode::Char(c) => {
                input.buffer.push(c);
                self.input = Some(input);
            }
            KeyCode::Enter => match input.kind.clone() {
                InputKind::SessionProject { id } => {
                    let mut flags = BTreeMap::from([("id".into(), id)]);
                    if input.buffer.trim().is_empty() {
                        flags.insert("clear".into(), "true".into());
                    } else {
                        flags.insert("project".into(), input.buffer.trim().into());
                    }
                    self.dispatch_with_flags(&["session", "project"], &[], flags);
                }
                InputKind::ProjectRoot { name } => {
                    if input.buffer.trim().is_empty() {
                        self.input = Some(input);
                    } else {
                        self.dispatch(&["project", "add"], &[name, input.buffer.trim().into()]);
                    }
                }
                InputKind::ProjectRemove { name } => {
                    if input.buffer == name {
                        self.dispatch(&["project", "remove"], &[name]);
                    } else {
                        self.input = Some(input);
                    }
                }
                InputKind::ProjectAdd => {
                    if input.step == 0 {
                        // Collected the name; advance to the path (defaults cwd).
                        let name = input.buffer.trim().to_string();
                        if name.is_empty() {
                            self.input = Some(input); // stay until a name is given
                            return;
                        }
                        let cwd = std::env::current_dir()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        self.input = Some(Input {
                            label: format!("path (Enter = {cwd})"),
                            buffer: String::new(),
                            step: 1,
                            collected: vec![name],
                            kind: InputKind::ProjectAdd,
                        });
                    } else {
                        // Collected the path; dispatch project add.
                        let name = input.collected.first().cloned().unwrap_or_default();
                        let mut path = input.buffer.trim().to_string();
                        if path.is_empty() {
                            path = std::env::current_dir()
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default();
                        }
                        self.dispatch(&["project", "add"], &[name, path]);
                    }
                }
                InputKind::Link { child } => {
                    let parent = input.buffer.trim().to_string();
                    if parent.is_empty() {
                        self.input = Some(input); // stay until a parent is named
                        return;
                    }
                    // The dispatcher owns the guardrails (cycle check,
                    // missing-child) — we just hand it the edge.
                    self.dispatch(&["graph", "link"], &[child, parent]);
                }
                InputKind::Compose { target } => {
                    let text = input.buffer.trim().to_string();
                    if text.is_empty() {
                        self.input = Some(input); // stay until a message is given
                        return;
                    }
                    // `args: vec![text]` round-trips the exact text through
                    // `session_send`'s own `inv.args.join(" ")`, whitespace
                    // and all — the same one-element-vec pattern
                    // `pending_approve`'s in-process re-drive uses
                    // (`conduct/src/graph/pending.rs`). `--yes` is a
                    // documented no-op for a REMOTE target (the receiving
                    // node gates its own delivery); `deliver_remote` folds
                    // that note straight into the Outcome message, so
                    // `status_message` surfaces it same as any other
                    // dispatch — no special-casing needed here.
                    let mut flags = BTreeMap::new();
                    flags.insert("to".to_string(), target);
                    flags.insert("yes".to_string(), "true".to_string());
                    self.dispatch_with_flags(&["send"], &[text], flags);
                }
            },
            _ => {
                self.input = Some(input);
            }
        }
    }
}

/// Is a session past its final barline? (the state `session prune` sweeps and the
/// `[live/total]` badge excludes from `live`.)
///
/// Delegates to [`graph::canonical_state`] rather than sniffing substrings, so
/// the conductor and the door can never disagree about what "ended" means. This
/// matters since the `stop`/`stopped` vocabulary was split off `done`: a
/// `stopped` session finished its TURN and is still very much alive, so it must
/// stay in the `live` count.
pub fn is_terminal(rec: &SessionRecord) -> bool {
    rec.agent == "shell" || rec.kind.as_deref() == Some("shell")
}

pub fn is_done(state: &str) -> bool {
    graph::canonical_state(state) == "done"
}

/// Fold `(live, total)` over one root's subtree, cycle-guarded.
fn group_counts(
    s: &SessionRecord,
    children: &BTreeMap<&str, Vec<&SessionRecord>>,
    visited: &mut HashSet<String>,
    (live, total): (usize, usize),
) -> (usize, usize) {
    if !visited.insert(s.session_id.clone()) {
        return (live, total);
    }
    let mut acc = (live + usize::from(!is_done(&s.state)), total + 1);
    if let Some(kids) = children.get(s.session_id.as_str()) {
        for kid in kids {
            acc = group_counts(kid, children, visited, acc);
        }
    }
    acc
}

/// Push one session and its spawned subtree as rows, prefixes accumulating the
/// usual `│ ├ └` tree geometry; the `visited` set guards a malformed cycle.
fn push_tree(
    rows: &mut Vec<DagRow>,
    s: &SessionRecord,
    branch: String,
    deeper: String,
    children: &BTreeMap<&str, Vec<&SessionRecord>>,
    visited: &mut HashSet<String>,
) {
    if !visited.insert(s.session_id.clone()) {
        return;
    }
    rows.push(DagRow::Session {
        rec: (*s).clone(),
        prefix: branch,
    });
    if let Some(kids) = children.get(s.session_id.as_str()) {
        for (i, kid) in kids.iter().enumerate() {
            let last = i + 1 == kids.len();
            let b = format!("{deeper}{}", if last { "└─ " } else { "├─ " });
            let d = format!("{deeper}{}", if last { "   " } else { "│  " });
            push_tree(rows, kid, b, d, children, visited);
        }
    }
}

/// Project names in the SAME order the PROJECTS panel renders (sorted by name),
/// so the selected index maps to the right project for `remove`.
pub fn sorted_project_names(projects: &[graph::Project]) -> Vec<String> {
    let mut names: Vec<String> = projects.iter().map(|p| p.name.clone()).collect();
    names.sort();
    names
}

// ── livery.json palette → ANSI-256 ─────────────────────────────────────────

/// The stage notes path — `stage/livery.json`, the canonical stage note file
/// (CONTRACTS.md §4). Both the palette load and the mtime watch go through
/// this, so the watch tracks the same file the palette loads.
fn stage_notes_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("livery.json")
}

/// Load exact palette/Base16 RGB and compatibility ANSI-256 indices.
pub fn load_palette(path: &std::path::Path) -> Palette {
    let Ok(s) = std::fs::read_to_string(path) else {
        return Palette::default();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) else {
        return Palette::default();
    };
    let pal = v.get("palette");
    let pick = |key: &str| -> Option<u8> {
        pal.and_then(|p| p.get(key))
            .and_then(|x| x.as_str())
            .and_then(hex_to_ansi256)
    };
    Palette {
        base16: std::array::from_fn(|i| {
            v.get("base16")
                .and_then(|p| p.get(format!("base{i:02X}")))
                .and_then(|v| v.as_str())
                .and_then(parse_hex)
        }),
        urgent_rgb: pal
            .and_then(|p| p.get("urgent"))
            .and_then(|v| v.as_str())
            .and_then(parse_hex),
        bg_rgb: pal
            .and_then(|p| p.get("bg"))
            .and_then(|v| v.as_str())
            .and_then(parse_hex),
        fg_rgb: pal
            .and_then(|p| p.get("fg"))
            .and_then(|v| v.as_str())
            .and_then(parse_hex),
        accent_rgb: pal
            .and_then(|p| p.get("accent"))
            .and_then(|v| v.as_str())
            .and_then(parse_hex),
        bg: pick("bg"),
        fg: pick("fg"),
        accent: pick("accent"),
        urgent: pick("urgent"),
    }
}

/// Parse `#rrggbb` (or `#rgb`) and map to the nearest ANSI-256 colour index.
pub fn hex_to_ansi256(hex: &str) -> Option<u8> {
    let (r, g, b) = parse_hex(hex)?;
    Some(rgb_to_ansi256(r, g, b))
}

fn parse_hex(hex: &str) -> Option<(u8, u8, u8)> {
    let h = hex.trim().trim_start_matches('#');
    if !h.is_ascii() {
        return None;
    }
    let (r, g, b) = match h.len() {
        6 => (
            u8::from_str_radix(&h[0..2], 16).ok()?,
            u8::from_str_radix(&h[2..4], 16).ok()?,
            u8::from_str_radix(&h[4..6], 16).ok()?,
        ),
        3 => {
            let r = u8::from_str_radix(&h[0..1], 16).ok()?;
            let g = u8::from_str_radix(&h[1..2], 16).ok()?;
            let b = u8::from_str_radix(&h[2..3], 16).ok()?;
            (r * 17, g * 17, b * 17) // 0xN → 0xNN
        }
        _ => return None,
    };
    Some((r, g, b))
}

/// Nearest xterm-256 index for an RGB triple. Considers both the 6×6×6 colour
/// cube and the 24-step grey ramp and picks whichever is closer, exactly like
/// the common terminal conversion.
pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    // 6×6×6 cube: channel steps are 0,95,135,175,215,255.
    fn cube_idx(c: u8) -> u8 {
        if c < 48 {
            0
        } else if c < 115 {
            1
        } else {
            ((c as u16 - 35) / 40) as u8
        }
    }
    fn cube_val(i: u8) -> u8 {
        if i == 0 {
            0
        } else {
            55 + 40 * i
        }
    }
    let (ri, gi, bi) = (cube_idx(r), cube_idx(g), cube_idx(b));
    let (cr, cg, cb) = (cube_val(ri), cube_val(gi), cube_val(bi));
    let cube = 16 + 36 * ri + 6 * gi + bi;
    let cube_dist = dist2(r, g, b, cr, cg, cb);

    // Grey ramp: indices 232..=255, values 8,18,…,238.
    let grey_level = ((r as u16 + g as u16 + b as u16) / 3) as u8;
    let gi2 = if grey_level < 8 {
        0
    } else {
        ((grey_level as u16 - 8) / 10).min(23) as u8
    };
    let gv = 8 + 10 * gi2;
    let grey = 232 + gi2;
    let grey_dist = dist2(r, g, b, gv, gv, gv);

    if grey_dist < cube_dist {
        grey
    } else {
        cube
    }
}

fn dist2(r: u8, g: u8, b: u8, r2: u8, g2: u8, b2: u8) -> u32 {
    let dr = r as i32 - r2 as i32;
    let dg = g as i32 - g2 as i32;
    let db = b as i32 - b2 as i32;
    (dr * dr + dg * dg + db * db) as u32
}

#[cfg(test)]
mod tests {
    #[test]
    fn ledger_only_session_appears_under_past_without_entering_live_graph() {
        let project = graph::Project {
            name: "work".into(),
            path: "/work".into(),
            ..Default::default()
        };
        let mut app = App::for_test(vec![project], vec![], vec![]);
        app.history = vec![aoide_storage::ledger::LedgerEntry {
            session_id: "past-only".into(),
            cwd: "/work/src".into(),
            agent: "codex".into(),
            title: Some("Previous task".into()),
            ..Default::default()
        }];
        assert!(matches!(
            &app.sidebar_rows()[1],
            SidebarRow::Past {
                count: 1,
                folded: true,
                ..
            }
        ));
        app.sidebar_activate(1);
        assert!(
            matches!(&app.sidebar_rows()[2], SidebarRow::History { entry, depth: 2, .. } if entry.session_id == "past-only")
        );
        app.sidebar_activate(2);
        assert_eq!(
            app.history_selected.as_ref().unwrap().session_id,
            "past-only"
        );
        assert!(app.merged().is_empty());
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.last_outcome.is_none());
    }

    #[test]
    fn history_deduplicates_stage_ids_and_preserves_recorded_project() {
        let current = SessionRecord {
            session_id: "current".into(),
            state: "idle".into(),
            ..Default::default()
        };
        let mut app = App::for_test(vec![], vec![current], vec![]);
        app.history = vec![
            aoide_storage::ledger::LedgerEntry {
                session_id: "current".into(),
                ..Default::default()
            },
            aoide_storage::ledger::LedgerEntry {
                session_id: "old".into(),
                project: Some("retired-project".into()),
                ..Default::default()
            },
        ];
        app.sidebar_past_open.insert("retired-project".into());
        let rows = app.sidebar_rows();
        assert_eq!(
            rows.iter()
                .filter(|r| matches!(r, SidebarRow::History { .. }))
                .count(),
            1
        );
        assert!(rows
            .iter()
            .any(|r| matches!(r, SidebarRow::Project { name, .. } if name == "retired-project")));
    }
    use super::*;

    #[test]
    fn sidebar_keeps_empty_projects_and_inherits_owner_outside_root() {
        let project = graph::Project {
            name: "aoide".into(),
            path: "/project".into(),
            ..Default::default()
        };
        let empty = graph::Project {
            name: "empty".into(),
            path: "/empty".into(),
            ..Default::default()
        };
        let owner = SessionRecord {
            session_id: "owner".into(),
            cwd: "/project".into(),
            agent: "claude".into(),
            state: "working".into(),
            ..Default::default()
        };
        let child = SessionRecord {
            session_id: "child-1234".into(),
            cwd: "/tmp".into(),
            parent_session_id: Some("owner".into()),
            agent: "claude".into(),
            petname: Some("small-fern".into()),
            state: "idle".into(),
            ..Default::default()
        };
        let app = App::for_test(vec![project, empty], vec![owner, child], vec![]);
        let rows = app.sidebar_rows();
        assert!(matches!(&rows[0], SidebarRow::Project { name, .. } if name == "aoide"));
        assert!(
            matches!(&rows[3], SidebarRow::Session { rec, label, depth: 3, past: false } if rec.session_id == "child-1234" && label == "small-fern · claude (…1234)")
        );
        assert!(matches!(&rows[4], SidebarRow::Project { name, .. } if name == "empty"));
        assert_eq!(Panel::Graph.index(), 7);
        assert_eq!(Panel::Pending.index(), 5);
        assert_eq!(app.panel, Panel::Home);
    }

    #[test]
    fn agent_and_terminal_sections_preserve_full_roster_inheritance() {
        let shell = SessionRecord {
            session_id: "wrapper".into(),
            agent: "shell".into(),
            cwd: "/project".into(),
            state: "idle".into(),
            ..Default::default()
        };
        let agent = SessionRecord {
            session_id: "native".into(),
            agent: "claude".into(),
            cwd: "/tmp".into(),
            parent_session_id: Some("wrapper".into()),
            state: "working".into(),
            ..Default::default()
        };
        let mut app = App::for_test(
            vec![graph::Project {
                name: "aoide".into(),
                path: "/project".into(),
                ..Default::default()
            }],
            vec![shell, agent],
            vec![],
        );
        let rows = app.sidebar_rows();
        assert!(matches!(
            &rows[1],
            SidebarRow::Section {
                terminal: false,
                count: 1,
                ..
            }
        ));
        assert!(
            matches!(&rows[2], SidebarRow::Session { rec, depth: 2, .. } if rec.session_id == "native")
        );
        assert!(matches!(
            &rows[3],
            SidebarRow::Section {
                terminal: true,
                count: 1,
                ..
            }
        ));
        app.sidebar_activate(2);
        assert_eq!(app.panel, Panel::Session);
        assert!(
            matches!(&app.dag_rows()[0], DagRow::Group { name, total: 1, .. } if name == "aoide")
        );
        assert!(
            matches!(&app.dag_rows()[1], DagRow::Session { rec, .. } if rec.session_id == "native")
        );
        app.sidebar_activate(4);
        assert_eq!(app.panel, Panel::Terminals);
        assert!(
            matches!(&app.dag_rows()[1], DagRow::Session { rec, .. } if rec.session_id == "wrapper")
        );
        assert_eq!(app.dag_rows().len(), 2);
        app.panel = Panel::Graph;
        assert_eq!(app.dag_rows().len(), 3);
        app.sidebar_activate(1);
        assert!(matches!(
            &app.sidebar_rows()[1],
            SidebarRow::Section { folded: true, .. }
        ));
        assert!(!app
            .sidebar_rows()
            .iter()
            .any(|r| matches!(r, SidebarRow::Session { rec, .. } if rec.session_id == "native")));
        assert!(app.last_outcome.is_none());
        assert!(is_terminal(&SessionRecord {
            agent: "bash".into(),
            kind: Some("shell".into()),
            ..Default::default()
        }));
        assert_eq!(Panel::Mail.index(), 1);
        assert_eq!(Panel::Terminals.index(), 3);
    }

    #[test]
    fn sidebar_past_is_collapsed_and_activation_only_navigates() {
        let rec = SessionRecord {
            session_id: "ended-5678".into(),
            agent: "claude".into(),
            state: "done".into(),
            ..Default::default()
        };
        let mut app = App::for_test(vec![], vec![rec], vec![]);
        assert_eq!(app.sidebar_rows().len(), 2);
        assert!(matches!(
            &app.sidebar_rows()[1],
            SidebarRow::Past {
                folded: true,
                count: 1,
                ..
            }
        ));
        app.sidebar_sel = 1;
        app.handle_sidebar_key(KeyEvent::from(KeyCode::Right));
        assert!(matches!(
            &app.sidebar_rows()[2],
            SidebarRow::Session { past: true, .. }
        ));
        app.sidebar_activate(2);
        assert_eq!(app.panel, Panel::Session);
        assert!(app.last_outcome.is_none());
        assert!(app.tail.is_none());
        app.sidebar_sel = 0;
        app.handle_sidebar_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.sidebar_rows().len(), 1);
        app.handle_sidebar_key(KeyEvent::from(KeyCode::Down));
        assert_eq!(app.sidebar_sel, 0);
        app.handle_sidebar_key(KeyEvent::from(KeyCode::Char('l')));
        assert_eq!(app.sidebar_rows().len(), 3);
        app.handle_sidebar_key(KeyEvent::from(KeyCode::Char('h')));
        assert_eq!(app.sidebar_rows().len(), 1);
    }

    #[test]
    fn audit_refresh_preserves_identity_and_keeps_snapshot_on_error() {
        with_isolated_stage(|| {
            let path = App::audit_path();
            std::fs::write(&path, "{\"ts\":2,\"message\":\"selected\"}\n").unwrap();
            let mut app = App::for_test(vec![], vec![], vec![]);
            app.reload_log();
            app.log_scroll = 10;
            std::fs::write(&path, "{\"ts\":1}\n{\"ts\":2,\"message\":\"selected\"}\n").unwrap();
            app.reload_log();
            assert_eq!(app.log_sel, 1);
            assert_eq!(app.log_scroll, 10);
            std::fs::write(&path, "malformed\n").unwrap();
            app.reload_log();
            assert!(app.log_error.is_some());
            assert_eq!(app.log.len(), 2);
            assert_eq!(app.log_sel, 1);
            std::fs::write(&path, "{\"ts\":3}\n").unwrap();
            app.reload_log();
            assert!(app.log_error.is_none());
            assert_eq!(app.log_sel, 0);
            assert_eq!(app.log_scroll, 0);
        });
    }

    #[test]
    fn stage_notes_path_is_unconditionally_livery_json() {
        // Phase 4: no fallback — the function returns dir/livery.json without
        // probing for any other file, even when no note file exists yet.
        let dir = std::env::temp_dir().join(format!(
            "aoide-conductor-stage-notes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(stage_notes_path(&dir), dir.join("livery.json"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex_maps_to_plausible_ansi256() {
        // Pure red → cube red (196) region.
        let red = hex_to_ansi256("#ff0000").unwrap();
        assert!((160..=231).contains(&red), "red mapped to {red}");
        // Near-black grey → the low grey ramp or cube 16.
        let dark = hex_to_ansi256("#1e1e2e").unwrap();
        assert!(dark == 16 || (232..=240).contains(&dark) || (16..=60).contains(&dark));
        // Catppuccin accent blue (#89b4fa) → some blue-ish cube index.
        let blue = hex_to_ansi256("#89b4fa").unwrap();
        assert!(blue >= 16);
        // 3-digit form works.
        assert_eq!(hex_to_ansi256("#fff"), hex_to_ansi256("#ffffff"));
        // Garbage → None.
        assert!(hex_to_ansi256("nope").is_none());
    }

    #[test]
    fn white_and_black_extremes() {
        assert_eq!(rgb_to_ansi256(255, 255, 255), 231); // top of the cube (white)
        assert_eq!(rgb_to_ansi256(0, 0, 0), 16); // bottom of the cube (black)
    }

    // ── Enter's branch: log tail vs. the focus jump ─────────────────────────

    use serde_json::Map;
    use std::sync::Mutex;

    /// A unique scratch dir per call (pid + nanos), mirroring
    /// `stage_notes_path_is_unconditionally_livery_json` above.
    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide-conductor-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A minimal `SessionRecord` fixture — same shape as `ui.rs`'s test
    /// helper of the same name.
    fn session(id: &str, cwd: &str, state: &str, parent: Option<&str>) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            enduring_agent_id: None,
            project: None,
            agent: "claude".into(),
            window_address: format!("0x{id}"),
            cwd: cwd.into(),
            state: state.into(),
            started_at: id.into(),
            parent_session_id: parent.map(str::to_string),
            conductable: None,
            socket: None,
            title: None,
            pid: None,
            workspace: None,
            activity: None,
            kind: None,
            say: None,
            tool: None,
            model: None,
            context_tokens: None,
            needs_sudo: None,
            context_ceiling: None,
            log_path: None,
            sources: None,
            petname: None,
            hook_ancestry: Vec::new(),
            headless: false,
            spawned: false,
            exempt: false,
            harness_session_id: None,
            resumed_from: None,
            native_role: None,
            origin: None,
            seal: None,
            sealed_issued_at: None,
            restore: None,
            extra: Map::new(),
        }
    }

    /// Serialises the tests below that touch `AOIDE_STAGE_DIR`/
    /// `AOIDE_AUDIT_LOG` — process-global env, so parallel `cargo test`
    /// threads within this crate must not race on it. `aoide_storage` has an
    /// equivalent lock but it's `pub(crate)` there, unreachable from this
    /// crate — this is this crate's own copy of the same guard.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Point `AOIDE_STAGE_DIR`/`AOIDE_AUDIT_LOG` at a fresh empty tempdir for
    /// the duration of `f`, restoring whatever was set before. Any test that
    /// calls `App::dispatch` or `App::poll_refresh` needs this — both read
    /// the real stage dirs otherwise, and on this machine that's the live
    /// `~/Aoide/state/stage` (conducting) and `~/Aoide/song/stage` (rice),
    /// not a fixture. `AOIDE_STAGE_DIR` overrides both at once, same as
    /// today — see `App::stage`/`App::rice_stage`.
    fn with_isolated_stage<R>(f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_dir("stage-isolated");
        let saved_stage = std::env::var("AOIDE_STAGE_DIR").ok();
        let saved_audit = std::env::var("AOIDE_AUDIT_LOG").ok();
        std::env::set_var("AOIDE_STAGE_DIR", &dir);
        std::env::set_var("AOIDE_AUDIT_LOG", dir.join("audit.log"));

        let result = f();

        match saved_stage {
            Some(v) => std::env::set_var("AOIDE_STAGE_DIR", v),
            None => std::env::remove_var("AOIDE_STAGE_DIR"),
        }
        match saved_audit {
            Some(v) => std::env::set_var("AOIDE_AUDIT_LOG", v),
            None => std::env::remove_var("AOIDE_AUDIT_LOG"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn enter_on_a_headless_roster_row_opens_the_tail_and_dispatches_nothing() {
        let dir = tmp_dir("tail-headless");
        let log = dir.join("s1.log");
        std::fs::write(&log, "hello\n").unwrap();

        let mut rec = session("s1", "/tmp", "running", None);
        rec.log_path = Some(log.to_string_lossy().into_owned());
        let mut app = App::for_test(Vec::new(), vec![rec], Vec::new());
        app.panel = Panel::Session;
        app.dag_sel = 1; // row 0 is the `(unanchored)` group header

        app.handle_key(KeyEvent::from(KeyCode::Enter));

        let tail = app.tail.as_ref().expect("tail opened on headless Enter");
        assert_eq!(tail.session_id, "s1");
        assert_eq!(tail.lines, vec!["hello".to_string(), String::new()]);
        assert!(
            app.last_outcome.is_none(),
            "headless Enter must not focus a session"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_on_a_windowed_roster_row_still_focuses_the_session() {
        with_isolated_stage(|| {
            // No `log_path` — only `window_address` (set by the `session`
            // fixture) — so this is the unchanged branch.
            let rec = session("s1", "/tmp", "running", None);
            let mut app = App::for_test(Vec::new(), vec![rec], Vec::new());
            app.panel = Panel::Session;
            app.dag_sel = 1;

            app.handle_key(KeyEvent::from(KeyCode::Enter));

            assert!(app.tail.is_none(), "a windowed session never opens a tail");
            assert!(
                app.last_outcome.is_some(),
                "windowed Enter still focuses the session"
            );

            // The focus jump calls `graph::focus_session` DIRECTLY (no
            // registry dispatch since the `graph focus` command was deleted),
            // hand-rolling its audit record — pin that the record actually
            // lands with the dispatcher's shape, so the single-audit-log
            // invariant holds without a CLI command behind it.
            let audit = std::fs::read_to_string(std::env::var("AOIDE_AUDIT_LOG").unwrap())
                .expect("cue_session wrote an audit line");
            assert!(
                audit.contains("\"command\":\"graph.focus\""),
                "hand-rolled audit record names graph.focus: {audit}"
            );
        });
    }

    #[test]
    fn enter_on_a_graph_node_whose_session_is_headless_opens_the_same_tail() {
        let dir = tmp_dir("tail-graphnode");
        let log = dir.join("s1.log");
        std::fs::write(&log, "hello\n").unwrap();

        let mut rec = session("s1", "/tmp", "running", None);
        rec.log_path = Some(log.to_string_lossy().into_owned());
        let mut app = App::for_test(Vec::new(), vec![rec], Vec::new());
        app.panel = Panel::Graph;
        app.graph_sel = 1; // node 0 is the synthetic `(unanchored)` root

        app.handle_key(KeyEvent::from(KeyCode::Enter));

        let tail = app.tail.as_ref().expect("tail opened from the graph panel");
        assert_eq!(tail.session_id, "s1");
        assert_eq!(tail.lines, vec!["hello".to_string(), String::new()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn close_tail_clears_the_overlay() {
        let dir = tmp_dir("tail-close");
        let log = dir.join("s1.log");
        std::fs::write(&log, "hi\n").unwrap();
        let mut rec = session("s1", "/tmp", "running", None);
        rec.log_path = Some(log.to_string_lossy().into_owned());

        let mut app = App::for_test(Vec::new(), vec![rec.clone()], Vec::new());
        app.open_tail(&rec);
        assert!(app.tail.is_some());

        app.close_tail();
        assert!(app.tail.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_tail_on_a_missing_log_file_opens_empty_without_panicking() {
        let mut rec = session("s1", "/tmp", "running", None);
        rec.log_path = Some("/nonexistent/aoide-conductor-test/does-not-exist.log".to_string());
        let mut app = App::for_test(Vec::new(), vec![rec.clone()], Vec::new());

        app.open_tail(&rec); // must not panic

        let tail = app
            .tail
            .as_ref()
            .expect("tail still opens on a missing file");
        assert!(
            tail.lines.is_empty(),
            "P1's tail_file returns empty on a missing file"
        );
    }

    #[test]
    fn poll_refresh_does_not_reread_the_tail_when_its_mtime_is_unchanged() {
        with_isolated_stage(|| {
            let dir = tmp_dir("tail-poll");
            let log = dir.join("s1.log");
            std::fs::write(&log, "one\n").unwrap();
            let mut rec = session("s1", "/tmp", "running", None);
            rec.log_path = Some(log.to_string_lossy().into_owned());

            let mut app = App::for_test(Vec::new(), vec![rec.clone()], Vec::new());
            app.open_tail(&rec);
            let after_open = app.tail.as_ref().unwrap().mtime;

            // No write to the file between ticks: the mtime-gate condition
            // (`m != t.mtime`) sees the same value both times, so the
            // `changed = true` inside it — the only place `poll_refresh`
            // marks a repaint for the tail — never fires. The isolated
            // stage dir holds no other files, so nothing else can trip
            // `changed` either: `false` here is proof the gate held.
            let changed = app.poll_refresh();

            assert!(
                !changed,
                "an unchanged tail mtime must not report a repaint"
            );
            assert_eq!(app.tail.as_ref().unwrap().mtime, after_open);
            assert_eq!(
                app.tail.as_ref().unwrap().lines,
                vec!["one".to_string(), String::new()]
            );

            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    // ── ROSTER: throttle mechanics (P-C4) ────────────────────────────────
    //
    // A dedicated counting `fn` (not a closure — `DispatchFn` is a plain fn
    // pointer, matching production) proves the throttle wiring end to end:
    // how many times the injected dispatcher actually ran, observed through
    // the real `App::poll_refresh`/`select_panel`/`handle_key` call sites
    // rather than a lower-level decision helper.

    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static ROSTER_CALLS: AtomicUsize = AtomicUsize::new(0);
    /// Serialises the roster throttle tests against the shared
    /// `ROSTER_CALLS` counter (parallel `cargo test` threads within this
    /// crate would otherwise race on it) — a dedicated lock, since
    /// `ENV_LOCK` above guards a different piece of shared state.
    static ROSTER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn counting_roster_dispatch(_: &Invocation) -> Outcome {
        ROSTER_CALLS.fetch_add(1, Ordering::SeqCst);
        Outcome::ok("session", "1 node(s), 0 session(s)")
            .with_data(json!({ "host": "h", "generatedAt": "t", "nodes": [] }))
    }

    #[test]
    fn roster_tick_with_a_fresh_cache_does_not_redispatch() {
        with_isolated_stage(|| {
            let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ROSTER_CALLS.store(0, Ordering::SeqCst);

            let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
            app.panel = Panel::Roster;
            app.roster.fetched_at = Some(Instant::now()); // just fetched — well inside the window

            app.poll_refresh();

            assert!(
                app.roster_rx.is_none(),
                "a fresh cache must not spawn a fetch"
            );
            assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn roster_tick_with_a_stale_cache_while_visible_redispatches() {
        with_isolated_stage(|| {
            let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ROSTER_CALLS.store(0, Ordering::SeqCst);

            let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
            app.panel = Panel::Roster; // visible, `fetched_at: None` — always stale

            app.poll_refresh();

            let rx = app
                .roster_rx
                .take()
                .expect("a stale, visible pane spawns a fetch");
            let outcome = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("the background dispatch completes");
            assert_eq!(outcome.command, "session");
            assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn roster_tick_while_hidden_never_dispatches_even_when_stale() {
        with_isolated_stage(|| {
            let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ROSTER_CALLS.store(0, Ordering::SeqCst);

            let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
            app.panel = Panel::Session; // NOT the roster pane

            app.poll_refresh();

            assert!(
                app.roster_rx.is_none(),
                "a hidden pane must never spawn a fetch"
            );
            assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn switching_into_roster_with_a_stale_cache_dispatches_immediately() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
        assert_eq!(app.panel, Panel::Home, "starts elsewhere");

        app.select_panel(Panel::Roster); // no tick involved at all

        let rx = app
            .roster_rx
            .take()
            .expect("landing on a stale ROSTER must fetch immediately, not wait for a tick");
        rx.recv_timeout(Duration::from_secs(2))
            .expect("dispatch completes");
        assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn switching_into_roster_with_a_fresh_cache_does_not_redispatch() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
        app.roster.fetched_at = Some(Instant::now());

        app.select_panel(Panel::Roster);

        assert!(
            app.roster_rx.is_none(),
            "a fresh cache needs no immediate fetch"
        );
        assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn manual_refresh_key_forces_a_dispatch_even_with_a_fresh_cache() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
        app.panel = Panel::Roster;
        app.roster.fetched_at = Some(Instant::now()); // fresh — a tick would skip it

        app.handle_key(KeyEvent::from(KeyCode::Char('r')));

        let rx = app
            .roster_rx
            .take()
            .expect("`r` forces a fetch regardless of the throttle window");
        rx.recv_timeout(Duration::from_secs(2))
            .expect("dispatch completes");
        assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_fetch_already_in_flight_is_never_duplicated() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_roster_dispatch);
        app.panel = Panel::Roster;
        app.spawn_roster_fetch();
        assert!(app.roster_rx.is_some());

        // A second manual refresh while the first is still in flight must be
        // a no-op — `spawn_roster_fetch`'s own guard, exercised directly
        // since a real fetch here completes in well under a millisecond and
        // could otherwise race the assertion.
        app.spawn_roster_fetch();

        let rx = app.roster_rx.take().unwrap();
        rx.recv_timeout(Duration::from_secs(2))
            .expect("dispatch completes");
        assert_eq!(
            ROSTER_CALLS.load(Ordering::SeqCst),
            1,
            "the in-flight guard must prevent a duplicate dispatch"
        );
    }

    #[test]
    fn roster_nodes_parses_the_who_json_shape_and_status_reports_freshness() {
        let mut app = App::for_test(Vec::new(), Vec::new(), Vec::new());
        assert!(app.roster_nodes().is_empty(), "no fetch yet");
        assert_eq!(app.roster_status(), "not yet fetched — press r");

        let data = json!({
            "host": "sakaki",
            "generatedAt": "2026-08-21T00:00:00Z",
            "nodes": [
                {
                    "name": "sakaki",
                    "isLocal": true,
                    "presence": "online",
                    "fetchedAt": null,
                    "error": null,
                    "sessions": [
                        {"sessionId": "s1", "label": "sakaki/root/s1", "petname": null,
                         "agent": "claude", "state": "working", "presence": "online", "cwd": "/x"}
                    ],
                },
                {
                    "name": "yomi-strix",
                    "isLocal": false,
                    "presence": "unreachable",
                    "fetchedAt": "2026-08-20T23:00:00Z",
                    "error": "HTTP 000",
                    "sessions": [],
                },
            ],
        });
        app.roster.outcome =
            Some(Outcome::ok("session", "2 node(s), 1 session(s)").with_data(data));
        app.roster.fetched_at = Some(Instant::now());

        let nodes = app.roster_nodes();
        assert_eq!(
            nodes.len(),
            2,
            "local + one node, in the roster's own order"
        );
        assert!(
            nodes[0].is_local && nodes[0].name == "sakaki",
            "local box first"
        );
        assert_eq!(nodes[0].sessions[0].label, "sakaki/root/s1");
        assert_eq!(nodes[0].sessions[0].state, "working");
        assert_eq!(nodes[1].name, "yomi-strix");
        assert_eq!(nodes[1].presence, "unreachable");
        assert_eq!(nodes[1].fetched_at.as_deref(), Some("2026-08-20T23:00:00Z"));

        assert!(
            app.roster_status().starts_with("fetched "),
            "{}",
            app.roster_status()
        );
    }

    #[test]
    fn roster_status_surfaces_a_non_ok_outcome_instead_of_hiding_it() {
        let mut app = App::for_test(Vec::new(), Vec::new(), Vec::new());
        app.roster.outcome = Some(Outcome::error(
            "session",
            "stage read failed: permission denied",
        ));
        app.roster.fetched_at = Some(Instant::now());

        let status = app.roster_status();
        assert!(
            status.starts_with("[err] session: stage read failed"),
            "the error message surfaces in the pane, not a bare age: {status}"
        );
        assert!(
            app.roster_nodes().is_empty(),
            "an error Outcome carries no `data`, so no rows — the status line is the only signal"
        );
    }

    // ── ROSTER: selection mechanics (P-C5) ───────────────────────────────

    #[test]
    fn roster_selection_walks_flat_rows_and_clamps_at_both_ends() {
        let mut app = App::for_test(Vec::new(), Vec::new(), Vec::new());
        app.panel = Panel::Roster;
        app.roster.outcome = Some(who_fixture_two_nodes());
        // sakaki (header) + s1 (session) + yomi-strix (header) + s2 (session) = 4 rows.
        assert_eq!(app.roster_flat_rows().len(), 4);

        assert_eq!(app.roster_sel, 0);
        app.handle_key(KeyEvent::from(KeyCode::Char('j')));
        assert_eq!(app.roster_sel, 1);
        for _ in 0..10 {
            app.handle_key(KeyEvent::from(KeyCode::Char('j')));
        }
        assert_eq!(app.roster_sel, 3, "j never walks past the last row");

        for _ in 0..10 {
            app.handle_key(KeyEvent::from(KeyCode::Char('k')));
        }
        assert_eq!(app.roster_sel, 0, "k never walks before the first row");
    }

    #[test]
    fn a_landed_background_fetch_that_shrinks_the_roster_clamps_selection_so_compose_never_silently_no_ops(
    ) {
        // Review nit: `drain_roster`/`poll_roster` (the background roster
        // fetch completing) is the one mutation that bypassed
        // `clamp_selection` — `reload_all` and `poll_refresh`'s
        // stage-mtime-gated block both call it, this path didn't. Start on
        // the LAST row of a 4-row roster, land a fetch that shrinks to 2
        // rows, and prove both that the cursor is clamped AND that `s`
        // then composes against the row actually on screen (index 1, s1) —
        // not silently no-op against the stale pre-shrink index 3, which is
        // exactly the bug: render's `.min()` would still highlight row 1
        // while `open_compose`'s raw `.get(3)` found nothing.
        let mut app = App::for_test(Vec::new(), Vec::new(), Vec::new());
        app.panel = Panel::Roster;
        app.roster.outcome = Some(who_fixture_two_nodes());
        app.roster_sel = 3; // yomi-strix/s2 — about to vanish in the shrink

        // Populate the exact channel `spawn_roster_fetch` uses, as if a
        // background fetch just landed — deterministic, no thread race.
        let (tx, rx) = mpsc::channel();
        let shrunk = Outcome::ok("session", "1 node(s), 1 session(s)").with_data(json!({
            "host": "sakaki", "generatedAt": "t",
            "nodes": [
                {
                    "name": "sakaki", "isLocal": true, "presence": "online",
                    "fetchedAt": null, "error": null,
                    "sessions": [
                        {"sessionId": "s1", "label": "sakaki/root/brave-otter (…s1)", "petname": "brave-otter",
                         "agent": "claude", "state": "working", "presence": "online", "cwd": "/x"},
                    ],
                },
            ],
        }));
        tx.send(shrunk).unwrap();
        app.roster_rx = Some(rx);

        let changed = app.poll_roster();

        assert!(changed, "a landed fetch is a repaint");
        assert_eq!(
            app.roster_flat_rows().len(),
            2,
            "header + the one remaining session"
        );
        assert_eq!(
            app.roster_sel, 1,
            "clamped onto the new last row, not left at the stale index 3"
        );

        app.handle_key(KeyEvent::from(KeyCode::Char('s')));
        let input = app
            .input
            .as_ref()
            .expect("`s` composes against the row actually on screen");
        assert_eq!(input.label, "send to sakaki/root/brave-otter (…s1)");
    }

    fn who_fixture_two_nodes() -> Outcome {
        let data = json!({
            "host": "sakaki",
            "generatedAt": "t",
            "nodes": [
                {
                    "name": "sakaki", "isLocal": true, "presence": "online",
                    "fetchedAt": null, "error": null,
                    "sessions": [
                        {"sessionId": "s1", "label": "sakaki/root/brave-otter (…s1)", "petname": "brave-otter",
                         "agent": "claude", "state": "working", "presence": "online", "cwd": "/x"},
                    ],
                },
                {
                    "name": "yomi-strix", "isLocal": false, "presence": "online",
                    "fetchedAt": "t", "error": null,
                    "sessions": [
                        {"sessionId": "s2", "label": "yomi-strix/root/misty-comet (…s2)", "petname": "misty-comet",
                         "agent": "claude", "state": "idle", "presence": "online", "cwd": "/y"},
                    ],
                },
            ],
        });
        Outcome::ok("session", "2 node(s), 2 session(s)").with_data(data)
    }

    // ── Compose: `s` on a ROSTER session row (P-C5) ──────────────────────

    static COMPOSE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static COMPOSE_CALLS: Mutex<Vec<(Vec<String>, Vec<String>, BTreeMap<String, String>)>> =
        Mutex::new(Vec::new());

    fn recording_compose_dispatch(inv: &Invocation) -> Outcome {
        COMPOSE_CALLS
            .lock()
            .unwrap()
            .push((inv.path.clone(), inv.args.clone(), inv.flags.clone()));
        Outcome::ok("send", "delivered")
    }

    #[test]
    fn compose_builds_the_exact_expected_invocation() {
        let _g = COMPOSE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        COMPOSE_CALLS.lock().unwrap().clear();

        with_isolated_stage(|| {
            let mut app = App::for_test_with_dispatch(recording_compose_dispatch);
            app.panel = Panel::Roster;
            app.roster.outcome = Some(who_fixture_two_nodes());
            app.roster_sel = 1; // the s1 session row (index 1: header, session, header, session)

            app.handle_key(KeyEvent::from(KeyCode::Char('s')));
            let input = app
                .input
                .as_ref()
                .expect("`s` on a session row opens compose");
            assert_eq!(input.label, "send to sakaki/root/brave-otter (…s1)");
            assert_eq!(
                input.kind,
                InputKind::Compose {
                    target: "sakaki/root/brave-otter (…s1)".to_string()
                }
            );

            for c in "hi".chars() {
                app.handle_key(KeyEvent::from(KeyCode::Char(c)));
            }
            app.handle_key(KeyEvent::from(KeyCode::Enter));

            assert!(app.input.is_none(), "submit closes the prompt");
            let calls = COMPOSE_CALLS.lock().unwrap();
            let send_call = calls
                .iter()
                .find(|(path, ..)| path == &vec!["send".to_string()])
                .expect("a send dispatch was recorded");
            assert_eq!(
                send_call.1,
                vec!["hi".to_string()],
                "text rides as a single positional arg"
            );
            let mut expected_flags = BTreeMap::new();
            expected_flags.insert(
                "to".to_string(),
                "sakaki/root/brave-otter (…s1)".to_string(),
            );
            expected_flags.insert("yes".to_string(), "true".to_string());
            assert_eq!(send_call.2, expected_flags);
        });
    }

    #[test]
    fn s_on_a_node_header_row_is_a_no_op() {
        let mut app = App::for_test_with_dispatch(recording_compose_dispatch);
        app.panel = Panel::Roster;
        app.roster.outcome = Some(who_fixture_two_nodes());
        app.roster_sel = 0; // the sakaki header row, not a session

        app.handle_key(KeyEvent::from(KeyCode::Char('s')));

        assert!(
            app.input.is_none(),
            "no session under the cursor — nothing to compose to"
        );
    }

    // ── Projects panel: `r` resurrects the focused project (P-D8) ────────

    static PROJECTS_TEST_LOCK: Mutex<()> = Mutex::new(());
    static RESURRECT_CALLS: Mutex<Vec<(Vec<String>, Vec<String>, BTreeMap<String, String>)>> =
        Mutex::new(Vec::new());

    fn recording_resurrect_dispatch(inv: &Invocation) -> Outcome {
        RESURRECT_CALLS.lock().unwrap().push((
            inv.path.clone(),
            inv.args.clone(),
            inv.flags.clone(),
        ));
        Outcome::ok("resurrect", "resurrected 1 session")
    }

    #[test]
    fn project_removal_requires_exact_confirmation_and_keeps_original_target() {
        let _g = PROJECTS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RESURRECT_CALLS.lock().unwrap().clear();
        let mut app = App::for_test_with_dispatch(recording_resurrect_dispatch);
        app.panel = Panel::Projects;
        app.projects = vec![
            graph::Project {
                name: "first".into(),
                ..Default::default()
            },
            graph::Project {
                name: "second".into(),
                ..Default::default()
            },
        ];
        app.handle_key(KeyEvent::from(KeyCode::Char('d')));
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        app.handle_key(KeyEvent::from(KeyCode::Delete));
        assert!(RESURRECT_CALLS.lock().unwrap().is_empty());
        app.input.as_mut().unwrap().buffer = "wrong".into();
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(RESURRECT_CALLS.lock().unwrap().is_empty());
        app.proj_sel = 1;
        app.input.as_mut().unwrap().buffer = "first".into();
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        let calls = RESURRECT_CALLS.lock().unwrap();
        let removes: Vec<_> = calls
            .iter()
            .filter(|(p, ..)| p == &["project", "remove"])
            .collect();
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0].1, vec!["first"]);
        assert!(app.input.is_none());
    }

    #[test]
    fn project_group_removal_can_be_cancelled_without_dispatch() {
        let _g = PROJECTS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RESURRECT_CALLS.lock().unwrap().clear();
        let mut app = App::for_test_with_dispatch(recording_resurrect_dispatch);
        app.panel = Panel::Session;
        app.projects = vec![graph::Project {
            name: "first".into(),
            ..Default::default()
        }];
        app.dag_sel = app
            .dag_rows()
            .iter()
            .position(|row| matches!(row, DagRow::Group { name, .. } if name == "first"))
            .unwrap();
        app.handle_key(KeyEvent::from(KeyCode::Char('d')));
        assert!(
            matches!(app.input.as_ref().map(|i| &i.kind), Some(InputKind::ProjectRemove { name }) if name == "first")
        );
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.input.is_none());
        assert!(RESURRECT_CALLS.lock().unwrap().is_empty());
    }

    #[test]
    fn r_on_the_projects_panel_resurrects_the_focused_project() {
        let _g = PROJECTS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RESURRECT_CALLS.lock().unwrap().clear();

        let mut app = App::for_test_with_dispatch(recording_resurrect_dispatch);
        app.panel = Panel::Projects;
        app.projects = vec![
            graph::Project {
                name: "aoide".to_string(),
                path: "/home/x/Aoide".to_string(),
                ..Default::default()
            },
            graph::Project {
                name: "melete".to_string(),
                path: "/home/x/Melete".to_string(),
                ..Default::default()
            },
        ];
        // `sorted_project_names` sorts by name: ["aoide", "melete"].
        app.proj_sel = 1; // "melete"

        app.handle_key(KeyEvent::from(KeyCode::Char('r')));

        // `dispatch_with_flags` also calls `reload_all()` right after, which
        // fires its own dispatches (session/graph view/…) through the SAME
        // injected fn — filter to the resurrect call specifically, same as
        // `compose_builds_the_exact_expected_invocation` does for `send`.
        let calls = RESURRECT_CALLS.lock().unwrap();
        let resurrect_calls: Vec<_> = calls
            .iter()
            .filter(|(path, ..)| path == &vec!["resurrect".to_string()])
            .collect();
        assert_eq!(
            resurrect_calls.len(),
            1,
            "exactly one resurrect dispatch fired"
        );
        let (path, args, flags) = resurrect_calls[0];
        assert_eq!(path, &vec!["resurrect".to_string()]);
        assert!(
            args.is_empty(),
            "the project rides as a flag, not a positional arg"
        );
        let mut expected_flags = BTreeMap::new();
        expected_flags.insert("project".to_string(), "melete".to_string());
        assert_eq!(flags, &expected_flags);
    }

    #[test]
    fn r_on_the_projects_panel_with_no_projects_is_a_no_op() {
        let _g = PROJECTS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        RESURRECT_CALLS.lock().unwrap().clear();

        let mut app = App::for_test_with_dispatch(recording_resurrect_dispatch);
        app.panel = Panel::Projects;
        app.projects = vec![];
        app.proj_sel = 0;

        app.handle_key(KeyEvent::from(KeyCode::Char('r')));

        assert!(
            RESURRECT_CALLS.lock().unwrap().is_empty(),
            "no project under the cursor — nothing to resurrect"
        );
    }

    // ── PENDING: command spellings, id-as-position, re-list mechanics (P-C5) ─

    static PENDING_TEST_LOCK: Mutex<()> = Mutex::new(());
    static PENDING_CALLS: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());
    static PENDING_QUEUE: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new()); // (sessionId, text)

    /// A fake `session pending list|approve|deny` over `PENDING_QUEUE` — proves
    /// the dispatch-order and re-list mechanics without touching real stage
    /// files. `list` renders whatever is currently in the queue (so a
    /// caller's own re-list after approve/deny sees the shrunk array,
    /// positions and all — mirroring the real door's behaviour exactly).
    fn recording_pending_dispatch(inv: &Invocation) -> Outcome {
        let path = inv.path.join(".");
        PENDING_CALLS
            .lock()
            .unwrap()
            .push((path.clone(), inv.args.clone()));
        match path.as_str() {
            "session.pending.list" => {
                let q = PENDING_QUEUE.lock().unwrap();
                let pending: Vec<Value> = q
                    .iter()
                    .enumerate()
                    .map(|(i, (sid, text))| {
                        json!({
                            "id": i.to_string(), "sessionId": sid, "text": text, "submit": false,
                            "queuedAt": "t", "from": Value::Null, "state": "pending",
                        })
                    })
                    .collect();
                let n = pending.len();
                Outcome::ok("session.pending.list", format!("{n} pending"))
                    .with_data(json!({ "pending": pending }))
            }
            "session.pending.approve" | "session.pending.deny" => {
                let idx: usize = inv.args[0].parse().unwrap_or(usize::MAX);
                let mut q = PENDING_QUEUE.lock().unwrap();
                if idx < q.len() {
                    let (sid, _) = q.remove(idx);
                    Outcome::ok(path.clone(), format!("resolved {sid}"))
                } else {
                    Outcome::error(path.clone(), format!("no pending entry at index {idx}"))
                }
            }
            other => Outcome::usage("test", format!("unexpected path {other}")),
        }
    }

    #[test]
    fn approve_dispatches_pending_approve_then_relists_and_positions_shift() {
        let _g = PENDING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PENDING_CALLS.lock().unwrap().clear();
        *PENDING_QUEUE.lock().unwrap() = vec![
            ("s0".into(), "a".into()),
            ("s1".into(), "b".into()),
            ("s2".into(), "c".into()),
        ];

        with_isolated_stage(|| {
            let mut app = App::for_test_with_dispatch(recording_pending_dispatch);
            app.select_panel(Panel::Pending); // immediate synchronous fetch — no tick needed
            assert_eq!(app.pending_rows().len(), 3);
            app.pending_sel = 0; // s0, the entry at position 0

            app.handle_key(KeyEvent::from(KeyCode::Char('a'))); // approve

            let calls = PENDING_CALLS.lock().unwrap();
            let last_two = &calls[calls.len() - 2..];
            assert_eq!(
                last_two[0],
                ("session.pending.approve".to_string(), vec!["0".to_string()])
            );
            assert_eq!(
                last_two[1],
                ("session.pending.list".to_string(), Vec::<String>::new())
            );
            drop(calls);

            // Positions shifted: s1 (was index 1) is now at index 0.
            let rows = app.pending_rows();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].session_id, "s1");
            assert_eq!(rows[1].session_id, "s2");
        });
    }

    #[test]
    fn deny_dispatches_pending_deny_then_relists() {
        let _g = PENDING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PENDING_CALLS.lock().unwrap().clear();
        *PENDING_QUEUE.lock().unwrap() = vec![("s0".into(), "a".into()), ("s1".into(), "b".into())];

        with_isolated_stage(|| {
            let mut app = App::for_test_with_dispatch(recording_pending_dispatch);
            app.select_panel(Panel::Pending);
            app.pending_sel = 0;

            app.handle_key(KeyEvent::from(KeyCode::Char('d'))); // deny

            let calls = PENDING_CALLS.lock().unwrap();
            let last_two = &calls[calls.len() - 2..];
            assert_eq!(
                last_two[0],
                ("session.pending.deny".to_string(), vec!["0".to_string()])
            );
            assert_eq!(
                last_two[1],
                ("session.pending.list".to_string(), Vec::<String>::new())
            );
            drop(calls);

            let rows = app.pending_rows();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].session_id, "s1");
        });
    }

    #[test]
    fn a_second_approve_after_the_first_resolves_the_row_now_at_the_cursor_not_a_stale_one() {
        // The invariant the module doc states as a constraint: without the
        // re-list, a second a/d in the same visit would resolve whatever
        // WAS at the selected index before the first resolve, not what's
        // there now. Three entries, approve twice at index 0: must take s0
        // then s1 (never s0 twice, never skip to s2).
        let _g = PENDING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PENDING_CALLS.lock().unwrap().clear();
        *PENDING_QUEUE.lock().unwrap() = vec![
            ("s0".into(), "a".into()),
            ("s1".into(), "b".into()),
            ("s2".into(), "c".into()),
        ];

        with_isolated_stage(|| {
            let mut app = App::for_test_with_dispatch(recording_pending_dispatch);
            app.select_panel(Panel::Pending);
            app.pending_sel = 0;

            app.handle_key(KeyEvent::from(KeyCode::Char('a')));
            app.handle_key(KeyEvent::from(KeyCode::Char('a')));

            let rows = app.pending_rows();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].session_id, "s2",
                "s0 then s1 were taken — never a stale re-resolve"
            );
        });
    }

    #[test]
    fn resolve_on_an_empty_pending_list_does_not_panic() {
        let _g = PENDING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PENDING_CALLS.lock().unwrap().clear();
        *PENDING_QUEUE.lock().unwrap() = Vec::new();

        let mut app = App::for_test_with_dispatch(recording_pending_dispatch);
        app.select_panel(Panel::Pending);
        assert!(app.pending_rows().is_empty());

        app.handle_key(KeyEvent::from(KeyCode::Char('a'))); // must not panic
        app.handle_key(KeyEvent::from(KeyCode::Char('d'))); // must not panic

        assert!(app.pending_rows().is_empty());
        // Neither key dispatched an approve/deny — nothing was selected.
        let calls = PENDING_CALLS.lock().unwrap();
        assert!(calls.iter().all(|(p, _)| p == "session.pending.list"));
    }

    #[test]
    fn pending_selection_walks_rows_and_clamps() {
        let _g = PENDING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PENDING_CALLS.lock().unwrap().clear();
        *PENDING_QUEUE.lock().unwrap() = vec![("s0".into(), "a".into()), ("s1".into(), "b".into())];

        let mut app = App::for_test_with_dispatch(recording_pending_dispatch);
        app.select_panel(Panel::Pending);

        assert_eq!(app.pending_sel, 0);
        app.handle_key(KeyEvent::from(KeyCode::Char('j')));
        assert_eq!(app.pending_sel, 1);
        app.handle_key(KeyEvent::from(KeyCode::Char('j')));
        assert_eq!(app.pending_sel, 1, "j never walks past the last row");
        app.handle_key(KeyEvent::from(KeyCode::Char('k')));
        assert_eq!(app.pending_sel, 0);
        app.handle_key(KeyEvent::from(KeyCode::Char('k')));
        assert_eq!(app.pending_sel, 0, "k never walks before the first row");
    }
    #[test]
    fn mail_draft_navigation_and_unicode_edits_do_not_send() {
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.open_mail_to("osaka/fable".into());
        app.handle_key(KeyEvent::from(KeyCode::Char('界')));
        app.handle_key(KeyEvent::from(KeyCode::Left));
        app.handle_key(KeyEvent::from(KeyCode::Char('A')));
        assert_eq!(app.mail_draft.as_ref().unwrap().subject, "A界");
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        app.handle_key(KeyEvent::from(KeyCode::Char('x')));
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.mail_draft.as_ref().unwrap().body, "x\n");
        assert!(app.last_outcome.is_none());
        app.handle_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(app.mail_draft.as_ref().unwrap().focus, MailField::Subject);
    }

    #[test]
    fn mail_draft_local_route_and_partial_submission_cannot_repeat() {
        fn partial(inv: &Invocation) -> Outcome {
            if !inv.flags.contains_key("to") {
                return Outcome::usage("test", "read ignored");
            }
            assert_eq!(inv.flags.get("to").map(String::as_str), Some("self/fable"));
            assert_eq!(inv.flags.get("subject").map(String::as_str), Some("Review"));
            let mut out = Outcome::usage("mail.send", "One recipient failed; others filed");
            out.data =
                Some(serde_json::json!({"accepted":1,"recipients":[{"msgid":"already-filed"}]}));
            out
        }
        let mut app = App::for_test_with_dispatch(partial);
        app.open_mail_to(format!(
            "{}/fable",
            aoide_storage::display::local_host_name()
        ));
        let draft = app.mail_draft.as_mut().unwrap();
        draft.subject = "Review".into();
        draft.body = "Please check".into();
        app.send_mail_draft();
        assert!(app.mail_draft.as_ref().unwrap().submitted);
        app.send_mail_draft();
        assert!(app
            .mail_draft
            .as_ref()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .starts_with("Already submitted"));
    }

    #[test]
    fn reply_all_and_forward_keep_original_and_explicit_destinations() {
        use aoide_storage::mail::Address;
        let local = aoide_storage::display::local_host_name();
        let content = aoide_storage::letter::LetterContent {
            subject: "Architecture".into(),
            to: vec![Address {
                node: local.clone(),
                name: "conductor-human".into(),
            }],
            cc: vec![Address {
                node: "osaka".into(),
                name: "reviewer".into(),
            }],
            body: "Original text".into(),
            thread_id: None,
            reply_to: None,
        }
        .encode()
        .unwrap();
        let mut app = App::for_test(vec![], vec![], vec![]);
        app.mail.letters.push(crate::mailview::MailLetter {
            seq: 1,
            msgid: "original-id".into(),
            from: "osaka/fable".into(),
            to: format!("{local}/conductor-human"),
            from_address: Address {
                node: "osaka".into(),
                name: "fable".into(),
            },
            to_address: Address {
                node: local,
                name: "conductor-human".into(),
            },
            text: content,
            received_at: "today".into(),
            minted_at: "today".into(),
        });
        app.open_mail(MailMode::ReplyAll);
        let draft = app.mail_draft.as_ref().unwrap();
        assert_eq!(draft.to, "osaka/fable");
        assert_eq!(draft.cc, "osaka/reviewer");
        assert_eq!(draft.subject, "Re: Architecture");
        assert!(draft.body.contains("> Original text"));
        assert_eq!(draft.original.as_ref().unwrap().msgid, "original-id");
        app.mail_draft = None;
        app.open_mail(MailMode::Forward);
        let draft = app.mail_draft.as_ref().unwrap();
        assert!(draft.to.is_empty());
        assert!(draft.cc.is_empty());
        assert_eq!(draft.subject, "Fwd: Architecture");
    }
    #[test]
    fn session_context_opens_without_dispatch_and_preserves_exact_assignment_id() {
        fn assignment(inv: &Invocation) -> Outcome {
            if inv.path == ["session", "project"] {
                assert_eq!(inv.flags.get("id").map(String::as_str), Some("wanted"));
                assert_eq!(
                    inv.flags.get("project").map(String::as_str),
                    Some("destination")
                );
                return Outcome::ok("session.project", "assigned exact target");
            }
            Outcome::usage("read", "ignored")
        }
        let mut app = App::for_test_with_dispatch(assignment);
        let mut rec = session("wanted", "/x", "working", None);
        rec.petname = Some("calm-rook".into());
        app.sessions = vec![rec.clone(), session("other", "/y", "working", None)];
        app.open_context_for_session(rec, 3, 4);
        assert!(app.last_outcome.is_none());
        let menu = app.context_menu.as_ref().unwrap();
        let index = menu
            .actions
            .iter()
            .position(|a| *a == ContextAction::AssignProject)
            .unwrap();
        app.dag_sel = 999;
        app.run_context_action(index);
        assert!(app.last_outcome.is_none());
        app.input.as_mut().unwrap().buffer = "destination".into();
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            app.last_outcome.as_ref().unwrap().command,
            "session.project"
        );
    }

    #[test]
    fn historical_context_resurrects_exact_entry_and_never_offers_live_actions() {
        fn resurrect(inv: &Invocation) -> Outcome {
            if inv.path == ["resurrect"] {
                assert_eq!(inv.flags.get("id").map(String::as_str), Some("ended-exact"));
                assert_eq!(
                    inv.flags.get("project").map(String::as_str),
                    Some("archive")
                );
                return Outcome::ok("resurrect", "exact history");
            }
            Outcome::usage("read", "ignored")
        }
        let mut app = App::for_test_with_dispatch(resurrect);
        app.projects = vec![graph::Project {
            name: "archive".into(),
            path: "/archive".into(),
            ..Default::default()
        }];
        let entry = aoide_storage::ledger::LedgerEntry {
            session_id: "ended-exact".into(),
            project: Some("archive".into()),
            harness_session_id: Some("native".into()),
            ..Default::default()
        };
        app.open_context_for_history(entry.clone(), 0, 0);
        assert_eq!(
            app.context_menu.as_ref().unwrap().actions,
            vec![ContextAction::Details, ContextAction::Resurrect]
        );
        app.run_context_action(1);
        assert_eq!(app.last_outcome.as_ref().unwrap().command, "resurrect");
        app.open_context_for_history(entry, 0, 0);
        app.run_context_action(0);
        assert_eq!(
            app.history_selected.as_ref().unwrap().session_id,
            "ended-exact"
        );
    }

    #[test]
    fn historical_context_does_not_guess_a_retired_explicit_project() {
        let mut app = App::for_test(
            vec![graph::Project {
                name: "new".into(),
                path: "/archive".into(),
                ..Default::default()
            }],
            vec![],
            vec![],
        );
        let entry = aoide_storage::ledger::LedgerEntry {
            session_id: "ended".into(),
            project: Some("retired".into()),
            cwd: "/archive".into(),
            harness_session_id: Some("native".into()),
            ..Default::default()
        };
        app.open_context_for_history(entry, 0, 0);
        assert_eq!(
            app.context_menu.as_ref().unwrap().actions,
            vec![ContextAction::Details]
        );
    }
}
