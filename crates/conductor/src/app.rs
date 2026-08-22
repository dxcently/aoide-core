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
//! The SESSIONS panel walks a flattened row model ([`App::dag_rows`]): project
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
use aoide_storage::fs::stage_dir;
use crossterm::event::{KeyCode, KeyEvent};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Instant, SystemTime};

/// The six panels, in Tab / 1-6 order. `Graph` is the visual DAG (the new hero
/// view — nodes/edges laid out and drawn); `Sessions` is the collapsible roster
/// (the terminal-sessions view, keyed off [`App::dag_rows`]). The two are
/// deliberately distinct lenses on the same data: `Graph` shows the *shape* of
/// the DAG, `Sessions` the *state* of each terminal. `Roster` (messaging/
/// presence plan, P-C4) is a distinct, later addition — appended last so the
/// existing 1-5 keys never shift (registry append-only discipline,
/// `pkgs/aoide/crates/AGENTS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Graph,
    Sessions,
    Projects,
    Log,
    Status,
    Roster,
}

impl Panel {
    pub const ALL: [Panel; 6] = [
        Panel::Graph,
        Panel::Sessions,
        Panel::Projects,
        Panel::Log,
        Panel::Status,
        Panel::Roster,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Panel::Graph => "DAG",
            Panel::Sessions => "SESSIONS",
            Panel::Projects => "PROJECTS",
            Panel::Log => "LOG",
            Panel::Status => "STATUS",
            Panel::Roster => "ROSTER",
        }
    }
    pub fn index(self) -> usize {
        Panel::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// The palette pulled from `stage/livery.json`, each hex mapped to nearest
/// ANSI-256. `None` fields mean "no colour — inherit the terminal".
#[derive(Debug, Clone, Default)]
pub struct Palette {
    pub bg: Option<u8>,
    pub fg: Option<u8>,
    pub accent: Option<u8>,
    pub urgent: Option<u8>,
}

/// One decoded audit-log line (the flat event feed the LOG panel tails).
#[derive(Debug, Clone)]
pub struct LogLine {
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
    ProjectAdd,
    /// Link the named child session under the parent the prompt collects.
    Link {
        child: String,
    },
}

/// The group name sessions fall under when no project anchors their cwd.
pub const UNANCHORED: &str = "(unanchored)";

/// How many ticks (~500 ms each) a newly-appeared session stays marked fresh.
pub const FRESH_TICKS: u8 = 4;

/// One row of the SESSIONS panel's flattened DAG: a project group header or a
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

/// mtimes of the stage files we poll, so a tick reloads only what changed.
/// Stage-files-only: the log tail's own mtime lives on [`LogTail`] itself,
/// gated separately in [`App::poll_refresh`] — a tail is a file read, not a
/// stage file, and it doesn't exist for most of an App's life (`None` while
/// closed).
#[derive(Debug, Clone, Default)]
struct StageMtimes {
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

/// Throttle window for the ROSTER panel's `who` dispatch (messaging/presence
/// plan, P-C4). `who` performs a LIVE network probe of every registered peer
/// on each invocation (`conduct/src/graph/who.rs`'s module doc), so the pane
/// re-dispatches at most this often — never on every ~500ms UI tick.
pub const ROSTER_THROTTLE: std::time::Duration = std::time::Duration::from_secs(15);

/// One session row under a [`RosterNode`] — reshaped straight from `who
/// --json`'s `nodes[].sessions[]` (`conduct/src/graph/who.rs::node_json`),
/// never re-derived: `label`/`state` are exactly the strings `who` already
/// computed (display-grammar label, canonical state vocabulary), so
/// `theme::state_glyph`/`state_style` — the SAME glyph mapping the SESSIONS
/// panel already paints — apply unchanged.
#[derive(Debug, Clone, Default)]
pub struct RosterSession {
    pub label: String,
    pub state: String,
}

/// One node (this box, or a registered peer) as `who --json` reports it —
/// parsed from the cached `Outcome`'s `data.nodes[]`. `presence` is one of
/// `who`'s own three node-level classes: `online` | `unreachable` |
/// `never-pulled` (`who.rs`'s module doc, "Presence model").
#[derive(Debug, Clone, Default)]
pub struct RosterNode {
    pub name: String,
    pub is_local: bool,
    pub presence: String,
    pub fetched_at: Option<String>,
    pub sessions: Vec<RosterSession>,
}

/// The ROSTER panel's cache: the last `who` [`Outcome`] plus when it landed.
/// `fetched_at: None` means "never fetched this run" — always stale, so the
/// first tick/visit fetches immediately. This is the ONLY state the panel
/// holds; there is no second copy of presence logic here, only a reshape of
/// what `who --json` already returned (crate `AGENTS.md`'s "frontend only").
#[derive(Debug, Clone, Default)]
pub struct RosterCache {
    pub outcome: Option<Outcome>,
    fetched_at: Option<Instant>,
}

/// The whole conductor state.
pub struct App {
    pub panel: Panel,
    pub help_open: bool,
    /// The open headless-log-tail overlay, or `None` (closed) — the same
    /// modal role [`help_open`](Self::help_open) plays, richer payload. Enter
    /// on a session whose record carries `log_path` opens this instead of
    /// dispatching `graph focus` ([`App::cue_session`]); lib.rs's
    /// `handle_key` swallows keys while it is `Some` the same way it does for
    /// the help overlay.
    pub tail: Option<LogTail>,
    /// Selected node in the DAG (Graph) panel (indexes the preorder node list
    /// [`crate::graphview::node_order`] the layout walks).
    pub graph_sel: usize,
    /// Selected row in the SESSIONS panel (indexes [`App::dag_rows`]).
    pub dag_sel: usize,
    /// Selected row in the PROJECTS panel.
    pub proj_sel: usize,
    /// Live data from the stage tree.
    pub projects: Vec<graph::Project>,
    pub sessions: Vec<SessionRecord>,
    pub hooks: Vec<graph::HookRecord>,
    /// The audit tail (newest last), capped to [`LOG_CAP`].
    pub log: Vec<LogLine>,
    pub palette: Palette,
    /// The last dispatched action's outcome — drives the status line.
    pub last_outcome: Option<Outcome>,
    /// Any active inline prompt.
    pub input: Option<Input>,
    /// Group names currently folded shut in the SESSIONS panel.
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
    /// The ROSTER panel's cache — last `who` fetch + when.
    pub roster: RosterCache,
    /// `Some` while a background `who` dispatch is in flight — set by
    /// [`App::spawn_roster_fetch`], drained (never blocked on) by
    /// [`App::drain_roster`]. See the module doc's "Roster: throttled,
    /// backgrounded dispatch" for why this exists at all.
    roster_rx: Option<mpsc::Receiver<Outcome>>,
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
            panel: Panel::Graph,
            help_open: false,
            tail: None,
            graph_sel: 0,
            dag_sel: 0,
            proj_sel: 0,
            projects: Vec::new(),
            sessions: Vec::new(),
            hooks: Vec::new(),
            log: Vec::new(),
            palette: Palette::default(),
            last_outcome: None,
            input: None,
            folded: HashSet::new(),
            fresh: BTreeMap::new(),
            known: HashSet::new(),
            initialized: false,
            mtimes: StageMtimes::default(),
            dispatch_fn: no_dispatch,
            roster: RosterCache::default(),
            roster_rx: None,
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

    fn stage() -> PathBuf {
        stage_dir()
    }
    fn audit_path() -> PathBuf {
        aoide_protocol::default_audit_log()
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
        self.palette = load_palette(&stage_notes_path(&dir));
        self.reload_log();

        self.mtimes = StageMtimes {
            sessions: Self::mtime(&dir.join("sessions.json")),
            hooks: Self::mtime(&dir.join("hooks.json")),
            projects: Self::mtime(&dir.join("projects.json")),
            notes: Self::mtime(&stage_notes_path(&dir)),
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

    /// Re-read the audit log tail (last [`LOG_CAP`] JSONL records).
    fn reload_log(&mut self) {
        let path = Self::audit_path();
        let Ok(content) = std::fs::read_to_string(&path) else {
            self.log.clear();
            return;
        };
        let mut lines: Vec<LogLine> = Vec::new();
        for raw in content.lines() {
            if raw.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                let field = |k: &str| -> String {
                    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
                };
                lines.push(LogLine {
                    ts: v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
                    door: field("door"),
                    class: field("class"),
                    command: field("command"),
                    status: field("status"),
                    message: field("message"),
                });
            }
        }
        if lines.len() > LOG_CAP {
            lines.drain(0..lines.len() - LOG_CAP);
        }
        self.log = lines;
    }

    /// A tick: reload any stage file / the audit log whose mtime advanced, age
    /// the fresh marks, and note any newly-arrived sessions. Returns `true`
    /// when anything changed (so the loop repaints).
    pub fn poll_refresh(&mut self) -> bool {
        let dir = Self::stage();
        let mut changed = false;

        let cur = StageMtimes {
            sessions: Self::mtime(&dir.join("sessions.json")),
            hooks: Self::mtime(&dir.join("hooks.json")),
            projects: Self::mtime(&dir.join("projects.json")),
            notes: Self::mtime(&stage_notes_path(&dir)),
            audit: Self::mtime(&Self::audit_path()),
        };

        if cur.projects != self.mtimes.projects {
            let p: ProjectsFile = Self::load_json(&dir.join("projects.json"));
            self.projects = p.projects;
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
            self.palette = load_palette(&stage_notes_path(&dir));
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

        // ROSTER: independent of the stage-mtime watch above — `who` is live
        // network state, not a stage file. Deliberately outside the
        // `if changed` block: draining/spawning a roster fetch must run every
        // tick regardless of whether anything else changed.
        if self.poll_roster() {
            changed = true;
        }

        changed
    }

    // ── ROSTER: throttled, backgrounded `who` dispatch (P-C4) ───────────────
    //
    // `who` performs a live network probe of every registered peer on EVERY
    // invocation (`conduct/src/graph/who.rs`'s module doc) — up to ~2s per
    // peer, run in parallel inside `who` itself but still ~2s wall-clock in
    // the worst case. Calling it through `App::dispatch` the way every other
    // action does would block the ~500ms tick loop for that long, so this
    // dispatch runs on its OWN `std::thread` (the exact pattern `who`'s own
    // `probe_peers` already uses one layer down) and reports back over an
    // `mpsc` channel that the tick loop only ever polls non-blockingly. This
    // is the ONE dispatch site in the crate that does not go through
    // `App::dispatch` — `who` never mutates anything, so there is no stage
    // write to `reload_all()` after, and the audit record still happens
    // (the dispatched `Invocation` still carries `Door::Cli`).

    /// Is the cached roster stale enough to re-fetch? `None` (never fetched)
    /// is always stale.
    fn roster_stale(&self) -> bool {
        match self.roster.fetched_at {
            None => true,
            Some(t) => t.elapsed() >= ROSTER_THROTTLE,
        }
    }

    /// Non-blocking: pick up a finished background `who` dispatch, if any.
    /// A fetch still running just leaves `roster_rx` in place for the next
    /// poll. Returns `true` when the cache changed (so the tick loop knows to
    /// repaint).
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

    /// Spawn the `who` dispatch on a background thread. A no-op while a
    /// fetch is already in flight — callers (the tick, a panel switch, the
    /// manual refresh key) never need to check that themselves.
    fn spawn_roster_fetch(&mut self) {
        if self.roster_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let dispatch_fn = self.dispatch_fn;
        std::thread::spawn(move || {
            let inv = Invocation {
                path: vec!["who".to_string()],
                args: Vec::new(),
                flags: BTreeMap::from([("json".to_string(), "true".to_string())]),
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
        if self.panel == Panel::Roster && self.roster_stale() {
            self.spawn_roster_fetch();
            changed = true; // a fresh "probing…" status is itself a repaint
        }
        changed
    }

    /// The ROSTER panel's rows, parsed from the cached `who` [`Outcome`]
    /// (never re-derived — the crate's one rule). Malformed/absent data
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

    /// A one-line fetch status for the pane header: probing, freshly
    /// fetched, never fetched yet, or — when `who` itself came back
    /// non-`Ok` — that error, in the same `[tag] command: message` shape
    /// [`App::status_message`] uses for the global status line (house
    /// style; P-C4 review nit). Without this branch a failed fetch would
    /// render as a bare "fetched Ns ago" over an empty roster, silently
    /// indistinguishable from "this box and every peer really have zero
    /// sessions."
    pub fn roster_status(&self) -> String {
        let probing = self.roster_rx.is_some();
        if let Some(o) = self.roster.outcome.as_ref().filter(|o| o.status != Status::Ok) {
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

    // ── The DAG row model (one truth for render + keys) ─────────────────────

    /// The merged sessions in the same deterministic order the DAG tree walks.
    pub fn merged(&self) -> Vec<SessionRecord> {
        graph::merged_sessions(&self.sessions, &self.hooks)
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

        let ids: HashSet<&str> = merged.iter().map(|s| s.session_id.as_str()).collect();
        let mut children: BTreeMap<&str, Vec<&SessionRecord>> = BTreeMap::new();
        let mut roots: Vec<&SessionRecord> = Vec::new();
        for s in &merged {
            match s.parent_session_id.as_deref().filter(|p| ids.contains(p)) {
                Some(p) => children.entry(p).or_default().push(s),
                None => roots.push(s),
            }
        }

        let mut per_project: Vec<Vec<&SessionRecord>> = vec![Vec::new(); projects.len()];
        let mut loose: Vec<&SessionRecord> = Vec::new();
        for r in &roots {
            match graph::anchor_for(&r.cwd, &projects) {
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
    }

    // ── Panel switching ─────────────────────────────────────────────────────

    /// Switch panels. Landing on ROSTER with a stale (or never-fetched)
    /// cache fires one immediate background fetch rather than waiting for
    /// the next ~500ms tick — the pane should not open to a blank "not yet
    /// fetched" that then sits idle for up to 15s.
    pub fn select_panel(&mut self, p: Panel) {
        self.panel = p;
        if p == Panel::Roster && self.roster_stale() {
            self.spawn_roster_fetch();
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
        self.input.is_some()
    }

    // ── The single dispatch seam (audit for free) ───────────────────────────

    /// Run a command through the ONE dispatcher with `Door::Cli`, store the
    /// outcome for the status line, and refresh live state (an action likely
    /// wrote a stage file + an audit line). This is the ONLY way the conductor
    /// mutates anything — and it fires on the keypress itself, not on the next
    /// tick, so a cue (Enter → `graph focus` → hyprctl) lands instantly.
    pub fn dispatch(&mut self, path: &[&str], args: &[String]) {
        let inv = Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.to_vec(),
            flags: BTreeMap::new(),
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
    /// UNCHANGED: `graph focus` dispatches exactly as before, including the
    /// no-window-address status error when neither is set.
    fn cue_session(&mut self, rec: &SessionRecord) {
        if rec.log_path.is_some() {
            self.open_tail(rec);
        } else {
            let id = rec.session_id.clone();
            self.dispatch(&["graph", "focus"], &[id]);
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
        if self.input.is_some() {
            self.handle_input_key(key);
            return;
        }
        match self.panel {
            Panel::Graph => self.handle_graph_key(key),
            Panel::Sessions => self.handle_dag_key(key),
            Panel::Projects => self.handle_projects_key(key),
            Panel::Roster => self.handle_roster_key(key),
            Panel::Log | Panel::Status => {} // read-only panels
        }
    }

    /// Keys for the ROSTER panel — read-only (messaging/presence plan
    /// P-C4): the one action is `r`, a manual refresh that FORCES a fetch
    /// regardless of the throttle window (unlike the tick-driven path,
    /// which only fires past [`ROSTER_THROTTLE`]). Still a no-op while a
    /// fetch is already in flight — [`App::spawn_roster_fetch`]'s own guard.
    fn handle_roster_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('r') {
            self.spawn_roster_fetch();
        }
    }

    /// Keys for the DAG (Graph) panel. Navigation walks the same preorder node
    /// list the layout draws, so `j`/`k` can never point at a node that isn't on
    /// screen. Enter cues the selected session's window (the same
    /// dispatch-backed `graph focus` the roster uses); `e` emits, `p` prunes —
    /// the two graph-wide verbs — so the visual view is not read-only.
    fn handle_graph_key(&mut self, key: KeyEvent) {
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
            KeyCode::Char('p') => self.dispatch(&["graph", "prune"], &[]),
            KeyCode::Char('e') => self.dispatch(&["graph", "emit"], &[]),
            _ => {}
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
                        self.dispatch(&["graph", "project", "remove"], &[name]);
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
            KeyCode::Char('p') => self.dispatch(&["graph", "prune"], &[]),
            KeyCode::Char('e') => self.dispatch(&["graph", "emit"], &[]),
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

    fn open_project_add(&mut self) {
        self.input = Some(Input {
            label: "project name".to_string(),
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
                    self.dispatch(&["graph", "project", "remove"], &[name]);
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
                        self.dispatch(&["graph", "project", "add"], &[name, path]);
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
            },
            _ => {
                self.input = Some(input);
            }
        }
    }
}

/// Is a session past its final barline? (the state `graph prune` sweeps and the
/// `[live/total]` badge excludes from `live`.)
///
/// Delegates to [`graph::canonical_state`] rather than sniffing substrings, so
/// the conductor and the door can never disagree about what "ended" means. This
/// matters since the `stop`/`stopped` vocabulary was split off `done`: a
/// `stopped` session finished its TURN and is still very much alive, so it must
/// stay in the `live` count.
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

/// Load `stage/livery.json`'s palette, mapping each hex to nearest ANSI-256.
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
        bg: pick("bg"),
        fg: pick("fg"),
        accent: pick("accent"),
        urgent: pick("urgent"),
    }
}

/// Parse `#rrggbb` (or `#rgb`) and map to the nearest ANSI-256 colour index.
pub fn hex_to_ansi256(hex: &str) -> Option<u8> {
    let h = hex.trim().trim_start_matches('#');
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
    Some(rgb_to_ansi256(r, g, b))
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
    use super::*;

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

    // ── Enter's branch: log tail vs. `graph focus` ──────────────────────────

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
            petname: None,
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
    /// the real stage dir otherwise, and on this machine that's the live
    /// `~/Aoide/song/stage`, not a fixture.
    fn with_isolated_stage<R>(f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap();
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
        app.panel = Panel::Sessions;
        app.dag_sel = 1; // row 0 is the `(unanchored)` group header

        app.handle_key(KeyEvent::from(KeyCode::Enter));

        let tail = app.tail.as_ref().expect("tail opened on headless Enter");
        assert_eq!(tail.session_id, "s1");
        assert_eq!(tail.lines, vec!["hello".to_string(), String::new()]);
        assert!(
            app.last_outcome.is_none(),
            "headless Enter must not dispatch graph focus"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_on_a_windowed_roster_row_still_dispatches_graph_focus() {
        with_isolated_stage(|| {
            // No `log_path` — only `window_address` (set by the `session`
            // fixture) — so this is the unchanged branch.
            let rec = session("s1", "/tmp", "running", None);
            let mut app = App::for_test(Vec::new(), vec![rec], Vec::new());
            app.panel = Panel::Sessions;
            app.dag_sel = 1;

            app.handle_key(KeyEvent::from(KeyCode::Enter));

            assert!(app.tail.is_none(), "a windowed session never opens a tail");
            assert!(
                app.last_outcome.is_some(),
                "windowed Enter still dispatches graph focus"
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

        let tail = app.tail.as_ref().expect("tail still opens on a missing file");
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

            assert!(!changed, "an unchanged tail mtime must not report a repaint");
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

    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static ROSTER_CALLS: AtomicUsize = AtomicUsize::new(0);
    /// Serialises the roster throttle tests against the shared
    /// `ROSTER_CALLS` counter (parallel `cargo test` threads within this
    /// crate would otherwise race on it) — a dedicated lock, since
    /// `ENV_LOCK` above guards a different piece of shared state.
    static ROSTER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn counting_who_dispatch(_: &Invocation) -> Outcome {
        ROSTER_CALLS.fetch_add(1, Ordering::SeqCst);
        Outcome::ok("who", "1 node(s), 0 session(s)")
            .with_data(json!({ "host": "h", "generatedAt": "t", "nodes": [] }))
    }

    #[test]
    fn roster_tick_with_a_fresh_cache_does_not_redispatch() {
        with_isolated_stage(|| {
            let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
            ROSTER_CALLS.store(0, Ordering::SeqCst);

            let mut app = App::for_test_with_dispatch(counting_who_dispatch);
            app.panel = Panel::Roster;
            app.roster.fetched_at = Some(Instant::now()); // just fetched — well inside the window

            app.poll_refresh();

            assert!(app.roster_rx.is_none(), "a fresh cache must not spawn a fetch");
            assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn roster_tick_with_a_stale_cache_while_visible_redispatches() {
        with_isolated_stage(|| {
            let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
            ROSTER_CALLS.store(0, Ordering::SeqCst);

            let mut app = App::for_test_with_dispatch(counting_who_dispatch);
            app.panel = Panel::Roster; // visible, `fetched_at: None` — always stale

            app.poll_refresh();

            let rx = app.roster_rx.take().expect("a stale, visible pane spawns a fetch");
            let outcome = rx
                .recv_timeout(Duration::from_secs(2))
                .expect("the background dispatch completes");
            assert_eq!(outcome.command, "who");
            assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn roster_tick_while_hidden_never_dispatches_even_when_stale() {
        with_isolated_stage(|| {
            let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
            ROSTER_CALLS.store(0, Ordering::SeqCst);

            let mut app = App::for_test_with_dispatch(counting_who_dispatch);
            app.panel = Panel::Sessions; // NOT the roster pane

            app.poll_refresh();

            assert!(app.roster_rx.is_none(), "a hidden pane must never spawn a fetch");
            assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn switching_into_roster_with_a_stale_cache_dispatches_immediately() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_who_dispatch);
        assert_eq!(app.panel, Panel::Graph, "starts elsewhere");

        app.select_panel(Panel::Roster); // no tick involved at all

        let rx = app
            .roster_rx
            .take()
            .expect("landing on a stale ROSTER must fetch immediately, not wait for a tick");
        rx.recv_timeout(Duration::from_secs(2)).expect("dispatch completes");
        assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn switching_into_roster_with_a_fresh_cache_does_not_redispatch() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_who_dispatch);
        app.roster.fetched_at = Some(Instant::now());

        app.select_panel(Panel::Roster);

        assert!(app.roster_rx.is_none(), "a fresh cache needs no immediate fetch");
        assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn manual_refresh_key_forces_a_dispatch_even_with_a_fresh_cache() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_who_dispatch);
        app.panel = Panel::Roster;
        app.roster.fetched_at = Some(Instant::now()); // fresh — a tick would skip it

        app.handle_key(KeyEvent::from(KeyCode::Char('r')));

        let rx = app
            .roster_rx
            .take()
            .expect("`r` forces a fetch regardless of the throttle window");
        rx.recv_timeout(Duration::from_secs(2)).expect("dispatch completes");
        assert_eq!(ROSTER_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_fetch_already_in_flight_is_never_duplicated() {
        let _rguard = ROSTER_TEST_LOCK.lock().unwrap();
        ROSTER_CALLS.store(0, Ordering::SeqCst);

        let mut app = App::for_test_with_dispatch(counting_who_dispatch);
        app.panel = Panel::Roster;
        app.spawn_roster_fetch();
        assert!(app.roster_rx.is_some());

        // A second manual refresh while the first is still in flight must be
        // a no-op — `spawn_roster_fetch`'s own guard, exercised directly
        // since a real fetch here completes in well under a millisecond and
        // could otherwise race the assertion.
        app.spawn_roster_fetch();

        let rx = app.roster_rx.take().unwrap();
        rx.recv_timeout(Duration::from_secs(2)).expect("dispatch completes");
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
        app.roster.outcome = Some(Outcome::ok("who", "2 node(s), 1 session(s)").with_data(data));
        app.roster.fetched_at = Some(Instant::now());

        let nodes = app.roster_nodes();
        assert_eq!(nodes.len(), 2, "local + one peer, in who's own order");
        assert!(nodes[0].is_local && nodes[0].name == "sakaki", "local box first");
        assert_eq!(nodes[0].sessions[0].label, "sakaki/root/s1");
        assert_eq!(nodes[0].sessions[0].state, "working");
        assert_eq!(nodes[1].name, "yomi-strix");
        assert_eq!(nodes[1].presence, "unreachable");
        assert_eq!(nodes[1].fetched_at.as_deref(), Some("2026-08-20T23:00:00Z"));

        assert!(app.roster_status().starts_with("fetched "), "{}", app.roster_status());
    }

    #[test]
    fn roster_status_surfaces_a_non_ok_outcome_instead_of_hiding_it() {
        let mut app = App::for_test(Vec::new(), Vec::new(), Vec::new());
        app.roster.outcome = Some(Outcome::error("who", "stage read failed: permission denied"));
        app.roster.fetched_at = Some(Instant::now());

        let status = app.roster_status();
        assert!(
            status.starts_with("[err] who: stage read failed"),
            "the error message surfaces in the pane, not a bare age: {status}"
        );
        assert!(
            app.roster_nodes().is_empty(),
            "an error Outcome carries no `data`, so no rows — the status line is the only signal"
        );
    }
}
