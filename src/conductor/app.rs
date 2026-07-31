//! The conductor's core: live state, selection, and the dispatch plumbing.
//!
//! [`App`] is pi's "core" — it holds the world (projects/sessions/hooks loaded
//! from the stage tree, the audit tail, the palette) and the interaction state
//! (which panel, which row, any inline input, the last dispatched
//! [`Outcome`](crate::output::Outcome)). It draws nothing; it hands panels the
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

use crate::daemon::Door;
use crate::dispatch::{self, Invocation};
use crate::graph::{self, HooksFile, ProjectsFile, SessionRecord, SessionsFile};
use crate::output::{Outcome, Status};
use crate::shellbridge::stage_dir;
use crossterm::event::{KeyCode, KeyEvent};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::time::SystemTime;

/// The five panels, in Tab / 1-5 order. `Graph` is the visual DAG (the new hero
/// view — nodes/edges laid out and drawn); `Sessions` is the collapsible roster
/// (the terminal-sessions view, keyed off [`App::dag_rows`]). The two are
/// deliberately distinct lenses on the same data: `Graph` shows the *shape* of
/// the DAG, `Sessions` the *state* of each terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Graph,
    Sessions,
    Projects,
    Log,
    Status,
}

impl Panel {
    pub const ALL: [Panel; 5] = [
        Panel::Graph,
        Panel::Sessions,
        Panel::Projects,
        Panel::Log,
        Panel::Status,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Panel::Graph => "DAG",
            Panel::Sessions => "SESSIONS",
            Panel::Projects => "PROJECTS",
            Panel::Log => "LOG",
            Panel::Status => "STATUS",
        }
    }
    pub fn index(self) -> usize {
        Panel::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// The palette pulled from `stage/drachma.json`, each hex mapped to nearest
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
#[derive(Debug, Clone, Default)]
struct StageMtimes {
    sessions: Option<SystemTime>,
    hooks: Option<SystemTime>,
    projects: Option<SystemTime>,
    notes: Option<SystemTime>,
    audit: Option<SystemTime>,
}

/// The whole conductor state.
pub struct App {
    pub panel: Panel,
    pub help_open: bool,
    /// Selected node in the DAG (Graph) panel (indexes the preorder node list
    /// [`crate::conductor::graphview::node_order`] the layout walks).
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
}

/// How many audit lines the LOG panel keeps in memory.
pub const LOG_CAP: usize = 500;

impl App {
    fn empty() -> Self {
        App {
            panel: Panel::Graph,
            help_open: false,
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

    /// Build the app from the stage tree (missing files → empty, tolerated).
    pub fn load() -> Self {
        let mut app = App::empty();
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
        crate::daemon::default_audit_log()
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
        self.palette = load_palette(&dir.join("drachma.json"));
        self.reload_log();

        self.mtimes = StageMtimes {
            sessions: Self::mtime(&dir.join("sessions.json")),
            hooks: Self::mtime(&dir.join("hooks.json")),
            projects: Self::mtime(&dir.join("projects.json")),
            notes: Self::mtime(&dir.join("drachma.json")),
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
            notes: Self::mtime(&dir.join("drachma.json")),
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
            self.palette = load_palette(&dir.join("drachma.json"));
            changed = true;
        }
        if cur.audit != self.mtimes.audit {
            self.reload_log();
            changed = true;
        }

        self.mtimes = cur;

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
        changed
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
        let n_nodes = crate::conductor::graphview::node_order(self).len();
        if self.graph_sel >= n_nodes.max(1) {
            self.graph_sel = n_nodes.saturating_sub(1);
        }
    }

    // ── Panel switching ─────────────────────────────────────────────────────

    pub fn select_panel(&mut self, p: Panel) {
        self.panel = p;
    }
    pub fn next_panel(&mut self) {
        let i = (self.panel.index() + 1) % Panel::ALL.len();
        self.panel = Panel::ALL[i];
    }
    pub fn prev_panel(&mut self) {
        let i = (self.panel.index() + Panel::ALL.len() - 1) % Panel::ALL.len();
        self.panel = Panel::ALL[i];
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
        let outcome = dispatch::dispatch(&inv);
        self.last_outcome = Some(outcome);
        // The action wrote to disk; pick it up immediately rather than waiting a
        // tick, so the panel reflects the change on the very next paint.
        self.reload_all();
    }

    /// The status-line message: the last outcome's message, or a ready hint.
    pub fn status_message(&self) -> String {
        match &self.last_outcome {
            Some(o) => {
                let tag = match o.status {
                    Status::Ok => "ok",
                    Status::Error => "err",
                    Status::Usage => "usage",
                    Status::NotImplemented => "n/i",
                };
                // Collapse the message to its first line for the one-row bar.
                let first = o.message.lines().next().unwrap_or("");
                format!("[{tag}] {}: {first}", o.command)
            }
            None => "ready".to_string(),
        }
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
            Panel::Log | Panel::Status => {} // read-only panels
        }
    }

    /// Keys for the DAG (Graph) panel. Navigation walks the same preorder node
    /// list the layout draws, so `j`/`k` can never point at a node that isn't on
    /// screen. Enter cues the selected session's window (the same
    /// dispatch-backed `graph focus` the roster uses); `e` emits, `p` prunes —
    /// the two graph-wide verbs — so the visual view is not read-only.
    fn handle_graph_key(&mut self, key: KeyEvent) {
        let nodes = crate::conductor::graphview::node_order(self);
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
                    if let Some(id) = &node.session_id {
                        self.dispatch(&["graph", "focus"], std::slice::from_ref(id));
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
            // Enter: on a session, cue it — dispatch `graph focus` right now
            // (jump latency is the whole multiplexer story; Hyprland windows
            // are our panes). On a group header, toggle the fold.
            KeyCode::Enter => match rows.get(self.dag_sel) {
                Some(DagRow::Session { rec, .. }) => {
                    let id = rec.session_id.clone();
                    self.dispatch(&["graph", "focus"], &[id]);
                }
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

// ── drachma.json palette → ANSI-256 ───────────────────────────────────────────

/// Load `stage/drachma.json`'s palette, mapping each hex to nearest ANSI-256.
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
}
