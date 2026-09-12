//! The DAG panel — a VISUAL, laid-out graph of the project/session DAG.
//!
//! Where the SESSION roster reads the DAG as an indented list (state at a
//! glance), this view draws its *shape*: a layered left-to-right graph, one
//! column per depth (projects in column 0, the sessions they anchor in column
//! 1, spawned children in column 2+), nodes wired with box-drawing edges.
//!
//! One rule holds, exactly as everywhere else in the conductor: this view NEVER
//! re-derives the graph. The node/edge structure comes verbatim from
//! [`aoide_conduct::graph::build_graph`] — the same pure function every
//! mutation's `restage_graph()` (and `graph prune`'s manual resync) writes to
//! `state/stage/graph.json` — so the picture on screen is the document on disk.
//! We parse that document into a forest (each session has at most one incoming
//! edge — spawned-by wins over anchors — so the layout is a tree walk), assign
//! `column = depth` and `row = preorder index`, and paint chips + connectors.
//!
//! Tags: read-only. The schema has no tag surface (see the module note in
//! [`crate::theme::session_tags`]); tags found on a session record's
//! round-tripped `extra.tags` are rendered as accent chips, never minted here.

use crate::app::App;
use crate::theme;
use aoide_conduct::graph;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::collections::{HashMap, HashSet};

/// Per-depth band width in cells. Wide enough to read as columns (distinct from
/// the roster's tight indentation) and to give edges a gutter to route through.
/// Widened 28->36 for the display grammar's `<host>/<role>/<petname>
/// (…<tail4>)` label (petnames plan P3) — `CHIP_MAX` (below) follows.
const COL_W: usize = 36;
/// Max chip width (label + state + tag chips), leaving a gutter for connectors.
const CHIP_MAX: usize = COL_W - 4;

/// What a node is — drives marker, colour, and whether Enter can cue it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Project,
    Session,
    /// The synthetic root gathering sessions anchored to no project (mirrors the
    /// `(unanchored)` group the Unicode tree render uses).
    Unanchored,
}

/// One laid-out node: identity, display bits, and its grid position.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    /// The bare session id (for the focus jump on Enter); `None` for anchors.
    pub session_id: Option<String>,
    pub state: Option<String>,
    pub tags: Vec<String>,
    /// The session's Claude model (agent or subagent's own), when known —
    /// straight off `graph.json`'s node `model` field. `None` for projects,
    /// the synthetic unanchored root, shells, and any session that hasn't
    /// produced an assistant turn yet.
    pub model: Option<String>,
    pub depth: usize,
    pub row: usize,
}

/// Node metadata carried from the parsed document into the DFS.
struct Meta {
    kind: NodeKind,
    label: String,
    session_id: Option<String>,
    state: Option<String>,
    tags: Vec<String>,
    model: Option<String>,
}

/// The parsed + laid-out forest: nodes in preorder (the selection order) and the
/// child adjacency needed to draw connectors.
pub struct Model {
    pub nodes: Vec<Node>,
    /// node id → child node ids, in draw order.
    children: HashMap<String, Vec<String>>,
}

/// The nodes in preorder — the single source of truth for both selection (the
/// app's `graph_sel` indexes this) and the drawn layout, so the cursor can never
/// land on a node the screen isn't showing.
pub fn node_order(app: &App) -> Vec<Node> {
    build_model(app).nodes
}

/// Build the layout model from the canonical graph document.
pub fn build_model(app: &App) -> Model {
    let doc = graph::build_graph(&app.projects, &app.sessions, &app.hooks);
    let merged = app.merged();
    let tag_by_id: HashMap<String, Vec<String>> = merged
        .iter()
        .map(|s| (s.session_id.clone(), theme::session_tags(s)))
        .collect();

    let empty = Vec::new();
    let nodes_j = doc["nodes"].as_array().unwrap_or(&empty);
    let edges_j = doc["edges"].as_array().unwrap_or(&empty);

    // Which session node ids are the `to` end of a "spawned" edge — exactly
    // `resolved_parent(...).is_some()` in `conduct`'s own terms (`build_graph`
    // emits "spawned" only for a session with a resolved parent, "anchors"
    // only for a parentless one) — so this is the display grammar's `role`
    // (petnames plan P3) read straight off the edge vocabulary already on the
    // document, no second parent walk needed.
    let spawned_targets: HashSet<&str> = edges_j
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some("spawned"))
        .filter_map(|e| e.get("to").and_then(|v| v.as_str()))
        .collect();
    // Resolved ONCE for this whole build — every session label in the panel
    // shares the same host (mirrors the `graph view` tree render's rule).
    let host = aoide_storage::display::local_host_name();

    // Metadata per node id, and the project ids in doc order (sorted by name).
    let mut meta: HashMap<String, Meta> = HashMap::new();
    let mut project_ids: Vec<String> = Vec::new();
    for n in nodes_j {
        let id = n
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        match n.get("kind").and_then(|v| v.as_str()) {
            Some("project") => {
                project_ids.push(id.clone());
                let name = str_field(n, "name");
                meta.insert(
                    id,
                    Meta {
                        kind: NodeKind::Project,
                        label: name,
                        session_id: None,
                        state: None,
                        tags: Vec::new(),
                        model: None,
                    },
                );
            }
            Some("session") => {
                let sid = id.strip_prefix("session:").unwrap_or(&id).to_string();
                let state = str_field(n, "state");
                let tags = tag_by_id.get(&sid).cloned().unwrap_or_default();
                // `model` rides on the node only when the record has one (agent
                // or subagent alike) — absent for shells, so no filter on `role`
                // is needed here.
                let model = n.get("model").and_then(|v| v.as_str()).map(str::to_string);
                // The display grammar (petnames plan P3): `<host>/<role>/
                // <petname> (…<tail4>)`, degrading to `<host>/<role>/
                // <sessionId>` for a legacy/petname-less node. `session_id`
                // (below) stays the bare canonical id — this is the LABEL
                // only, never what Enter's focus jump reads.
                let role = if spawned_targets.contains(id.as_str()) { "child" } else { "root" };
                let petname = n.get("petname").and_then(|v| v.as_str()).map(str::to_string);
                let rec = aoide_storage::records::SessionRecord {
                    session_id: sid.clone(),
                    petname,
                    ..Default::default()
                };
                let label = aoide_storage::display::session_label(&rec, &host, role);
                meta.insert(
                    id.clone(),
                    Meta {
                        kind: NodeKind::Session,
                        label,
                        session_id: Some(sid),
                        state: Some(state),
                        tags,
                        model,
                    },
                );
            }
            _ => {}
        }
    }

    // Adjacency + the set of nodes that are somebody's child.
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut incoming: HashSet<String> = HashSet::new();
    for e in edges_j {
        let from = e.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let to = e.get("to").and_then(|v| v.as_str()).unwrap_or("");
        if from.is_empty() || to.is_empty() {
            continue;
        }
        children
            .entry(from.to_string())
            .or_default()
            .push(to.to_string());
        incoming.insert(to.to_string());
    }

    // Roots: projects first, then a synthetic `(unanchored)` root gathering
    // session nodes with no incoming edge.
    let mut roots: Vec<String> = project_ids;
    let mut unanchored: Vec<String> = Vec::new();
    for n in nodes_j {
        let id = n.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let is_session = n.get("kind").and_then(|v| v.as_str()) == Some("session");
        if is_session && !incoming.contains(id) {
            unanchored.push(id.to_string());
        }
    }
    if !unanchored.is_empty() {
        let uid = "unanchored".to_string();
        meta.insert(
            uid.clone(),
            Meta {
                kind: NodeKind::Unanchored,
                label: "(unanchored)".to_string(),
                session_id: None,
                state: None,
                tags: Vec::new(),
                model: None,
            },
        );
        children.insert(uid.clone(), unanchored);
        roots.push(uid);
    }

    // Preorder DFS: row = push order, depth = distance from the root.
    let mut nodes: Vec<Node> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    for r in &roots {
        walk(r, 0, &meta, &children, &mut visited, &mut nodes);
    }

    Model { nodes, children }
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn walk(
    id: &str,
    depth: usize,
    meta: &HashMap<String, Meta>,
    children: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    out: &mut Vec<Node>,
) {
    if !visited.insert(id.to_string()) {
        return; // cycle guard (a hand-edited stage file could carry one)
    }
    if let Some(m) = meta.get(id) {
        out.push(Node {
            id: id.to_string(),
            kind: m.kind,
            label: m.label.clone(),
            session_id: m.session_id.clone(),
            state: m.state.clone(),
            tags: m.tags.clone(),
            model: m.model.clone(),
            depth,
            row: out.len(),
        });
    }
    if let Some(kids) = children.get(id) {
        for k in kids {
            walk(k, depth + 1, meta, children, visited, out);
        }
    }
}

// ── Rendering: model → cell grid → ratatui Lines ────────────────────────────

/// One painted cell: a symbol and its style.
#[derive(Clone)]
struct GCell {
    ch: char,
    style: Style,
}

impl Default for GCell {
    fn default() -> Self {
        GCell {
            ch: ' ',
            style: Style::default(),
        }
    }
}

/// Draw the DAG panel into `area`, highlighting the node at `sel`.
pub fn render(f: &mut Frame, area: Rect, app: &App, sel: usize) {
    let model = build_model(app);
    if model.nodes.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from("  no graph yet — no projects registered, no sessions live.")
                .style(theme::dim()),
            Line::from(""),
            Line::from("  Seed a stage tree:  pkgs/aoide/tests/fixtures/seed.sh $AOIDE_STAGE_DIR")
                .style(theme::dim()),
            Line::from("  Then re-open the conductor — every stage mutation restages the graph.")
                .style(theme::dim()),
        ];
        f.render_widget(Paragraph::new(lines), area);
        return;
    }

    let grid = lay_out(&model, sel, &app.palette);
    let lines = grid_to_lines(&grid);

    // Scroll to keep the selected node in view (vertical and horizontal).
    let vh = area.height as usize;
    let vw = area.width as usize;
    let (sy, sx) = model
        .nodes
        .get(sel)
        .map(|n| {
            let y = if n.row >= vh { n.row - vh + 1 } else { 0 };
            let node_x = n.depth * COL_W;
            let x = if node_x + CHIP_MAX > vw {
                (node_x + CHIP_MAX).saturating_sub(vw)
            } else {
                0
            };
            (y as u16, x as u16)
        })
        .unwrap_or((0, 0));

    f.render_widget(Paragraph::new(lines).scroll((sy, sx)), area);
}

/// Compose the styled cell grid: connectors first (box-drawing edges routed in
/// the gutter left of each child column), then node chips on top.
fn lay_out(model: &Model, sel: usize, pal: &crate::app::Palette) -> Vec<Vec<GCell>> {
    // Pre-compose each node's chip cells so we know its on-screen width.
    let chips: Vec<Vec<GCell>> = model
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| chip_cells(n, i == sel, pal))
        .collect();

    let height = model.nodes.len();
    let width = model
        .nodes
        .iter()
        .zip(&chips)
        .map(|(n, c)| n.depth * COL_W + c.len() + 1)
        .max()
        .unwrap_or(1)
        .max(1);

    let mut grid: Vec<Vec<GCell>> = vec![vec![GCell::default(); width]; height];
    let conn = theme::dim();

    // Row + depth lookup by node id (for connector endpoints).
    let pos: HashMap<&str, (usize, usize, usize)> = model
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.as_str(), (n.row, n.depth, chips[i].len())))
        .collect();

    // Connectors: for every parent with children, a bus in the gutter.
    for n in &model.nodes {
        let Some(kids) = model.children.get(&n.id) else {
            continue;
        };
        let kids: Vec<&str> = kids
            .iter()
            .filter(|k| pos.contains_key(k.as_str()))
            .map(String::as_str)
            .collect();
        if kids.is_empty() {
            continue;
        }
        let (prow, pdepth, plen) = pos[n.id.as_str()];
        let ccol = (pdepth + 1) * COL_W;
        let jx = ccol.saturating_sub(2);
        let p_right = pdepth * COL_W + plen;
        let last_row = kids.iter().map(|k| pos[k].0).max().unwrap_or(prow);

        // Horizontal from the parent chip to the bus, then the corner.
        for x in p_right..jx {
            set(&mut grid, x, prow, '─', conn);
        }
        set(&mut grid, jx, prow, '┐', conn);
        // The vertical bus down to the last child.
        for y in (prow + 1)..=last_row {
            set(&mut grid, jx, y, '│', conn);
        }
        // A tee/elbow into each child, then a lead-in to the chip.
        for k in &kids {
            let (crow, _, _) = pos[*k];
            let corner = if crow == last_row { '└' } else { '├' };
            set(&mut grid, jx, crow, corner, conn);
            for x in (jx + 1)..ccol {
                set(&mut grid, x, crow, '─', conn);
            }
        }
    }

    // Chips on top.
    for (i, n) in model.nodes.iter().enumerate() {
        let x0 = n.depth * COL_W;
        for (dx, cell) in chips[i].iter().enumerate() {
            set_cell(&mut grid, x0 + dx, n.row, cell.clone());
        }
    }

    grid
}

fn push_cells(buf: &mut Vec<GCell>, s: &str, style: Style) {
    for ch in s.chars() {
        buf.push(GCell { ch, style });
    }
}

/// Build a node's chip as styled cells: marker, label, a short state word, and
/// read-only tag chips — fit to [`CHIP_MAX`].
///
/// Send-back fix (P3 review): post-P2 every session carries a minted
/// petname, so the display-grammar label (`<host>/<role>/<petname>
/// (…<tail4>)`) routinely runs 30+ chars on its own — wider than the whole
/// old bare-id chip. The SUFFIX (state, model, tag chips) is sized first and
/// the label gets whatever budget is left, never the other way — state must
/// survive on every row, the label is what yields. [`fit_label`] degrades
/// the label gracefully into that budget rather than being blind-truncated
/// by the final backstop below.
fn chip_cells(n: &Node, selected: bool, pal: &crate::app::Palette) -> Vec<GCell> {
    let accent = theme::accent(pal).unwrap_or(Color::Cyan);
    let (marker, marker_style, label_style) = match n.kind {
        NodeKind::Project | NodeKind::Unanchored => (
            '◆',
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        ),
        NodeKind::Session => {
            let st = theme::state_style(n.state.as_deref().unwrap_or(""), pal);
            ('●', st, Style::default())
        }
    };

    // The suffix — state, then model, then tag chips — in the SAME order
    // and styling as always; only the sizing is new (computed before the
    // label, so the label knows what's left).
    let mut suffix: Vec<GCell> = Vec::new();
    if let Some(state) = &n.state {
        if !state.is_empty() {
            push_cells(&mut suffix, &format!(" {state}"), theme::dim());
        }
    }
    // The running Claude model, when known — same `⟐` glyph the gadget dock
    // uses for a subagent's model text, rendered uniformly on agent AND
    // subagent chips alike; absent for projects, unanchored, and shells.
    if let Some(model) = &n.model {
        if !model.is_empty() {
            push_cells(
                &mut suffix,
                &format!(" ⟐{model}"),
                Style::default().fg(accent).add_modifier(Modifier::DIM),
            );
        }
    }
    for t in &n.tags {
        push_cells(
            &mut suffix,
            &format!(" ⟨{t}⟩"),
            Style::default().fg(accent).add_modifier(Modifier::DIM),
        );
    }

    // marker + space = 2 fixed cells; the label gets whatever's left after
    // that and the suffix above.
    let label_budget = CHIP_MAX.saturating_sub(2).saturating_sub(suffix.len());
    let label = fit_label(&n.label, label_budget);

    let mut cells: Vec<GCell> = Vec::new();
    push_cells(&mut cells, &marker.to_string(), marker_style);
    push_cells(&mut cells, " ", label_style);
    push_cells(&mut cells, &label, label_style);
    cells.extend(suffix);

    // Backstop only now — sizing above already fits the budget in the
    // overwhelming common case; this only bites the pathological one where
    // the suffix ALONE exceeds CHIP_MAX-2 (label_budget saturated to 0),
    // and even then it cuts from the END (tags, then model), never from the
    // front where marker+state live.
    cells.truncate(CHIP_MAX);
    if selected {
        for c in &mut cells {
            c.style = c.style.add_modifier(Modifier::REVERSED);
        }
    }
    cells
}

/// Fit a display-grammar label (`<host>/<role>/<petname> (…<tail4>)`, or the
/// legacy `<host>/<role>/<sessionId>` with no tail bracket) into `budget`
/// characters. The tail4 grep-back handle is the LAST thing to die — it is
/// the only link back to the canonical id once host/role/petname are gone:
///
/// 1. Fits as-is → returned unchanged.
/// 2. `<host>/<role>/` and the ` (…<tail4>)` bracket both preserved; the
///    petname/id between them middle-elided (`hardy-…rbor`) to make room.
/// 3. Host dropped: `<role>/<petname-truncated>… (…<tail4>)`.
/// 4. Role dropped too: `<petname-prefix> (…<tail4>)`.
/// 5. No room for any petname/id at all — just the tail bracket, itself
///    front-truncated if `budget` is smaller than the bracket.
/// 6. No tail to preserve (a legacy label, or `budget` too small for even
///    a lone bracket char) — a blunt front-truncate of the raw label.
fn fit_label(label: &str, budget: usize) -> String {
    let len = label.chars().count();
    if len <= budget {
        return label.to_string();
    }
    if budget == 0 {
        return String::new();
    }

    let (head, tail) = match label.rfind(" (…") {
        Some(i) => (&label[..i], &label[i..]),
        None => (label, ""),
    };
    let tail_len = tail.chars().count();
    let mut segs = head.splitn(3, '/');
    let (host, role, name) = match (segs.next(), segs.next(), segs.next()) {
        (Some(h), Some(r), Some(nm)) => (h, r, nm),
        _ => ("", "", head),
    };

    // Rung 1: host/role/ + middle-elided name + tail.
    if !host.is_empty() && !role.is_empty() {
        let fixed = host.chars().count() + 1 + role.chars().count() + 1 + tail_len;
        if fixed < budget {
            let name_budget = budget - fixed;
            return format!("{host}/{role}/{}{tail}", elide_middle(name, name_budget));
        }
    }
    // Rung 2: role/ + end-truncated name + tail (host dropped).
    if !role.is_empty() {
        let fixed = role.chars().count() + 1 + tail_len;
        if fixed < budget {
            let name_budget = budget - fixed;
            return format!("{role}/{}{tail}", truncate_end(name, name_budget));
        }
    }
    // Rung 3: name-prefix + tail (host AND role dropped).
    if tail_len < budget {
        let name_budget = budget - tail_len;
        let prefix: String = name.chars().take(name_budget).collect();
        return format!("{prefix}{tail}");
    }
    // Rung 4: the tail bracket alone — nothing else survives — itself
    // front-truncated if even the bracket doesn't fit.
    if tail_len > 0 {
        return tail.chars().take(budget).collect();
    }
    // No tail at all (legacy label) — blunt front-truncate, the true last resort.
    label.chars().take(budget).collect()
}

/// Middle-elide `s` into `budget` chars: `hardy-harbor` at budget 7 becomes
/// `har…bor` — keeps BOTH ends visible (the common case has plenty of room
/// for this; see [`fit_label`] rung 1).
fn elide_middle(s: &str, budget: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= budget {
        return s.to_string();
    }
    if budget == 0 {
        return String::new();
    }
    if budget == 1 {
        return "…".to_string();
    }
    let keep = budget - 1; // reserve 1 cell for the ellipsis itself.
    let head_n = keep - keep / 2;
    let tail_n = keep / 2;
    let head: String = chars[..head_n].iter().collect();
    let tail: String = chars[chars.len() - tail_n..].iter().collect();
    format!("{head}…{tail}")
}

/// End-truncate `s` into `budget` chars with a trailing ellipsis (used once
/// the host is already gone — see [`fit_label`] rung 2 — where showing only
/// the FRONT of the petname/id reads more naturally than a middle elision).
fn truncate_end(s: &str, budget: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= budget {
        return s.to_string();
    }
    if budget == 0 {
        return String::new();
    }
    if budget == 1 {
        return "…".to_string();
    }
    let head: String = chars[..budget - 1].iter().collect();
    format!("{head}…")
}

fn set(grid: &mut [Vec<GCell>], x: usize, y: usize, ch: char, style: Style) {
    set_cell(grid, x, y, GCell { ch, style });
}

fn set_cell(grid: &mut [Vec<GCell>], x: usize, y: usize, cell: GCell) {
    if let Some(row) = grid.get_mut(y) {
        if let Some(slot) = row.get_mut(x) {
            *slot = cell;
        }
    }
}

/// Coalesce each grid row's runs of same-style cells into ratatui spans.
fn grid_to_lines(grid: &[Vec<GCell>]) -> Vec<Line<'static>> {
    grid.iter()
        .map(|row| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut buf = String::new();
            let mut cur: Option<Style> = None;
            for cell in row {
                match cur {
                    Some(s) if s == cell.style => buf.push(cell.ch),
                    _ => {
                        if let Some(s) = cur {
                            spans.push(Span::styled(std::mem::take(&mut buf), s));
                        }
                        buf.push(cell.ch);
                        cur = Some(cell.style);
                    }
                }
            }
            if let Some(s) = cur {
                spans.push(Span::styled(buf, s));
            }
            Line::from(spans)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use aoide_conduct::graph::{Project, SessionRecord};
    use serde_json::Map;

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
            origin: None,
            seal: None,
            sealed_issued_at: None,
            restore: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn model_lays_out_projects_then_spawned_children_in_columns() {
        let app = App::for_test(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![
                session("root", "/home/k/Aoide", "running", None),
                session("kid", "/home/k/Aoide", "idle", Some("root")),
            ],
            Vec::new(),
        );
        let m = build_model(&app);
        // project (depth 0) → root session (depth 1) → spawned kid (depth 2).
        // Session labels now render the display grammar (petnames plan P3),
        // not the bare id — so lookups here go through `session_id`, the
        // field that stays the bare canonical id (Enter's focus jump
        // unaffected by the label change).
        let proj = m.nodes.iter().find(|n| n.label == "aoide").unwrap();
        let root = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("root")).unwrap();
        let kid = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("kid")).unwrap();
        assert_eq!(proj.depth, 0);
        assert_eq!(root.depth, 1);
        assert_eq!(kid.depth, 2);
        // preorder rows are strictly increasing down the chain.
        assert!(proj.row < root.row && root.row < kid.row);
        assert_eq!(kid.session_id.as_deref(), Some("kid"));
    }

    #[test]
    fn unanchored_sessions_gather_under_a_synthetic_root() {
        let app = App::for_test(
            vec![],
            vec![session("loose", "/tmp/x", "idle", None)],
            Vec::new(),
        );
        let m = build_model(&app);
        assert!(m.nodes.iter().any(|n| n.kind == NodeKind::Unanchored));
        assert!(m.nodes.iter().any(|n| n.session_id.as_deref() == Some("loose")));
    }

    #[test]
    fn model_flows_from_the_graph_document_onto_agent_and_subagent_nodes() {
        let mut root = session("root", "/home/k/Aoide", "running", None);
        root.model = Some("claude-sonnet-5".into());
        let mut sub = session("kid", "/home/k/Aoide", "working", Some("root"));
        sub.kind = Some("subagent".into());
        sub.model = Some("claude-fable-5".into());
        // A shell has no model — the fixture leaves it `None`, mirroring what
        // `extract_model` actually produces for a conducted terminal.
        let shell = session("term", "/home/k/Aoide", "idle", None);
        let app = App::for_test(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![root, sub, shell],
            Vec::new(),
        );
        let m = build_model(&app);
        let root_n = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("root")).unwrap();
        let kid_n = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("kid")).unwrap();
        let term_n = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("term")).unwrap();
        assert_eq!(root_n.model.as_deref(), Some("claude-sonnet-5"));
        assert_eq!(kid_n.model.as_deref(), Some("claude-fable-5"));
        assert_eq!(term_n.model, None);
    }

    #[test]
    fn tags_flow_from_extra_read_only() {
        let mut s = session("t", "/home/k/Aoide", "running", None);
        s.extra
            .insert("tags".into(), serde_json::json!(["backend", "wip"]));
        let app = App::for_test(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![s],
            Vec::new(),
        );
        let m = build_model(&app);
        let node = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("t")).unwrap();
        assert_eq!(node.tags, vec!["backend".to_string(), "wip".to_string()]);
    }

    #[test]
    fn session_label_renders_the_display_grammar_while_session_id_stays_bare() {
        // Petnames plan P3: `Meta.label` (and so `Node.label`) is the
        // grammar string — `<host>/<role>/<petname> (…<tail4>)`, legacy
        // degrading to `<host>/<role>/<sessionId>` — but `Node::session_id`
        // stays the bare canonical id no matter what, since Enter/`graph
        // focus` reads that field, never the label.
        let mut root = session("root", "/home/k/Aoide", "running", None);
        root.petname = Some("brave-otter".into());
        let mut kid = session("kid", "/home/k/Aoide", "working", Some("root"));
        kid.petname = Some("calm-thorn".into());
        // Legacy: no petname minted.
        let legacy = session("legacy-full-id", "/home/k/Aoide", "idle", None);
        let app = App::for_test(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![root, kid, legacy],
            Vec::new(),
        );
        let m = build_model(&app);
        let host = aoide_storage::display::local_host_name();

        let root_n = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("root")).unwrap();
        assert_eq!(root_n.label, format!("{host}/root/brave-otter (…root)"));
        assert_eq!(root_n.session_id.as_deref(), Some("root"), "session_id stays the bare canonical id");

        let kid_n = m.nodes.iter().find(|n| n.session_id.as_deref() == Some("kid")).unwrap();
        assert_eq!(kid_n.label, format!("{host}/child/calm-thorn (…kid)"));
        assert_eq!(kid_n.session_id.as_deref(), Some("kid"));

        let legacy_n = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("legacy-full-id"))
            .unwrap();
        assert_eq!(
            legacy_n.label,
            format!("{host}/root/legacy-full-id"),
            "legacy (petname-less) node degrades to host/role/full-id"
        );
        assert_eq!(legacy_n.session_id.as_deref(), Some("legacy-full-id"));
    }

    #[test]
    fn chip_cells_keeps_state_and_the_tail_visible_on_a_realistic_petnamed_row() {
        // Send-back regression (P3 review): post-P2 every session carries a
        // minted petname, so a REAL row's label is `<host>/<role>/<petname>
        // (…<tail4>)` — routinely 30+ chars on a real box, wider than the
        // whole pre-P3 chip. This fixture deliberately does NOT shrink the
        // host, petname, or session id (unlike the layout tests above) —
        // it drives the actual overflow path `fit_label` exists for, not a
        // fixture engineered to dodge it.
        let mut root = session(
            "sess-realistically-long-canonical-id-0001",
            "/home/k/Aoide",
            "working",
            None,
        );
        root.petname = Some("hardy-harbor".into()); // wordlist-shaped (petname.rs).
        root.extra.insert("tags".into(), serde_json::json!(["backend"]));
        let app = App::for_test(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
                ..Default::default()
            }],
            vec![root],
            Vec::new(),
        );
        let m = build_model(&app);
        let node = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("sess-realistically-long-canonical-id-0001"))
            .unwrap();
        // Sanity: this fixture actually exercises overflow — the full label
        // alone is already wider than the whole chip budget.
        assert!(
            node.label.chars().count() > CHIP_MAX,
            "fixture must exercise the overflow path: {} chars vs CHIP_MAX={CHIP_MAX}",
            node.label.chars().count()
        );

        let cells = chip_cells(node, false, &app.palette);
        let rendered: String = cells.iter().map(|c| c.ch).collect();

        // (a) the acceptance bar: state survives.
        assert!(rendered.contains("working"), "state chip survives: {rendered:?}");
        // (b) the tail4 grep-back handle survives — the last thing to die.
        assert!(rendered.contains(" (…"), "tail4 handle survives: {rendered:?}");
        // (c) the row never overflows the chip's budget.
        assert!(
            cells.len() <= CHIP_MAX,
            "chip must fit CHIP_MAX={CHIP_MAX}, got {} cells: {rendered:?}",
            cells.len()
        );
    }

    #[test]
    fn fit_label_ladder_preserves_the_tail_longest_and_degrades_in_order() {
        let label = "yomi-strix/child/hardy-harbor (…ab12)";
        // Fits as-is.
        assert_eq!(fit_label(label, 100), label);
        // Rung 1: host/role/ + middle-elided name + tail all present.
        let r1 = fit_label(label, 30);
        assert!(r1.starts_with("yomi-strix/child/"), "rung 1 keeps host/role/: {r1}");
        assert!(r1.ends_with(" (…ab12)"), "rung 1 keeps the tail: {r1}");
        // Rung 2: budget too small for host — role/name/tail only.
        let r2 = fit_label(label, 18);
        assert!(!r2.contains("yomi-strix"), "rung 2 drops the host: {r2}");
        assert!(r2.starts_with("child/"), "rung 2 keeps role/: {r2}");
        assert!(r2.ends_with(" (…ab12)"), "rung 2 keeps the tail: {r2}");
        // Even at a brutal budget, the tail bracket is the last thing cut.
        let tiny = fit_label(label, 8);
        assert!(tiny.ends_with(" (…ab12)"), "tail survives an 8-cell budget: {tiny}");
        let tinier = fit_label(label, 5);
        assert_eq!(tinier.chars().count(), 5);
        assert!(
            tinier.contains("ab12") || tinier.contains('…'),
            "even a 5-cell budget keeps SOME fragment of the tail or an ellipsis: {tinier}"
        );
    }
}
