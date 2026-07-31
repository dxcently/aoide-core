//! The DAG panel — a VISUAL, laid-out graph of the project/session DAG.
//!
//! Where the SESSIONS roster reads the DAG as an indented list (state at a
//! glance), this view draws its *shape*: a layered left-to-right graph, one
//! column per depth (projects in column 0, the sessions they anchor in column
//! 1, spawned children in column 2+), nodes wired with box-drawing edges.
//!
//! One rule holds, exactly as everywhere else in the conductor: this view NEVER
//! re-derives the graph. The node/edge structure comes verbatim from
//! [`crate::graph::build_graph`] — the same pure function `graph emit` stages to
//! `song/stage/graph.json` — so the picture on screen is the document on disk.
//! We parse that document into a forest (each session has at most one incoming
//! edge — spawned-by wins over anchors — so the layout is a tree walk), assign
//! `column = depth` and `row = preorder index`, and paint chips + connectors.
//!
//! Tags: read-only. The schema has no tag surface (see the module note in
//! [`crate::conductor::theme::session_tags`]); tags found on a session record's
//! round-tripped `extra.tags` are rendered as accent chips, never minted here.

use crate::conductor::app::App;
use crate::conductor::theme;
use crate::graph;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::collections::{HashMap, HashSet};

/// Per-depth band width in cells. Wide enough to read as columns (distinct from
/// the roster's tight indentation) and to give edges a gutter to route through.
const COL_W: usize = 28;
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
    /// The bare session id (for `graph focus` on Enter); `None` for anchors.
    pub session_id: Option<String>,
    pub state: Option<String>,
    pub tags: Vec<String>,
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
                    },
                );
            }
            Some("session") => {
                let sid = id.strip_prefix("session:").unwrap_or(&id).to_string();
                let state = str_field(n, "state");
                let tags = tag_by_id.get(&sid).cloned().unwrap_or_default();
                meta.insert(
                    id.clone(),
                    Meta {
                        kind: NodeKind::Session,
                        label: sid.clone(),
                        session_id: Some(sid),
                        state: Some(state),
                        tags,
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
            Line::from("  Then re-open the conductor, or press e to emit the graph.")
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
fn lay_out(model: &Model, sel: usize, pal: &crate::conductor::app::Palette) -> Vec<Vec<GCell>> {
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

/// Build a node's chip as styled cells: marker, label, a short state word, and
/// read-only tag chips — truncated to [`CHIP_MAX`].
fn chip_cells(n: &Node, selected: bool, pal: &crate::conductor::app::Palette) -> Vec<GCell> {
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

    let mut cells: Vec<GCell> = Vec::new();
    let mut push = |s: &str, style: Style| {
        for ch in s.chars() {
            cells.push(GCell { ch, style });
        }
    };
    push(&marker.to_string(), marker_style);
    push(" ", label_style);
    push(&n.label, label_style);
    if let Some(state) = &n.state {
        if !state.is_empty() {
            push(&format!(" {state}"), theme::dim());
        }
    }
    for t in &n.tags {
        push(
            &format!(" ⟨{t}⟩"),
            Style::default().fg(accent).add_modifier(Modifier::DIM),
        );
    }

    cells.truncate(CHIP_MAX);
    if selected {
        for c in &mut cells {
            c.style = c.style.add_modifier(Modifier::REVERSED);
        }
    }
    cells
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
    use crate::conductor::app::App;
    use crate::graph::{Project, SessionRecord};
    use serde_json::Map;

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
            model: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn model_lays_out_projects_then_spawned_children_in_columns() {
        let app = App::for_test(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
            }],
            vec![
                session("root", "/home/k/Aoide", "running", None),
                session("kid", "/home/k/Aoide", "idle", Some("root")),
            ],
            Vec::new(),
        );
        let m = build_model(&app);
        // project (depth 0) → root session (depth 1) → spawned kid (depth 2).
        let proj = m.nodes.iter().find(|n| n.label == "aoide").unwrap();
        let root = m.nodes.iter().find(|n| n.label == "root").unwrap();
        let kid = m.nodes.iter().find(|n| n.label == "kid").unwrap();
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
        assert!(m.nodes.iter().any(|n| n.label == "loose"));
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
            }],
            vec![s],
            Vec::new(),
        );
        let m = build_model(&app);
        let node = m.nodes.iter().find(|n| n.label == "t").unwrap();
        assert_eq!(node.tags, vec!["backend".to_string(), "wip".to_string()]);
    }
}
