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
//! `column = depth` and center parents over their descendant leaves, and paint rectangular nodes + connectors.
//!
//! Tags: read-only. The schema has no tag surface (see the module note in
//! [`crate::theme::session_tags`]); tags found on a session record's
//! round-tripped `extra.tags` are rendered as accent chips, never minted here.

use crate::app::App;
use crate::theme;
use aoide_conduct::graph;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::collections::{HashMap, HashSet};

/// Generous wire gutter separates fixed world cards.
const GUTTER: usize = 12;
/// Fixed node width; title, identity, and state each have their own line.
const CHIP_MAX: usize = 32;
const NODE_H: usize = 7;
const LEAF_PITCH: usize = NODE_H + 4;

/// What a node is — drives marker, colour, and whether Enter can cue it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Project,
    Session,
    /// The synthetic root gathering sessions anchored to no project (mirrors the
    /// projectless group the Unicode tree render uses).
    Unanchored,
}

/// One laid-out node: identity, display bits, and its grid position.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub title: String,
    pub activity: String,
    pub petname: Option<String>,
    pub role: String,
    pub harness: String,
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
    world_y: usize,
    width: usize,
    height: usize,
}

/// Node metadata carried from the parsed document into the DFS.
struct Meta {
    kind: NodeKind,
    label: String,
    title: String,
    role: String,
    harness: String,
    session_id: Option<String>,
    state: Option<String>,
    tags: Vec<String>,
    model: Option<String>,
}

/// The parsed + laid-out forest: nodes in preorder (the selection order) and the
/// child adjacency needed to draw connectors.
pub struct Model {
    zoom: i8,
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

pub fn selected_session_id(app: &App) -> Option<String> {
    node_order(app)
        .get(app.graph_sel)
        .and_then(|node| node.session_id.clone())
}

pub fn session_id_at(area: Rect, app: &App, x: u16, y: u16) -> Option<String> {
    let index = hit_node(area, app, x, y)?;
    node_order(app)
        .get(index)
        .and_then(|node| node.session_id.clone())
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
                        title: str_field(n, "path"),
                        role: "project".into(),
                        harness: String::new(),
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
                let role = if spawned_targets.contains(id.as_str()) {
                    "child"
                } else {
                    "root"
                };
                let petname = n
                    .get("petname")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
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
                        title: str_field(n, "title"),
                        role: str_field(n, "role"),
                        harness: str_field(n, "agent"),
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

    // Roots: projects first, then a synthetic projectless root gathering
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
                label: crate::app::UNANCHORED.to_string(),
                title: "Sessions without a project".into(),
                role: "group".into(),
                harness: String::new(),
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

    let mut leaf_y = 0;
    for root in &roots {
        place_subtree(root, &children, &mut nodes, &mut leaf_y);
        leaf_y += LEAF_PITCH;
    }

    for node in &mut nodes {
        if let Some(record) = node
            .session_id
            .as_ref()
            .and_then(|id| merged.iter().find(|s| &s.session_id == id))
        {
            node.petname = record.petname.clone();
            node.activity = match (
                record.tool.as_deref().filter(|s| !s.is_empty()),
                record
                    .activity
                    .as_deref()
                    .or(record.say.as_deref())
                    .filter(|s| !s.is_empty()),
            ) {
                (Some(tool), Some(activity)) if tool != activity => format!("{tool} · {activity}"),
                (Some(tool), _) => tool.into(),
                (_, Some(activity)) => activity.into(),
                _ => String::new(),
            };
        }
    }
    Model {
        nodes,
        children,
        zoom: app.graph_zoom,
    }
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
            title: m.title.clone(),
            activity: String::new(),
            petname: None,
            role: m.role.clone(),
            harness: m.harness.clone(),
            session_id: m.session_id.clone(),
            state: m.state.clone(),
            tags: m.tags.clone(),
            model: m.model.clone(),
            depth,
            row: out.len(),
            world_y: 0,
            width: CHIP_MAX,
            height: NODE_H,
        });
    }
    if let Some(kids) = children.get(id) {
        for k in kids {
            walk(k, depth + 1, meta, children, visited, out);
        }
    }
}

/// Selection remains preorder; spatial placement uses leaf lanes instead.
fn place_subtree(
    id: &str,
    children: &HashMap<String, Vec<String>>,
    nodes: &mut [Node],
    next_y: &mut usize,
) -> usize {
    let Some(index) = nodes.iter().position(|n| n.id == id) else {
        return *next_y;
    };
    let depth = nodes[index].depth;
    let kids: Vec<String> = children
        .get(id)
        .into_iter()
        .flatten()
        .filter(|child| {
            nodes
                .iter()
                .any(|n| &n.id == *child && n.depth == depth + 1)
        })
        .cloned()
        .collect();
    let y = if kids.is_empty() {
        let y = *next_y;
        *next_y += LEAF_PITCH;
        y
    } else {
        let positions: Vec<usize> = kids
            .iter()
            .map(|child| place_subtree(child, children, nodes, next_y))
            .collect();
        (positions[0] + positions[positions.len() - 1]) / 2
    };
    nodes[index].world_y = y;
    y
}

// ── Rendering: model → cell grid → ratatui Lines ────────────────────────────

/// One painted cell: a symbol and its style.
#[derive(Clone)]
struct GCell {
    ch: char,
    style: Style,
    continuation: bool,
}

impl Default for GCell {
    fn default() -> Self {
        GCell {
            ch: ' ',
            style: Style::default(),
            continuation: false,
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

    let grid = lay_out(
        &model,
        if app.sidebar_focused { usize::MAX } else { sel },
        &app.palette,
    );
    let lines = grid_to_lines(&grid);

    let (sy, sx) = viewport(&model, sel, area, app.graph_pan);
    f.render_widget(Paragraph::new(lines).scroll((sy as u16, sx as u16)), area);
}

/// Empty canvas kept around the forest on every side, so the camera can pan
/// and zoom PAST the outermost cards instead of clamping to their edges.
const CANVAS_PAD: (usize, usize) = (40, 16);
fn node_rect(n: &Node) -> (usize, usize, usize, usize) {
    (
        CANVAS_PAD.0 + n.depth * (n.width + GUTTER),
        CANVAS_PAD.1 + n.world_y,
        n.width,
        n.height,
    )
}
fn camera_scale(zoom: i8) -> usize {
    (100 + zoom.clamp(-2, 2) as i16 * 25) as usize
}
fn screen_rect(n: &Node, zoom: i8) -> (usize, usize, usize, usize) {
    let (x, y, w, h) = node_rect(n);
    let scale = camera_scale(zoom);
    let sx = x * scale / 100;
    let sy = y * scale / 100;
    (
        sx,
        sy,
        (x + w) * scale / 100 - sx,
        (y + h) * scale / 100 - sy,
    )
}
fn extent(model: &Model) -> (usize, usize) {
    let scale = camera_scale(model.zoom);
    let (w, h) = model.nodes.iter().fold((0, 0), |(w, h), node| {
        let (x, y, nw, nh) = screen_rect(node, model.zoom);
        (w.max(x + nw), h.max(y + nh))
    });
    (
        w + CANVAS_PAD.0 * scale / 100,
        h + CANVAS_PAD.1 * scale / 100,
    )
}

pub fn zoom_label(app: &App) -> &'static str {
    match app.graph_zoom.clamp(-2, 2) {
        -2 => "50%",
        -1 => "75%",
        1 => "125%",
        2 => "150%",
        _ => "100%",
    }
}

/// Zoom the camera over a fixed world layout. Terminal glyphs remain cell-sized.
pub fn zoom_at(app: &mut App, area: Rect, pointer: (u16, u16), delta: i8) {
    if delta == 0 || !area.contains(ratatui::layout::Position::new(pointer.0, pointer.1)) {
        return;
    }
    let next = app.graph_zoom.saturating_add(delta.signum()).clamp(-2, 2);
    if next == app.graph_zoom {
        return;
    }
    let old = camera_scale(app.graph_zoom);
    let new = camera_scale(next);
    let origin = graph_origin(app, area);
    let px = (pointer.0 - area.x) as usize;
    let py = (pointer.1 - area.y) as usize;
    let x = ((origin.0 + px) * new / old).saturating_sub(px);
    let y = ((origin.1 + py) * new / old).saturating_sub(py);
    app.graph_zoom = next;
    let (w, h) = graph_extent(app);
    app.graph_pan = Some((
        x.min(w.saturating_sub(area.width as usize)),
        y.min(h.saturating_sub(area.height as usize)),
    ));
    app.graph_drag = None;
}

/// Graph canvas size in cells, for bounded drag and wheel panning.
pub fn graph_extent(app: &App) -> (usize, usize) {
    extent(&build_model(app))
}
pub fn graph_origin(app: &App, area: Rect) -> (usize, usize) {
    let (y, x) = viewport(&build_model(app), app.graph_sel, area, app.graph_pan);
    (x, y)
}

fn viewport(
    model: &Model,
    sel: usize,
    area: Rect,
    manual: Option<(usize, usize)>,
) -> (usize, usize) {
    if let Some((x, y)) = manual {
        let (w, h) = extent(model);
        return (
            y.min(h.saturating_sub(area.height as usize)),
            x.min(w.saturating_sub(area.width as usize)),
        );
    }
    // The camera follows the selection: the selected card sits at the centre
    // of the pane, and the canvas pad gives it room to get there.
    let (ew, eh) = extent(model);
    model
        .nodes
        .get(sel)
        .map(|n| {
            let (x, y, w, h) = screen_rect(n, model.zoom);
            // A card larger than the pane anchors its top-left instead.
            let centre = |o: usize, len: usize, pane: usize| {
                if len <= pane {
                    (o + len / 2).saturating_sub(pane / 2)
                } else {
                    o
                }
            };
            let cy = centre(y, h, area.height as usize);
            let cx = centre(x, w, area.width as usize);
            (
                cy.min(eh.saturating_sub(area.height as usize)),
                cx.min(ew.saturating_sub(area.width as usize)),
            )
        })
        .unwrap_or((0, 0))
}
/// Hit testing uses exactly the painted rectangles and viewport.
pub fn hit_node(area: Rect, app: &App, x: u16, y: u16) -> Option<usize> {
    if !area.contains(ratatui::layout::Position::new(x, y)) {
        return None;
    }
    let model = build_model(app);
    let (sy, sx) = viewport(&model, app.graph_sel, area, app.graph_pan);
    let gx = (x - area.x) as usize + sx;
    let gy = (y - area.y) as usize + sy;
    model.nodes.iter().position(|n| {
        let (nx, ny, w, h) = screen_rect(n, model.zoom);
        gx >= nx && gx < nx + w && gy >= ny && gy < ny + h
    })
}

/// Compose the styled cell grid: connectors first (box-drawing edges routed in
/// the gutter left of each child column), then node blocks on top.
fn lay_out(model: &Model, sel: usize, pal: &crate::app::Palette) -> Vec<Vec<GCell>> {
    let height = extent(model).1;
    let width = extent(model).0;
    let mut grid = vec![vec![GCell::default(); width]; height];
    // A wire wears the colour of the live session it leads to (its state hue),
    // so an active agent lights its own connections; project trunks keep the
    // accent.
    let wire = |n: &Node| match n.state.as_deref() {
        Some(s) if n.kind == NodeKind::Session => theme::state_style(s, pal),
        _ => theme::accent_style(pal),
    };
    let pos: HashMap<&str, (usize, usize, Style)> = model
        .nodes
        .iter()
        .map(|n| {
            let (x, y, _, h) = screen_rect(n, model.zoom);
            (n.id.as_str(), (x, y + h / 2, wire(n)))
        })
        .collect();
    for n in &model.nodes {
        let Some(kids) = model.children.get(&n.id) else {
            continue;
        };
        let kids: Vec<_> = kids.iter().filter_map(|k| pos.get(k.as_str())).collect();
        if kids.is_empty() {
            continue;
        }
        let (px, py, conn) = pos[n.id.as_str()];
        let (_, _, w, _) = screen_rect(n, model.zoom);
        let jx = (CANVAS_PAD.0 + n.depth * (n.width + GUTTER) + n.width + GUTTER / 2)
            * camera_scale(model.zoom)
            / 100;
        let top = kids.iter().map(|(_, y, _)| *y).min().unwrap().min(py);
        let bottom = kids.iter().map(|(_, y, _)| *y).max().unwrap().max(py);
        for x in px + w..=jx {
            set(&mut grid, x, py, '─', conn);
        }
        for y in top..=bottom {
            set(&mut grid, jx, y, '│', conn);
        }
        for (cx, cy, kc) in kids {
            for x in jx + 1..*cx {
                set(&mut grid, x, *cy, '─', *kc);
            }
            set(
                &mut grid,
                jx,
                *cy,
                if top == bottom {
                    '─'
                } else if *cy == top {
                    '┌'
                } else if *cy == bottom {
                    '└'
                } else {
                    '├'
                },
                *kc,
            );
        }
        set(
            &mut grid,
            jx,
            py,
            if top == bottom {
                '─'
            } else if py == top {
                '┬'
            } else if py == bottom {
                '┴'
            } else {
                '┼'
            },
            conn,
        );
    }
    for (i, n) in model.nodes.iter().enumerate() {
        let (x, y, w, h) = screen_rect(n, model.zoom);
        for (dy, row) in block_cells_at(n, i == sel, pal, w, h).iter().enumerate() {
            for (dx, cell) in row.iter().enumerate() {
                set_cell(&mut grid, x + dx, y + dy, cell.clone());
            }
        }
    }
    grid
}

#[cfg(test)]
fn block_cells(n: &Node, selected: bool, pal: &crate::app::Palette) -> Vec<Vec<GCell>> {
    block_cells_at(n, selected, pal, n.width, n.height)
}
fn block_cells_at(
    n: &Node,
    selected: bool,
    pal: &crate::app::Palette,
    width: usize,
    height: usize,
) -> Vec<Vec<GCell>> {
    let surface = theme::surface(
        pal,
        if n.kind != NodeKind::Session {
            10
        } else if n.role == "shell" || n.harness == "shell" {
            3
        } else {
            6
        },
    );
    let accent = theme::role_color(
        pal,
        if n.kind != NodeKind::Session {
            theme::Role::Project
        } else if n.harness == "shell" || n.role == "terminal" {
            theme::Role::Terminal
        } else {
            theme::Role::Agent
        },
    );
    let border = if selected {
        surface.fg(accent).add_modifier(Modifier::BOLD)
    } else if n.kind != NodeKind::Session {
        surface.fg(accent)
    } else {
        surface.patch(theme::state_style(n.state.as_deref().unwrap_or(""), pal))
    };
    let mut block = vec![
        vec![
            GCell {
                ch: ' ',
                style: surface,
                continuation: false
            };
            width
        ];
        height
    ];
    let (tl, tr, bl, br, h, v) = if selected {
        ('┏', '┓', '┗', '┛', '━', '┃')
    } else {
        ('┌', '┐', '└', '┘', '─', '│')
    };
    for x in 1..width - 1 {
        set(&mut block, x, 0, h, border);
        set(&mut block, x, height - 1, h, border);
    }
    for y in 1..height - 1 {
        set(&mut block, 0, y, v, border);
        set(&mut block, width - 1, y, v, border);
    }
    for (x, y, ch) in [
        (0, 0, tl),
        (width - 1, 0, tr),
        (0, height - 1, bl),
        (width - 1, height - 1, br),
    ] {
        set(&mut block, x, y, ch, border);
    }
    let state = n.state.as_deref().unwrap_or("");
    let role = if n.role.is_empty() {
        if n.harness == "shell" {
            "terminal"
        } else if !n.harness.is_empty() {
            "agent"
        } else {
            "session"
        }
    } else if n.role == "shell" {
        "terminal"
    } else {
        &n.role
    };
    let mark = theme::mark(match role {
        "project" | "root" => theme::Mark::Project,
        "terminal" => theme::Mark::Terminal,
        _ if n.kind != NodeKind::Session => theme::Mark::Project,
        _ => theme::Mark::Agent,
    });
    let heading = if state.is_empty() {
        format!("{mark} {}", role.to_uppercase())
    } else {
        format!("{mark} {} · {}", role.to_uppercase(), state)
    };
    let heading = if n.tags.is_empty() {
        heading
    } else {
        format!(
            "{} {}",
            heading,
            n.tags
                .iter()
                .map(|t| format!("[{t}]"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let main = if n.kind == NodeKind::Session && !n.title.is_empty() {
        &n.title
    } else {
        &n.label
    };
    let identity = if n.kind == NodeKind::Session {
        if n.title.is_empty() {
            String::new()
        } else {
            fit_label(&n.label, width - 4)
        }
    } else {
        truncate_end(&n.title, width - 4)
    };
    let detail = match (&n.harness, n.model.as_deref()) {
        (h, Some(m)) if !h.is_empty() => format!("{h} · {m}"),
        (_, Some(m)) => m.into(),
        (h, None) => h.clone(),
    };
    let card_identity = n
        .petname
        .as_ref()
        .map(|name| {
            let tail: String = n
                .session_id
                .as_deref()
                .unwrap_or("")
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{name} (…{tail})")
        })
        .unwrap_or_else(|| n.label.clone());
    let rows = if n.kind == NodeKind::Session {
        vec![
            (
                1,
                truncate_end(
                    if n.title.is_empty() {
                        &n.harness
                    } else {
                        &n.title
                    },
                    width - 4,
                ),
                surface.add_modifier(Modifier::BOLD),
            ),
            (2, fit_label(&card_identity, width - 4), surface),
            (3, truncate_end(&detail, width - 4), surface.fg(accent)),
            (4, heading, surface.patch(theme::state_style(state, pal))),
            (5, truncate_end(&n.activity, width - 4), surface),
        ]
    } else {
        vec![
            (1, heading, surface.fg(accent).add_modifier(Modifier::BOLD)),
            (
                2,
                if n.kind == NodeKind::Session && n.title.is_empty() {
                    fit_label(main, width - 4)
                } else {
                    truncate_end(main, width - 4)
                },
                surface.add_modifier(Modifier::BOLD),
            ),
            (3, identity, surface),
            (4, detail, surface),
            (
                5,
                n.tags
                    .iter()
                    .map(|tag| format!("[{tag}]"))
                    .collect::<Vec<_>>()
                    .join(" "),
                surface.fg(accent),
            ),
        ]
    };
    for (y, text, style) in rows {
        if y >= height - 1 {
            continue;
        }
        let mut dx = 0;
        for ch in text.chars() {
            let cells = Span::raw(ch.to_string()).width();
            if cells == 0 {
                continue;
            }
            if dx + cells > width - 4 {
                break;
            }
            set(&mut block, 2 + dx, y, ch, style);
            for i in 1..cells {
                block[y][2 + dx + i].continuation = true;
            }
            dx += cells;
        }
    }
    block
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
    set_cell(
        grid,
        x,
        y,
        GCell {
            ch,
            style,
            continuation: false,
        },
    );
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
                if cell.continuation {
                    continue;
                }
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
            native_role: None,
            origin: None,
            seal: None,
            sealed_issued_at: None,
            restore: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn block_viewport_and_hit_testing_share_every_selected_rectangle() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("child", "/x", "idle", Some("root")),
            ],
            vec![],
        );
        let area = Rect::new(3, 2, 44, 12);
        let model = build_model(&app);
        for sel in 0..model.nodes.len() {
            app.graph_sel = sel;
            let (sy, sx) = viewport(&model, sel, area, app.graph_pan);
            let (x, y, w, h) = node_rect(&model.nodes[sel]);
            assert!(x >= sx && x + w <= sx + area.width as usize);
            assert!(y >= sy && y + h <= sy + area.height as usize);
            for dy in 0..h {
                for dx in 0..w {
                    assert_eq!(
                        hit_node(
                            area,
                            &app,
                            (area.x as usize + x - sx + dx) as u16,
                            (area.y as usize + y - sy + dy) as u16
                        ),
                        Some(sel)
                    );
                }
            }
        }
        app.graph_sel = 0;
        assert_eq!(
            hit_node(area, &app, area.x, area.y + NODE_H as u16),
            None,
            "row gutter is not a node"
        );
        let tiny = Rect::new(0, 0, 8, 3);
        let (sy, sx) = viewport(&model, 2, tiny, None);
        let (x, y, _, _) = node_rect(&model.nodes[2]);
        assert_eq!((sx, sy), (x, y));
    }

    #[test]
    fn manual_pan_overrides_selection_and_hit_tests_the_visible_block() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("child", "/x", "idle", Some("root")),
            ],
            vec![],
        );
        let area = Rect::new(3, 4, 32, 7);
        let model = build_model(&app);
        let child = model
            .nodes
            .iter()
            .position(|n| n.session_id.as_deref() == Some("child"))
            .unwrap();
        let (x, y, w, h) = node_rect(&model.nodes[child]);
        app.graph_sel = 0;
        app.graph_pan = Some((x, y));
        assert_eq!(viewport(&model, 0, area, app.graph_pan), (y, x));
        assert_eq!(hit_node(area, &app, area.x, area.y), Some(child));
        assert_eq!(
            hit_node(area, &app, area.x + w as u16 - 1, area.y + h as u16 - 1),
            Some(child)
        );
        let extent = graph_extent(&app);
        assert_eq!(extent, (x + w + CANVAS_PAD.0, y + h + CANVAS_PAD.1));
        assert_eq!(
            viewport(&model, 0, area, Some((usize::MAX, usize::MAX))),
            (extent.1 - 7, extent.0 - 32)
        );
        app.graph_pan = None;
        assert_eq!(hit_node(area, &app, area.x, area.y), Some(0));
        let cells = block_cells(&model.nodes[0], false, &app.palette);
        assert_eq!(cells[0][0].ch, '┌');
    }

    #[test]
    fn blocks_preserve_metadata_edges_and_palette_contrast() {
        let mut parent = session("root", "/x", "working", None);
        parent.title = Some("Distinct task title".into());
        parent.petname = Some("brave-otter".into());
        parent.model = Some("model-one".into());
        let app = App::for_test(
            vec![],
            vec![parent, session("child", "/x", "idle", Some("root"))],
            vec![],
        );
        let model = build_model(&app);
        let root = model
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("root"))
            .unwrap();
        let child = model
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("child"))
            .unwrap();
        let grid = lay_out(&model, 1, &app.palette);
        let junction = CANVAS_PAD.0 + root.depth * (CHIP_MAX + GUTTER) + CHIP_MAX + GUTTER / 2;
        assert_eq!(
            grid[CANVAS_PAD.1 + root.world_y + NODE_H / 2][junction].ch,
            '─'
        );
        assert_eq!(root.world_y, child.world_y);
        for (bg, fg) in [(0, 15), (15, 0)] {
            let pal = crate::app::Palette {
                bg: Some(bg),
                fg: Some(fg),
                accent: Some(3),
                urgent: Some(1),
                ..Default::default()
            };
            let cells = block_cells(root, true, &pal);
            let text: String = cells.iter().flatten().map(|c| c.ch).collect();
            assert!(
                text.contains("Distinct task title")
                    && text.contains(" (…root)")
                    && text.contains("claude · model-one")
            );
            assert_eq!(cells[0][0].ch, '┏');
            assert_eq!(cells[2][2].style.fg, theme::surface(&pal, 0).fg);
            assert!(cells[2][2].style.bg.is_some());
        }
        let mut wide = root.clone();
        wide.title = "界".repeat(50);
        let lines = grid_to_lines(&block_cells(&wide, false, &app.palette));
        assert!(lines.iter().all(|l| l.width() == CHIP_MAX));
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
        let root = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("root"))
            .unwrap();
        let kid = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("kid"))
            .unwrap();
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
        assert!(m
            .nodes
            .iter()
            .any(|n| n.session_id.as_deref() == Some("loose")));
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
        let root_n = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("root"))
            .unwrap();
        let kid_n = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("kid"))
            .unwrap();
        let term_n = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("term"))
            .unwrap();
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
        let node = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("t"))
            .unwrap();
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

        let root_n = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("root"))
            .unwrap();
        assert_eq!(root_n.label, format!("{host}/root/brave-otter (…root)"));
        assert_eq!(
            root_n.session_id.as_deref(),
            Some("root"),
            "session_id stays the bare canonical id"
        );

        let kid_n = m
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some("kid"))
            .unwrap();
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
    fn block_keeps_state_and_identity_on_separate_bounded_lines() {
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
        root.extra
            .insert("tags".into(), serde_json::json!(["backend"]));
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

        let block = block_cells(node, false, &app.palette);
        let cells = &block[3];
        let rendered: String = block.iter().flatten().map(|c| c.ch).collect();

        // (a) the acceptance bar: state survives.
        assert!(
            rendered.contains("working"),
            "state chip survives: {rendered:?}"
        );
        // (b) the tail4 grep-back handle survives — the last thing to die.
        assert!(
            rendered.contains(" (…"),
            "tail4 handle survives: {rendered:?}"
        );
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
        assert!(
            r1.starts_with("yomi-strix/child/"),
            "rung 1 keeps host/role/: {r1}"
        );
        assert!(r1.ends_with(" (…ab12)"), "rung 1 keeps the tail: {r1}");
        // Rung 2: budget too small for host — role/name/tail only.
        let r2 = fit_label(label, 18);
        assert!(!r2.contains("yomi-strix"), "rung 2 drops the host: {r2}");
        assert!(r2.starts_with("child/"), "rung 2 keeps role/: {r2}");
        assert!(r2.ends_with(" (…ab12)"), "rung 2 keeps the tail: {r2}");
        // Even at a brutal budget, the tail bracket is the last thing cut.
        let tiny = fit_label(label, 8);
        assert!(
            tiny.ends_with(" (…ab12)"),
            "tail survives an 8-cell budget: {tiny}"
        );
        let tinier = fit_label(label, 5);
        assert_eq!(tinier.chars().count(), 5);
        assert!(
            tinier.contains("ab12") || tinier.contains('…'),
            "even a 5-cell budget keeps SOME fragment of the tail or an ellipsis: {tinier}"
        );
    }
    #[test]
    fn branches_have_centered_parents_separate_lanes_and_connected_ports() {
        let app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("left", "/x", "working", Some("root")),
                session("right", "/x", "idle", Some("root")),
                session("leaf", "/x", "idle", Some("left")),
            ],
            vec![],
        );
        let model = build_model(&app);
        let node = |id: &str| {
            model
                .nodes
                .iter()
                .find(|n| n.session_id.as_deref() == Some(id))
                .unwrap()
        };
        let (root, left, right, leaf) = (node("root"), node("left"), node("right"), node("leaf"));
        assert_eq!(left.world_y, leaf.world_y);
        assert!(right.world_y >= left.world_y + LEAF_PITCH);
        assert_eq!(root.world_y, (left.world_y + right.world_y) / 2);
        for zoom in -2..=2 {
            let mut model = build_model(&app);
            model.zoom = zoom;
            let cells = lay_out(&model, 0, &app.palette);
            for n in &model.nodes {
                let (x, y, w, h) = screen_rect(n, zoom);
                // no port circles: the card border stays whole where wires arrive
                assert!(matches!(cells[y + h / 2][x].ch, '│' | '┃'));
                assert!(matches!(cells[y + h / 2][x + w - 1].ch, '│' | '┃'));
            }
        }
    }

    #[test]
    fn camera_zoom_preserves_pointer_and_fixed_world_layout() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("child", "/x", "idle", Some("root")),
            ],
            vec![],
        );
        let area = Rect::new(3, 4, 12, 4);
        app.graph_pan = Some((44, 1));
        let pointer = (area.x + 4, area.y + 2);
        let before = hit_node(area, &app, pointer.0, pointer.1);
        let world: Vec<_> = build_model(&app).nodes.iter().map(node_rect).collect();
        zoom_at(&mut app, area, pointer, 1);
        assert_eq!(graph_origin(&app, area), (56, 1));
        assert_eq!(hit_node(area, &app, pointer.0, pointer.1), before);
        assert_eq!(
            build_model(&app)
                .nodes
                .iter()
                .map(node_rect)
                .collect::<Vec<_>>(),
            world
        );
        zoom_at(&mut app, area, pointer, 1);
        assert_eq!(app.graph_zoom, 2);
        let pan = app.graph_pan;
        zoom_at(&mut app, area, pointer, 1);
        assert_eq!(app.graph_pan, pan);
        assert_eq!(zoom_label(&app), "150%");
        let zoom = app.graph_zoom;
        zoom_at(&mut app, area, (0, 0), -1);
        assert_eq!(app.graph_zoom, zoom);
    }

    #[test]
    fn camera_rectangles_match_render_and_hit_at_every_scale() {
        let mut app = App::for_test(vec![], vec![session("root", "/x", "working", None)], vec![]);
        let area = Rect::new(2, 3, 60, 20);
        for zoom in [-2, -1, 0, 1, 2] {
            app.graph_zoom = zoom;
            app.graph_sel = 1;
            let model = build_model(&app);
            let node = &model.nodes[1];
            assert_eq!((node.width, node.height), (CHIP_MAX, NODE_H));
            let (x, y, w, h) = screen_rect(node, zoom);
            let cells = block_cells_at(node, true, &app.palette, w, h);
            assert_eq!((cells[0].len(), cells.len()), (w, h));
            assert!(grid_to_lines(&cells).iter().all(|line| line.width() == w));
            let (sy, sx) = viewport(&model, 1, area, None);
            for dy in 0..h {
                for dx in 0..w {
                    assert_eq!(
                        hit_node(
                            area,
                            &app,
                            (area.x as usize + x - sx + dx) as u16,
                            (area.y as usize + y - sy + dy) as u16
                        ),
                        Some(1)
                    );
                }
            }
        }
    }

    #[test]
    fn normal_session_card_has_widget_fields_and_resolves_action_target() {
        let mut rec = session("canonical-id", "/x", "working", None);
        rec.title = Some("Review conductor".into());
        rec.petname = Some("calm-rook".into());
        rec.model = Some("fable".into());
        rec.tool = Some("Read".into());
        rec.activity = Some("Inspect graph".into());
        let mut app = App::for_test(vec![], vec![rec], vec![]);
        app.graph_sel = 1;
        let model = build_model(&app);
        let cells = block_cells(&model.nodes[1], true, &app.palette);
        let line = |y: usize| cells[y].iter().map(|c| c.ch).collect::<String>();
        assert!(line(1).contains("Review conductor"));
        assert!(line(2).contains("calm-rook"));
        assert!(line(3).contains("claude · fable"));
        assert!(line(4).contains("working"));
        assert!(line(5).contains("Read · Inspect graph"));
        assert_eq!(selected_session_id(&app).as_deref(), Some("canonical-id"));
        let area = Rect::new(0, 0, 32, 7);
        assert_eq!(
            session_id_at(area, &app, 1, 1).as_deref(),
            Some("canonical-id")
        );
        app.graph_sel = 0;
        assert!(selected_session_id(&app).is_none());
    }
}
