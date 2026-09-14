//! The Graph panel — a RETAINED scene of the project/session graph.
//!
//! Where the SESSION roster reads the graph as an indented list (state at a
//! glance), this view draws its *shape*: fixed-size cards standing at their own
//! world coordinates, wired with box-drawing edges, under a camera that pans
//! and zooms over them.
//!
//! Two rules hold here.
//!
//! **The structure is never re-derived.** Nodes and edges come verbatim from
//! [`aoide_conduct::graph::build_graph`] — the same pure function every
//! mutation's `restage_graph()` (and `graph prune`'s manual resync) writes to
//! `state/stage/graph.json` — so the picture on screen is the document on
//! disk. Each session has at most one incoming edge (spawned-by wins over
//! anchors), so the document parses into a forest and the fresh layout is a
//! tree walk: `column = depth`, parents centred over their descendant leaves.
//!
//! **The positions are retained, not recomputed.** That tree walk only
//! proposes; [`crate::scene::Positions`] decides. A card already on the canvas
//! keeps its world coordinates when unrelated sessions arrive or end, so the
//! forest stops reshuffling under the operator's cursor between refreshes.
//! Cards are a fixed size in world cells; the camera scales the whole layout
//! rather than switching card presets, and terminal glyphs stay cell-sized and
//! clip inside their card.
//!
//! Drawing is bounded by the viewport, never by the world: edges paint first,
//! cards on top, every write clipped through [`crate::scene::Painter`], so a
//! card the camera cannot see costs a comparison instead of a cell.
//!
//! Tags: read-only. The schema has no tag surface (see the module note in
//! [`crate::theme::session_tags`]); tags found on a session record's
//! round-tripped `extra.tags` are rendered as accent chips, never minted here.

use crate::app::App;
use crate::scene::{Camera, Painter, Placed, View, WorldRect};
use crate::theme;
use aoide_conduct::graph;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};
use ratatui::Frame;
use std::collections::{HashMap, HashSet, VecDeque};

/// Generous wire gutter separates fixed world cards.
const GUTTER: i32 = 12;
/// Fixed card size in world cells; title, identity, and state each have their
/// own line. Cards never change size — the camera does.
const CARD_W: i32 = 32;
const CARD_H: i32 = 7;
/// Vertical pitch of one leaf lane in the fresh layout.
const LANE: i32 = CARD_H + 4;
/// Empty canvas kept around the forest on every side, so the camera can pan
/// and zoom PAST the outermost cards instead of clamping to their edges.
const CANVAS_PAD: (i32, i32) = (40, 16);

/// What a node is — drives marker, colour, and whether Enter can cue it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Project,
    Session,
    /// The synthetic root gathering sessions anchored to no project (mirrors the
    /// projectless group the Unicode tree render uses).
    Unanchored,
}

/// One laid-out node: identity, display bits, and its retained world rectangle.
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
    /// The card's retained rectangle in world cells.
    pub world: WorldRect,
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

/// The parsed, world-placed forest and the camera over it.
pub struct Model {
    pub nodes: Vec<Node>,
    /// node id → child node ids, in draw order.
    children: HashMap<String, Vec<String>>,
    /// Indices into `nodes`, in preorder — the slice the current view draws.
    visible: Vec<usize>,
    /// Index into `visible` of the selected card.
    selected: usize,
    camera: Camera,
}

impl Model {
    /// The nodes the current view draws, in preorder.
    pub fn visible(&self) -> impl Iterator<Item = &Node> {
        self.visible.iter().map(|&i| &self.nodes[i])
    }
    pub fn visible_len(&self) -> usize {
        self.visible.len()
    }
    pub fn selected(&self) -> usize {
        self.selected
    }
}

/// The visible nodes in preorder — the single source of truth for both
/// selection (`j`/`k` walk this) and the drawn layout, so the cursor can never
/// land on a node the screen isn't showing.
pub fn node_order(app: &App) -> Vec<Node> {
    let model = build_model(app);
    model.visible().cloned().collect()
}

/// Where the selected card sits in [`node_order`].
pub fn selected_index(app: &App) -> usize {
    build_model(app).selected
}

/// Move the selection onto the `i`th visible card and release the camera back
/// to following it.
pub fn select_index(app: &mut App, i: usize) {
    let model = build_model(app);
    let picked = model.visible().nth(i).map(|n| n.id.clone());
    if let Some(id) = picked {
        app.graph.selected = id;
        app.graph.camera.pan = None;
    }
}

pub fn selected_node(app: &App) -> Option<Node> {
    let model = build_model(app);
    let node = model.visible().nth(model.selected).cloned();
    node
}

pub fn selected_session_id(app: &App) -> Option<String> {
    selected_node(app).and_then(|node| node.session_id)
}

pub fn session_id_at(area: Rect, app: &App, x: u16, y: u16) -> Option<String> {
    let index = hit_node(area, app, x, y)?;
    node_order(app)
        .get(index)
        .and_then(|node| node.session_id.clone())
}

/// Swap between the focused component and the whole forest.
pub fn toggle_view(app: &mut App) {
    app.graph.view = app.graph.view.toggled();
    app.graph.camera.pan = None;
}

pub fn zoom_label(app: &App) -> &'static str {
    app.graph.camera.zoom_label()
}

pub fn view_label(app: &App) -> &'static str {
    app.graph.view.label()
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
        let uid = UNANCHORED_ID.to_string();
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

    place(&mut nodes, &children, &roots, &app.graph.positions);

    let visible = visible_order(&nodes, &children, &app.graph);
    let selected = visible
        .iter()
        .position(|&i| nodes[i].id == app.graph.selected)
        .unwrap_or(0);

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
        visible,
        selected,
        camera: app.graph.camera,
    }
}

/// The synthetic gathering root's node id.
pub const UNANCHORED_ID: &str = "unanchored";

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
            world: WorldRect::new(0, 0, CARD_W, CARD_H),
        });
    }
    if let Some(kids) = children.get(id) {
        for k in kids {
            walk(k, depth + 1, meta, children, visited, out);
        }
    }
}

// ── World placement: a fresh proposal, the retained store decides ───────────

/// Lay the forest out fresh, then resolve it against the retained store and
/// stamp the surviving coordinates onto the nodes.
fn place(
    nodes: &mut [Node],
    children: &HashMap<String, Vec<String>>,
    roots: &[String],
    retained: &crate::scene::Positions,
) {
    let mut lane = 0;
    let mut lanes: HashMap<String, i32> = HashMap::new();
    for root in roots {
        lay_lanes(root, children, nodes, &mut lane, &mut lanes);
        lane += LANE;
    }
    let fresh: Vec<(String, Placed)> = nodes
        .iter()
        .map(|n| {
            (
                n.id.clone(),
                Placed {
                    x: CANVAS_PAD.0 + n.depth as i32 * (CARD_W + GUTTER),
                    y: CANVAS_PAD.1 + lanes.get(&n.id).copied().unwrap_or(0),
                    depth: n.depth,
                },
            )
        })
        .collect();
    for (node, placed) in nodes
        .iter_mut()
        .zip(retained.place(&fresh, (CARD_W, CARD_H), LANE))
    {
        node.world = WorldRect::new(placed.x, placed.y, CARD_W, CARD_H);
    }
}

/// The fresh proposal: leaves take successive lanes, a parent centres over its
/// first and last descendant leaf. Selection order stays preorder.
fn lay_lanes(
    id: &str,
    children: &HashMap<String, Vec<String>>,
    nodes: &[Node],
    next: &mut i32,
    out: &mut HashMap<String, i32>,
) -> i32 {
    let Some(node) = nodes.iter().find(|n| n.id == id) else {
        return *next;
    };
    let depth = node.depth;
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
        let y = *next;
        *next += LANE;
        y
    } else {
        let spans: Vec<i32> = kids
            .iter()
            .map(|child| lay_lanes(child, children, nodes, next, out))
            .collect();
        (spans[0] + spans[spans.len() - 1]) / 2
    };
    out.insert(id.to_string(), y);
    y
}

// ── The view choice: focused component, or the whole forest ─────────────────

/// Indices of the nodes the current view draws, in preorder.
///
/// `All` is every node. `Focus` — the default — is the connected component
/// around the picked card: the tree of agents and terminals it controls or is
/// connected to, and nothing else. The synthetic gathering root is not a
/// connection, so its edges are not traversed: a terminal that belongs to
/// nothing shows itself alone rather than borrowing a forest of strangers.
/// Picking the gathering root itself still opens the sessions under it.
fn visible_order(
    nodes: &[Node],
    children: &HashMap<String, Vec<String>>,
    scene: &crate::scene::SceneState,
) -> Vec<usize> {
    if scene.view == View::All || nodes.is_empty() {
        return (0..nodes.len()).collect();
    }
    let anchor = if nodes.iter().any(|n| n.id == scene.selected) {
        scene.selected.clone()
    } else {
        nodes[0].id.clone()
    };
    let bridged = anchor != UNANCHORED_ID;
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
    for (parent, kids) in children {
        for kid in kids {
            if bridged && (parent == UNANCHORED_ID || kid == UNANCHORED_ID) {
                continue;
            }
            adjacency.entry(parent).or_default().push(kid);
            adjacency.entry(kid).or_default().push(parent);
        }
    }
    let mut seen: HashSet<&str> = HashSet::from([anchor.as_str()]);
    let mut queue: VecDeque<&str> = VecDeque::from([anchor.as_str()]);
    while let Some(id) = queue.pop_front() {
        for next in adjacency.get(id).into_iter().flatten() {
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    (0..nodes.len())
        .filter(|&i| seen.contains(nodes[i].id.as_str()))
        .collect()
}

// ── Camera geometry: one transform, shared by render, hit test and pan ──────

/// The visible canvas size in scaled cells, padded so the camera reaches past
/// the outermost cards.
pub fn graph_extent(app: &App) -> (i32, i32) {
    extent(&build_model(app))
}

fn extent(model: &Model) -> (i32, i32) {
    let pad = model
        .camera
        .scale_rect(WorldRect::new(0, 0, CANVAS_PAD.0, CANVAS_PAD.1));
    model.visible().fold((pad.w, pad.h), |(w, h), node| {
        let r = model.camera.scale_rect(node.world);
        (w.max(r.right() + pad.w), h.max(r.bottom() + pad.h))
    })
}

/// The camera origin — the scaled point the viewport's top-left shows.
pub fn graph_origin(app: &App, area: Rect) -> (i32, i32) {
    origin(&build_model(app), area)
}

fn origin(model: &Model, area: Rect) -> (i32, i32) {
    let (ew, eh) = extent(model);
    let (pw, ph) = (area.width as i32, area.height as i32);
    let clamp = |v: i32, e: i32, pane: i32| v.clamp(0, (e - pane).max(0));
    if let Some((x, y)) = model.camera.pan {
        return (clamp(x, ew, pw), clamp(y, eh, ph));
    }
    // The camera follows the selection: the selected card sits at the centre
    // of the pane, and the canvas pad gives it room to get there. A card
    // larger than the pane anchors its top-left instead.
    model
        .visible()
        .nth(model.selected)
        .map(|n| {
            let r = model.camera.scale_rect(n.world);
            let centre = |o: i32, len: i32, pane: i32| {
                if len <= pane {
                    (o + len / 2 - pane / 2).max(0)
                } else {
                    o
                }
            };
            (
                clamp(centre(r.x, r.w, pw), ew, pw),
                clamp(centre(r.y, r.h, ph), eh, ph),
            )
        })
        .unwrap_or((0, 0))
}

/// Zoom the camera over the retained world. Terminal glyphs remain cell-sized:
/// the layout is transformed, never relaid out into a different card preset.
pub fn zoom_at(app: &mut App, area: Rect, pointer: (u16, u16), delta: i8) {
    if delta == 0 || !area.contains(ratatui::layout::Position::new(pointer.0, pointer.1)) {
        return;
    }
    let next = app
        .graph
        .camera
        .zoom
        .saturating_add(delta.signum())
        .clamp(crate::scene::ZOOM_MIN, crate::scene::ZOOM_MAX);
    if next == app.graph.camera.zoom {
        return;
    }
    let old = app.graph.camera.scale();
    let new = Camera {
        zoom: next,
        ..app.graph.camera
    }
    .scale();
    let (ox, oy) = graph_origin(app, area);
    let px = (pointer.0 - area.x) as i32;
    let py = (pointer.1 - area.y) as i32;
    // Keep the world point under the pointer under the pointer.
    let x = ((ox + px) * new / old - px).max(0);
    let y = ((oy + py) * new / old - py).max(0);
    app.graph.camera.zoom = next;
    let (w, h) = graph_extent(app);
    app.graph.camera.pan = Some((
        x.min((w - area.width as i32).max(0)),
        y.min((h - area.height as i32).max(0)),
    ));
    app.graph.drag = None;
}

/// The card under a viewport point, as an index into [`node_order`].
///
/// Hit testing runs the same camera transform over the same retained world
/// that render does, so a click and a key resolve the same card.
pub fn hit_node(area: Rect, app: &App, x: u16, y: u16) -> Option<usize> {
    if !area.contains(ratatui::layout::Position::new(x, y)) {
        return None;
    }
    let model = build_model(app);
    let o = origin(&model, area);
    let (px, py) = ((x - area.x) as i32 + o.0, (y - area.y) as i32 + o.1);
    let index = model
        .visible()
        .position(|n| model.camera.scale_rect(n.world).contains(px, py));
    index
}

// ── Rendering: the scene, clipped to the viewport ───────────────────────────

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

/// The retained graph scene as a widget: edges first, cards on top, every
/// write clipped to the viewport.
pub struct GraphScene<'a> {
    model: &'a Model,
    palette: &'a crate::app::Palette,
    /// The card drawn with the bright selection, or `usize::MAX` for none
    /// (another pane holds the keyboard).
    selected: usize,
}

impl Widget for GraphScene<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let o = origin(self.model, area);
        let cam = self.model.camera;
        let viewport = WorldRect::new(o.0, o.1, area.width as i32, area.height as i32);
        let mut p = Painter::new(buf, area);

        // A wire wears the colour of the live session it leads to (its state
        // hue), so an active agent lights its own connections; project trunks
        // keep the accent.
        let wire = |n: &Node| match n.state.as_deref() {
            Some(s) if n.kind == NodeKind::Session => theme::state_style(s, self.palette),
            _ => theme::accent_style(self.palette),
        };
        let port = |n: &Node| {
            let r = cam.scale_rect(n.world);
            (r, r.y + r.h / 2, wire(n))
        };
        let drawn: HashMap<&str, &Node> =
            self.model.visible().map(|n| (n.id.as_str(), n)).collect();

        for n in self.model.visible() {
            let kids: Vec<&Node> = self
                .model
                .children
                .get(&n.id)
                .into_iter()
                .flatten()
                .filter_map(|k| drawn.get(k.as_str()).copied())
                .collect();
            if kids.is_empty() {
                continue;
            }
            let (pr, py, conn) = port(n);
            let ports: Vec<_> = kids.iter().map(|k| port(k)).collect();
            let left = ports.iter().map(|(r, _, _)| r.x).min().unwrap();
            // The junction column sits midway between the parent's right edge
            // and the leftmost child's left edge — with uniform columns that is
            // exactly the gutter's centre line.
            let jx = pr.right().max((pr.right() + left) / 2);
            let top = ports.iter().map(|(_, y, _)| *y).min().unwrap().min(py);
            let bottom = ports.iter().map(|(_, y, _)| *y).max().unwrap().max(py);
            // Cull the whole bundle when no part of it can be on screen.
            if !WorldRect::new(pr.x, top, jx - pr.x + 1, bottom - top + 1).intersects(&viewport)
                && !ports
                    .iter()
                    .any(|(r, y, _)| WorldRect::new(jx, *y, r.x - jx + 1, 1).intersects(&viewport))
            {
                continue;
            }
            hline(&mut p, o, pr.right(), jx, py, '─', conn);
            vline(&mut p, o, jx, top, bottom, '│', conn);
            for ((r, cy, kc), _) in ports.iter().zip(&kids) {
                hline(&mut p, o, jx + 1, r.x - 1, *cy, '─', *kc);
                set(
                    &mut p,
                    o,
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
                &mut p,
                o,
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

        // Cards last, so an edge never draws over the card it arrives at.
        for (i, n) in self.model.visible().enumerate() {
            let r = cam.scale_rect(n.world);
            if !r.intersects(&viewport) {
                continue; // culled: off camera costs a comparison, not a cell
            }
            let cells = block_cells_at(n, i == self.selected, self.palette, r.w, r.h);
            for (dy, row) in cells.iter().enumerate() {
                for (dx, cell) in row.iter().enumerate() {
                    if cell.continuation {
                        continue;
                    }
                    let width = Span::raw(cell.ch.to_string()).width() as i32;
                    set_cell(
                        &mut p,
                        o,
                        r.x + dx as i32,
                        r.y + dy as i32,
                        cell.ch,
                        width.max(1),
                        cell.style,
                    );
                }
            }
        }
    }
}

fn set(p: &mut Painter, o: (i32, i32), x: i32, y: i32, ch: char, style: Style) {
    set_cell(p, o, x, y, ch, 1, style);
}

fn set_cell(p: &mut Painter, o: (i32, i32), x: i32, y: i32, ch: char, width: i32, style: Style) {
    let mut buf = [0u8; 4];
    p.set(x - o.0, y - o.1, ch.encode_utf8(&mut buf), width, style);
}

/// A horizontal run, clipped to the viewport before it is walked — the loop is
/// bounded by the pane, never by the canvas.
fn hline(p: &mut Painter, o: (i32, i32), x0: i32, x1: i32, y: i32, ch: char, style: Style) {
    let lo = x0.max(o.0);
    let hi = x1.min(o.0 + p.area().width as i32 - 1);
    for x in lo..=hi {
        set(p, o, x, y, ch, style);
    }
}

fn vline(p: &mut Painter, o: (i32, i32), x: i32, y0: i32, y1: i32, ch: char, style: Style) {
    let lo = y0.max(o.1);
    let hi = y1.min(o.1 + p.area().height as i32 - 1);
    for y in lo..=hi {
        set(p, o, x, y, ch, style);
    }
}

/// Draw the Graph panel into `area`, highlighting the selected node.
pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let model = build_model(app);
    if model.visible_len() == 0 {
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
    f.render_widget(
        GraphScene {
            model: &model,
            palette: &app.palette,
            selected: if app.sidebar_focused {
                usize::MAX
            } else {
                model.selected
            },
        },
        area,
    );
}

// ── Card content ────────────────────────────────────────────────────────────

#[cfg(test)]
fn block_cells(n: &Node, selected: bool, pal: &crate::app::Palette) -> Vec<Vec<GCell>> {
    block_cells_at(n, selected, pal, n.world.w, n.world.h)
}

fn block_cells_at(
    n: &Node,
    selected: bool,
    pal: &crate::app::Palette,
    width: i32,
    height: i32,
) -> Vec<Vec<GCell>> {
    let (width, height) = (width.max(2) as usize, height.max(2) as usize);
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
        put(&mut block, x, 0, h, border);
        put(&mut block, x, height - 1, h, border);
    }
    for y in 1..height - 1 {
        put(&mut block, 0, y, v, border);
        put(&mut block, width - 1, y, v, border);
    }
    for (x, y, ch) in [
        (0, 0, tl),
        (width - 1, 0, tr),
        (0, height - 1, bl),
        (width - 1, height - 1, br),
    ] {
        put(&mut block, x, y, ch, border);
    }
    let budget = width.saturating_sub(4);
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
            fit_label(&n.label, budget)
        }
    } else {
        truncate_end(&n.title, budget)
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
                    budget,
                ),
                surface.add_modifier(Modifier::BOLD),
            ),
            (2, fit_label(&card_identity, budget), surface),
            (3, truncate_end(&detail, budget), surface.fg(accent)),
            (4, heading, surface.patch(theme::state_style(state, pal))),
            (5, truncate_end(&n.activity, budget), surface),
        ]
    } else {
        vec![
            (1, heading, surface.fg(accent).add_modifier(Modifier::BOLD)),
            (
                2,
                if n.kind == NodeKind::Session && n.title.is_empty() {
                    fit_label(main, budget)
                } else {
                    truncate_end(main, budget)
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
            if dx + cells > budget {
                break;
            }
            put(&mut block, 2 + dx, y, ch, style);
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

fn put(grid: &mut [Vec<GCell>], x: usize, y: usize, ch: char, style: Style) {
    if let Some(row) = grid.get_mut(y) {
        if let Some(slot) = row.get_mut(x) {
            *slot = GCell {
                ch,
                style,
                continuation: false,
            };
        }
    }
}

/// Coalesce each grid row's runs of same-style cells into ratatui spans.
#[cfg(test)]
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
    use crate::scene::Placed;
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

    fn aoide() -> Project {
        Project {
            name: "aoide".into(),
            path: "/home/k/Aoide".into(),
            ..Default::default()
        }
    }

    /// Paint the scene exactly as [`render`] does, into a standalone buffer.
    fn paint(app: &App, area: Rect) -> Buffer {
        let model = build_model(app);
        let mut buf = Buffer::empty(area);
        GraphScene {
            model: &model,
            palette: &app.palette,
            selected: model.selected,
        }
        .render(area, &mut buf);
        buf
    }

    fn dump(buf: &Buffer) -> String {
        let area = *buf.area();
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buf[(area.x + x, area.y + y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn painted(buf: &Buffer) -> usize {
        buf.content()
            .iter()
            .filter(|c| c.symbol() != " " && !c.symbol().is_empty())
            .count()
    }

    fn node<'a>(model: &'a Model, id: &str) -> &'a Node {
        model
            .nodes
            .iter()
            .find(|n| n.session_id.as_deref() == Some(id) || n.id == id || n.label == id)
            .unwrap_or_else(|| panic!("no node {id}"))
    }

    // ── The document → the typed model ─────────────────────────────────────

    #[test]
    fn model_lays_out_projects_then_spawned_children_in_columns() {
        let app = App::for_test(
            vec![aoide()],
            vec![
                session("root", "/home/k/Aoide", "running", None),
                session("kid", "/home/k/Aoide", "idle", Some("root")),
            ],
            Vec::new(),
        );
        let m = build_model(&app);
        // project (depth 0) → root session (depth 1) → spawned kid (depth 2).
        // Session labels render the display grammar (petnames plan P3), not the
        // bare id — so lookups go through `session_id`, the field that stays
        // the bare canonical id (Enter's focus jump unaffected by the label).
        let (proj, root, kid) = (node(&m, "aoide"), node(&m, "root"), node(&m, "kid"));
        assert_eq!((proj.depth, root.depth, kid.depth), (0, 1, 2));
        assert!(proj.row < root.row && root.row < kid.row);
        assert_eq!(kid.session_id.as_deref(), Some("kid"));
        // Columns are world coordinates, one card plus one gutter apart.
        assert_eq!(root.world.x - proj.world.x, CARD_W + GUTTER);
        assert_eq!(kid.world.x - root.world.x, CARD_W + GUTTER);
        assert_eq!((kid.world.w, kid.world.h), (CARD_W, CARD_H));
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
        let app = App::for_test(vec![aoide()], vec![root, sub, shell], Vec::new());
        let m = build_model(&app);
        assert_eq!(node(&m, "root").model.as_deref(), Some("claude-sonnet-5"));
        assert_eq!(node(&m, "kid").model.as_deref(), Some("claude-fable-5"));
        assert_eq!(node(&m, "term").model, None);
    }

    #[test]
    fn tags_flow_from_extra_read_only() {
        let mut s = session("t", "/home/k/Aoide", "running", None);
        s.extra
            .insert("tags".into(), serde_json::json!(["backend", "wip"]));
        let app = App::for_test(vec![aoide()], vec![s], Vec::new());
        let m = build_model(&app);
        assert_eq!(
            node(&m, "t").tags,
            vec!["backend".to_string(), "wip".to_string()]
        );
    }

    #[test]
    fn session_label_renders_the_display_grammar_while_session_id_stays_bare() {
        // Petnames plan P3: `Node.label` is the grammar string —
        // `<host>/<role>/<petname> (…<tail4>)`, legacy degrading to
        // `<host>/<role>/<sessionId>` — but `Node::session_id` stays the bare
        // canonical id no matter what, since Enter/`graph focus` reads that
        // field, never the label.
        let mut root = session("root", "/home/k/Aoide", "running", None);
        root.petname = Some("brave-otter".into());
        let mut kid = session("kid", "/home/k/Aoide", "working", Some("root"));
        kid.petname = Some("calm-thorn".into());
        let legacy = session("legacy-full-id", "/home/k/Aoide", "idle", None);
        let app = App::for_test(vec![aoide()], vec![root, kid, legacy], Vec::new());
        let m = build_model(&app);
        let host = aoide_storage::display::local_host_name();

        assert_eq!(
            node(&m, "root").label,
            format!("{host}/root/brave-otter (…root)")
        );
        assert_eq!(node(&m, "root").session_id.as_deref(), Some("root"));
        assert_eq!(
            node(&m, "kid").label,
            format!("{host}/child/calm-thorn (…kid)")
        );
        assert_eq!(
            node(&m, "legacy-full-id").label,
            format!("{host}/root/legacy-full-id"),
            "legacy (petname-less) node degrades to host/role/full-id"
        );
    }

    // ── Retention: the whole point of a retained scene ─────────────────────

    #[test]
    fn world_coordinates_survive_a_refresh_that_adds_and_removes_sessions() {
        let mut app = App::for_test(
            vec![aoide()],
            vec![
                session("a", "/home/k/Aoide", "working", None),
                session("b", "/home/k/Aoide", "idle", None),
                session("c", "/home/k/Aoide", "idle", None),
            ],
            Vec::new(),
        );
        app.sync_graph_scene();
        let before: HashMap<String, WorldRect> = build_model(&app)
            .nodes
            .iter()
            .map(|n| (n.id.clone(), n.world))
            .collect();
        assert_eq!(app.graph.positions.len(), before.len());

        // `b` ends and a new session arrives. A recomputed layout would hoist
        // `c` into `b`'s lane and shuffle every card under the operator's
        // cursor; the retained scene must not move anything that stayed.
        app.sessions.retain(|s| s.session_id != "b");
        app.sessions
            .push(session("d", "/home/k/Aoide", "working", None));
        app.sync_graph_scene();
        let after = build_model(&app);
        for n in &after.nodes {
            if let Some(was) = before.get(&n.id) {
                assert_eq!(&n.world, was, "{} moved on refresh", n.id);
            }
        }
        let d = node(&after, "d");
        assert!(
            after
                .nodes
                .iter()
                .filter(|n| n.id != d.id)
                .all(|n| !n.world.intersects(&d.world)),
            "the arrival lands clear of every retained card"
        );
        assert!(app.graph.positions.get("session:b").is_none());
    }

    #[test]
    fn selection_names_the_same_card_across_a_refresh() {
        let mut app = App::for_test(
            vec![aoide()],
            vec![session("zulu", "/home/k/Aoide", "working", None)],
            Vec::new(),
        );
        app.sync_graph_scene();
        select_index(&mut app, 1);
        assert_eq!(selected_session_id(&app).as_deref(), Some("zulu"));

        // A session sorting BEFORE the selected one arrives. Under an index
        // this silently moved the cursor onto the newcomer; an id cannot.
        app.sessions
            .insert(0, session("alpha", "/home/k/Aoide", "idle", None));
        app.sync_graph_scene();
        assert_eq!(
            selected_session_id(&app).as_deref(),
            Some("zulu"),
            "the cursor still names the card it was put on"
        );

        // Once the selected card leaves the forest the selection falls back to
        // the first node rather than pointing at nothing.
        app.sessions.retain(|s| s.session_id != "zulu");
        app.sync_graph_scene();
        assert_eq!(app.graph.selected, build_model(&app).nodes[0].id);
    }

    #[test]
    fn a_re_parented_session_moves_to_its_new_column() {
        let mut app = App::for_test(
            vec![aoide()],
            vec![
                session("parent", "/home/k/Aoide", "working", None),
                session("orphan", "/home/k/Aoide", "idle", None),
            ],
            Vec::new(),
        );
        app.sync_graph_scene();
        let was = node(&build_model(&app), "orphan").world;

        // The spawn edge resolves late: `orphan` is a child now, and a retained
        // column would draw it to the LEFT of its own parent.
        app.sessions
            .iter_mut()
            .find(|s| s.session_id == "orphan")
            .unwrap()
            .parent_session_id = Some("parent".into());
        app.sync_graph_scene();
        let m = build_model(&app);
        let now = node(&m, "orphan");
        assert_eq!(now.depth, node(&m, "parent").depth + 1);
        assert_eq!(now.world.x, node(&m, "parent").world.x + CARD_W + GUTTER);
        assert_ne!(now.world.x, was.x);
    }

    // ── The view choice ────────────────────────────────────────────────────

    #[test]
    fn focus_draws_the_picked_component_and_all_draws_the_whole_forest() {
        let other = Project {
            name: "dxflake".into(),
            path: "/home/k/dxflake".into(),
            ..Default::default()
        };
        let mut app = App::for_test(
            vec![aoide(), other],
            vec![
                session("mine", "/home/k/Aoide", "working", None),
                session("mykid", "/home/k/Aoide", "idle", Some("mine")),
                session("theirs", "/home/k/dxflake", "idle", None),
            ],
            Vec::new(),
        );
        app.sync_graph_scene();
        assert_eq!(app.graph.view, View::Focus, "focus is the default");

        select_index(&mut app, 1); // the aoide project's own session
        let visible: Vec<String> = node_order(&app).iter().map(|n| n.id.clone()).collect();
        assert!(visible
            .iter()
            .any(|id| id == "project:aoide" || id.contains("aoide")));
        assert!(visible.iter().any(|id| id.ends_with("mine")));
        assert!(visible.iter().any(|id| id.ends_with("mykid")));
        assert!(
            !visible.iter().any(|id| id.ends_with("theirs")),
            "another project's forest is not connected: {visible:?}"
        );

        toggle_view(&mut app);
        assert_eq!(app.graph.view, View::All);
        assert_eq!(node_order(&app).len(), build_model(&app).nodes.len());
        assert!(node_order(&app).iter().any(|n| n.id.ends_with("theirs")));
    }

    #[test]
    fn a_session_connected_to_nothing_shows_itself_alone() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("lonely", "/tmp/a", "idle", None),
                session("stranger", "/tmp/b", "idle", None),
            ],
            Vec::new(),
        );
        app.sync_graph_scene();
        // The synthetic gathering root is a grouping, never a connection —
        // picking one loose terminal must not drag in the other.
        let all = build_model(&app);
        let index = all
            .nodes
            .iter()
            .position(|n| n.session_id.as_deref() == Some("lonely"))
            .unwrap();
        app.graph.selected = all.nodes[index].id.clone();
        let visible = node_order(&app);
        assert_eq!(
            visible.len(),
            1,
            "{:?}",
            visible.iter().map(|n| &n.id).collect::<Vec<_>>()
        );
        assert_eq!(visible[0].session_id.as_deref(), Some("lonely"));

        // Picking the gathering root itself opens the sessions under it.
        app.graph.selected = UNANCHORED_ID.into();
        assert_eq!(node_order(&app).len(), 3);
    }

    // ── Camera: one transform for render, hit test and pan ─────────────────

    #[test]
    fn the_camera_follows_the_selection_and_hit_tests_the_card_it_painted() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("child", "/x", "idle", Some("root")),
            ],
            Vec::new(),
        );
        app.graph.view = View::All;
        let area = Rect::new(3, 2, 44, 12);
        for sel in 0..build_model(&app).visible_len() {
            select_index(&mut app, sel);
            let model = build_model(&app);
            let o = origin(&model, area);
            let r = model
                .camera
                .scale_rect(model.visible().nth(sel).unwrap().world);
            assert!(r.x >= o.0 && r.right() <= o.0 + area.width as i32);
            assert!(r.y >= o.1 && r.bottom() <= o.1 + area.height as i32);
            for dy in 0..r.h {
                for dx in 0..r.w {
                    let (x, y) = (
                        (area.x as i32 + r.x - o.0 + dx) as u16,
                        (area.y as i32 + r.y - o.1 + dy) as u16,
                    );
                    assert_eq!(hit_node(area, &app, x, y), Some(sel), "cell {dx},{dy}");
                }
            }
        }
        select_index(&mut app, 0);
        assert_eq!(
            hit_node(area, &app, area.x, area.y + CARD_H as u16),
            None,
            "the lane gutter is not a card"
        );
    }

    #[test]
    fn a_manual_pan_overrides_the_follow_camera_and_moves_the_hit_map_with_it() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("child", "/x", "idle", Some("root")),
            ],
            Vec::new(),
        );
        app.graph.view = View::All;
        let area = Rect::new(3, 4, 32, 7);
        let model = build_model(&app);
        let child = model
            .visible()
            .position(|n| n.session_id.as_deref() == Some("child"))
            .unwrap();
        let r = model
            .camera
            .scale_rect(model.visible().nth(child).unwrap().world);
        select_index(&mut app, 0);
        app.graph.camera.pan = Some((r.x, r.y));
        assert_eq!(graph_origin(&app, area), (r.x, r.y));
        assert_eq!(hit_node(area, &app, area.x, area.y), Some(child));
        assert_eq!(
            hit_node(area, &app, area.x + r.w as u16 - 1, area.y + r.h as u16 - 1),
            Some(child)
        );
        // A pan past the far edge clamps onto the padded canvas, never past it.
        app.graph.camera.pan = Some((i32::MAX, i32::MAX));
        let (w, h) = graph_extent(&app);
        assert_eq!(
            graph_origin(&app, area),
            (w - area.width as i32, h - area.height as i32)
        );
        // Releasing the pan hands the camera back to the selection.
        app.graph.camera.pan = None;
        assert_eq!(hit_node(area, &app, area.x, area.y), Some(0));
    }

    #[test]
    fn zoom_keeps_the_pointer_over_the_same_card_and_never_relays_out_the_world() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("child", "/x", "idle", Some("root")),
            ],
            Vec::new(),
        );
        app.graph.view = View::All;
        let area = Rect::new(3, 4, 24, 8);
        app.graph.camera.pan = Some((44, 1));
        let pointer = (area.x + 4, area.y + 2);
        let before = hit_node(area, &app, pointer.0, pointer.1);
        let world: Vec<WorldRect> = build_model(&app).nodes.iter().map(|n| n.world).collect();

        zoom_at(&mut app, area, pointer, 1);
        assert_eq!(app.graph.camera.zoom, 1);
        assert_eq!(hit_node(area, &app, pointer.0, pointer.1), before);
        assert_eq!(
            build_model(&app)
                .nodes
                .iter()
                .map(|n| n.world)
                .collect::<Vec<_>>(),
            world,
            "zoom is a camera transform: the retained world never moves"
        );
        zoom_at(&mut app, area, pointer, 1);
        assert_eq!(zoom_label(&app), "150%");
        let pan = app.graph.camera.pan;
        zoom_at(&mut app, area, pointer, 1);
        assert_eq!(app.graph.camera.pan, pan, "the ladder stops at 150%");
        let zoom = app.graph.camera.zoom;
        zoom_at(&mut app, area, (0, 0), -1);
        assert_eq!(
            app.graph.camera.zoom, zoom,
            "a pointer outside the pane is not a zoom"
        );
    }

    #[test]
    fn card_rectangles_match_the_painted_cells_and_the_hit_map_at_every_scale() {
        let mut app = App::for_test(vec![], vec![session("root", "/x", "working", None)], vec![]);
        app.graph.view = View::All;
        let area = Rect::new(2, 3, 60, 20);
        for zoom in crate::scene::ZOOM_MIN..=crate::scene::ZOOM_MAX {
            app.graph.camera.zoom = zoom;
            select_index(&mut app, 1);
            let model = build_model(&app);
            let n = model.visible().nth(1).unwrap();
            assert_eq!(
                (n.world.w, n.world.h),
                (CARD_W, CARD_H),
                "cards never resize"
            );
            let r = model.camera.scale_rect(n.world);
            let cells = block_cells_at(n, true, &app.palette, r.w, r.h);
            assert_eq!((cells[0].len() as i32, cells.len() as i32), (r.w, r.h));
            assert!(grid_to_lines(&cells)
                .iter()
                .all(|line| line.width() as i32 == r.w));

            let o = origin(&model, area);
            let buf = paint(&app, area);
            // The painted corner is the selected card's own heavy border.
            let (sx, sy) = (
                (area.x as i32 + r.x - o.0) as u16,
                (area.y as i32 + r.y - o.1) as u16,
            );
            assert_eq!(buf[(sx, sy)].symbol(), "┏", "zoom {zoom}");
            for dy in 0..r.h {
                for dx in 0..r.w {
                    assert_eq!(
                        hit_node(area, &app, (sx as i32 + dx) as u16, (sy as i32 + dy) as u16),
                        Some(1)
                    );
                }
            }
        }
    }

    // ── Painting: bounded by the viewport, cards over edges ────────────────

    #[test]
    fn culling_keeps_the_world_outside_the_camera_out_of_the_buffer() {
        let mut sessions = vec![session("root", "/x", "working", None)];
        for i in 0..40 {
            sessions.push(session(&format!("kid{i}"), "/x", "idle", Some("root")));
        }
        let mut app = App::for_test(vec![], sessions, Vec::new());
        app.graph.view = View::All;
        app.sync_graph_scene();
        let model = build_model(&app);
        assert!(model.visible_len() > 40, "a forest larger than any pane");

        let area = Rect::new(0, 0, 40, 12);
        // Camera parked on the near pad: every card is below and right of it.
        app.graph.camera.pan = Some((0, 0));
        let buf = paint(&app, area);
        assert_eq!(
            painted(&buf),
            0,
            "an empty corner of the canvas paints nothing:\n{}",
            dump(&buf)
        );

        // Camera on the first card: the fortieth child is far off screen and
        // must not reach the buffer, however large the forest is.
        select_index(&mut app, 0);
        app.graph.camera.pan = None;
        let buf = paint(&app, area);
        let text = dump(&buf);
        assert!(painted(&buf) > 0, "the selected card is painted");
        let last = node(&model, "kid39");
        assert!(
            !text.contains(&last.label[..last.label.len().min(12)]),
            "an off-camera card stayed out of the buffer:\n{text}"
        );
        // Nothing painted outside the pane, at any camera position.
        assert!(painted(&buf) <= (area.width * area.height) as usize);
    }

    #[test]
    fn a_card_paints_over_the_wire_that_crosses_it() {
        let app_base = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("left", "/x", "working", Some("root")),
                session("right", "/x", "idle", Some("root")),
            ],
            Vec::new(),
        );
        let mut app = app_base;
        app.graph.view = View::All;
        let base = build_model(&app);
        // Force a card onto the junction column: the vertical trunk between
        // `root` and its two children now runs straight through `right`'s
        // rectangle, so this proves the layering rather than assuming it.
        let ids: Vec<String> = base.nodes.iter().map(|n| n.id.clone()).collect();
        let mut placed: Vec<Placed> = base
            .nodes
            .iter()
            .map(|n| Placed {
                x: n.world.x,
                y: n.world.y,
                depth: n.depth,
            })
            .collect();
        let root = base
            .nodes
            .iter()
            .position(|n| n.id.ends_with("root"))
            .unwrap();
        let right = base
            .nodes
            .iter()
            .position(|n| n.id.ends_with("right"))
            .unwrap();
        let junction = placed[root].x + CARD_W + GUTTER / 2;
        placed[right].x = junction - CARD_W / 2;
        app.graph.positions.commit(ids, &placed);

        let model = build_model(&app);
        let ext = graph_extent(&app);
        let area = Rect::new(0, 0, ext.0 as u16, ext.1 as u16);
        app.graph.camera.pan = Some((0, 0));
        let o = origin(&model, area);
        let buf = paint(&app, area);
        let card = model.camera.scale_rect(node(&model, "right").world);
        assert!(
            (card.x..card.right()).contains(&junction),
            "the fixture really does park the card on the trunk"
        );
        // The card owns its interior: the trunk that runs through this column
        // shows above and below the card and nowhere inside it.
        for dy in 1..card.h - 1 {
            for dx in 1..card.w - 1 {
                let (x, y) = ((card.x - o.0 + dx) as u16, (card.y - o.1 + dy) as u16);
                let sym = buf[(x, y)].symbol();
                assert!(
                    !matches!(sym, "│" | "┬" | "┼" | "├"),
                    "a wire glyph survived inside the card at {dx},{dy}: {sym}\n{}",
                    dump(&buf)
                );
            }
        }
        // …and the trunk is not gone, only underneath: it still shows in the
        // same column band one row above the card.
        let above = (card.x..card.right())
            .filter(|x| buf[((x - o.0) as u16, (card.y - o.1 - 1) as u16)].symbol() == "│")
            .count();
        assert!(
            above > 0,
            "the trunk still runs through this column band:\n{}",
            dump(&buf)
        );
    }

    #[test]
    fn branches_take_separate_lanes_with_a_centred_parent_and_connected_ports() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("left", "/x", "working", Some("root")),
                session("right", "/x", "idle", Some("root")),
                session("leaf", "/x", "idle", Some("left")),
            ],
            Vec::new(),
        );
        app.graph.view = View::All;
        let model = build_model(&app);
        let (root, left, right, leaf) = (
            node(&model, "root"),
            node(&model, "left"),
            node(&model, "right"),
            node(&model, "leaf"),
        );
        assert_eq!(left.world.y, leaf.world.y);
        assert!(right.world.y >= left.world.y + LANE);
        assert_eq!(root.world.y, (left.world.y + right.world.y) / 2);

        // At every scale the card border stays whole where a wire arrives —
        // no port circles punched through it.
        for zoom in crate::scene::ZOOM_MIN..=crate::scene::ZOOM_MAX {
            app.graph.camera.zoom = zoom;
            app.graph.camera.pan = Some((0, 0));
            let ext = graph_extent(&app);
            let area = Rect::new(0, 0, ext.0 as u16, ext.1 as u16);
            let model = build_model(&app);
            let buf = paint(&app, area);
            for n in model.visible() {
                let r = model.camera.scale_rect(n.world);
                let y = (r.y + r.h / 2) as u16;
                for x in [r.x as u16, (r.right() - 1) as u16] {
                    assert!(
                        matches!(buf[(x, y)].symbol(), "│" | "┃"),
                        "zoom {zoom}: card edge at {x},{y} is {:?}",
                        buf[(x, y)].symbol()
                    );
                }
            }
        }
    }

    #[test]
    fn the_junction_sits_in_the_gutter_and_the_wire_reaches_both_cards() {
        let mut app = App::for_test(
            vec![],
            vec![
                session("root", "/x", "working", None),
                session("kid", "/x", "idle", Some("root")),
            ],
            Vec::new(),
        );
        app.graph.view = View::All;
        app.graph.camera.pan = Some((0, 0));
        let model = build_model(&app);
        let ext = graph_extent(&app);
        let area = Rect::new(0, 0, ext.0 as u16, ext.1 as u16);
        let buf = paint(&app, area);
        let root = node(&model, "root");
        let junction = (root.world.x + CARD_W + GUTTER / 2) as u16;
        let port = (root.world.y + CARD_H / 2) as u16;
        assert_eq!(buf[(junction, port)].symbol(), "─");
        assert_eq!(
            buf[((root.world.x + CARD_W) as u16, port)].symbol(),
            "─",
            "the wire leaves the parent's right edge"
        );
        assert_eq!(
            buf[((node(&model, "kid").world.x - 1) as u16, port)].symbol(),
            "─",
            "and reaches the child's left edge"
        );
    }

    #[test]
    fn a_narrow_pane_still_paints_the_selected_card() {
        let mut app = App::for_test(
            vec![aoide()],
            vec![
                session("root", "/home/k/Aoide", "working", None),
                session("kid", "/home/k/Aoide", "idle", Some("root")),
            ],
            Vec::new(),
        );
        app.sync_graph_scene();
        // 80x24 and 120x40 are the documented floors; the last two are the
        // degenerate panes a fold or a split can produce.
        for (w, h) in [(80, 24), (120, 40), (20, 6), (4, 2)] {
            for zoom in crate::scene::ZOOM_MIN..=crate::scene::ZOOM_MAX {
                app.graph.camera.zoom = zoom;
                for sel in 0..node_order(&app).len() {
                    select_index(&mut app, sel);
                    let area = Rect::new(0, 0, w, h);
                    let buf = paint(&app, area);
                    assert!(
                        painted(&buf) > 0,
                        "{w}x{h} zoom {zoom} sel {sel} painted nothing"
                    );
                    // Hit testing agrees with what was painted, narrow or not.
                    assert_eq!(
                        hit_node(area, &app, area.x, area.y).is_some(),
                        buf[(0, 0)].symbol() != " ",
                        "{w}x{h} zoom {zoom}: hit map and paint disagree at the corner"
                    );
                }
            }
        }
    }

    // ── Card content ──────────────────────────────────────────────────────

    #[test]
    fn blocks_preserve_metadata_and_palette_contrast() {
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
        let root = node(&model, "root");
        assert_eq!(root.world.y, node(&model, "child").world.y);
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
        assert!(lines.iter().all(|l| l.width() as i32 == CARD_W));
    }

    #[test]
    fn block_keeps_state_and_identity_on_separate_bounded_lines() {
        // Send-back regression (P3 review): post-P2 every session carries a
        // minted petname, so a REAL row's label is `<host>/<role>/<petname>
        // (…<tail4>)` — routinely 30+ chars on a real box, wider than the
        // whole pre-P3 chip. This fixture deliberately does NOT shrink the
        // host, petname, or session id — it drives the actual overflow path
        // `fit_label` exists for, not a fixture engineered to dodge it.
        let mut root = session(
            "sess-realistically-long-canonical-id-0001",
            "/home/k/Aoide",
            "working",
            None,
        );
        root.petname = Some("hardy-harbor".into()); // wordlist-shaped (petname.rs).
        root.extra
            .insert("tags".into(), serde_json::json!(["backend"]));
        let app = App::for_test(vec![aoide()], vec![root], Vec::new());
        let m = build_model(&app);
        let node = node(&m, "sess-realistically-long-canonical-id-0001");
        assert!(
            node.label.chars().count() as i32 > CARD_W,
            "fixture must exercise the overflow path: {} chars vs CARD_W={CARD_W}",
            node.label.chars().count()
        );

        let block = block_cells(node, false, &app.palette);
        let rendered: String = block.iter().flatten().map(|c| c.ch).collect();
        assert!(
            rendered.contains("working"),
            "state chip survives: {rendered:?}"
        );
        assert!(
            rendered.contains(" (…"),
            "tail4 handle survives: {rendered:?}"
        );
        assert!(block[3].len() as i32 <= CARD_W, "the row fits the card");
    }

    #[test]
    fn fit_label_ladder_preserves_the_tail_longest_and_degrades_in_order() {
        let label = "yomi-strix/child/hardy-harbor (…ab12)";
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
    fn a_session_card_carries_its_widget_fields_and_resolves_the_action_target() {
        let mut rec = session("canonical-id", "/x", "working", None);
        rec.title = Some("Review conductor".into());
        rec.petname = Some("calm-rook".into());
        rec.model = Some("fable".into());
        rec.tool = Some("Read".into());
        rec.activity = Some("Inspect graph".into());
        let mut app = App::for_test(vec![], vec![rec], vec![]);
        app.graph.view = View::All;
        select_index(&mut app, 1);
        let model = build_model(&app);
        let cells = block_cells(model.visible().nth(1).unwrap(), true, &app.palette);
        let line = |y: usize| cells[y].iter().map(|c| c.ch).collect::<String>();
        assert!(line(1).contains("Review conductor"));
        assert!(line(2).contains("calm-rook"));
        assert!(line(3).contains("claude · fable"));
        assert!(line(4).contains("working"));
        assert!(line(5).contains("Read · Inspect graph"));
        assert_eq!(selected_session_id(&app).as_deref(), Some("canonical-id"));

        let area = Rect::new(0, 0, 60, 20);
        let o = origin(&model, area);
        let r = model
            .camera
            .scale_rect(model.visible().nth(1).unwrap().world);
        assert_eq!(
            session_id_at(area, &app, (r.x - o.0) as u16, (r.y - o.1) as u16).as_deref(),
            Some("canonical-id")
        );
        select_index(&mut app, 0);
        assert!(selected_session_id(&app).is_none());
    }
}
