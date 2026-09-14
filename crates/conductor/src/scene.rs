//! Scene primitives for the retained graph — world space, camera, clipped
//! painter, and the retained position store.
//!
//! The graph is a RETAINED scene, not a picture recomputed from scratch each
//! frame. Three facts make that true and live here, away from the graph's
//! content:
//!
//! * **World space.** A card is a fixed [`WorldRect`] in world cells (one
//!   world cell is one terminal cell at 100%). Cards never resize, reflow or
//!   swap presets; only the [`Camera`] between world and screen changes.
//! * **Retained coordinates.** [`Positions`] is the store a card's world
//!   coordinates survive a refresh in. A node already placed keeps exactly
//!   where it is when unrelated nodes appear or vanish, so the canvas stops
//!   reshuffling under the operator's cursor.
//! * **Culling.** [`Painter`] clips every write to the viewport, so a card or
//!   a wire outside the camera costs one comparison — never a buffer cell,
//!   never an allocation. Nothing ever materialises the whole world.
//!
//! The scene's own state ([`SceneState`]) lives on the app, outside render:
//! camera, selection, view choice and retained positions all persist between
//! frames, and render records the rectangles it actually painted so a mouse
//! hit reads the same geometry a key does.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use std::collections::BTreeMap;

/// A card's rectangle in world cells. Signed so clipping arithmetic stays
/// honest once the camera puts a card left of or above the viewport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorldRect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl WorldRect {
    pub fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        WorldRect { x, y, w, h }
    }
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }
    pub fn intersects(&self, other: &WorldRect) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }
}

/// The zoom ladder, in percent — 50/75/100/125/150.
pub const ZOOM_MIN: i8 = -2;
pub const ZOOM_MAX: i8 = 2;

/// The camera between world space and the viewport.
///
/// `pan` is the viewport's top-left in SCALED cells (world × zoom): panning is
/// a screen gesture, so the camera remembers where the screen sits rather than
/// where the world does, and a pan keeps its screen meaning across a zoom.
/// `None` means the camera follows the selection instead of a manual pan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Camera {
    pub pan: Option<(i32, i32)>,
    pub zoom: i8,
}

impl Camera {
    /// Camera scale in percent.
    pub fn scale(&self) -> i32 {
        100 + self.zoom.clamp(ZOOM_MIN, ZOOM_MAX) as i32 * 25
    }

    /// Human label for the zoom step — the canvas readout.
    pub fn zoom_label(&self) -> &'static str {
        match self.zoom.clamp(ZOOM_MIN, ZOOM_MAX) {
            -2 => "50%",
            -1 => "75%",
            1 => "125%",
            2 => "150%",
            _ => "100%",
        }
    }

    /// World rect → scaled rect, absolute (the pan is not applied yet).
    /// Both edges scale before the width is taken, so adjacent cards stay
    /// adjacent and no card loses or gains a cell to rounding.
    pub fn scale_rect(&self, r: WorldRect) -> WorldRect {
        let s = self.scale();
        let x = r.x * s / 100;
        let y = r.y * s / 100;
        WorldRect::new(x, y, r.right() * s / 100 - x, r.bottom() * s / 100 - y)
    }

    /// World rect → viewport-relative rect, given the resolved origin.
    pub fn project(&self, r: WorldRect, origin: (i32, i32)) -> WorldRect {
        let s = self.scale_rect(r);
        WorldRect::new(s.x - origin.0, s.y - origin.1, s.w, s.h)
    }

    /// A viewport-relative point → the scaled point under it.
    pub fn unproject(&self, x: i32, y: i32, origin: (i32, i32)) -> (i32, i32) {
        (origin.0 + x, origin.1 + y)
    }
}

/// Which slice of the forest the canvas draws.
///
/// `Focus` is the default the operator asked for: the picked node plus
/// everything it is actually connected to, and nothing else. `All` is the
/// explicit whole-forest view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    #[default]
    Focus,
    All,
}

impl View {
    pub fn label(&self) -> &'static str {
        match self {
            View::Focus => "FOCUS",
            View::All => "ALL",
        }
    }
    pub fn toggled(&self) -> View {
        match self {
            View::Focus => View::All,
            View::All => View::Focus,
        }
    }
}

/// One card's retained world coordinates, with the depth they were chosen for.
///
/// Depth rides along because a retained position must not outlive the lineage
/// it describes: a session that gains a parent genuinely moved in the graph,
/// and re-placing it is the honest picture. Everything else stays put.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Placed {
    pub x: i32,
    pub y: i32,
    pub depth: usize,
}

/// The retained position store: node id → the world coordinates it keeps
/// across refreshes.
#[derive(Clone, Debug, Default)]
pub struct Positions(BTreeMap<String, Placed>);

impl Positions {
    /// Resolve a freshly laid-out forest against the retained store, in
    /// `fresh` order. Pure: the caller decides whether the result becomes the
    /// new retained truth ([`Positions::commit`]).
    ///
    /// A node already retained at the same depth keeps its coordinates. A new
    /// node takes the fresh layout's slot, pushed down one `lane` at a time
    /// until it overlaps nothing already fixed — so an arrival never lands on
    /// top of a card that was already on the canvas.
    pub fn place(&self, fresh: &[(String, Placed)], card: (i32, i32), lane: i32) -> Vec<Placed> {
        let retained: Vec<Option<Placed>> = fresh
            .iter()
            .map(|(id, f)| self.0.get(id).copied().filter(|p| p.depth == f.depth))
            .collect();
        let mut taken: Vec<Placed> = retained.iter().flatten().copied().collect();
        let mut out = Vec::with_capacity(fresh.len());
        for ((_, f), kept) in fresh.iter().zip(&retained) {
            let placed = kept.unwrap_or_else(|| {
                let mut y = f.y;
                while taken
                    .iter()
                    .any(|t| t.x == f.x && y < t.y + card.1 && t.y < y + card.1)
                {
                    y += lane.max(1);
                }
                let p = Placed {
                    x: f.x,
                    y,
                    depth: f.depth,
                };
                taken.push(p);
                p
            });
            out.push(placed);
        }
        out
    }

    /// Make a resolved placement the retained truth, dropping every node that
    /// left the forest.
    pub fn commit(&mut self, ids: impl IntoIterator<Item = String>, placed: &[Placed]) {
        self.0 = ids
            .into_iter()
            .zip(placed.iter().copied())
            .collect::<BTreeMap<_, _>>();
    }

    pub fn get(&self, id: &str) -> Option<Placed> {
        self.0.get(id).copied()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A clipped cell writer over the frame buffer — the culling seam.
///
/// Coordinates are viewport-relative and signed; anything outside `area` is
/// dropped without touching the buffer. Painting the scene is therefore a
/// walk over the nodes the camera can see, never over the world.
pub struct Painter<'a> {
    buf: &'a mut Buffer,
    area: Rect,
}

impl<'a> Painter<'a> {
    pub fn new(buf: &'a mut Buffer, area: Rect) -> Self {
        Painter { buf, area }
    }

    pub fn area(&self) -> Rect {
        self.area
    }

    /// Paint one glyph `width` cells wide. A glyph that would straddle the
    /// viewport edge is dropped whole, so a wide character never half-paints
    /// over the cell beyond the clip.
    pub fn set(&mut self, x: i32, y: i32, symbol: &str, width: i32, style: Style) {
        if y < 0 || x < 0 || width <= 0 {
            return;
        }
        if y >= self.area.height as i32 || x + width > self.area.width as i32 {
            return;
        }
        let (cx, cy) = (self.area.x + x as u16, self.area.y + y as u16);
        self.buf[(cx, cy)].set_symbol(symbol).set_style(style);
        // ratatui's own convention for a wide glyph: the cells it covers carry
        // an empty symbol so the buffer's width bookkeeping stays right.
        for i in 1..width as u16 {
            self.buf[(cx + i, cy)].set_symbol("").set_style(style);
        }
    }
}

/// The graph scene's persistent state — camera, selection, view choice and
/// retained positions.
///
/// It lives on the app, outside render, so a frame never has to reconstruct
/// what the previous one decided. Render stays pure and reads it: a mouse hit
/// and a key resolve the same card because both run the same [`Camera`]
/// transform over the same retained world, not because one frame recorded
/// rectangles for the next event to find.
#[derive(Clone, Debug, Default)]
pub struct SceneState {
    pub camera: Camera,
    pub view: View,
    pub positions: Positions,
    /// The selected node's id — the scene's anchor. Empty means "the first
    /// node in the forest". An index cannot survive a refresh: a session
    /// arriving earlier in preorder would silently move the cursor onto a
    /// different card. An id names the same card or no card at all.
    pub selected: String,
    pub pan_mode: bool,
    /// An in-flight camera drag: pointer origin and the camera origin it started from.
    pub drag: Option<(u16, u16, i32, i32)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: (i32, i32) = (32, 7);
    const LANE: i32 = 11;

    fn fresh(rows: &[(&str, i32, i32, usize)]) -> Vec<(String, Placed)> {
        rows.iter()
            .map(|(id, x, y, d)| {
                (
                    (*id).to_string(),
                    Placed {
                        x: *x,
                        y: *y,
                        depth: *d,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn camera_projects_and_unprojects_the_same_point_at_every_scale() {
        let card = WorldRect::new(40, 16, CARD.0, CARD.1);
        for zoom in ZOOM_MIN..=ZOOM_MAX {
            let cam = Camera { pan: None, zoom };
            let scaled = cam.scale_rect(card);
            // Adjacent world cards stay adjacent: the next column's left edge
            // is exactly this one's scaled right edge.
            let next = cam.scale_rect(WorldRect::new(card.right(), 16, CARD.0, CARD.1));
            assert_eq!(next.x, scaled.right(), "no rounding gap at zoom {zoom}");

            let origin = (scaled.x - 3, scaled.y - 2);
            let screen = cam.project(card, origin);
            assert_eq!((screen.x, screen.y), (3, 2));
            assert_eq!((screen.w, screen.h), (scaled.w, scaled.h));
            // A viewport point unprojects onto the scaled point it covers.
            assert_eq!(cam.unproject(3, 2, origin), (scaled.x, scaled.y));
            // Every cell of the projected rect maps back inside the scaled rect.
            for dy in 0..screen.h {
                for dx in 0..screen.w {
                    let (sx, sy) = cam.unproject(screen.x + dx, screen.y + dy, origin);
                    assert!(scaled.contains(sx, sy), "zoom {zoom} cell {dx},{dy}");
                }
            }
        }
    }

    #[test]
    fn zoom_clamps_to_the_ladder_and_labels_every_step() {
        for (zoom, label) in [
            (-9, "50%"),
            (-2, "50%"),
            (-1, "75%"),
            (0, "100%"),
            (9, "150%"),
        ] {
            let cam = Camera { pan: None, zoom };
            assert_eq!(cam.zoom_label(), label);
        }
        assert_eq!(
            Camera {
                pan: None,
                zoom: -2
            }
            .scale(),
            50
        );
        assert_eq!(Camera { pan: None, zoom: 2 }.scale(), 150);
    }

    #[test]
    fn retained_positions_survive_arrivals_and_departures() {
        let mut store = Positions::default();
        let first = fresh(&[("a", 40, 16, 0), ("b", 84, 16, 1), ("c", 84, 27, 1)]);
        let placed = store.place(&first, CARD, LANE);
        assert_eq!(placed[1].y, 16);
        store.commit(first.iter().map(|(id, _)| id.clone()), &placed);

        // `b` departs. The fresh layout would hoist `c` into `b`'s lane —
        // the retained store keeps `c` exactly where the operator last saw it.
        let second = fresh(&[("a", 40, 16, 0), ("c", 84, 16, 1)]);
        let placed = store.place(&second, CARD, LANE);
        assert_eq!(placed[0], store.get("a").unwrap());
        assert_eq!(placed[1].y, 27, "c keeps its retained lane");
        store.commit(second.iter().map(|(id, _)| id.clone()), &placed);
        assert_eq!(store.len(), 2, "the departed node leaves the store");
        assert!(store.get("b").is_none());

        // A newcomer whose fresh slot is occupied gets pushed clear instead of
        // stacking on the retained card.
        let third = fresh(&[("a", 40, 16, 0), ("c", 84, 16, 1), ("d", 84, 27, 1)]);
        let placed = store.place(&third, CARD, LANE);
        assert_eq!(placed[1].y, 27, "c still retained");
        assert!(
            placed[2].y >= 27 + CARD.1,
            "the newcomer clears the retained card: {:?}",
            placed[2]
        );
    }

    #[test]
    fn a_node_that_changes_depth_is_replaced_not_retained() {
        let mut store = Positions::default();
        let first = fresh(&[("a", 40, 16, 0), ("b", 40, 27, 0)]);
        let placed = store.place(&first, CARD, LANE);
        store.commit(first.iter().map(|(id, _)| id.clone()), &placed);

        // `b` gained a parent: it belongs in column 1 now, and a retained
        // column-0 coordinate would draw a child left of its own parent.
        let second = fresh(&[("a", 40, 16, 0), ("b", 84, 16, 1)]);
        let placed = store.place(&second, CARD, LANE);
        assert_eq!(placed[0].y, 16, "the unchanged node stays put");
        assert_eq!(
            (placed[1].x, placed[1].depth),
            (84, 1),
            "the re-parented node moves to its new column"
        );
    }

    #[test]
    fn the_painter_drops_every_write_outside_the_viewport() {
        let area = Rect::new(4, 2, 6, 3);
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 10));
        let mut p = Painter::new(&mut buf, area);
        p.set(0, 0, "A", 1, Style::default());
        p.set(5, 2, "B", 1, Style::default());
        // Outside on every side, and a wide glyph straddling the right edge.
        p.set(-1, 0, "x", 1, Style::default());
        p.set(0, -1, "x", 1, Style::default());
        p.set(6, 0, "x", 1, Style::default());
        p.set(0, 3, "x", 1, Style::default());
        p.set(5, 1, "界", 2, Style::default());

        assert_eq!(buf[(4, 2)].symbol(), "A");
        assert_eq!(buf[(9, 4)].symbol(), "B");
        assert_eq!(
            buf[(9, 3)].symbol(),
            " ",
            "the straddling wide glyph is dropped"
        );
        let painted = buf
            .content()
            .iter()
            .filter(|c| c.symbol() != " " && !c.symbol().is_empty())
            .count();
        assert_eq!(
            painted, 2,
            "nothing outside the viewport reached the buffer"
        );
    }

    #[test]
    fn the_painter_blanks_the_cells_a_wide_glyph_covers() {
        let area = Rect::new(0, 0, 4, 1);
        let mut buf = Buffer::empty(area);
        Painter::new(&mut buf, area).set(1, 0, "界", 2, Style::default());
        assert_eq!(buf[(1, 0)].symbol(), "界");
        assert_eq!(buf[(2, 0)].symbol(), "");
    }

    #[test]
    fn world_rects_report_overlap_in_both_directions() {
        let a = WorldRect::new(0, 0, 10, 5);
        assert!(a.intersects(&WorldRect::new(9, 4, 10, 5)));
        assert!(WorldRect::new(9, 4, 10, 5).intersects(&a));
        assert!(!a.intersects(&WorldRect::new(10, 0, 10, 5)));
        assert!(!a.intersects(&WorldRect::new(0, 5, 10, 5)));
        assert!(a.contains(9, 4) && !a.contains(10, 4));
    }
}
