//! `aoide screen` — a read-only view onto the desktop for agents, plus
//! passive capture. Phase 1 of the `screen` verb family: `screen info`
//! (monitors/cursor/workspace/clients/layers via typed `hyprctl -j` parses,
//! `hypr.rs`) and `screen shot` (grim/slurp capture + a JSON sidecar,
//! `capture.rs`) — Phase 4 extends `screen shot` with `--session`/`--window`
//! targeting (still `capture.rs`). Phase 2 adds `screen point` (pointer
//! synthesis via wlrctl, `point.rs`). Phase 3 adds `screen ocr` (tesseract
//! text extraction into the capture's own sidecar, `ocr.rs`). Phase 5 adds
//! `screen send` (`send.rs`) — hand a capture to a conducted session or a
//! registered A2A agent, the payoff of the whole family: capture → ocr →
//! SEND. `tools/pointer.sh` was Phase 2's behavioral spec, read but not
//! reused as code (a bash prototype, not a library).
//!
//! **Why `conduct`, not a new `management` crate**: the domain-crate charter
//! table (PACKAGE-LAYOUT.md) puts session/graph/window resolution in
//! `conduct`, and the later `screen` phases capture *session*-addressed
//! windows — the natural continuation of that charter. The host-generic
//! capture half (screen info/shot with no session in the loop, as built
//! here) is a plausible future `management`-crate carve-out once that crate
//! actually exists (it's deferred indefinitely, PACKAGE-LAYOUT.md's Phase 5
//! status note) — noted, not built: nothing here assumes or scaffolds that
//! split.
//!
//! **Module split** (khoa, 2026-08-16, module-hygiene note): `hypr` holds
//! every hyprctl-specific query (Hyprland's own compositor JSON); `capture`
//! holds the grim/slurp capture path (generic wlr protocols); `ocr` (phase 3)
//! holds the tesseract text-extraction path. Files, not a trait or a
//! backend seam — plain module hygiene.

pub mod capture;
pub mod hypr;
pub mod ocr;
pub mod point;
pub mod send;

pub use capture::shot;
pub use hypr::info;
pub use ocr::ocr;
pub use point::{point_click, point_idle, point_move, point_restore, point_save, point_scroll};
pub use send::send;
