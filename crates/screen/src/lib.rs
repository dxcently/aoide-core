//! `aoide screen` — a read-only view onto the desktop for agents, plus
//! passive capture. Phase 1 of the `screen` verb family: `screen info`
//! (monitors/cursor/workspace/clients/layers via typed `hyprctl -j` parses,
//! `hypr.rs`) and `screen shot` (grim/slurp capture + a JSON sidecar,
//! `capture.rs`) — Phase 4 extends `screen shot` with `--session`/`--window`
//! targeting (still `capture.rs`). Phase 2 adds `screen point` (pointer
//! synthesis, `point.rs`). Phase 3 adds `screen ocr` (tesseract
//! text extraction into the capture's own sidecar, `ocr.rs`). Phase 5 adds
//! `screen send` (`send.rs`) — hand a capture to a conducted session or a
//! registered A2A agent, the payoff of the whole family: capture → ocr →
//! SEND. `tools/pointer.sh` was Phase 2's behavioral spec, read but not
//! reused as code (a bash prototype, not a library). Phase A of the
//! pointer-emulation workstream (khoa, 2026-08-17) then replaced Phase 2's
//! wlrctl shell-out with a native `zwlr_virtual_pointer_v1` backend
//! (`synth.rs`) behind the same boundary — `point.rs`'s verbs are unchanged.
//! Phase B (khoa, same day) adds `screen point drag`/`screen point hover`
//! and extends `click`/`scroll` (`--count`, a second scroll axis) — still
//! `point.rs`/`hypr.rs`, no new module. Phase D (khoa, 2026-08-17) closes the
//! model-space<->screen-space loop: `screen shot` gains `--fit WxH` (a
//! model-friendly downscale with an exact inverse scale recorded in the
//! sidecar) and `--cursor`, plus a full `desktop` snapshot embedded in every
//! sidecar (`capture.rs`/`hypr.rs`); every coordinate-taking `screen point`
//! verb gains `--from-shot <capture>` to consume image-space coordinates off
//! that same sidecar (`point.rs`) — still no new module, the loop closes
//! entirely within `capture`/`hypr`/`point`. Phase E (khoa, 2026-08-17) adds
//! `screen diff` (`diff.rs`) — mechanical act-verification: re-shoot a prior
//! `screen shot`'s identical rect, decode both images (the first module in
//! this workspace with any reason to; `capture_image` itself still never
//! decodes), and report a pixel-changed bounding box plus a `hypr::info_delta`
//! inventory, turning "did my click do anything?" from an LLM judgement into
//! a measurement. `capture.rs`'s own capture-to-sidecar tail was extracted
//! into `write_capture` this phase so `diff()`'s after-shot is not a second
//! capture pipeline. Phase F (khoa, 2026-08-17) adds `screen point text`
//! (`text.rs`) — click a word/phrase `screen ocr` already located by NAME
//! instead of by picking a pixel off the image by eye; `--from-shot` here
//! selects the OCR source, never a coordinate space (see that module's own
//! header for why no transform applies).
//!
//! **Own crate, not `conduct`, not a `management` crate** (P-A1 of the
//! binary-split workstream, 2026-08-21): this module lived in `aoide-conduct`
//! from Phase 1 through P-A0 — the domain-crate charter table
//! (PACKAGE-LAYOUT.md) put session/graph/window resolution there, and the
//! *session*-addressed `screen` phases were a natural continuation of that
//! charter. The split (Workstream A, binary-split plan) pulls it out into
//! its own leaf crate instead: `screen` carries this workspace's only heavy
//! deps (wayland-client/wayland-protocols-wlr/image) and belongs to the
//! future graphical binary (`lyra`), while `conduct`'s session/graph core
//! stays in the headless-safe core binary. `screen` still reaches back into
//! `aoide_conduct::graph` for seven session-graph symbols (`SessionRecord`,
//! `SessionsFile`, `load_stage`, `write_stage`, `sessions_path`,
//! `session_send`, `normalize_addr` — the last widened from `pub(crate)` to
//! `pub` for exactly this) rather than duplicating any of that logic. The
//! host-generic capture half (screen info/shot with no session in the loop,
//! as built here) is a plausible future `management`-crate carve-out once
//! that crate actually exists (it's deferred indefinitely, PACKAGE-LAYOUT.md's
//! Phase 5 status note) — noted, not built: nothing here assumes or
//! scaffolds that split.
//!
//! **Module split** (khoa, 2026-08-16, module-hygiene note; extended
//! 2026-08-17 as later phases landed): `hypr` holds every hyprctl-specific
//! query (Hyprland's own compositor JSON); `capture` holds the grim/slurp
//! capture path (generic wlr protocols); `ocr` (phase 3) holds the tesseract
//! text-extraction path; `synth` (Phase A) holds the native
//! `zwlr_virtual_pointer_v1` pointer-synthesis boundary; `diff` (Phase E)
//! holds the pixel/inventory diff path, including the one `image`-crate
//! decode boundary in this workspace; `text` (Phase F) holds the pure
//! OCR-word text matcher plus `screen point text`'s handler. Files, not a
//! trait or a backend seam — plain module hygiene.

pub mod capture;
/// The `screen *` verbs' registry wiring (moved from
/// `aoide-conduct`'s `commands/screen.rs` at P-A1) — thin registrations over
/// this crate's domain modules; see its own header for the split from
/// verb logic.
pub mod commands;
pub mod diff;
pub mod hypr;
pub mod ocr;
pub mod point;
pub mod send;
/// The pointer-synthesis boundary's HOW half (Phase A, pointer-emulation
/// workstream) — the only module allowed to name `wayland_client`/
/// `wayland_protocols_wlr` types; see its own header for the full story.
pub mod synth;
/// `screen point text` (Phase F, pointer-emulation workstream) — click a
/// word/phrase `screen ocr` already located; see this module's own header
/// for the pure matcher and the `--from-shot` semantics warning.
pub mod text;

pub use capture::shot;
pub use diff::diff;
pub use hypr::info;
pub use ocr::ocr;
pub use point::{
    point_click, point_drag, point_hover, point_idle, point_move, point_restore, point_save,
    point_scroll,
};
pub use send::send;
pub use text::point_text;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STATE_DIR`, `AOIDE_STAGE_DIR`, `XDG_RUNTIME_DIR`,
/// `AOIDE_AUDIT_LOG`, …) — `send.rs`'s tests moved here verbatim from
/// `aoide-conduct` at P-A1 still need one. Delegates to
/// `aoide-test-support`'s single process-wide mutex (the `aoide-storage`
/// pattern, `crates/storage/src/lib.rs`) rather than re-declaring conduct's
/// own crate-local static: this crate's tests don't share a test binary
/// with conduct's, so there's nothing conduct-local left to serialise
/// against — the shared mutex is just as correct and avoids a second,
/// pointlessly-crate-scoped lock.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
