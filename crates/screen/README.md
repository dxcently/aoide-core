# aoide-screen

`aoide screen`/`lyra screen` — a read-only view onto the desktop for agents,
plus pointer synthesis: `screen info` (monitors/cursor/workspace/clients via
`hyprctl -j`), `screen shot` (grim/slurp capture + JSON sidecar), `screen
point` (native `zwlr_virtual_pointer_v1` pointer synthesis), `screen ocr`
(tesseract text extraction), `screen diff` (pixel/inventory
act-verification), `screen point text` (click by OCR'd word, not by pixel).
Paint-side — ships in `lyra`, not core.

## Named seams (what it exposes)

- `capture` — grim/slurp shot pipeline + sidecar; `write_capture` is the
  shared capture-to-sidecar tail `diff` reuses.
- `hypr` — every Hyprland-specific `hyprctl -j` query.
- `point`/`synth` — pointer commands over the native wayland-protocol backend
  (no `wlrctl` shell-out).
- `ocr`/`text` — tesseract extraction and OCR-word-name click targeting.
- `diff` — pixel-changed bounding box + `hypr::info_delta`, turning "did my
  click do anything?" into a measurement.
- `commands` — this crate's CLI commands (`screen info/shot/point/ocr/diff/…`).

## What it consumes

`aoide-protocol`, `aoide-storage`, `aoide-conduct` (7 session-graph symbols,
including `normalize_addr`), `aoide-client`. Carries this workspace's only
heavy deps: `wayland-client`, `wayland-protocols-wlr`, `image`.

## How it composes

Only `lyra` depends on it — `screen` is graphical-binary surface, extracted
out of `conduct` at P-A1 specifically so core stays headless-safe.
**Charter smudge**: it reaches back into `aoide_conduct::graph` for
session/graph symbols rather than duplicating them, because the
*session*-addressed screen commands were a natural continuation of `conduct`'s
original charter even after the crate itself moved
(`docs/architecture/PACKAGE-LAYOUT.md`).
