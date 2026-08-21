# AGENTS.md — aoide-screen

## Invariants

- **This crate is lyra-only.** Only `lyra` may register its commands; core
  `cli` must never depend on `aoide-screen` — that's the whole point of the
  P-A1 extraction (isolating the wayland/image dep weight off core).
- **Reach into `aoide_conduct::graph`, never duplicate it.** The 7
  session-graph symbols this crate uses (`SessionRecord`, `SessionsFile`,
  `load_stage`, `write_stage`, `sessions_path`, `session_send`,
  `normalize_addr`) are the sanctioned path; copying session logic in here
  reintroduces the split-brain the extraction was designed to avoid.
- **`capture_image` never decodes** except through `diff`'s explicit decode
  boundary (`image` crate) — the capture path itself stays decode-free; keep
  that scoping precise if extending it.
- **Module split is files, not a trait/backend seam** — `hypr`/`capture`/
  `ocr`/`synth`/`diff`/`text` are plain module hygiene, not an abstraction
  to generalize prematurely.

## Extension points

- **A new `screen` verb** adds a `cmd!`/`register` entry in `commands.rs`,
  wired into `lyra`'s `commands::all()` only.
- **A new coordinate-space source** (beyond `--from-shot`) extends `point`'s
  existing transform seam rather than adding a parallel one.

## Docs update required in the same commit

- This `README.md` when a new module, verb family, or dependency lands.
- `docs/architecture/PACKAGE-LAYOUT.md`'s charter-smudge note if the
  `conduct` back-reference changes shape.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
