//! Command groups — lyra's own bundle assembly (P-A4 of the binary-split
//! workstream, docs/architecture/PACKAGE-LAYOUT.md). Each DOMAIN crate
//! contributes its entries via its own `commands::register(&mut Registry)`
//! function — the SAME functions `aoide-cli` calls for these groups; lyra is
//! a second composition root over shared handler code, not a fork of it
//! (Cordis correspondence, plan's "Verified facts" section: an app crate's
//! explicit `register()` list is the bundle's profile, not an import-list
//! violation).
//!
//! [`all`] assembles the graphical bundle in the SAME relative order these
//! groups hold in core's `commands/mod.rs::all()` today: meta (guide/
//! schema/mcp serve — root-coupled, see `commands/infra.rs`'s doc comment
//! for why `mcp serve` is here despite not being named in the plan's group
//! list), onboard (P-I3: the nix half of the onboarding flow — root-coupled
//! like `meta`, appended right after it: a root-level command, registered
//! before `mcp.serve`, matching core's own relative placement of `onboard`
//! in `crates/cli/src/commands/mod.rs::all()`), rice, draft,
//! mode, cover, livery, rice-late stubs (declare/transpose only — NOT
//! content/make/update, which stay core), shellbridge, quickshell
//! (healthcheck only — the placeholder-screen watchdog), reload (the one
//! mode-aware iteration command, `lyra reload` design settled 2026-08-31 —
//! absorbed `quickshell reload` outright, registered right after
//! `quickshell` where that path used to sit), screen, herald, take, element
//! (L-E1, docs/architecture/ELEMENTS.md: `element seed`, the render
//! pipeline's shell-reachable bridge), secrets (P3: `secrets ask`, the
//! rice-shaped TOTP code-entry popup), pair (`pair ask` + `pair show`, the
//! pairing-ceremony's own two dialog shapes — a typed-code entry surface on
//! either direction and a reply-code display surface, sharing `secrets
//! ask`'s six-box QML component's PARENT module (`dialog_qml`) without
//! sharing its entry surface — root-coupled like `meta`/`onboard` in shape),
//! preview (P1: `preview` + `preview.set`, an ISOLATED quickshell canvas for
//! iterating on one widget — its own root under `$XDG_RUNTIME_DIR/aoide-
//! preview`, never the live daemon's socket dir — plus a same-lane
//! follow-up's `preview.declare`, the canvas's own `rice declare`
//! counterpart), preview_tools (P6: `preview.shot` + `preview.tree` +
//! `preview.notes`, shell-first agent tools over that same isolated
//! canvas — a screenshot of the screen/canvas/widget/one element, the
//! canvas's live item tree joined against a static parse of the widget's
//! own QML source, and a small scaffolding-notes store — all appended
//! LAST per golden discipline's "append, never reorder,"
//! `pkgs/aoide/crates/AGENTS.md`). Core-only groups (graph, adapter melete,
//! conductor, a2a serve, agents, nodes, usage, hooks, daemon, soundcheck)
//! are absent — lyra never registers them.
//!
//! Path count: 2 (meta) + 1 (onboard) + 1 (mcp.serve) + 3 (rice) + 3 (draft)
//! + 4 (mode) + 1 (cover) + 3 (livery) + 2 (rice-late) + 1 (shellbridge) + 1
//! (quickshell: healthcheck) + 1 (reload) + 14 (screen) + 1 (herald) + 6
//! (take) + 1 (element.seed) + 1 (secrets ask) + 2 (pair ask, pair show) +
//! 3 (preview, preview.set, preview.declare) + 3 (preview.shot,
//! preview.tree, preview.notes) + 3 (icon.collections, icon.list, icon.resolve) =
//! 57 (P-I3: 42 -> 43; P3: 43 -> 44; L-E1: 44 -> 45; P-PV3 landing: 45 ->
//! 46; P-PV3 revert (`pair confirm` added): 46 -> 47; `quickshell
//! healthcheck`: 47 -> 48; R2's own repurpose (`pair confirm` -> `pair
//! show`): 48 -> 48, net zero; `reload`'s absorption of `quickshell reload`
//! (`lyra reload` design, settled 2026-08-31): 48 -> 48, net zero — one path
//! dies, one lands, same as R2's own swap; P1's `preview`/`preview.set`:
//! 48 -> 50; a same-lane follow-up's `preview.declare`: 50 -> 51; P6's
//! `preview.shot`/`preview.tree`/`preview.notes`: 51 -> 54; I1's `icon.collections`/`icon.list`/`icon.resolve`: 54 -> 57). The
//! plan's phase description estimated 41 (the named groups
//! alone, without `mcp.serve`); verified by
//! generating (`lyra schema --json | jq '.commands|length'`) — `mcp.serve`
//! must be a registered path for `aoide_protocol::door::parse` to ever reach
//! `lib.rs`'s `special` closure on `mcp serve --stdio`, exactly like core's
//! own `mcp.serve` entry. See `crates/lyra/src/registry.rs`'s golden test
//! for the exact path list — that list, not this arithmetic, is the
//! authority (`pkgs/aoide/crates/AGENTS.md`'s "no count or tally lives
//! anywhere else").
pub mod dialog_qml;
pub mod icon;
pub mod infra;
pub mod meta;
pub mod onboard;
pub mod pair;
pub mod preview;
pub mod preview_tools;
pub mod secrets;
pub mod stubs;

use crate::registry::Registry;

pub fn all() -> Registry {
    let mut r = Registry::new();

    meta::register(&mut r); // guide, schema
    onboard::register(&mut r); // onboard (P-I3: the nix half of the onboarding flow, root-coupled like meta)
    infra::register_mcp(&mut r); // mcp serve (root-coupled: reads this assembled registry)
    aoide_song::commands::rice::register(&mut r); // rice lint, stage, compose
    aoide_song::commands::draft::register(&mut r); // rice draft save/list/drop
    aoide_song::commands::mode::register(&mut r); // rice mode status/stage/declarative/draft
    aoide_song::commands::cover::register(&mut r); // cover set
    aoide_song::commands::livery::register(&mut r); // livery emit, resolve, lint
    stubs::register_rice_late(&mut r); // rice declare, transpose
    aoide_conduct::commands::shellbridge::register(&mut r); // shellbridge (own module since P-A2)
    aoide_song::commands::quickshell::register(&mut r); // quickshell healthcheck — placeholder-screen watchdog
    aoide_song::commands::reload::register(&mut r); // reload — the one mode-aware iteration command (absorbed quickshell reload)
    aoide_screen::commands::register(&mut r); // screen info, shot, point *, ocr, diff, send (own crate since P-A1)
    aoide_conduct::commands::herald::register(&mut r); // herald push — dunst's script hook into the notification ledger
    aoide_song::commands::take::register(&mut r); // rice take/take.*, rice back — explicit take-store snapshot
    aoide_song::commands::elements::register(&mut r); // element seed — full render into run/elements/ (L-E1)
    secrets::register(&mut r); // secrets ask — the rice-shaped TOTP code-entry popup (P3)
    pair::register(&mut r); // pair ask + pair show — the pairing-ceremony's own two dialog shapes
    preview::register(&mut r); // preview + preview.set + preview.declare — an isolated quickshell canvas for one widget (P1, then a same-lane follow-up added declare)
    preview_tools::register(&mut r); // preview.shot + preview.tree + preview.notes — shell-first agent tools over that same canvas (P6): screenshots, the live/static-joined item tree, and scaffolding notes
    icon::register(&mut r); // icon.collections + icon.list + icon.resolve — the pinned icon collections (Iconify data) resolved into the facet's own SVG tree, no network at render (I1)

    r
}
