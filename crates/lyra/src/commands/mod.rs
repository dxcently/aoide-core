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
//! content/make/update, which stay core), shellbridge, quickshell, screen,
//! herald, take, secrets (P3: `secrets ask`, the rice-shaped TOTP code-entry
//! popup — root-coupled like `meta`/`onboard` in shape, but appended LAST
//! per golden discipline's "append, never reorder," `pkgs/aoide/crates/
//! AGENTS.md`). Core-only groups (graph, adapter melete, conductor, a2a
//! serve, agents, peers, usage, hooks, daemon, soundcheck) are absent —
//! lyra never registers them.
//!
//! Path count: 2 (meta) + 1 (onboard) + 1 (mcp.serve) + 3 (rice) + 3 (draft)
//! + 4 (mode) + 1 (cover) + 3 (livery) + 2 (rice-late) + 1 (shellbridge) + 1
//! (quickshell) + 14 (screen) + 1 (herald) + 6 (take) + 1 (secrets ask) = 44
//! (P-I3: 42 -> 43; P3: 43 -> 44). The plan's phase description estimated 41
//! (the named groups alone, without `mcp.serve`); verified by generating
//! (`lyra schema --json | jq '.commands|length'`) — `mcp.serve` must be a
//! registered path for `aoide_protocol::door::parse` to ever reach
//! `lib.rs`'s `special` closure on `mcp serve --stdio`, exactly like core's
//! own `mcp.serve` entry. See `crates/lyra/src/registry.rs`'s golden test
//! for the exact path list.
pub mod infra;
pub mod meta;
pub mod onboard;
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
    aoide_song::commands::quickshell::register(&mut r); // quickshell reload — IPC hot-reload trigger
    aoide_screen::commands::register(&mut r); // screen info, shot, point *, ocr, diff, send (own crate since P-A1)
    aoide_conduct::commands::herald::register(&mut r); // herald push — dunst's script hook into the notification ledger
    aoide_song::commands::take::register(&mut r); // rice take/take.*, rice back — explicit take-store snapshot
    secrets::register(&mut r); // secrets ask — the rice-shaped TOTP code-entry popup (P3)

    r
}
