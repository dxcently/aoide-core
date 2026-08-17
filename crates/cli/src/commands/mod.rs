//! Command groups — each DOMAIN crate contributes its entries to a
//! [`crate::registry::Registry`] via its own `commands::register(&mut
//! Registry)` function (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md: a domain's CLI verbs live with the
//! domain). Only the root-coupled groups stay here: `meta` (guide/schema —
//! reads the assembled registry), `stubs` (not-implemented placeholders with
//! no domain yet), and `infra` (`mcp serve` — reads the assembled registry's
//! tool count). [`all`] assembles every contribution in the exact order that
//! reproduces the historical `schema.rs` table order (see `registry.rs`
//! module docs for why that order is load-bearing).

mod infra;
mod meta;
mod stubs;

use crate::registry::Registry;

/// Build the full command registry, in the historical `schema --json` order:
/// guide, schema, rice lint/stage/compose, rice draft
/// save/list/drop, rice mode status/stage/declarative/draft, cover set, rice
/// declare/transpose(stub), content(stub x5), make(stub), update(stub),
/// onboard(stub), mcp serve, daemon, shellbridge, graph(x15) + conduct,
/// adapter melete, conductor, a2a serve + agent add/list/remove, peer
/// add/list/remove/pull/status (CONTRACTS.md §7, slotted directly after the
/// `a2a agent` group it's the same-network-federation sibling of — nothing
/// EXISTING moves, so the historical table above it is still untouched),
/// usage, hooks install, quickshell reload (appended newest — the Quickshell
/// IPC hot-reload trigger, `crates/song/src/ipc.rs`; named `quickshell`, not
/// `shell` — `shell` collided with `--agent shell`, the value `graph
/// conduct`'s kitty wrapper uses, and broke every terminal on this desktop
/// until caught and renamed, khoa 2026-08-15).
///
/// `rice gen` was cut outright (khoa 2026-08-14) — a speculative
/// prompt/wallpaper generator that was never built and had no path to being
/// built without a design nobody had; `rice compose` (scaffold) → `rice
/// mode stage` (go live) → `rice mode draft` (route into a saved
/// iteration) → `rice declare` (commit) is the real loop.
///
/// `draft::register`/`mode::register` sit directly after `rice::register`
/// (rather than off on their own) so the whole `rice` family —
/// `lint`/`stage`/`compose`/`draft *`/`mode *` — stays contiguous in
/// `schema --json`'s command order, even though each is its own module (the
/// draft feature; see `crates/song/src/commands/draft.rs`; the mode-toggle
/// feature, now three-way (`staging`/`declarative`/`draft`) with `rice mode
/// draft`'s symlink routing; see `crates/storage/src/mode.rs`).
pub fn all() -> Registry {
    let mut r = Registry::new();

    meta::register(&mut r); // guide, schema
    aoide_song::commands::rice::register(&mut r); // rice lint, stage, compose
    aoide_song::commands::draft::register(&mut r); // rice draft save/list/stage/drop
    aoide_song::commands::mode::register(&mut r); // rice mode status/stage/declarative
    aoide_song::commands::cover::register(&mut r); // cover set
    aoide_song::commands::livery::register(&mut r); // livery emit, resolve, lint (the native note engine's verbs)
    stubs::register_rice_late(&mut r); // rice declare, transpose
    stubs::register_content(&mut r); // content register/propose/approve/ingest/query
    stubs::register_make(&mut r); // make
    stubs::register_update(&mut r); // update
    stubs::register_onboard(&mut r); // onboard
    infra::register_mcp(&mut r); // mcp serve (root-coupled: reads this assembled registry)
    aoide_server::commands::register_infra(&mut r); // daemon, shellbridge
    aoide_conduct::commands::graph::register(&mut r); // graph x15 + conduct
    aoide_client::commands::register_post_graph(&mut r); // adapter melete
    aoide_conductor::commands::register(&mut r); // conductor
    aoide_server::commands::register_a2a_serve(&mut r); // a2a serve
    aoide_client::commands::register_agents(&mut r); // a2a agent add/list/remove/send (CONTRACTS.md §6)
    aoide_client::commands::register_peers(&mut r); // peer add/list/remove/pull/status — same-network federation (CONTRACTS.md §7, appended newest)
    aoide_storage::commands::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)
    aoide_conduct::commands::hooks::register(&mut r); // hooks install — the hook-installer verb (appended newest)
    aoide_song::commands::quickshell::register(&mut r); // quickshell reload — IPC hot-reload trigger
    aoide_conduct::commands::screen::register(&mut r); // screen info, screen shot — Phase 1 of the `screen` verb family (appended newest)

    r
}
