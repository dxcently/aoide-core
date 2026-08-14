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
/// guide, schema, rice gen(stub), rice lint/stage/compose, rice design
/// status/enter/exit, rice mode status/stage/declarative, cover set, rice
/// adopt/transpose(stub), content(stub x5), make(stub), update(stub),
/// onboard(stub), mcp serve, daemon, shellbridge, graph(x15) + conduct,
/// adapter melete, conductor, a2a serve + agent add/list/remove, usage
/// (appended — the newest group, so it never reorders the historical table
/// above it), hooks install (newest).
///
/// `design::register`/`mode::register` sit directly after `rice::register`
/// (rather than off on their own) so the whole `rice` family —
/// `lint`/`stage`/`compose`/`design status`/`mode status` — stays contiguous
/// in `schema --json`'s command order, even though each is its own module
/// (Phase A of the design-mode feature; see `crates/storage/src/design.rs`;
/// the mode-toggle feature; see `crates/storage/src/mode.rs`).
pub fn all() -> Registry {
    let mut r = Registry::new();

    meta::register(&mut r); // guide, schema
    stubs::register_rice_gen(&mut r); // rice gen
    aoide_song::commands::rice::register(&mut r); // rice lint, stage, compose
    aoide_song::commands::design::register(&mut r); // rice design status/enter/exit
    aoide_song::commands::mode::register(&mut r); // rice mode status/stage/declarative
    aoide_song::commands::cover::register(&mut r); // cover set
    aoide_song::commands::livery::register(&mut r); // livery emit, resolve, lint (the native note engine's verbs)
    stubs::register_rice_late(&mut r); // rice adopt, transpose
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
    aoide_storage::commands::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)
    aoide_conduct::commands::hooks::register(&mut r); // hooks install — the hook-installer verb (appended newest)

    r
}
