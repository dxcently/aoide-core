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
/// guide, schema, content(stub x5), make(stub), update(stub), onboard(stub),
/// mcp serve, daemon, graph(x15) + conduct, adapter melete, conductor, a2a
/// serve + agent add/list/remove, peer add/list/remove/pull/status
/// (CONTRACTS.md §7, slotted directly after the `a2a agent` group it's the
/// same-network-federation sibling of — nothing EXISTING moves, so the
/// historical table above it is still untouched), usage, hooks install,
/// soundcheck (the mechanical-integrity verb's WORKING-tree half,
/// `aoide-upkeep`; report-only, forever — see its own module doc for the
/// finding format and why the COMMITTED-tree half lives in `nix flake
/// check` instead), who (live presence over sessions + registered peers,
/// messaging workstream C2), inbox list/read/clear (appended newest — the
/// durable per-host message store, messaging workstream C6).
///
/// P-A5 (binary-split workstream) removed the 11 register lines for the
/// graphical bundle — rice/draft/mode/cover/livery/rice-late-stubs/
/// shellbridge/quickshell/screen/herald/take — from this list; those 39
/// command paths now live ONLY in `crates/lyra/src/commands/mod.rs::all()`
/// (docs/architecture/PACKAGE-LAYOUT.md, CONTRACTS.md §3). Core's golden
/// went 87 -> 48 in the same commit; nothing else in this list moved or
/// reordered.
pub fn all() -> Registry {
    let mut r = Registry::new();

    meta::register(&mut r); // guide, schema
    stubs::register_content(&mut r); // content register/propose/approve/ingest/query
    stubs::register_make(&mut r); // make
    stubs::register_update(&mut r); // update
    stubs::register_onboard(&mut r); // onboard
    infra::register_mcp(&mut r); // mcp serve (root-coupled: reads this assembled registry)
    aoide_server::commands::register_infra(&mut r); // daemon
    aoide_conduct::commands::graph::register(&mut r); // graph x15 + conduct
    aoide_client::commands::register_post_graph(&mut r); // adapter melete
    aoide_conductor::commands::register(&mut r); // conductor
    aoide_server::commands::register_a2a_serve(&mut r); // a2a serve
    aoide_client::commands::register_agents(&mut r); // a2a agent add/list/remove/send (CONTRACTS.md §6)
    aoide_client::commands::register_peers(&mut r); // peer add/list/remove/pull/status — same-network federation (CONTRACTS.md §7, appended newest)
    aoide_storage::commands::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)
    aoide_conduct::commands::hooks::register(&mut r); // hooks install — the hook-installer verb
    aoide_upkeep::commands::register(&mut r); // soundcheck — mechanical-integrity WORKING-tree sweep, report-only
    aoide_conduct::commands::who::register(&mut r); // who — live presence over sessions + registered peers (messaging workstream C2)
    aoide_storage::commands::register_inbox(&mut r); // inbox list/read/clear — durable per-host message store (messaging workstream C6, appended newest)

    r
}
