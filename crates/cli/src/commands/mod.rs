//! Command groups — each DOMAIN crate contributes its entries to a
//! [`crate::registry::Registry`] via its own `commands::register(&mut
//! Registry)` function (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md: a domain's CLI commands live with the
//! domain). Only the root-coupled groups stay here: `meta` (guide/schema —
//! reads the assembled registry), `stubs` (not-implemented placeholders with
//! no domain yet), `onboard` (the first-boot flow, P-I2 — reads the
//! assembled registry too, to call `hooks.install` and render the closing
//! guide), and `infra` (`mcp serve` — reads the assembled registry's tool
//! count). [`all`] assembles every contribution in the exact order that
//! reproduces the historical `schema.rs` table order (see `registry.rs`
//! module docs for why that order is load-bearing).

mod infra;
mod meta;
mod onboard;
mod stubs;

use crate::registry::Registry;

/// Build the full command registry, in the historical `schema --json` order:
/// guide, schema, content(stub x5), make(stub), update(stub), onboard (P-I2:
/// the first-boot flow, real as of this commit — stub count 8->7),
/// mcp serve, daemon, graph(x15) + conduct, adapter melete, conductor, a2a
/// serve, peer add/remove/pull/status (CONTRACTS.md §7,
/// same-network federation — nothing EXISTING moves, so the historical table
/// above it is still untouched), usage, hooks install,
/// soundcheck (the mechanical-integrity command's WORKING-tree half,
/// `aoide-upkeep`; report-only, forever — see its own module doc for the
/// finding format and why the COMMITTED-tree half lives in `nix flake
/// check` instead), who (live presence over sessions + registered peers,
/// messaging workstream C2), inbox list/read/clear (appended newest — the
/// durable per-host message store, messaging workstream C6), secrets
/// serve/exec/add/rm/grant/revoke (appended newest — Workstream SECRETS's
/// broker daemon + client + admin CLI surface, P-V2), events tail
/// (appended newest — the aoided event bus's own terminal-reachable follow
/// command, P-D3, `docs/architecture/AOIDED.md`'s "L1" section), identity
/// (this instance's ed25519 identity show command, P-P1 of the pairing
/// workstream), peer pair request/pending/approve/reject (appended newest —
/// the pairing ceremony's CLI half, P-P2, `docs/architecture/PAIRING.md`).
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
    onboard::register(&mut r); // onboard (P-I2: core's shell-only half, real as of this commit)
    infra::register_mcp(&mut r); // mcp serve (root-coupled: reads this assembled registry)
    aoide_server::commands::register_infra(&mut r); // daemon
    aoide_conduct::commands::graph::register(&mut r); // graph x15 + conduct
    aoide_client::commands::register_post_graph(&mut r); // adapter melete
    aoide_conductor::commands::register(&mut r); // conductor
    aoide_server::commands::register_a2a_serve(&mut r); // a2a serve
    aoide_client::commands::register_peers(&mut r); // peer add/remove/pull/status — same-network federation (CONTRACTS.md §7, appended newest)
    aoide_storage::commands::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)
    aoide_conduct::commands::hooks::register(&mut r); // hooks install — the hook-installer command
    aoide_upkeep::commands::register(&mut r); // soundcheck — mechanical-integrity WORKING-tree sweep, report-only
    aoide_conduct::commands::who::register(&mut r); // who — live presence over sessions + registered peers (messaging workstream C2)
    aoide_storage::commands::register_inbox(&mut r); // inbox list/read/clear — durable per-host message store (messaging workstream C6, appended newest)
    aoide_secrets::commands::register(&mut r); // secrets serve/exec/add/rm/grant/revoke — the secrets broker (Workstream SECRETS P-V2, appended newest)
    aoide_server::commands::register_events(&mut r); // events tail — aoided's own feed follow command (P-D3, appended newest)
    aoide_storage::commands::register_identity(&mut r); // identity — this instance's ed25519 identity show command (pairing workstream P-P1, appended newest)
    aoide_client::commands::register_peer_pair(&mut r); // peer pair request/pending/approve/reject — the pairing ceremony's CLI half (P-P2, appended newest)
    aoide_client::commands::register_peer_discovery(&mut r); // peer discover/invite — the LAN discovery beacon's CLI half (P-P6, appended newest)

    r
}
