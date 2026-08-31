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
/// guide, schema, content(stub), make(stub), update(stub), onboard (P-I2:
/// the first-boot flow, real as of this commit),
/// mcp serve, daemon, graph + conduct, adapter melete, conductor, a2a
/// serve, peer add/remove/pull/status (CONTRACTS.md §7,
/// same-network federation), usage, hooks install,
/// soundcheck (the mechanical-integrity command's WORKING-tree half,
/// `aoide-upkeep`; report-only, forever — see its own module doc for the
/// finding format and why the COMMITTED-tree half lives in `nix flake
/// check` instead), inbox list/read/clear (the
/// durable per-host message store, messaging workstream C6), secrets
/// serve/exec/add/rm/grant/revoke (Workstream SECRETS's
/// broker daemon + client + admin CLI surface, P-V2), events tail
/// (the aoided event bus's own terminal-reachable follow
/// command, P-D3, `docs/architecture/AOIDED.md`'s "L1" section), identity
/// (this instance's ed25519 identity show command, P-P1 of the pairing
/// workstream), melete status/graph/call (the Melete MCP client, M2, task
/// #14), peer advertise/list (task #120), pair/pair reject/pair watch (the
/// pairing ceremony's whole CLI face — P-P2 built it, P-PV2 and task #135
/// P3' each collapsed it further, ending in ONE smart verb: bare `pair`
/// resolves/approves/starts, `pair reject`, `pair watch`; see
/// `docs/architecture/PAIRING.md`), config + config set (task #135 P-C —
/// the portable runtime config file, `$AOIDE_ROOT/config.toml`).
///
/// P-A5 (binary-split workstream) removed the register lines for the
/// graphical bundle — rice/draft/mode/cover/livery/rice-late-stubs/
/// shellbridge/quickshell/screen/herald/take — from this list; those
/// command paths now live ONLY in `crates/lyra/src/commands/mod.rs::all()`
/// (docs/architecture/PACKAGE-LAYOUT.md, CONTRACTS.md §3). P-PV2 (the
/// User's locked spec) collapsed `peer invite`/`peer pair request` into
/// ONE smart-target `peer pair` and renamed `peer pair pending` to `peer
/// pending`.
///
/// The exact command-path set lives in `registry.rs`'s golden snapshot
/// test, the sole authority — never here.
pub fn all() -> Registry {
    let mut r = Registry::new();

    meta::register(&mut r); // guide, schema
    stubs::register_content(&mut r); // content register/propose/approve/ingest/query
    stubs::register_make(&mut r); // make
    stubs::register_update(&mut r); // update
    onboard::register(&mut r); // onboard (P-I2: core's shell-only half, real as of this commit)
    infra::register_mcp(&mut r); // mcp serve (root-coupled: reads this assembled registry)
    aoide_server::commands::register_infra(&mut r); // daemon
    aoide_conduct::commands::graph::register(&mut r); // graph + conduct
    aoide_client::commands::register_post_graph(&mut r); // adapter melete
    aoide_conductor::commands::register(&mut r); // conductor
    aoide_server::commands::register_a2a_serve(&mut r); // a2a serve
    aoide_client::commands::register_peers(&mut r); // peer add/remove/pull/status — same-network federation (CONTRACTS.md §7, appended newest)
    aoide_storage::commands::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)
    aoide_conduct::commands::hooks::register(&mut r); // hooks install — the hook-installer command
    aoide_upkeep::commands::register(&mut r); // soundcheck — mechanical-integrity WORKING-tree sweep, report-only
    aoide_storage::commands::register_inbox(&mut r); // inbox list/read/clear — durable per-host message store (messaging workstream C6, appended newest)
    aoide_secrets::commands::register(&mut r); // secrets serve/exec/add/rm/grant/revoke — the secrets broker (Workstream SECRETS P-V2, appended newest)
    aoide_server::commands::register_events(&mut r); // events tail — aoided's own feed follow command (P-D3, appended newest)
    aoide_storage::commands::register_identity(&mut r); // identity — this instance's ed25519 identity show command (pairing workstream P-P1, appended newest)
    aoide_client::commands::register_peer_discovery(&mut r); // peer discover/advertise — LAN discovery's CLI half (P-P6 + task #120, appended newest)
    aoide_client::mcp_client::register_melete(&mut r); // melete status/graph/call — the Melete MCP client (M2, task #14, appended newest)
    aoide_conduct::commands::peer_list::register(&mut r); // peer list — the one-glance mesh roster over the roster core's probe (formerly who's) + one discovery sweep (task #120 P2, appended newest)
    aoide_client::commands::register_pair(&mut r); // pair + pair reject/watch — the pairing ceremony's whole CLI face, one smart verb (task #135 P3', superseding the peer pair family — hard cutover)
    aoide_storage::commands::register_config(&mut r); // config, config set — the portable runtime config file (task #135 P-C, appended newest)

    r
}
