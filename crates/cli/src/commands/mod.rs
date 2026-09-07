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
/// serve, node add/remove/pull/status (CONTRACTS.md §7,
/// same-network federation), usage, hooks install,
/// soundcheck (the mechanical-integrity command's WORKING-tree half,
/// `aoide-upkeep`; report-only, forever — see its own module doc for the
/// finding format and why the COMMITTED-tree half lives in `nix flake
/// check` instead), secrets
/// serve/exec/add/rm/grant/revoke (Workstream SECRETS's
/// broker daemon + client + admin CLI surface, P-V2), events tail
/// (the aoided event bus's own terminal-reachable follow
/// command, P-D3, `docs/architecture/AOIDED.md`'s "L1" section), identity
/// (this instance's ed25519 identity show command, P-P1 of the pairing
/// workstream), melete status/graph/call (the Melete MCP client, M2, task
/// #14), node advertise/list (task #120), pair/pair reject/pair watch (the
/// pairing ceremony's whole CLI face — P-P2 built it, P-PV2 and task #135
/// P3' each collapsed it further, ending in ONE smart command: bare `pair`
/// resolves/approves/starts, `pair reject`, `pair watch`; see
/// `docs/architecture/PAIRING.md`), config + config set (task #135 P-C —
/// the portable runtime config file, `$AOIDE_ROOT/config.toml`), mesh +
/// mesh pair (task #135 P4/P5 — the read compares every declared
/// `[mesh.<name>]` against the live node registry and reports drift without
/// writing either side; the converge closes that drift by running the
/// ordinary `pair` ceremony against every declared node with no verified
/// record, and never touches a verified one), mail send/read/show/mark/rm
/// (the addressed, signed, append-only mailbase — the durable per-host
/// message store, messaging plan P-M1, `docs/architecture/MAIL.md`).
///
/// P-A5 (binary-split workstream) removed the register lines for the
/// graphical bundle — rice/draft/mode/cover/livery/rice-late-stubs/
/// shellbridge/quickshell/screen/herald/take — from this list; those
/// command paths now live ONLY in `crates/lyra/src/commands/mod.rs::all()`
/// (docs/architecture/PACKAGE-LAYOUT.md, CONTRACTS.md §3). P-PV2 (the
/// User's locked spec) collapsed `node invite`/`node pair request` into
/// ONE smart-target `node pair` and renamed `node pair pending` to `node
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
    aoide_client::commands::register_nodes(&mut r); // node add/remove/pull/status — same-network federation (CONTRACTS.md §7, appended newest)
    aoide_storage::commands::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)
    aoide_conduct::commands::hooks::register(&mut r); // hooks install — the hook-installer command
    aoide_upkeep::commands::register(&mut r); // soundcheck — mechanical-integrity WORKING-tree sweep, report-only
    aoide_secrets::commands::register(&mut r); // secrets serve/exec/add/rm/grant/revoke — the secrets broker (Workstream SECRETS P-V2, appended newest)
    aoide_server::commands::register_events(&mut r); // events tail — aoided's own feed follow command (P-D3, appended newest)
    aoide_storage::commands::register_identity(&mut r); // identity — this instance's ed25519 identity show command (pairing workstream P-P1, appended newest)
    aoide_client::commands::register_node_discovery(&mut r); // node discover/advertise — LAN discovery's CLI half (P-P6 + task #120, appended newest)
    aoide_client::mcp_client::register_melete(&mut r); // melete status/graph/call — the Melete MCP client (M2, task #14, appended newest)
    aoide_conduct::commands::node_list::register(&mut r); // node list — the one-glance mesh roster over the roster core's probe (formerly who's) + one discovery sweep (task #120 P2, appended newest)
    aoide_client::commands::register_pair(&mut r); // pair + pair reject/watch — the pairing ceremony's whole CLI face, one smart command (task #135 P3', superseding the node pair family — hard cutover)
    aoide_storage::commands::register_config(&mut r); // config, config set — the portable runtime config file (task #135 P-C, appended newest)
    aoide_client::mesh::register(&mut r); // mesh + mesh pair — the declared-mesh-vs-live-registry drift report and the converge that closes it (task #135 P4/P5, appended newest)
    aoide_storage::commands::register_mail(&mut r); // mail send/read/show/mark/rm — the addressed, signed, append-only mailbase (messaging plan P-M1, docs/architecture/MAIL.md, appended newest, supersedes register_inbox)

    r
}
