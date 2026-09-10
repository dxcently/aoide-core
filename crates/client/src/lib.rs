//! aoide-client — Aoide's outbound A2A door (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md): the client-side wire builders/parsers
//! (`wire`) and the melete neutral-event adapter (`adapter`).
//!
//! Extracted from root `src/a2a.rs` (its CLIENT-side region only — the
//! server-side JSON-RPC/HTTP door stays in root, Phase 4c's job) and root
//! `src/adapter.rs` wholesale, following the same shim discipline
//! `aoide-protocol` (Phase 2), `aoide-storage` (Phase 3a), and `aoide-conduct`
//! (Phase 3b) established: every moved symbol is re-exported at its old root
//! path via `pub use`, so no existing call site changes.
//!
//! `daemon` (P-D6, `docs/architecture/AOIDED.md`'s "L4 — graph residency")
//! is this crate's second outbound door, beside the A2A one: `daemon::
//! daemon_dispatch` is the connect-or-`None` client every session-write
//! handler in `aoide-conduct` tries first, over the resident `aoided`'s
//! own control socket.
//!
//! `discover` (P-P6 + task #120, `docs/architecture/PAIRING.md`'s
//! "Discovery (advertise-but-locked)" section) is the discovery
//! advertisement's LISTEN half — `node discover`/`node invite`'s shared
//! UDP sweep (a plain fixed-port bind hears the broadcast; no group join,
//! no probing), its bounded dedupe fold, and (for `node invite`) the pure
//! heard-set resolution its ambiguous/absent-name refusal is built on. The
//! SEND half (`a2a serve`'s own advertise thread) lives in
//! `aoide-server::discovery` instead — this crate is outbound-only, and
//! LISTENING is the client-side action here, mirroring every other
//! `node *` command's shape.
//!
//! `tunnel` (P-S3, ssh-transport lane) is the ONE place `ssh` is ever
//! spawned: `open_or_reuse`/`close`/`close_all_for_session` open, probe,
//! reuse, and tear down the loopback forward a cross-box node action dials
//! through when a `--via`/`Node.via` transport marker is present.
//! `aoide_storage::tunnel` (P-S2) owns the record's shape and every pure
//! helper around it; this module owns the child process.
//!
//! `mcp_client` (M2, task #14) is the Melete MCP client: `melete
//! status|graph|call` speak MCP (JSON-RPC 2.0 over HTTP POST) over
//! `commands::post_json`, the SAME curl transport `node` already uses — no
//! new outbound protocol stack, just a new method vocabulary over the
//! existing one.
//!
//! `mail_wire` (messaging plan P-M2, `docs/architecture/MAIL.md`) is the
//! outbox drain: the one place a spooled envelope actually dials
//! `aoide/mailDeposit` over `commands`' own signed-request machinery.
//! `aoide_storage::outbox` owns the spool's file shape; this module owns
//! the wire half, and tears its own tunnel down before it returns
//! (`tunnel`'s "every tunnel stays open" default is deliberately NOT this
//! module's rule).

pub mod adapter;
pub mod commands;
pub mod context;
pub mod daemon;
pub mod discover;
pub mod mail_wire;
pub mod mcp_client;
pub mod mesh;
pub mod pair_watch;
pub mod node;
pub mod tunnel;
pub mod wire;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_DAEMON_SOCKET` today) OR binds `aoide_storage::advertise::PORT`,
/// the ONE fixed UDP port `discover::run_sweep` and every test that drives
/// it through (`discover`'s own real-loopback test, `commands`' `node
/// discover` tests) all bind directly (#126). `cargo test` runs `#[test]`
/// fns across multiple threads by default, and two concurrent binds of the
/// same fixed port collide (`EADDRINUSE`) — the `commands.rs` sweep tests
/// were already serialized against EACH OTHER (`with_node_state` takes this
/// lock for its whole closure), but `discover`'s own real-socket test held
/// no lock at all, so it could still race either of them. Delegates to
/// `aoide-test-support`'s single mutex, the same pattern
/// `aoide-storage`/`aoide-conduct` already hold (`pkgs/aoide/crates/
/// AGENTS.md`'s "per-crate tests only").
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
