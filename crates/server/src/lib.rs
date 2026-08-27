//! aoide-server — Aoide's door serve-loops: the A2A JSON-RPC/HTTP server, the
//! MCP stdio server, and the `aoided` policy skeleton (Phase 4c restructure,
//! docs/architecture/PACKAGE-LAYOUT.md).
//!
//! Extracted from root `src/a2a.rs` (the SERVER half — the client half,
//! outbound registration/driving of external agents, stays in root as a
//! Phase 4a/4b shim), `src/mcp.rs` (wholesale), and `src/daemon.rs`'s `run`
//! (the policy-type re-exports stay in root; they already live in
//! `aoide-protocol` since Phase 4a).
//!
//! **The one non-mechanical seam this phase threads through:** both serve
//! loops used to reach the crate-global, fully-assembled command registry
//! (`dispatch::registry()`) and dispatcher (`dispatch::dispatch()`) directly.
//! That registry pulls in every command family (`commands::all()`) and does
//! not move to any crate until Phase 6 (`cli`) — a `server` crate reaching for
//! it would be `server → root`, exactly the dependency direction this split
//! exists to forbid. So [`mcp::serve_stdio`] and [`a2a::serve`] (and every
//! function under them that used to consult the registry) take it as a
//! parameter instead; root `lib.rs`'s two launch sites now pass
//! `dispatch::registry()` and `dispatch::dispatch` in.
//!
//! Sits ABOVE `aoide-conduct` (the session core `do_inject`/`do_spawn`/
//! `tasks/get` read/write through) and `aoide-storage`, and depends on
//! `aoide-protocol` for the `Registry`/`Invocation`/`Outcome`/audit/`Door`
//! contract every door shares. Does NOT depend on `aoide-client` in
//! production (only as a dev-dependency for one round-trip test — see
//! `Cargo.toml`) — the outbound A2A client stays entirely in root/`aoide-client`.

pub mod a2a;
pub mod commands;
pub mod daemon;
pub mod discovery;
pub mod events;
pub mod mcp;
pub mod producers;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, …) — mirrors `aoide::env_lock()` (root `src/lib.rs`),
/// `aoide_storage::env_lock()`, and `aoide_conduct::env_lock()`. Each crate's
/// tests run in their own process (`cargo test -p <crate>`), so a single
/// crate-local lock is enough; it doesn't need to coordinate across crates.
///
/// **P-D6 safety net (incident, this phase — see `aoide-conduct/AGENTS.md`'s
/// sibling note for the full story):** the first call in the WHOLE test
/// binary also stamps `AOIDE_STAGE_DIR` to a fresh, private tempdir, unless
/// a test already set one. `daemon::run_loop`'s tick now WRITES through
/// `aoide_conduct::graph::restage_graph`/`aoide_conduct::reap::reap_and_announce`
/// (`docs/architecture/AOIDED.md`'s "L4") — a `run_loop` test spawns that
/// tick loop on a background thread it never joins (by design, so the test
/// itself can return once its own assertion is proven), so that thread
/// keeps ticking for the rest of THIS PROCESS's life; without this floor it
/// would eventually read `AOIDE_STAGE_DIR` as unset (once whichever test set
/// it restores its own prior value) and start reading/writing the REAL
/// `~/Aoide/state/stage/*` on this box. Every test that wants its OWN
/// isolated tempdir still calls `env_lock()` first (existing convention)
/// and restores to what it captured on exit — which, because of this floor,
/// is never "fully unset" for the rest of the binary's life once the first
/// test has run.
///
/// **P-D8 addendum, same reasoning, one env var over:** also floors
/// `AOIDE_STATE_DIR`. `daemon::run_loop` now calls `run_boot_auto_resume`
/// once at entry, which reads/writes a marker under `aoide_storage::fs::
/// state_dir()` — the SAME `run_loop` test's un-joined background thread
/// makes that call too, so without this floor it would eventually read
/// `AOIDE_STATE_DIR` as unset and touch the real
/// `~/Aoide/state/auto-resume-boot-epoch` on this box (`aoide-conduct`'s
/// own `env_lock()` carries the identical second floor, for the identical
/// reason — see that crate's `lib.rs`).
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ISOLATE_STAGE_DIR: std::sync::Once = std::sync::Once::new();
    ISOLATE_STAGE_DIR.call_once(|| {
        if std::env::var("AOIDE_STAGE_DIR").is_err() {
            let dir = std::env::temp_dir().join(format!("aoide-server-tests-floor-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            std::env::set_var("AOIDE_STAGE_DIR", &dir);
        }
        if std::env::var("AOIDE_STATE_DIR").is_err() {
            let dir = std::env::temp_dir().join(format!("aoide-server-tests-state-floor-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            std::env::set_var("AOIDE_STATE_DIR", &dir);
        }
    });
    &LOCK
}
