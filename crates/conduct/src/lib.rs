//! aoide-conduct — Aoide's session core: the PTY multiplexer (`aoide
//! conduct`), the session DAG (`aoide graph`), Claude-Code hook plumbing, and
//! liveness reaping (Phase 3b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md).
//!
//! Extracted from root `src/graph.rs` + `src/graph/*.rs` + `src/reap.rs` +
//! the socket-loop half of `src/shellbridge.rs`, following the same shim
//! discipline `aoide-protocol` (Phase 2) and `aoide-storage` (Phase 3a)
//! established: every moved symbol is re-exported at its old root path via
//! `pub use`, so no existing call site changes. Sits ABOVE `aoide-storage`
//! (the durable session-record substrate) and `aoide-protocol` (the
//! Invocation/Outcome/audit contract every door shares).

pub mod commands;
pub mod graph;
pub mod herald;
pub mod reap;
pub mod shellbridge;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `XDG_RUNTIME_DIR`, `AOIDE_AUDIT_LOG`,
/// `HYPRLAND_INSTANCE_SIGNATURE`, …) — mirrors `aoide::env_lock()` (root
/// `src/lib.rs`) and `aoide_storage::env_lock()` (Phase 3a). Needed here
/// because the moved `graph`/`reap`/`shellbridge` tests touch the same
/// process-global env vars and must serialise against each other under the
/// multithreaded test harness.
///
/// **P-D6 safety net (incident, this phase — see `AGENTS.md`'s own note):**
/// the first call in the WHOLE test binary also stamps `AOIDE_DAEMON_SOCKET`
/// to a path that can never have a real listener, unless a test already set
/// one. Every `graph session start/phase/end/hook` and `graph reap` handler
/// now tries the daemon FIRST (`docs/architecture/AOIDED.md`'s "L4") — a dev
/// box (this one included) commonly has a REAL resident `aoided` bound on
/// the real default socket, and a test that forgot its own override used to
/// silently dispatch against PRODUCTION state instead of its own tempdir
/// fixture (caught live: `cargo test -p aoide-conduct` mutated the real
/// `~/Aoide/song/stage/sessions.json` through the real daemon before this
/// stamp existed). This establishes the SAFE DEFAULT only — a test that
/// wants to prove routing against a FAKE daemon still installs its own
/// `AOIDE_DAEMON_SOCKET` override afterward, same as any other env var here.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ISOLATE_DAEMON_SOCKET: std::sync::Once = std::sync::Once::new();
    ISOLATE_DAEMON_SOCKET.call_once(|| {
        if std::env::var("AOIDE_DAEMON_SOCKET").is_err() {
            std::env::set_var(
                "AOIDE_DAEMON_SOCKET",
                "/nonexistent/aoide-conduct-tests-never-a-real-daemon.sock",
            );
        }
    });
    &LOCK
}
