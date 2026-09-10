//! Shared test scaffolding for every aoide crate's test modules: env-var
//! save/restore, a scratch-dir helper, the process-wide env lock, and the
//! fixture note payloads several command groups' tests need.
//!
//! Extracted from the root package's `commands/mod.rs::test_support` +
//! `lib.rs::env_lock` (Phase 9 restructure,
//! docs/architecture/PACKAGE-LAYOUT.md) so the domain crates' own
//! `commands` tests use the SAME rig — pulled in as a **dev-dependency**
//! only; nothing in a production build may edge on this crate.

use aoide_protocol::{Door, Invocation};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn unique_tmp(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "aoide-dispatch-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn inv(path: &[&str], args: &[&str]) -> Invocation {
    Invocation {
        path: path.iter().map(|s| s.to_string()).collect(),
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: BTreeMap::new(),
        door: Door::Cli,
    }
}

// Restore env vars on drop so a panicking assertion never leaks state.
pub struct EnvSaver {
    keys: Vec<(&'static str, Option<String>)>,
}
impl EnvSaver {
    pub fn capture(keys: &[&'static str]) -> Self {
        EnvSaver {
            keys: keys.iter().map(|k| (*k, std::env::var(k).ok())).collect(),
        }
    }
}
impl Drop for EnvSaver {
    fn drop(&mut self) {
        for (k, v) in &self.keys {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// Point `AOIDE_ROOT` at a fresh, isolated temp directory for the returned
/// guard's lifetime, and clear `AOIDE_STATE_DIR`/`AOIDE_STAGE_DIR` so
/// neither can leave a stale absolute override pointing somewhere else —
/// restored on drop via [`EnvSaver`]. `aoide-storage`'s own `env_lock()`
/// floors nothing (unlike `aoide-conduct`'s and `aoide-server`'s own), so a
/// storage test that sets only `AOIDE_STATE_DIR` still resolves
/// `stage_dir()` — and so `try_stage_lock`'s `.stage.lock` — against the
/// REAL, unset root; that gap is exactly how a fixture once wrote real rows
/// into the live inbox. Pointing `AOIDE_ROOT` itself moves both
/// `state_dir()` and `stage_dir()` off the real root at once. Every
/// `aoide-storage` test that touches `mail` must use this, never
/// `AOIDE_STATE_DIR` alone.
///
/// Also pins `AOIDE_DAEMON_SOCKET` at a path inside the isolated root that
/// nothing ever binds (P-M5a-2: `mail send`'s self branch now forwards
/// `mail ring` through `aoide_client::daemon::daemon_dispatch`, which
/// resolves the daemon socket from `AOIDE_DAEMON_SOCKET` or else
/// `$XDG_RUNTIME_DIR/aoide/aoided.sock` — falling all the way back to the
/// hardcoded `/run/user/1000` when even `XDG_RUNTIME_DIR` is unset). Without
/// this, a `mail send --to self/...` test on a machine with a REAL resident
/// `aoided` dials that live daemon for real and can inject a real nudge
/// line into a real conducted session. `daemon_dispatch` treats a dead
/// socket as an ordinary, silent "no daemon" — exactly the outcome these
/// tests want — so pointing it at a guaranteed-dead path costs nothing.
///
/// Caller must already hold [`env_lock`] (the same convention every other
/// env-touching test here follows — acquired once, at the top of the test,
/// before constructing any guard). Owns the environment only, not the
/// directory: the caller still removes it at the end of the test, the same
/// way every `unique_tmp` caller already does.
pub fn isolated_mail_root(tag: &str) -> (EnvSaver, PathBuf) {
    let env = EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_STATE_DIR", "AOIDE_STAGE_DIR", "AOIDE_DAEMON_SOCKET"]);
    let root = unique_tmp(tag);
    std::env::set_var("AOIDE_ROOT", &root);
    std::env::remove_var("AOIDE_STATE_DIR");
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::set_var("AOIDE_DAEMON_SOCKET", root.join("no-daemon.sock"));
    (env, root)
}

pub const VALID_NOTES: &str = r##"{ "schemaVersion":"0",
    "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"} }"##;

// Carries a `window` block (border colours), so `hyprctl` keyword-batch
// construction has something to resolve — VALID_NOTES deliberately does
// not, to exercise the "empty batch" path elsewhere.
pub const NOTES_WITH_WINDOW: &str = r##"{ "schemaVersion":"0",
    "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
    "window": {"border":"#82aaff","borderInactive":"#0b1021"} }"##;

// A song with palette + window + a full geometry block, for `rice compose`
// tests that need to assert every tier round-trips.
pub const NOTES_WITH_GEOMETRY: &str = r##"{ "schemaVersion":"0",
    "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
    "window": {"border":"#82aaff","borderInactive":"#0b1021"},
    "geometry": {"gapsOut":10,"gapsIn":4,"borderSize":3,"rounding":6,
                 "blurEnabled":false,"blurSize":5,"blurPasses":2} }"##;

// A hostile palette value carrying live Nix interpolation syntax — proves
// `nix_scalar` neutralizes `${…}` rather than letting it round-trip into
// `rice.nix` as a real interpolation (a real injection: a value like
// `"${builtins.readFile /etc/hostname}"` would otherwise EVALUATE).
pub const NOTES_WITH_INTERPOLATION: &str = r##"{ "schemaVersion":"0",
    "palette": {"bg":"${builtins.currentTime}","fg":"#c8d3f5",
                 "accent":"#82aaff","urgent":"#ff757f"} }"##;

/// A suite-wide lock serialising every test that mutates process-global env
/// (`AOIDE_STAGE_DIR`, `PATH`, …). `std::env::set_var` is
/// process-global, so env-touching tests across modules must share ONE mutex or
/// they race each other under the multithreaded test harness.
///
/// Acquisition is poison-tolerant everywhere, by convention:
/// `.lock().unwrap_or_else(|e| e.into_inner())`, never a bare `.unwrap()`.
/// A test that panics while holding this guard has already failed ITSELF, and
/// every critical section sets the env it needs at entry — there is no
/// predecessor state to trust, so the poison carries no information. A bare
/// `.unwrap()` here converts one real failure into a suite-wide cascade that
/// buries the root under dozens of `PoisonError` panics (worst on a loaded
/// builder, where a timing-sensitive test is likeliest to trip first). The
/// same rule applies to every crate-local test guard shaped like this one.
pub fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
