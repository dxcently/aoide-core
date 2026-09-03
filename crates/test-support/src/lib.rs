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
