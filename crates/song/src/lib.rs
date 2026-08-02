//! aoide-song — Aoide's ricing/design engine.
//!
//! `notes` locates the `drachma` binary and delegates lint runs to it;
//! `live` computes the Hyprland geometry/border keyword list a staged notes
//! document implies and (best-effort) applies it to a running compositor.
//! Both are dependency-free leaves (Phase 5a); `mint`/`cover` land in a
//! later phase with a storage dependency.

pub mod live;
pub mod notes;

/// A crate-wide lock serialising every test that mutates process-global env
/// (`HYPRLAND_INSTANCE_SIGNATURE`, …). `std::env::set_var` is process-global,
/// so env-touching tests across modules must share ONE mutex or they race
/// each other under the multithreaded test harness. Mirrors the root
/// `aoide` crate's `env_lock()` (src/lib.rs) — this is the crate-local copy
/// for `aoide-song`'s own tests.
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}
