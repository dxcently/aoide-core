//! aoide-upkeep — mechanical integrity, the WORKING-tree half.
//!
//! `nix flake check` (`lib/checks.nix`'s `fmt`/`lint`/`discovery`) already
//! polices the COMMITTED tree — the git-filtered store copy `nix` evaluates.
//! It structurally cannot see anything gitignored or merely uncommitted:
//! `result`, `state/`, an agent's stray file dropped at repo root a moment
//! ago. That gap is this crate's whole charter, and its only command is
//! `aoide soundcheck` (`commands::register`).
//!
//! **Report-only, forever — this is a binding correction, not a v0
//! shortcut.** `soundcheck` never moves, deletes, formats, or repairs
//! anything; it only names a problem precisely enough that a human or an
//! agent can go fix it. See `commands`' module doc for the finding format
//! and `scan`'s for exactly which checks live here.
//!
//! One-package-one-charter (`docs/architecture/PACKAGE-LAYOUT.md`): repo
//! hygiene is not `aoide-storage`'s "durable session data" charter, so this
//! is its own small crate rather than a stretch of that one (soundcheck
//! design doc, FORK 3, advisor-confirmed).

pub mod commands;
pub mod scan;

/// A crate-wide lock serialising every test that mutates process-global env
/// — mirrors every other domain crate's own `env_lock` (delegates to
/// `aoide-test-support`'s single mutex so a test in THIS crate's binary
/// never races one in a dev-dependency's own suite).
#[cfg(test)]
pub(crate) fn env_lock() -> &'static std::sync::Mutex<()> {
    aoide_test_support::env_lock()
}
