//! aoide-upkeep — mechanical integrity, the WORKING-tree half.
//!
//! `nix flake check` (`lib/checks.nix`'s `fmt`/`lint`/`discovery`) already
//! polices the COMMITTED tree — the git-filtered store copy `nix` evaluates.
//! It structurally cannot see anything gitignored or merely uncommitted:
//! `result`, `state/`, an agent's stray file dropped at repo root a moment
//! ago. That gap is this crate's whole charter. Its own command is `aoide
//! soundcheck` (`commands::register`), a human/agent-invoked report; its own
//! AUTOMATIC wiring is [`checklane`], invoked from `aoide-conduct`'s `session
//! hook` at SessionStart/Stop so the same gap gets flagged without anyone
//! having to remember to ask.
//!
//! **Report-only, forever — this is a binding correction, not a v0
//! shortcut.** Neither `soundcheck` nor [`checklane`] ever moves, deletes,
//! formats, or repairs anything; each only names a problem precisely enough
//! that a human or an agent can go fix it. See `commands`' module doc for the
//! finding format, `scan`'s for exactly which checks live here, and
//! [`checklane`]'s for the SessionStart/Stop split.
//!
//! One-package-one-charter (`docs/architecture/PACKAGE-LAYOUT.md`): repo
//! hygiene is not `aoide-storage`'s "durable session data" charter, so this
//! is its own small crate rather than a stretch of that one (soundcheck
//! design doc, FORK 3, advisor-confirmed).

pub mod checklane;
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
