//! Sibling-binary resolver: how one aoide process locates the OTHER aoide
//! binary (core `aoide` from lyra's side is not this phase's problem — P-A6
//! only wires conduct's shellbridge, which needs `aoide` for itself and
//! `lyra` for the rice-mode toggle) without hardcoding a bare name that
//! could resolve to nothing off `PATH`.
//!
//! Three tiers, tried in order:
//!   1. an explicit env var override (`AOIDE_CORE_BIN`/`AOIDE_RICE_BIN`) —
//!      the tier a nix unit sets across store-path boundaries, where
//!      sibling resolution cannot work (P-A8: `lyra` moves to its own
//!      output, so it is never actually `current_exe()`'s sibling on a
//!      built system).
//!   2. the sibling of `current_exe()` — the same directory THIS process
//!      was launched from — ONLY if that file actually exists. A
//!      single-binary dev build (`cargo run -p aoide-cli`) has no `lyra`
//!      sibling; handing back a path that doesn't exist would just move
//!      the failure from "resolve" to "spawn" for no benefit, so this
//!      tier falls through instead.
//!   3. the bare name (`"aoide"`/`"lyra"`), left for `Command::spawn` to
//!      resolve off `PATH` at exec time — the tier that always exists.
//!
//! NEVER re-exec the SIBLING binary (this module's result) from inside
//! `with_stage_lock`: the lock is a `flock`, already cross-process safe,
//! but it is held per-PROCESS — a child spawned while the parent holds it
//! would deadlock waiting on a lock its own parent is still sitting on,
//! and nothing breaks that wait. Re-execing the SAME running binary
//! (`current_exe()`, the idiom `graph/spawn.rs`, `graph/permit.rs`, and
//! `server/src/a2a.rs` all use) is a different, unrelated case — none of
//! those three cross the lock either, but the reasoning doesn't transfer:
//! this module is only ever the CROSS-binary case.

use std::path::Path;

/// Pure tier logic: no env or filesystem reads of its own, every input
/// supplied by the caller. `exe_dir` is the directory `current_exe()`
/// resolved to (`None` if that call failed); `sibling_exists` stands in
/// for the real `Path::exists()` check the public wrappers perform below,
/// kept as a plain bool here so this stays table-testable without a real
/// `current_exe()` or a real file on disk.
fn resolve(env_value: Option<&str>, exe_dir: Option<&Path>, sibling_exists: bool, name: &str) -> String {
    if let Some(trimmed) = env_value.map(str::trim).filter(|v| !v.is_empty()) {
        return trimmed.to_string();
    }
    if let Some(dir) = exe_dir {
        if sibling_exists {
            return dir.join(name).to_string_lossy().into_owned();
        }
    }
    name.to_string()
}

/// The impure wrapper shared by [`core_bin`]/[`rice_bin`]: reads the real
/// env var and `current_exe()`, does the real `exists()` stat, then hands
/// everything to [`resolve`] for the actual tier decision.
fn resolve_bin(env_var: &str, name: &str) -> String {
    let env_value = std::env::var(env_var).ok();
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    let sibling_exists = exe_dir.as_deref().is_some_and(|dir| dir.join(name).exists());
    resolve(env_value.as_deref(), exe_dir.as_deref(), sibling_exists, name)
}

/// Resolve the core `aoide` binary for a cross-binary re-exec:
/// `AOIDE_CORE_BIN` env override, else `current_exe()`'s sibling named
/// `aoide` if it exists, else the bare name `"aoide"` for `PATH`
/// resolution at spawn time. See the module doc for the with_stage_lock
/// hazard this exists to route around, not to walk into.
pub fn core_bin() -> String {
    resolve_bin("AOIDE_CORE_BIN", "aoide")
}

/// Resolve the paint binary `lyra` for a cross-binary re-exec:
/// `AOIDE_RICE_BIN` env override, else `current_exe()`'s sibling named
/// `lyra` if it exists, else the bare name `"lyra"` for `PATH` resolution
/// at spawn time. See the module doc for the with_stage_lock hazard this
/// exists to route around, not to walk into.
pub fn rice_bin() -> String {
    resolve_bin("AOIDE_RICE_BIN", "lyra")
}

/// Is `name` a program discoverable on `PATH`? The proactive probe the tier
/// logic above deliberately skips: tier 3 (the bare name) is left for
/// `Command::spawn` to resolve at exec time rather than checked here, but a
/// caller that needs to know BEFORE spawning has nowhere else in the tree to
/// ask — every existing PATH-adjacent check (`aoide-secrets`' age-binary
/// probe) is a spawn-failure/ENOENT catch instead. Onboard's own lyra probe
/// (ONBOARD.md decision 3) is the first caller: `rice_bin()`'s tier-1/2
/// results are already trusted by the resolver itself (env unconditionally,
/// the sibling only after its own `exists()` check), so this only needs
/// calling on a bare-name result. `agents::on_path` is the other caller,
/// over an `AgentProfile`'s own `launch` program name.
pub fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row per tier decision the resolver has to make. No real env,
    /// no real filesystem, no real exec anywhere in this table —
    /// `resolve` takes every input as a plain argument.
    struct Case {
        label: &'static str,
        env_value: Option<&'static str>,
        exe_dir: Option<&'static str>,
        sibling_exists: bool,
        name: &'static str,
        expect: &'static str,
    }

    #[test]
    fn tiers_resolve_in_order() {
        let cases = [
            Case {
                label: "env wins even when a sibling exists",
                env_value: Some("/opt/custom/aoide"),
                exe_dir: Some("/usr/bin"),
                sibling_exists: true,
                name: "aoide",
                expect: "/opt/custom/aoide",
            },
            Case {
                label: "env wins over the bare-name fallback too",
                env_value: Some("/opt/custom/lyra"),
                exe_dir: None,
                sibling_exists: false,
                name: "lyra",
                expect: "/opt/custom/lyra",
            },
            Case {
                label: "a blank env value is treated as unset",
                env_value: Some("   "),
                exe_dir: Some("/usr/bin"),
                sibling_exists: true,
                name: "aoide",
                expect: "/usr/bin/aoide",
            },
            Case {
                label: "sibling used only when it actually exists",
                env_value: None,
                exe_dir: Some("/usr/bin"),
                sibling_exists: true,
                name: "lyra",
                expect: "/usr/bin/lyra",
            },
            Case {
                label: "sibling absent falls through to the bare name",
                env_value: None,
                exe_dir: Some("/usr/bin"),
                sibling_exists: false,
                name: "lyra",
                expect: "lyra",
            },
            Case {
                label: "no exe dir at all falls through to the bare name",
                env_value: None,
                exe_dir: None,
                sibling_exists: false,
                name: "aoide",
                expect: "aoide",
            },
        ];

        for c in cases {
            let exe_dir = c.exe_dir.map(Path::new);
            let got = resolve(c.env_value, exe_dir, c.sibling_exists, c.name);
            assert_eq!(got, c.expect, "{}", c.label);
        }
    }

    #[test]
    fn core_bin_and_rice_bin_resolve_to_different_env_vars() {
        // No filesystem/env stubbing here (the process env is process-wide
        // and races under parallel tests) — this only checks the two public
        // entries stay wired to their own env var / bare name and never
        // collide, using the pure `resolve` core directly rather than the
        // real `std::env::var`/`current_exe` the wrappers call.
        assert_eq!(resolve(None, None, false, "aoide"), "aoide");
        assert_eq!(resolve(None, None, false, "lyra"), "lyra");
        assert_ne!(resolve(None, None, false, "aoide"), resolve(None, None, false, "lyra"));
    }
}
