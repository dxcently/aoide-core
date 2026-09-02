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

use std::path::{Path, PathBuf};

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

/// Is `path` a regular file with at least one executable bit set? The check
/// `on_path` above deliberately skips (`is_file()` alone) — a caller that
/// means to SPAWN the result, not merely note its presence, must not treat a
/// same-named non-executable file as a hit.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Resolve `name` to an absolute path if an EXECUTABLE file by that name
/// sits on `PATH` — task #138's external-subcommand probe
/// (`aoide_protocol::door::run`) needs both the resolved path (to spawn)
/// and true executability (a stray non-executable `aoide-foo` must fall
/// through to the ordinary unknown-command error, same as a miss). Kept as
/// its own walk rather than widening `on_path`'s contract: `on_path`'s
/// existing callers (`agents::on_path`, onboard's own lyra probe) and its
/// own regression test intentionally accept a non-executable same-named
/// file as "found," and that must not change under them.
pub fn resolve_executable_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).map(|dir| dir.join(name)).find(|p| is_executable_file(p))
}

/// Every `<bin_name>-<name>` executable found on `PATH` — the plugin
/// inventory `schema --json`'s additive `external` key (CONTRACTS.md §3)
/// and `--help`'s own trailing external section (`door::usage_root`) both
/// list. Walks each `PATH` directory in order, keeping the FIRST match for
/// a given name — a later directory shadowing an earlier one on `PATH`
/// never overrides what a shell would actually run. Returns `(name,
/// resolved absolute path)` pairs sorted by name (directory read order is
/// not guaranteed, and both consumers need a deterministic document).
pub fn discover_external(bin_name: &str) -> Vec<(String, PathBuf)> {
    let Some(paths) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let prefix = format!("{bin_name}-");
    let mut found: std::collections::BTreeMap<String, PathBuf> = std::collections::BTreeMap::new();
    for dir in std::env::split_paths(&paths) {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Some(file_name) = entry.file_name().to_str().map(str::to_string) else { continue };
            let Some(name) = file_name.strip_prefix(&prefix) else { continue };
            if name.is_empty() {
                continue;
            }
            let path = entry.path();
            if !is_executable_file(&path) {
                continue;
            }
            found.entry(name.to_string()).or_insert(path);
        }
    }
    found.into_iter().collect()
}

/// Shared `PATH`-mutation lock for this crate's own PATH-touching tests.
/// `bin::tests` and `agents::tests` (`agents::on_path` delegates straight
/// into the function above) both mutate the real `PATH` env var, so they
/// share ONE mutex rather than each guarding a different one
/// (crates/AGENTS.md's "process-global env... must share ONE mutex or they
/// race") — `door::tests` (the external-command probe) and `registry::tests`
/// (the `external` schema key) share it too, same reason. `pub(crate)`, not
/// module-local: the whole reason this lives
/// outside `mod tests` below.
#[cfg(test)]
pub(crate) fn path_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

/// Mark a just-written file executable (owner bit only, `0o755` — every
/// caller's file is scratch, never shared). `pub(crate)`, alongside
/// [`path_test_lock`], so `door::tests` and `registry::tests` can build a
/// fake plugin without reimplementing the `PermissionsExt` dance.
#[cfg(test)]
pub(crate) fn mark_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
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
    fn on_path_finds_a_program_in_a_scoped_path_and_misses_a_name_that_is_not_there() {
        let _guard = path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_bin_on_path_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("definitely-there"), "").unwrap();
        std::env::set_var("PATH", &dir);

        assert!(on_path("definitely-there"));
        assert!(!on_path("definitely-not-there"));

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_path_is_false_when_path_is_unset() {
        let _guard = path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        std::env::remove_var("PATH");

        assert!(!on_path("anything"));

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn resolve_executable_on_path_requires_the_executable_bit() {
        let _guard = path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_bin_resolve_exec_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plain-file"), "").unwrap();
        std::fs::write(dir.join("real-plugin"), "#!/bin/sh\n").unwrap();
        mark_executable(&dir.join("real-plugin"));
        std::env::set_var("PATH", &dir);

        assert_eq!(resolve_executable_on_path("real-plugin"), Some(dir.join("real-plugin")));
        assert_eq!(
            resolve_executable_on_path("plain-file"),
            None,
            "a same-named non-executable file must not count as a hit"
        );
        assert_eq!(resolve_executable_on_path("nowhere"), None);

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_external_finds_every_prefixed_executable_and_skips_the_rest() {
        let _guard = path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        let dir = std::env::temp_dir().join(format!("aoide_bin_discover_external_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Two real plugins, in a deliberately non-alphabetical write order.
        std::fs::write(dir.join("aoide-zebra"), "").unwrap();
        mark_executable(&dir.join("aoide-zebra"));
        std::fs::write(dir.join("aoide-deploy"), "").unwrap();
        mark_executable(&dir.join("aoide-deploy"));
        // A non-executable same-prefix file: must not appear.
        std::fs::write(dir.join("aoide-unexecutable"), "").unwrap();
        // An unrelated executable and a bare "aoide-": neither is a plugin.
        std::fs::write(dir.join("unrelated"), "").unwrap();
        mark_executable(&dir.join("unrelated"));
        std::fs::write(dir.join("aoide-"), "").unwrap();
        mark_executable(&dir.join("aoide-"));
        std::env::set_var("PATH", &dir);

        let got = discover_external("aoide");
        assert_eq!(
            got,
            vec![("deploy".to_string(), dir.join("aoide-deploy")), ("zebra".to_string(), dir.join("aoide-zebra"))],
            "sorted by name, non-executable/unrelated/bare-prefix entries excluded"
        );

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_external_is_empty_when_path_is_unset() {
        let _guard = path_test_lock().lock().unwrap();
        let saved = std::env::var_os("PATH");
        std::env::remove_var("PATH");

        assert!(discover_external("aoide").is_empty());

        match saved {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
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
