//! Command groups — each contributes its entries to a [`crate::registry::Registry`]
//! via a `register(&mut Registry)` function. [`all`] assembles them in the
//! exact order that reproduces the historical `schema.rs` table order (see
//! `registry.rs` module docs for why that order is load-bearing).

mod a2a;
mod cover;
mod graph;
mod infra;
mod meta;
mod rice;
mod stubs;
mod usage;

use crate::registry::Registry;

/// Build the full command registry, in the historical `schema --json` order:
/// guide, schema, rice gen(stub), rice lint/preview/mint, cover set,
/// rice adopt/transpose(stub), content(stub x5), make(stub), update(stub),
/// onboard(stub), mcp serve, daemon, shellbridge, graph(x15) + conduct,
/// adapter melete, conductor, a2a serve + agent add/list/remove(stub x3),
/// usage (appended — the newest group, so it never reorders the historical
/// table above it).
pub fn all() -> Registry {
    let mut r = Registry::new();

    meta::register(&mut r); // guide, schema
    stubs::register_rice_gen(&mut r); // rice gen
    rice::register(&mut r); // rice lint, preview, mint
    cover::register(&mut r); // cover set
    stubs::register_rice_late(&mut r); // rice adopt, transpose
    stubs::register_content(&mut r); // content register/propose/approve/ingest/query
    stubs::register_make(&mut r); // make
    stubs::register_update(&mut r); // update
    stubs::register_onboard(&mut r); // onboard
    infra::register_pre_graph(&mut r); // mcp serve, daemon, shellbridge
    graph::register(&mut r); // graph x15 + conduct
    infra::register_post_graph(&mut r); // adapter melete, conductor
    a2a::register(&mut r); // a2a serve (real), agent add/list/remove/send (real, client side — CONTRACTS.md §6)
    usage::register(&mut r); // usage — local token/cost rollup (CONTRACTS.md §4)

    r
}

/// Shared test scaffolding for the command-group test modules (`rice.rs`,
/// `cover.rs`): env-var save/restore, a scratch-dir helper, and the fixture
/// note payloads several groups' tests need.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::daemon::Door;
    use crate::dispatch::Invocation;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    pub(crate) fn unique_tmp(tag: &str) -> PathBuf {
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

    pub(crate) fn inv(path: &[&str], args: &[&str]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: BTreeMap::new(),
            door: Door::Cli,
        }
    }

    // Restore env vars on drop so a panicking assertion never leaks state.
    pub(crate) struct EnvSaver {
        keys: Vec<(&'static str, Option<String>)>,
    }
    impl EnvSaver {
        pub(crate) fn capture(keys: &[&'static str]) -> Self {
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

    pub(crate) const VALID_NOTES: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"} }"##;

    // Carries a `window` block (border colours), so `hyprctl` keyword-batch
    // construction has something to resolve — VALID_NOTES deliberately does
    // not, to exercise the "empty batch" path elsewhere.
    pub(crate) const NOTES_WITH_WINDOW: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
        "window": {"border":"#82aaff","borderInactive":"#0b1021"} }"##;

    // A song with palette + window + a full geometry block, for `rice mint`
    // tests that need to assert every tier round-trips.
    pub(crate) const NOTES_WITH_GEOMETRY: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"#0b1021","fg":"#c8d3f5","accent":"#82aaff","urgent":"#ff757f"},
        "window": {"border":"#82aaff","borderInactive":"#0b1021"},
        "geometry": {"gapsOut":10,"gapsIn":4,"borderSize":3,"rounding":6,
                     "blurEnabled":false,"blurSize":5,"blurPasses":2} }"##;

    // A hostile palette value carrying live Nix interpolation syntax — proves
    // `nix_scalar` neutralizes `${…}` rather than letting it round-trip into
    // `rice.nix` as a real interpolation (a real injection: a value like
    // `"${builtins.readFile /etc/hostname}"` would otherwise EVALUATE).
    pub(crate) const NOTES_WITH_INTERPOLATION: &str = r##"{ "schemaVersion":"0",
        "palette": {"bg":"${builtins.currentTime}","fg":"#c8d3f5",
                     "accent":"#82aaff","urgent":"#ff757f"} }"##;

    // Force drachma un-locatable so lint outcomes don't depend on the sandbox
    // PATH (drachma is not a build dep of aoide; the checkPhase has no PATH copy).
    pub(crate) fn hide_drachma() {
        std::env::set_var("PATH", "");
        std::env::set_var("AOIDE_DRACHMA_BIN", "");
    }
}
