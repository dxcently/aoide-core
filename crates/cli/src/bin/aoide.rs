//! The `aoide` binary — the CLI trunk (Tier 1) and the MCP server entrypoint.

fn main() {
    // One-shot, idempotent `~/Aoide` → `$AOIDE_ROOT` migration (L-C2, task
    // #107) — see `aoide_storage::fs::root`'s own doc for why this runs
    // here, explicitly, rather than hanging off a path getter.
    aoide_storage::fs::migrate_root_once();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = aoide::run_cli(&argv);
    std::process::exit(code);
}
