//! The `lyra` binary — the graphical/rice CLI trunk (P-A4).

fn main() {
    // One-shot, idempotent `~/Aoide` → `$AOIDE_ROOT` migration (L-C2, task
    // #107) — see `aoide_storage::fs::root`'s own doc for why this runs
    // here, explicitly, rather than hanging off a path getter.
    aoide_storage::fs::migrate_root_once();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = aoide_lyra::run_lyra(&argv);
    std::process::exit(code);
}
