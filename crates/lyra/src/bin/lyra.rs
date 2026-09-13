//! The `lyra` binary — the graphical/rice CLI trunk (P-A4).

fn main() {
    // `lyra preview tree | head` must end quietly when `head` closes the
    // pipe (SIGPIPE's default), not panic on a failed stdout write.
    // SAFETY: resets one signal disposition to its default before any
    // thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // One-shot, idempotent `~/Aoide` → `$AOIDE_ROOT` migration (L-C2, task
    // #107) — see `aoide_storage::fs::root`'s own doc for why this runs
    // here, explicitly, rather than hanging off a path getter.
    aoide_storage::fs::migrate_root_once();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = aoide_lyra::run_lyra(&argv);
    std::process::exit(code);
}
