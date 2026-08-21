//! The `lyra` binary — the graphical/rice CLI trunk (P-A4).

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = aoide_lyra::run_lyra(&argv);
    std::process::exit(code);
}
