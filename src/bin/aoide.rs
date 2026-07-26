//! The `aoide` binary — the CLI trunk (Tier 1) and the MCP server entrypoint.

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = aoide::run_cli(&argv);
    std::process::exit(code);
}
