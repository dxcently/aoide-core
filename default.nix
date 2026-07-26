# pkgs/aoide/default.nix — the `aoide` CLI + `aoided` daemon (Rust).
#
# ┌─ WAVE-0 PLACEHOLDER ─────────────────────────────────────────────────────┐
# │ This is a trivial derivation so `nix flake check` evals & builds green    │
# │ with an empty package dir. AGENT B replaces the body below with a real    │
# │ `rustPlatform.buildRustPackage { ... }` (see docs/BUILD.md). Keep the     │
# │ callPackage signature (pkgs args) stable so flake.nix never changes.      │
# └──────────────────────────────────────────────────────────────────────────┘
#
# Contract Agent B must honour (so flake.nix / checks stay untouched):
#   * This file stays `pkgs/aoide/default.nix` and is `callPackage`-able.
#   * The built package must install a binary named `aoide` on PATH, and that
#     binary must implement `aoide schema --json` and `aoide guide` (the CLI
#     trunk — see CONTRACTS.md and concepts/Agent-Interface).
#   * `pname = "aoide"`.
{
  lib,
  runCommand,
  # ── Agent B: uncomment/add the real build inputs, e.g. ──
  # rustPlatform,
  ...
}:
runCommand "aoide-0.0.0-placeholder"
  {
    pname = "aoide";
    version = "0.0.0-placeholder";
    meta = {
      description = "Aoide CLI + daemon (Wave-0 placeholder; Agent B replaces).";
      mainProgram = "aoide";
    };
  }
  ''
    mkdir -p "$out/bin"
    cat > "$out/bin/aoide" <<'EOF'
    #!/bin/sh
    echo "aoide: Wave-0 placeholder — the Rust CLI has not been built yet." >&2
    echo "See docs/BUILD.md (Agent B) and CONTRACTS.md for the CLI contract." >&2
    exit 69
    EOF
    chmod +x "$out/bin/aoide"
  ''
