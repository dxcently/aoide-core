# pkgs/aoide/default.nix — the `aoide` CLI + `aoided` daemon (Rust).
#
# Built by Agent B (Wave 1). Replaces the Wave-0 placeholder in place; the
# `callPackage` signature is kept stable so flake.nix never changes.
#
# Contract honoured (docs/BUILD.md, CONTRACTS.md, concepts/Agent-Interface):
#   * File stays `pkgs/aoide/default.nix` and is `callPackage`-able.
#   * Installs a binary named `aoide` (meta.mainProgram) implementing the
#     command tree, `aoide schema --json` (the source of truth) and
#     `aoide guide`.
#   * Also installs `aoided` (the daemon skeleton: policy / lint / gated
#     rebuild / single audit log).
#   * cargo deps vendored via `cargoLock.lockFile` so the build is pure/offline.
{
  lib,
  rustPlatform,
  ...
}:
rustPlatform.buildRustPackage {
  pname = "aoide";
  version = "0.0.0";

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  # The workspace root is VIRTUAL (Phase 9 restructure,
  # docs/architecture/PACKAGE-LAYOUT.md): the `aoide`/`aoided` binaries come
  # from the `aoide-cli` app crate, so cargo builds/tests/installs from its
  # subdir (the workspace lock + every `crates/*` path dep still resolve
  # upward to the root).
  buildAndTestSubdir = "crates/cli";

  # Walking skeleton: no live-system integration tests in the sandbox.
  doCheck = true;

  meta = {
    description = "Aoide CLI + daemon — an API that happens to be typeable (agent-first NixOS desktop control).";
    mainProgram = "aoide";
    license = lib.licenses.mit;
  };
}
