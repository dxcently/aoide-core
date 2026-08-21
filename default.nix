# pkgs/aoide/default.nix — the `aoide` CLI + `aoided` daemon + `lyra` (Rust).
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
#   * Also installs `lyra` (P-A7 of the binary-split workstream) — the
#     graphical/rice binary from `crates/lyra`, sharing this one derivation
#     rather than a second package (see the `cargoBuildFlags` comment below).
#   * cargo deps vendored via `cargoLock.lockFile` so the build is pure/offline.
{
  lib,
  rustPlatform,
  git,
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

  # ...but `buildAndTestSubdir` also SCOPES the check phase to that one crate,
  # so without this the sandbox tested `aoide-cli` alone — about 30 of the
  # tree's 330 tests — while every crate beneath it (storage, song, protocol,
  # conduct, upkeep) was compiled but never exercised. A green `nix build`
  # meant far less than it looked like. `--workspace` restores the obvious
  # reading: the package build runs the whole suite.
  cargoTestFlags = [ "--workspace" ];

  # P-A7 of the binary-split workstream: this one derivation now ships THREE
  # binaries (aoide, aoided, lyra — `lyra` lives in the separate `crates/lyra`
  # app crate, docs/architecture/PACKAGE-LAYOUT.md). `buildAndTestSubdir`'s
  # `pushd` only changes cargo's cwd; `--workspace` on the build (mirroring
  # the test flag above) still builds every workspace member from there,
  # because cargo resolves the workspace root upward from the virtual
  # manifest regardless of cwd. `cargoBuildHook` forces `CARGO_TARGET_DIR` to
  # the repo root before the `pushd`, so `lyra`'s binary lands in the exact
  # same `target/<triple>/release/` directory nixpkgs' `cargoInstallHook`
  # already sweeps for executables — no `postInstall` copy needed (rung (a)
  # of the plan's ladder, first form; verified live via `ls result/bin`).
  cargoBuildFlags = [ "--workspace" ];

  # Walking skeleton: no live-system integration tests in the sandbox.
  doCheck = true;

  # `aoide-storage::git` shells out to `git` (the project-revert plan's git
  # seam, R2) — its own tests drive a real temp repo, so `git` must be on
  # PATH in the sandboxed check phase.
  nativeCheckInputs = [ git ];

  meta = {
    description = "Aoide CLI + daemon — an API that happens to be typeable (agent-first NixOS desktop control).";
    mainProgram = "aoide";
    license = lib.licenses.mit;
  };
}
