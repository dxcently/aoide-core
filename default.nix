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
#     As of P-A8, `lyra` ships in this derivation's separate `rice` output
#     (`pkgs.aoide.rice`) — droppable from a headless closure that only ever
#     references `pkgs.aoide` (the `out` output: `aoide` + `aoided`).
#   * cargo deps vendored via `cargoLock.lockFile` so the build is pure/offline.
#   * `paint ? true` — false builds ONLY the core `aoide`/`aoided` pair
#     (`-p aoide-cli`, no `rice` output, no test phase) for the static-musl
#     variant (`aoide-static`, pkgs/aoide/flake.nix). Nothing about the
#     dynamic default changes: every caller that omits the arg gets exactly
#     today's three-binary, tested build.
{
  lib,
  rustPlatform,
  git,
  curl,
  paint ? true,
  ...
}:
rustPlatform.buildRustPackage {
  pname = "aoide";
  # Prebeta versioning start (2026-08-22, root README.md's "Versioning"
  # section) — matches pkgs/aoide/Cargo.toml's [workspace.package].version,
  # the single Cargo-side source every crate inherits from.
  version = "0.0.1";

  src = lib.cleanSource ./.;

  # P-A8 of the binary-split workstream: `lyra` moves off $out into its own
  # `rice` output, so a config that never enables the paint half (headless
  # boxes — sakaki and any future doors-only host) can install `pkgs.aoide`
  # (aoide + aoided only) without `pkgs.aoide.rice` ever entering its closure.
  # `out` stays first so plain `pkgs.aoide`/`${pkgs.aoide}` keeps resolving to
  # the core pair, unchanged for every existing caller. `paint = false` drops
  # `rice` — there is no `lyra` to give it an output.
  outputs = [ "out" ] ++ lib.optionals paint [ "rice" ];

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

  # task #117 (resolved): the sandbox check runs parallel again. The
  # nondeterministic deploy-build cascade traced to aoide-conduct's hooks
  # tests taking a DIFFERENT env-lock mutex (aoide_test_support's) than the
  # rest of the crate (crate::env_lock) — two locks, no mutual exclusion,
  # so an env rewrite raced every concurrent state_dir() resolver and one
  # panic poisoned a held lock for everything behind it. fec4c54 aliases
  # both spellings to ONE mutex; the lift bar (fix + 3x green parallel
  # aoide-conduct runs, the #81 precedent) was met and independently
  # re-proven in review before the serialization switch came back out.

  # task #81 (this commit): the secrets crate's EnvGuard test helper
  # (backend.rs) now takes the SAME crate::env_lock() every other
  # process-env-mutating test in this crate already held — before this fix
  # it mutated AOIDE_SECRETS_BACKEND_TIMEOUT/PATH with no lock at all, so
  # under libtest's default parallelism one test's timeout override could
  # bleed into a concurrently-running test's fetch and kill it mid-read
  # (two failed deploy builds, 2026-08-23), and the resulting panic — since
  # it usually landed inside SOME OTHER test's env_lock()-held section —
  # poisoned that lock for every test queued behind it. `cargo test -p
  # aoide-secrets` is green under default parallelism, repeated 3x, so the
  # sandbox check now runs the secrets crate's suite parallel like every
  # other crate; the `dontUseCargoParallelTests` switch this comment used to
  # document is dropped.

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
  # of the plan's ladder, first form; verified live via `ls result/bin`). All
  # three still install to $out at this point; P-A8's `postFixup` below is
  # what relocates `lyra` alone into `$rice`.
  # `paint = false` scopes the build to the core crate alone — no lyra, no
  # song/screen weight — for the static variant.
  cargoBuildFlags =
    if paint then
      [ "--workspace" ]
    else
      [
        "-p"
        "aoide-cli"
      ];

  # `paint = false` also turns the test phase off. The dynamic `pkg-aoide`
  # check already runs this exact suite over identical sources; this
  # variant's job is a link-and-run proof, not a second test run, and
  # skipping it keeps musl-specific flakiness (128 KB default thread stacks,
  # NSS differences) out of the gate. Inverse if musl divergence ever
  # matters: turn `doCheck` on with `cargoTestFlags` scoped to core crates.
  doCheck = paint;

  # P-A8: relocate `lyra` into the `rice` output. `cargoInstallHook` (like
  # every nixpkgs install hook) installs to $out regardless of the declared
  # `outputs` list, so all three binaries land in $out/bin first; this runs
  # in `postFixup` (the documented moveToOutput call site — nixpkgs manual
  # §"multiple-output packages") so it happens AFTER stripping/patchelf have
  # already run against the file at its $out path, then simply relocates the
  # finished artifact. `moveToOutput` is provided unconditionally by the
  # `multiple-outputs.sh` setup hook baked into stdenv — no extra input
  # needed. No `dev`/`doc` split declared here, so there is no
  # dev-output-interference hazard to work around. `paint = false` never
  # built a `lyra` binary, so there is nothing to move.
  postFixup = lib.optionalString paint ''
    moveToOutput bin/lyra "$rice"
  '';

  # `aoide-storage::git` shells out to `git` (the project-revert plan's git
  # seam, R2) — its own tests drive a real temp repo, so `git` must be on
  # PATH in the sandboxed check phase. `aoide-client::commands::run_curl`
  # (the crate's one HTTP transport, `post_json`/`peer add`'s AgentCard
  # fetch) shells out to `curl` the same way — the ssh-transport lane's
  # dial-resolution tests (P-S4) drive real `curl` calls (a fast connection
  # refusal against a reserved port, or a real loopback HTTP round trip
  # through a reused tunnel record) rather than mocking the transport, so
  # `curl` needs the same PATH availability `git` already has here.
  nativeCheckInputs = [
    git
    curl
  ];

  meta = {
    description = "Aoide tracks and conducts terminal and agent sessions, collaborating across agents and hosts with the human in the loop.";
    mainProgram = "aoide";
    license = lib.licenses.mit;
  };
}
