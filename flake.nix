# pkgs/aoide/flake.nix — the Aoide core (aoide CLI + aoided daemon) as its own
# flake.
#
# Topology (b) of AOIDE-DEV §7 "Separate Aoide from AoideOS": the core is a
# self-flaked package, nixpkgs-only, consumed by the root AoideOS flake as a
# `path:` input (root flake.nix, `inputs.aoide`). This file is the marker that
# flips `pkgs/aoide` from a callPackage target into an input: lib/pkgs.nix
# skips any package dir carrying its own flake.nix. Graduation to a separate
# repo is a one-line input swap.
#
# Deliberately nixpkgs-only — there is no NixOS below `cli` (PACKAGE-LAYOUT),
# and the nixpkgs input follows the root's, so the core always builds against
# the same revision the AoideOS flake locks. The build itself is default.nix
# (rustPlatform + vendored cargo deps, doCheck runs the cargo tests), so
# `checks.default` IS the package build.
{
  description = "Aoide core — the aoide CLI + aoided daemon (agent-first desktop control), as a self-contained nixpkgs-only flake.";

  # ── Inputs ─────────────────────────────────────────────────────────────────
  # nixpkgs only, by charter. The root flake overrides it with `follows`, so
  # this lock file is advisory there; standalone use (this dir as its own
  # flake) locks nixos-unstable like the root does.
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  # ── Outputs ────────────────────────────────────────────────────────────────
  # Plain (non-flake-parts) style, matching the root flake. One system,
  # mirroring the root's `systems` list — the core builds where AoideOS does.
  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems f;
    in
    {
      # ── Packages ───────────────────────────────────────────────────────────
      # One derivation, two names: `default` is the consumer-friendly alias the
      # root reads (`packages.${system}.default`); `aoide` is the explicit one.
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          aoide = pkgs.callPackage ./default.nix { };
        in
        {
          default = aoide;
          inherit aoide;
        }
      );

      # ── Apps ───────────────────────────────────────────────────────────────
      # The two binaries the package installs, exposed as flake apps.
      apps = forAllSystems (system: {
        aoide = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/aoide";
        };
        aoided = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/aoided";
        };
      });

      # ── Checks ─────────────────────────────────────────────────────────────
      # The check IS the package build: default.nix runs `cargo test` in the
      # sandbox (doCheck), so a green `checks.default` is the full Rust suite.
      checks = forAllSystems (system: {
        default = self.packages.${system}.default;
      });

      # ── Dev shell ──────────────────────────────────────────────────────────
      # The Rust toolchain only — the root devShell's Rust half, mirrored. The
      # root adds the Nix tooling (nixfmt/nil/…) on top for the AoideOS
      # packaging surface; the core's own shell stays toolchain-only.
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            name = "aoide-core-dev";
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              rust-analyzer
            ];
          };
        }
      );
    };
}
