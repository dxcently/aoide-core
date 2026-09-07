# pkgs/aoide/flake.nix — the Aoide core (aoide CLI + aoided daemon) as its own
# flake.
#
# Topology (b) of `docs/architecture/PACKAGE-LAYOUT.md` ("Two binaries"): the
# core is a self-flaked package, nixpkgs-only, consumed by the root flake as a
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
          # aoide-static — the core pair (`aoide`/`aoided`, no `lyra`) linked
          # against musl with `+crt-static`, for a host with no nix store: a
          # link-and-run proof, not a second copy of the test suite (see
          # default.nix's `doCheck` comment). `pkgsStatic` retargets the
          # WHOLE package set (not just rustc) to `pkgsCross.musl64` plus
          # `+crt-static`, so `rustPlatform.buildRustPackage` from it needs
          # no extra flags — same call shape as the dynamic build above, one
          # more argument.
          aoide-static = pkgs.pkgsStatic.callPackage ./default.nix { paint = false; };
        in
        {
          default = aoide;
          inherit aoide aoide-static;
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
      # The COMPLETE dev surface for this workspace — every tool development
      # in `crates/` actually uses, so that when this directory graduates to
      # its own repo (the header's one-line input swap) the shell needs
      # nothing from the AoideOS flake. Inventory derived from the code, not
      # aspiration: `grep -r 'Command::new' crates/` enumerates the runtime
      # shell-outs; the toolchain and jq are the build/probe loop.
      #
      # Deliberately ABSENT, each for a reason:
      #   - hyprctl / quickshell — session-owned: hyprctl's IPC is
      #     version-coupled to the RUNNING compositor, and a shell-provided
      #     copy that skews from the host session is worse than none. Both
      #     come from the deployed system, never from this shell.
      #   - loginctl / systemctl — systemd host tools; shipping them in a
      #     shell on a non-systemd host would only fake the probe
      #     (`watch --popup`'s LockedHint check degrades honestly instead).
      #   - nix — lyra's song eval shells out to it, but any machine entering
      #     this shell has nix by construction.
      #   - sh / coreutils / kill — stdenv givens.
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            name = "aoide-core-dev";
            packages = with pkgs; [
              # Rust toolchain — the build/test loop. rustfmt is present for
              # editor tooling only; running it against this tree is banned
              # (HEAD is not rustfmt-clean; a run manufactures churn).
              cargo
              rustc
              rustfmt
              clippy
              rust-analyzer
              # The --json contract's other half: every dev probe is
              # `aoide <cmd> --json | jq …`.
              jq
              # Core runtime shell-outs (crates/client, storage, secrets):
              curl # client node pulls / A2A dials
              git # storage::git derivation capture
              qrencode # secrets enroll — otpauth QR render
              age # secrets age backend — without it the crate's age-gated tests self-skip
              zenity # secrets watch --popup — the code-entry dialog
              libnotify # notify-send, herald's local fallback
              # Paint-side probes (crates/screen — wayland-session tools,
              # inert off-desktop but standalone and version-insensitive):
              grim # screen shot
              slurp # screen region pick
              tesseract # screen ocr
              # This flake's own .nix files (checks.fmt upstream is
              # nixfmt-only; same formatter here).
              nixfmt
            ];
            # AF_UNIX SUN_LEN guard: `nix develop` mints a deep
            # /tmp/nix-shell.XXXXXX TMPDIR, and conduct's socket tests have
            # ~5 bytes of headroom under /tmp — the deep default overflows
            # sun_path and poisons the suite's env_lock in a 58-test cascade
            # that looks like a broken crate. Pin TMPDIR back to /tmp so
            # `cargo test -p <crate>` works without the manual TMPDIR=/tmp
            # incantation.
            shellHook = ''
              export TMPDIR=/tmp
            '';
          };
        }
      );
    };
}
