# pkgs/aoide/module

The core's NixOS deployment bundle, exported as `nixosModules.default`
from `pkgs/aoide/flake.nix`. Lives inside the core flake (not the root
flake) so a consumer outside this repo gets the option contract and the
package build from the same one-line input.

## Named seams

- `default.nix` — composes the bundle: imports the siblings below and
  applies `overlays.default` (the same export `packages.<sys>.aoide`
  names), so a consumer that imports this module needs no separate
  overlay line of their own.
- `options.nix` — THE core `aoide.*` option contract: `enable`, `root`,
  `checkout`, `auditLog`, `terminal`, `user`, `sessionTarget`. Every
  AoideOS-side unit (`modules/nucleus/aoided.nix`, `secrets.nix`,
  `shellbridge.nix`, `config.nix`) reads these options; this file only
  declares them.
- `aoided.nix` — the `aoided` systemd user service itself: the tmpfiles
  rules for the runtime tree and the core session variables
  (`AOIDE_TERMINAL`, `AOIDE_ROOT`, `AOIDE_FLAKE_ROOT`), portable and
  nixpkgs-only. The unit's `wantedBy`/`after`/`partOf` anchor to
  `aoide.sessionTarget` — the seam a paint-dependent value enters
  through, since this file may not read a facet option directly.
  `modules/nucleus/aoided.nix` sets that option and carries the
  lyra-gated `AOIDE_SONG_TEMPLATES` variable plus every door
  (mcp/a2a/pair-watch), the discovery firewall carve, and the usage
  poller — all still AoideOS-side deployment.

## How a consumer imports it

```nix
{
  imports = [ inputs.aoide.nixosModules.default ];
}
```

One line pulls in the option contract, the `aoided` unit, and the
overlay together — no separate `nixpkgs.overlays` entry, no second
`aoide.*` declaration to keep in sync. `modules/nucleus/options.nix`
is this repo's own consumer: it imports the same line rather than
declaring the seven options itself.

A stranger outside this repo pins the same five lines — no `modules/`
import, no `inputs.quickshell`/`hyprland`/`nvf`:

```nix
inputs.aoide.url = "path:/path/to/pkgs/aoide";
inputs.aoide.inputs.nixpkgs.follows = "nixpkgs";
modules = [ aoide.nixosModules.default ];
aoide.enable = true;
aoide.user = "stranger";
```

## This directory is outside the package `src`

`pkgs/aoide/default.nix`'s `src` filter drops the top-level `module/`
directory, so a file added or edited here never moves the `aoide`
derivation's store path or reruns its cargo test phase — the package
is the crate tree; this module ships beside it.
