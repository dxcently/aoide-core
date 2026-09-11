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
  `checkout`, `auditLog`, `terminal`, `user`. Every AoideOS-side unit
  (`modules/nucleus/aoided.nix`, `secrets.nix`, `shellbridge.nix`,
  `config.nix`) reads these options; this file only declares them.

## How a consumer imports it

```nix
{
  imports = [ inputs.aoide.nixosModules.default ];
}
```

One line pulls in the option contract and the overlay together — no
separate `nixpkgs.overlays` entry, no second `aoide.*` declaration to
keep in sync. `modules/nucleus/options.nix` is this repo's own
consumer: it imports the same line rather than declaring the six
options itself.
