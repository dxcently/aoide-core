# AGENTS.md — pkgs/aoide/module

## Invariants

- **nixpkgs-only.** This directory lives inside the core flake (root
  `AGENTS.md`, "Two binaries") — no file here reaches into `modules/`
  or `song/`, and none may gain an input beyond nixpkgs.
- **Explicit `imports`, no walker.** `default.nix` names every sibling
  it pulls in by hand. `modules/`'s `lib/walk.nix` discovery is a
  different tree's convention; this one stays a plain, readable list —
  a consumer reads one file and knows what it imports.
- **Every capability off by default.** An option declared here
  defaults to inert (`enable` is `mkEnableOption`, off unless a host
  flips it); nothing in this bundle wires behavior a host didn't ask
  for.
- **A new core unit is a new file plus one `imports` line.** Follow
  `default.nix`'s existing shape — never fold a new unit's options into
  `options.nix` itself, and never grow `default.nix` into anything but
  a flat import list plus the overlay.

## Docs update required in the same commit

- This `README.md` when a new file or option namespace is added here.
- `docs/architecture/PACKAGE-LAYOUT.md`'s `nixosModules.default` row
  when the bundle's contract changes shape.
