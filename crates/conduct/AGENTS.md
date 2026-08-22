# AGENTS.md — aoide-conduct

## Invariants

- **This crate is core, never lyra.** Nothing here may gain a
  wayland/image/quickshell dependency — that's exactly what P-A1 moved OUT
  (to `screen`) to keep this crate headless-safe. `cargo tree -p
  aoide-conduct` staying free of those deps is a standing gate.
- **`shellbridge.rs`/`herald.rs` are a named, deliberate charter smudge.**
  Their CLI verbs live in `lyra`; the files stay here because `permit.rs`
  (this crate) publishes through `herald`, and `conductor/ui.rs` reads the
  socket path `shellbridge` owns. Don't move the files to chase the verbs —
  see `docs/architecture/PACKAGE-LAYOUT.md`'s "Charter exceptions" for the
  full reasoning before touching either.
- **`normalize_addr` is `pub`, not `pub(crate)`, on purpose** — `screen`
  reaches it directly rather than duplicating it. Don't narrow it back
  without checking that dependency first.
- **A killed terminal never self-reports `done`.** `reap` is the only
  sanctioned sweep of dead sessions; don't add a second liveness mechanism.
- **`who` is a projection, never a store.** It must never write
  `state/peer-cache/<name>.json` — `build_graph`'s own fold (`doc.rs`) is
  the ONLY writer of that cache. `who`'s live probe reads straight off the
  network via `aoide_client::commands::pull_peer_live` and falls back to
  the cache (read-only) for an unreachable peer; don't "helpfully" have a
  successful live probe refresh the cache as a side effect.

## Extension points

- **A new `graph`/`conduct`/`hooks` verb** adds a `cmd!`/`register` entry in
  `commands/`, wired into `cli`'s `commands::all()` (this crate's verbs are
  core, never `lyra`'s).
- **A new hook event or harness profile** extends `aoide_protocol::agents`,
  not this crate — the harness-profile table lives one layer down.

## Docs update required in the same commit

- This `README.md` when a public module, seam, or charter-smudge reasoning
  changes.
- `CONTRACTS.md` when a graph/session wire shape changes.
- `pkgs/aoide/crates/AGENTS.md` for cross-crate invariants — not restated
  here.
