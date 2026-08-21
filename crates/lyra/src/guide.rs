//! `lyra guide` — the tier-0 onboarding for the graphical/rice binary.
//!
//! Terser than core's `aoide guide` on purpose: lyra owns one bundle (the
//! self-ricing loop, screen, herald, shellbridge, quickshell), not the full
//! four-tier orchestration surface. `aoide guide` stays the tier map for
//! conducting/graph/A2A/peers; this text only orients within lyra's own
//! command tree.

pub const GUIDE: &str = "\
Lyra — the graphical/rice binary (lyra guide · tier-0 onboarding)

Lyra owns AoideOS's painted surface: the self-ricing loop, screen capture/
pointer/OCR, the herald notification ledger, the shellbridge stage bridge,
and the Quickshell IPC reload trigger. Conducting, the project/session
graph, A2A, peers, and the daemon are core `aoide` identity — lyra never
registers those commands.

`lyra <cmd>` is lyra's whole surface. Every command takes and emits
`--json`; `lyra schema --json` is the machine-readable command tree.

Rice loop (headline): `lyra rice compose <name> [--from <song>]` scaffolds
a song → `lyra rice mode stage <name>` unlocks + stages it live → edit the
song's files → `lyra rice lint` validates → `lyra rice draft save <name>`
saves the iteration → `lyra rice declare <name>` commits (USER gates this).

Screen: `lyra screen shot|info|ocr|point *|diff|send` — desktop capture,
pointer synthesis, OCR, and act-verification for an agent driving the
desktop.

Herald/shellbridge/quickshell: `lyra herald push` files a notification into
the herald ledger (dunst's hook); `lyra shellbridge --run` publishes
session/hook state to song/stage/ atomically; `lyra quickshell reload`
triggers Quickshell's in-process scene reload.

Tier 2 — stdio MCP: `lyra mcp serve --stdio` serves lyra's own tool list,
generated from this same schema.

See CONTRACTS.md for the versioned interfaces and docs/architecture/
PACKAGE-LAYOUT.md for how lyra and core divide the command tree.
";
