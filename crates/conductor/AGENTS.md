# AGENTS.md — aoide-conductor

## Invariants

- Frontend only: every mutation uses the injected `DispatchFn` with a normal
  invocation. Reuse existing command outcomes and storage types; do not
  create another project registry, mail store, policy engine or dispatcher.
- Rendering stays pure. `ui`, `board` and graph views draw from state;
  input handling owns state changes and dispatch. Mouse hit testing and
  drawing share geometry and row ordering, including scrolling and narrow
  layouts. An action must mean the same thing by mouse and keyboard.
- Graph zoom is a camera transform of fixed world rectangles at 50/75/100/125/150%.
  Pointer-anchored zoom, pan limits, render and hit tests share geometry.
  Terminal glyphs stay fixed-size and clip inside cards; never relayout
  entities into alternative card presets when zoom changes.
- One identity mark per kind, from `theme::mark`; never a second glyph for
  the same kind, never a mark wider than one cell, never `@` (addresses).
  Colour comes from a `Role`, not from the glyph. Measure labels with
  `board::cells`, never `len()`.
- Only the keyboard-focused pane gets a bright selection; other selected
  regions use subdued livery shading. Controls use ASCII markers and plain
  field labels, without editing badges or double borders.
- Project removal snapshots its target and requires an exact-name confirmation;
  initial keys, empty input and Escape never unregister a project.
- Context menus snapshot their exact target. Historical actions may resurrect
  only through the existing registered-project/native-ID or restore-snapshot
  path; never route them to a stale live focus or project mutation. Project
  resurrection retains the backend's undying semantics. Do not advertise
  unsupported Rename or Kill actions.
- Semantic colors read exact RGB Base16 tokens from rice-stage livery;
  ANSI colors are fallbacks for absent tokens, not a competing theme.
- History is separate from live state. Ledger entries never enter
  `App::merged()` or the live graph. Opening one only selects historical
  detail; stale live selection must not receive Enter, kill or focus while
  history is displayed. Preserve explicit recorded project attribution;
  use the existing root matcher only when attribution is absent.
- Human mail browsing is non-consuming. Read the existing immutable base
  through storage's `Entry` shape without recipient read/mark, receipts,
  repair or migration writes. Keep original message IDs, canonical
  addresses and text. Structured conversation identity is the signed
  `threadId`, never the current participant set or subject. Aggregate
  canonical sender, envelope target, To and Cc endpoints without changing
  routing identity. Legacy pair correspondence stays labeled; a legacy
  reply thread includes only the exact original whose msgid anchors it.
  Preserve `replyTo`; new letters and forwards receive new thread IDs.
- The mail form owns input before global navigation. Its selected field and
  UTF-8 cursor stay consistent with mouse hit testing. Opening a tree
  recipient action only edits a draft; it never dispatches implicitly.
  The visible recipient tree obeys the selected To/Cc target and never
  treats a project group as an implicit broadcast destination. To/Cc targeting
  persists across additions. Ctrl-P changes tree/form focus; Escape leaves
  the tree before cancelling the form. Text entry owns printable keys.
  Reply and Forward retain the immutable original as context. Partial
  accepted submissions cannot repeat the whole fanout; surface recipient
  results and keep the draft locked against duplicate sends.
- A human-composed letter is attributed to `conductor-human` and sent only
  by explicit dispatch. Enter in the body inserts a newline. Do not
  silently rewrite or re-sign agent-authored/delivered mail as that agent.
- Mail interception needs a real daemon proposal gate. Neither transport
  hold nor Pending input approvals is an editable-mail policy. Preserve
  originals, actor attribution and exact revision decisions if that seam
  is implemented. Do not claim outgoing archive completeness or remote sync.
- Bounded mail/audit reads ignore incomplete final records without
  modifying files. Failed refreshes expose the error and retain prior
  data. Raw audit fields remain inspectable; absent facts stay unknown.
- Conducting stage and rice stage are distinct. Project/session/hook reads
  use `App::stage`; palette notes use `App::rice_stage`. Historical ledger,
  mail and audit paths use their existing owning APIs.
- Roster probes remain bounded and asynchronous; refresh throttling must
  not freeze input. Offline cached sessions retain their last-seen status.
- Pending IDs are array positions. Relist after every approve/deny before
  using another selection; never recycle those indices as durable mail
  proposal identifiers.
- All exit paths preserve `TermGuard` restoration and panic-hook cleanup.
  Keep terminal/mouse state correct after normal exit, errors and panics.
- No Wayland, image, Qt, Nix or song runtime dependency enters this core
  frontend. The bundled logo is plain text branding, sourced from the
  Fastfetch art, not a runtime call to the desktop module.

## Extension points

A panel adds an App selection/state seam and pure renderer, then joins the
shared navigation, keyboard and mouse geometry. Number keys 1–9 then 0 and Tab cycling follow the visible tab order. Panel-specific keys
are scoped to their handlers; text input and overlays take priority.

Project rows represent projects, not individual roots. Use `Project::roots`
and existing attribution/grouping helpers. Tree row models are the common
source for rendering, focus, collapse and activation.

Tests use isolated paths or injected fixtures. Never read or mutate the
operator's ambient mail cursors, ledger, registry or terminal during unit
checks. Add meaningful state-transition and narrow-layout tests for changed
input/view seams; run this crate's tests, not an unrelated workspace sweep.

## Documentation updates

Update README.md for user-visible behavior and named seams, and DESIGN.md
for state flow or integrity boundaries in the same commit as the change.
Keep documents integral and current; implementation history belongs in the
commit/log. Cross-crate invariants belong in the parent AGENTS.md.
