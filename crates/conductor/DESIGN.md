# Conductor workspace

The conductor is a terminal view and action surface over Aoide's existing
engine. Home provides an entry point; the project tree maintains context
while the main area changes views. Even surface shading and single lines
separate navigation, content and status. Only the keyboard-focused pane
uses bright selection; remembered selections elsewhere remain subdued.
The single-line `𝄞 CONDUCTOR` header provides semantic-colored project,
agent and terminal count buttons. Home centers its logo as one preformatted block and pads the continuous
light surface around shared action and project hit rectangles, retaining
darker exterior margins. Home groups actions and recent projects
on one continuous light surface, with the logo outside that region.

```text
Home: bundled logo · recent projects · new project
                         │
Workspace                ▼
┌ Project tree ───────────┬ Main view ─────────────────────────┐
│ project                │ Agents / Terminals / Graph         │
│   Agents               │ Projects / Mesh / Status           │
│   Terminals            │ Mail / Activity / Pending          │
│   Past                 │                                    │
│     durable history    │ Selected item detail               │
└────────────────────────┴────────────────────────────────────┘
```

Tree selection is navigation. Historical entries display ledger facts and
never masquerade as a live process. Current sessions and historical records
remain separate even when they share a project or resumable harness ID.

Project removal captures the project name in a confirmation prompt before any
mutation. Only entering that exact name dispatches `project remove`; Escape
discards it. Refreshes or selection changes cannot retarget the confirmation.
The operation unregisters the project and keeps its files.

## State and actions

```text
conducting stage ── projects / sessions / hooks ─┐
session ledger ──── historical entries ─────────┤
mail base ───────── bounded letters ────────────┤
audit JSONL ─────── bounded full events ────────┼─ App ── pure views
roster dispatch ─── live/cache classification ──┤           │
rice stage ──────── palette only ───────────────┘     shared geometry
                                                         │
                                                keyboard / mouse
                                                         │
                                      selection or explicit DispatchFn
                                                         │
                                              existing Aoide engine
```

Context menus hold a snapshot of the selected tree, graph, project or
session target. Right-click and `e` enter the same controller; arrows or
`j` / `k` select, Enter applies and Escape closes. Details is universal.
Live local sessions expose Open / focus and Set project; mailbox agents
also expose Write letter. Project actions reuse the recipient chooser,
Add folder and existing undying resurrection. Historical resurrection
requires a registered project plus native session ID or restore snapshot
and dispatches the exact project and ID. It never substitutes live focus.

Local mail/audit reads capture complete records within a bounded tail.
They do not repair an actively appended file. Ledger reads use the storage
API and refresh on file changes. Network roster reads run asynchronously
with their existing bounds and cache semantics.

The graph uses an interim fixed world layout of rectangular project and
session nodes, recomputed on every refresh: it is not the retained scene
graph (stable world nodes and edges, node dragging, positions preserved
across refresh), which is designer-owned follow-up work. Its camera scales through 50%, 75%, 100%, 125% and 150%; Ctrl + wheel
keeps the pointer's world location stable, bounded by canvas edges. Zoom
transforms card rectangles and edges without switching layout presets.
Terminal glyphs remain cell-sized and labels clip to the transformed card.
Rendering, hit tests, extents, drag and wheel panning share that geometry.

## Conversations

```text
existing local mail base
        │ decode signed threadId / replyTo when present
        ├─ threadId ───────────── stable thread across participant changes
        └─ no threadId ────────── labeled legacy endpoint-pair correspondence
                                  │ exact msgid anchors a later reply thread
                                  ▼
conversation list (most recently received first)
        │
chronological letters ── selected immutable original
        │
        └─ human reply draft ── explicit send through daemon
```

Thread identity comes from signed content, not the subject or the current
participant set. Observed participants are the canonical union of envelope
sender, envelope recipient and declared To/Cc recipients. They may grow
without splitting the conversation. Subject labels use the earliest
nonempty subject; letters use local receipt sequence rather than remote
clock ordering. The participant roster describes observed correspondence,
not room membership or proven delivery to every declared recipient.

Legacy messages remain grouped by exact canonical endpoint pairs. A reply
to legacy content uses the selected original's msgid as its thread ID;
only that original joins the new thread, leaving other pair history alone.
Replies preserve the thread ID and set replyTo to the selected original's
msgid. New letters and forwards start new threads. Local archive visibility
does not establish complete sent history across hosts.

```text
new / reply / reply all / forward / tree recipient
                         │
                         ▼
From (readonly) · To · Cc · Subject · Message
                         │ immutable original remains visible
                         │ explicit Send / Ctrl-S
                         ▼
mail send → signed structured content → recipient envelopes
                         │
           all accepted ─┴─ partial failure
                  │               │
             close draft    show recipient results
                            lock repeated submission
```

Reply targets the original sender; Reply all also retains declared recipients
except the human sender and duplicates. Forward requires a new explicit
recipient. The composer keeps its recipient tree visible: `[+ To]` and
`[+ Cc]` select which field receives an individual mailbox. Project groups
organize recipients without becoming broadcast addresses. These entry points
share one form. The To/Cc destination remains selected across additions;
Ctrl-P switches between tree and form, and Escape first returns tree focus
to the form. Printable text, including quit shortcut letters, belongs to
the active input field. Plain field labels, visible cursor, mouse field
selection and keyboard focus cycling expose focus without editing badges. To and Cc use explicit comma-separated
`node/mailbox` addresses; canonical local names route to local delivery.

The composer attributes new letters to `conductor-human`. Subject, recipient,
threadId and replyTo metadata live inside the existing signed text, leaving
envelope verification intact. Actual delivery uses one envelope per recipient; a
metadata address alone is not a delivery claim. A partial failure retains
results without offering a repeat of already accepted recipients. Full
rejection leaves the form editable. Viewing a letter does not advance any
agent's read cursor or create a delivery receipt. Outbox transport state,
delivery acknowledgment and human browsing are different facts.

## Remaining integration seam: policy-backed mail review

The frontend does not intercept agent mail. A trustworthy review workflow
requires an engine-side proposal lifecycle before dispatch:

```text
agent proposal → held original + stable ID/revision
                         │
                  operator reviews/edits
                         │
            approve exact revision / reject
                         │
              atomic dispatch decision → signed letter
```

The backend must preserve original text, edited revisions, requester,
editor, approver and final message identity. Revision checks prevent stale
approval; an atomic state transition prevents repeated approval minting
multiple letters. Transport retries reuse the decided envelope. Unknown
delivery remains unknown rather than offering a false recall.

Existing outbox hold is a transport condition and can be collected by peer
polling; it is not this policy. Existing Pending entries concern conductor
input and A2A approvals, not mail revision review. Receiver-side interception
would separately preserve the verified original while holding agent
consumption/notification. Delivered signed envelopes remain immutable;
corrections are new attributed letters.
