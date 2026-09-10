//! Stage-file record shapes (CONTRACTS.md §4 shapes).
//!
//! Moved from `graph/model.rs` (Phase 3a restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old path so every
//! existing `crate::graph::{Project, SessionRecord, …}` caller is untouched.
//! The pure DAG-shaping derivations (`cwd_under`, `anchor_for`,
//! `merged_sessions`, `sorted_projects`, `resolved_parent`) stay in root
//! `graph/model.rs` — they're conduct's charter and move in Phase 3b.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// graph.json / projects.json stage-file format version (CONTRACTS.md §4).
pub const STAGE_GRAPH_VERSION: &str = "0";

/// `skip_serializing_if` helper for a plain (non-`Option`) `bool` field whose
/// common case is `false` — keeps the common case off the wire without the
/// `Option<bool>` round-trip ceremony every other additive flag here uses.
fn is_false(b: &bool) -> bool {
    !*b
}

/// One registered project anchor root (`state/stage/projects.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Project {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub path: String,
    /// Every anchor root of this project, in order, `path` mirrored at
    /// `roots[0]` — the FULL list, not "second root onward." Always written
    /// by `project add`/`project edit`/`project remove` (no
    /// `skip_serializing_if`: a project touched by the new code always has
    /// a non-empty `roots`, ROOTS SERIALIZED COMPLETE). A legacy record
    /// predating this field, or one hand-edited so `roots[0]` disagrees
    /// with `path` or repeats it, still reads correctly — [`Project::roots`]
    /// is path-first-then-`roots`-deduped, never a raw field read, and is
    /// never rewritten just by reading it. Read through [`Project::roots`],
    /// never directly.
    #[serde(default)]
    pub roots: Vec<String>,
    /// Additive/v0-safe (P-D8, `docs/architecture/AOIDED.md`'s "L5"): when
    /// true, the daemon's `run_loop` entry (once per BOOT, boot-epoch
    /// guarded — `aoide-server`'s `daemon.rs`) resurrects this project's
    /// single most recent resumable ledger session whenever it currently
    /// has no live one. Default `false`; `skip_serializing_if` keeps a
    /// `false` value off the wire, same discipline `SessionRecord.headless`
    /// set the precedent for. Set via `graph project add --auto-resume`
    /// (idempotent-upsert). `project edit` replaces a project's roots and
    /// never touches `autoResume`; clearing it back to `false` still means
    /// hand-editing `projects.json`.
    #[serde(rename = "autoResume", default, skip_serializing_if = "is_false")]
    pub auto_resume: bool,
}

impl Project {
    /// Every anchor root of this project: `path` first, then `roots`,
    /// deduped. The ONE way new code enumerates a project's roots —
    /// `p.path` alone is the legacy single-root read and stays correct
    /// because `path` always equals the first root. A hand-edited record
    /// whose `roots[0]` differs from `path`, or that repeats `path` inside
    /// `roots`, is READ this way and never rewritten on read.
    pub fn roots(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        if !self.path.is_empty() {
            out.push(self.path.as_str());
        }
        for r in &self.roots {
            if !r.is_empty() && !out.contains(&r.as_str()) {
                out.push(r.as_str());
            }
        }
        out
    }
}

/// A conducted TERMINAL's continuously-captured restore snapshot (P-C5,
/// durable-sessions plan) — what the shell was doing at the last ~1 Hz PTY
/// tick (`aoide-conduct`'s `conduct_refresh_shell`/`restore_snapshot`), so a
/// LATER phase's `graph resurrect` can bring an undying terminal back to
/// more than a bare cwd. Captured continuously in the live `conduct` process and
/// carried on the record change-only, exactly like `cwd`/`activity`/`state`
/// — never computed at reap time: by the time a sweep condemns a session its
/// process is already gone (that is the signal it reaped on), so a `/proc`
/// read there returns nothing, every time, for the exact case this exists
/// for. Embedded identically on both `SessionRecord.restore` (additive,
/// `skip_serializing_if`) and `aoide_storage::ledger::LedgerEntry.restore`
/// (always serializes, per that file's own closed-historical-record
/// discipline) — this struct's own fields never use `skip_serializing_if`,
/// so a populated snapshot reads the same complete shape in either home.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RestoreSnapshot {
    /// The shell's live working directory at the last tick. `None` when
    /// unreadable (a permissions edge case, or the process exited mid-read).
    #[serde(default)]
    pub cwd: Option<String>,
    /// Whether the pty's foreground process group was the bare shell itself
    /// (`fg <= 0 || fg == shell_pid`, the same predicate `shell_snapshot`
    /// computes for `state`) — kept as ITS OWN field rather than read back
    /// off `state` later: the reap sweep overwrites `state` to `"done"`
    /// BEFORE its ledger write, so idleness is unrecoverable from `state` by
    /// then.
    #[serde(default)]
    pub idle: bool,
    /// RAW, uncollapsed, unclipped `argv` off `/proc/<fg>/cmdline`
    /// (`proc_argv`) — never `proc_command`'s basename-collapsed,
    /// 48-char-truncated DISPLAY label, which would re-exec the wrong or a
    /// truncated binary. `None` while `idle` (no foreground process to
    /// capture) or when `/proc` is unreadable.
    #[serde(default)]
    pub argv: Option<Vec<String>>,
    /// The reconstructed unsubmitted prompt line — REFUSAL-based, never a
    /// guess: `Some` only for a clean, unedited keystroke run since the last
    /// submit; any readline-editing byte (an escape sequence, `^R`, Tab,
    /// `^U`/`^W`) or invalid UTF-8 poisons it to `None` instead. Only ever
    /// populated when `idle` is true — a shell mid-command has no prompt
    /// line to reconstruct. A silently WRONG `typed` would put text the
    /// operator never composed one keystroke from running; `None` is a
    /// fully acceptable product of this capture, a guess is not.
    #[serde(default)]
    pub typed: Option<String>,
}

/// One session record (`state/stage/sessions.json`, written by shellbridge).
/// `parentSessionId` is the optional additive spawned-by edge; `extra`
/// round-trips any fields this version does not know about.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionRecord {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    /// Explicit continuity binding; not a harness name or an authorization grant.
    #[serde(rename = "enduringAgentId", default, skip_serializing_if = "Option::is_none")]
    pub enduring_agent_id: Option<String>,
    /// Explicit project membership; absent means automatic cwd anchoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default)]
    pub agent: String,
    #[serde(rename = "windowAddress", default)]
    pub window_address: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub state: String,
    #[serde(rename = "startedAt", default)]
    pub started_at: String,
    #[serde(
        rename = "parentSessionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub parent_session_id: Option<String>,
    /// Conductor-channel additive fields (v0-safe; absent on a legacy record).
    /// `conductable` marks a session spawned under `aoide conduct` (it owns a
    /// PTY + control socket); `socket` is that per-session injection socket
    /// (`$XDG_RUNTIME_DIR/aoide/session-<id>.sock`); `title` is the auto-renamed
    /// one-line task the last delivered `graph send` wrote onto the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conductable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The lifecycle-OWNING process's pid (the `conduct`/`wrap` process itself,
    /// NOT the wrapped child) — the liveness anchor for the reaper. While this
    /// process lives, normal-exit cleanup (`do_session_end`) is guaranteed; when
    /// it is SIGKILLed (SUPER+Q kills the whole terminal process tree,
    /// uncatchably) the record orphans `running` and `/proc/<pid>` vanishes,
    /// which is exactly the signal `is_session_dead` reaps on. Additive/v0-safe:
    /// absent on a legacy record and on hook-only sessions that never had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The Hyprland workspace id this session's window currently lives on,
    /// stamped by the `socket2` window-event listener alongside `windowAddress`
    /// (and re-stamped when the window moves between workspaces). Additive and
    /// v0-safe: absent on a legacy record and whenever the window/workspace
    /// could not be resolved (off-Hyprland, or the window not yet open). The
    /// gadget-dock roster reads it to preview-highlight the bar's WorkspaceRow
    /// on hover (concepts/Terminal-Commander) — a pure-data bridge, no dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<i64>,
    /// The live "current command / current tool" for this session: for a
    /// conducted SHELL it is the foreground command (`cargo test`, `vim …`),
    /// captured by conduct's PTY tick and cleared at the bare prompt; for an
    /// AGENT it is the tool currently running (set from the PreToolUse hook,
    /// cleared when the turn settles). Additive/v0-safe — absent when there is
    /// nothing running. The roster shows it so a row reads as what it is *doing*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<String>,
    /// What KIND of thing this record is, published so the widgets never infer
    /// it from the agent string: `agent` (a Claude/agent session), `shell` (a
    /// conducted terminal), or `subagent` (a Task the agent spawned — a leaf
    /// of the conductor tree). Additive/v0-safe (absent on a legacy record;
    /// readers fall back to agent!="shell").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The agent's latest *words* — a one-line tail of the session's Claude Code
    /// transcript (the last non-sidechain assistant `text` block), distinct from
    /// `activity` (the current *tool*). Read straight off the on-disk JSONL
    /// transcript at hook boundaries (Stop / PostToolUse / Notification), so the
    /// conductor can show what the agent is *saying*, not just what it is running.
    /// Additive/v0-safe — absent for shells and for an agent that has not spoken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub say: Option<String>,
    /// The agent's latest TOOL CALL as a one-line label (`Bash: cargo test`),
    /// read off the same transcript tail as `say` at the same refresh points.
    /// Deliberately not `activity`: that field is the tool running RIGHT NOW
    /// (hook-set, cleared the moment the turn settles), so a card between tools
    /// shows nothing; this one is the transcript's record of what the agent last
    /// reached for and stays put until it reaches for something else.
    /// Additive/v0-safe — absent for shells and until the first tool call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The Claude model this session is currently running, taken straight from
    /// the freshest `type:"assistant"` line's `message.model` in the on-disk
    /// JSONL transcript (e.g. `claude-sonnet-5`, `claude-opus-4-8`), refreshed
    /// at the same hook boundaries as `say`. For a subagent it is that
    /// subagent's OWN model (from its own transcript) — genuinely able to differ
    /// from its parent's. Additive/v0-safe — absent for shells and until the
    /// session has produced at least one assistant turn. The bar shows it as the
    /// clock's subtext; widgets read the raw id and map it to a short label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The context-window fill of this session's LAST request: `input_tokens +
    /// cache_creation_input_tokens + cache_read_input_tokens` off the freshest
    /// `type:"assistant"` line's `message.usage` in the on-disk JSONL transcript
    /// (deliberately excludes `output_tokens` — that's what the turn just
    /// produced, not what sat in the window when the request was made).
    /// Refreshed at the same hook boundaries as `say`/`model`. Additive/v0-safe
    /// — absent for shells and until the session has produced at least one
    /// assistant turn (same lifecycle as `model`). The dock reads the published
    /// `context_ceiling` field (below) to turn this raw count into a meter,
    /// rather than computing its own ceiling from `model` client-side.
    #[serde(
        rename = "contextTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_tokens: Option<u64>,
    /// The context-window ceiling (tokens) for this session's current `model`,
    /// computed at refresh time by `aoide_protocol::context_ceiling_for_model`
    /// and published so the dock renders the fill meter without reimplementing the
    /// 200k/1M split (the widget-side guessing this replaces). Re-derived whenever
    /// `model` changes, so a mid-session model switch re-caps automatically.
    /// Additive/v0-safe — absent for shells and until the first assistant turn
    /// lands (same lifecycle as `model`/`contextTokens`); a legacy record without
    /// it falls back to 200k client-side.
    #[serde(
        rename = "contextCeiling",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_ceiling: Option<u64>,
    /// True while this conducted SHELL is blocked at a `sudo` password prompt
    /// — detected by conduct's PTY tick (the foreground process is `sudo`, or
    /// the `[sudo] password for` text was just seen crossing master→stdout)
    /// and force-published alongside `state:"awaiting"`. Additive/v0-safe:
    /// absent on a legacy record and cleared back to `None` (never written as
    /// `Some(false)`) the moment the prompt clears — so the key disappears
    /// rather than lingering false. Agents are hook-driven and never set this.
    /// The dock reads it to show a lock badge + ping distinct from an
    /// ordinary permission-prompt `awaiting` — "it's YOUR password", not the
    /// agent's.
    #[serde(rename = "needsSudo", default, skip_serializing_if = "Option::is_none")]
    pub needs_sudo: Option<bool>,
    /// Absolute path to the pty-master transcript of a HEADLESS `aoide conduct`
    /// session (`state/sessions/<sessionId>.log`, CONTRACTS.md §4) — raw bytes,
    /// append-only, unrotated. Stamped right after `do_session_start` by
    /// `set_session_log_path`, once the log file is open. Additive/v0-safe:
    /// absent on a legacy record and on every INTERACTIVE session (conduct
    /// never sets it when a real controlling tty is attached).
    #[serde(rename = "logPath", default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// A human-readable `adjective-noun` DISPLAY handle, minted once (see
    /// `petname::mint_for`) — never a lookup key and never encoding machine
    /// or role (those are derived at render time, `display::session_label`).
    /// `sessionId` stays the sole canonical identity everywhere: JSON
    /// payloads, sockets, CONTRACTS keys, `Node::session_id`. Additive/
    /// v0-safe: absent on a legacy record and never backfilled onto one —
    /// same "field this version doesn't know about round-trips, an absent
    /// one stays absent" discipline as `logPath` above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub petname: Option<String>,
    /// Up to 8 ancestor pids of the HOOK-FIRING process (a `/proc` `ppid`
    /// walk, self-first), stamped ONCE at a hook session's own
    /// SessionStart/self-heal registration (`graph session hook`,
    /// CONTRACTS.md §4) — never re-stamped later, since it records a birth
    /// fact, not a live signal. This captures the harness process's real OS
    /// ancestry regardless of shell nesting, so a LATER `wrap`/`conduct`/
    /// `spawn` registration with no explicit `--parent` can find its true
    /// launching agent by walking ITS OWN `/proc` ancestry and intersecting
    /// against every live agent's `hookAncestry` — the automatic-parenting
    /// fix (task #89) for a nested headless spawn otherwise registering as a
    /// SIBLING of its launching agent (via a stale ambient `AOIDE_SESSION_ID`)
    /// instead of its child. Additive/v0-safe: empty on a legacy record and
    /// on every non-agent kind (shells/subagents never stamp it).
    #[serde(rename = "hookAncestry", default, skip_serializing_if = "Vec::is_empty")]
    pub hook_ancestry: Vec<i32>,
    /// True for a HEADLESS `aoide conduct` wrap's own record — a PERMANENT,
    /// self-reported registration fact (stamped once, at `--headless`
    /// registration, never cleared) distinct from "`windowAddress` happens
    /// to be empty right now": a bug in window discovery or the backfill
    /// listener could otherwise stamp a stray window onto a headless wrap
    /// (task #89, review round 2 — an unconditional discovery call did
    /// exactly that, finding the ENCLOSING terminal's window through the
    /// wrap's own `/proc` ancestry). `windowless_by_lineage` and
    /// `resolve_pending_session_windows` both key off THIS field first, not
    /// `windowAddress` emptiness, so a headless wrap's windowlessness (and
    /// its whole hook-child subtree's) survives even a corrupted address.
    /// Additive/v0-safe: `false`/absent for every INTERACTIVE session and
    /// every legacy record (`skip_serializing_if` keeps a `false` value off
    /// the wire entirely — no "false" noise on the common case).
    #[serde(default, skip_serializing_if = "is_false")]
    pub headless: bool,
    /// True for a record created by `aoide spawn` — the DETACHED launch an
    /// agent uses to leave a worker terminal running behind it, in either
    /// launch mode (`--windowed` no less than the headless default). A
    /// PERMANENT registration fact stamped once, inside the spawned child at
    /// its own registration, and never cleared. It has to be stamped there
    /// rather than by `spawn` after the fact: `spawn` gives up waiting for
    /// the child's control socket after `REGISTRATION_BUDGET` and returns
    /// `registered: false` anyway, and a spawn that got that far wrong is
    /// precisely the one most likely to be abandoned — the same reasoning
    /// `headless` above records for stamping unconditionally.
    ///
    /// `parentSessionId` cannot answer this question: `graph/doc.rs` clears a
    /// child's parent edge when the parent is removed, so the evidence an
    /// agent created the shell disappears at exactly the moment the shell
    /// becomes leftover. `reap`'s `abandoned_spawned_shells` keys off THIS
    /// field for that reason.
    ///
    /// Additive/v0-safe: `false`/absent for every legacy record and for every
    /// terminal a human opened themselves.
    #[serde(default, skip_serializing_if = "is_false")]
    pub spawned: bool,
    /// True while this session is EXEMPT from the reaper's staleness
    /// judgments (task #20, `aoide session grant exempt on|off`) — the
    /// safety valve for `session reap --now`, which otherwise takes every
    /// idle spawned shell including one an agent is merely between commands
    /// on. Set/cleared by `graph/grant.rs::exempt_grant`, the same
    /// `#[serde(default, skip_serializing_if = "is_false")]` shape as
    /// `spawned` above — additive/v0-safe, absent on a legacy record.
    ///
    /// Unlike `undying` (a separate, POST-MORTEM state file whose meaning
    /// starts at death), this field's meaning ENDS at death: a resurrected
    /// session mints a fresh id, so the mark has nothing to survive onto and
    /// belongs on the record itself, not a durable set — it vanishes with
    /// the record the moment a REAL death signal (window-gone, pid-gone, a
    /// pre-boot ghost, an orphaned subagent) takes it. `reap.rs`'s
    /// `is_session_dead` (the `stale_abandoned` signal) and
    /// `abandoned_spawned_shells` are the only two judgments it vetoes —
    /// staleness is the only signal class that can ever take a LIVE
    /// session, so vetoing exactly those two is "never reap a live exempt
    /// session, never lie about a dead one." It survives `--now`
    /// structurally: both reap arms filter exempt records out of candidacy
    /// before any band/gesture question is asked, so a human pressing
    /// `[ reap ]` still cannot take a live exempt session.
    #[serde(default, skip_serializing_if = "is_false")]
    pub exempt: bool,
    /// The harness's OWN session id, straight off the raw hook payload's own
    /// `session_id` field (P-D7) — stamped on every `graph session hook`
    /// event that carries one, regardless of whether it equals this
    /// record's own `sessionId` (today, for a hook-registered record, it
    /// always does — `map_hook` mints the record's id FROM this same
    /// value — but the field is stamped unconditionally so a later
    /// consumer, e.g. `graph resurrect`'s ledger reader (P-D8), never has
    /// to know which registration path produced a given record to find the
    /// id a harness's own `resume_args` needs). Additive/v0-safe: absent on
    /// a legacy record and on any record no hook has ever touched.
    #[serde(
        rename = "harnessSessionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub harness_session_id: Option<String>,
    /// Additive/v0-safe (P-D8, `docs/architecture/AOIDED.md`'s "L5"): names
    /// the durable ledger entry's own `sessionId` this record was REVIVED
    /// from by `graph resurrect` — never a live lookup key (the named
    /// session has already left the roster by construction; this is
    /// provenance only). Stamped once, right after registration, by
    /// `stamp_resumed_from`; `build_graph` projects it as an additive
    /// `resumed` edge beside `spawned`/`anchors` (CONTRACTS.md §4). Absent
    /// means "not a resurrected session" (the common case, and every legacy
    /// record); readers must tolerate both forms and round-trip fields they
    /// do not know.
    #[serde(
        rename = "resumedFrom",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resumed_from: Option<String>,
    /// Who caused this session to exist, when it wasn't a local registration
    /// (P-P3, `docs/architecture/PAIRING.md` decision 7): `"node:<name>"`
    /// for a session the A2A door spawned on behalf of an identified,
    /// paired node (`aoide-server`'s `a2a::do_spawn`). Additive/v0-safe —
    /// absent on a legacy record and on every LOCALLY-registered session
    /// (a plain `aoide conduct`/`graph spawn`/hook registration never sets
    /// it). Stamped once, at registration (`stamp_origin`), never changed
    /// afterward; `ledger_session_exit` (`aoide-conduct::graph::doc`)
    /// projects it verbatim into the durable session ledger on exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The daemon-sealed session credential (LANE IDENTITY P-ID1,
    /// `docs/architecture/CONTRACTS.md`'s identity section): a hex ed25519
    /// signature (`aoide_storage::sealed_id::mint_seal`) over a
    /// `SealedIdentity{sessionId, pid, pidStarttime, originClass, issuedAt}`
    /// built from THIS record — an opaque, never-secret blob (it's a
    /// signature; verifying it needs only the daemon's public key, never
    /// this field back). Additive/v0-safe — absent on a legacy record and
    /// on every record no daemon has sealed (today: the common case). **No
    /// gate reads this field yet** — P-ID1 only mints/stores/verifies the
    /// mechanism; P-ID2 wires a verify-on-accept check into the control
    /// socket and send gate. Stamped by `aoide_conduct::graph::stamp_seal`,
    /// change-only like `origin`/`hookAncestry` — never re-derived once set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<String>,
    /// The `issuedAt` field baked into `seal`'s signed payload (LANE
    /// IDENTITY P-ID2, `CONTRACTS.md`'s identity section). Additive
    /// alongside `seal`, stamped in the SAME call — `verify_seal` needs the
    /// EXACT `SealedIdentity` that was signed to check a signature against,
    /// and unlike `pid`/`sessionId`/`originClass` (already on this record)
    /// or `pidStarttime` (safely RE-DERIVED fresh from `/proc/<pid>/stat`
    /// at verify time — a stale mint-time value simply fails to match,
    /// which is the pid-reuse defense working as intended), `issuedAt` is a
    /// mint-time timestamp with no live fact to re-derive it from. Without
    /// storing it, a verifier has no way to reconstruct the signed message
    /// short of brute-forcing every plausible timestamp (exactly what
    /// `daemon.rs`'s own P-ID1 test helper `sealed_id_issued_at_from` does,
    /// as a TEST-ONLY expedient — not something a real verify-on-accept
    /// path can do). Never secret (it's a timestamp, not key material);
    /// absent means "no seal minted" (same lifecycle as `seal` — always
    /// `Some` together, always `None` together).
    #[serde(
        rename = "sealedIssuedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sealed_issued_at: Option<i64>,
    /// Additive/v0-safe (P-C5, durable-sessions plan): a conducted SHELL's
    /// continuously-captured restore snapshot (`RestoreSnapshot`, above) —
    /// cwd/idle/argv/typed off the PTY tick. Absent for every non-shell
    /// session and every legacy record predating this field; readers must
    /// tolerate both forms and round-trip fields they do not know.
    /// Consumed internally (`doc.rs::ledger_session_exit`'s projection into
    /// the durable ledger's own `restore`) rather than rendered into
    /// `graph.json`, like `headless`/`hookAncestry`/`origin` above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<RestoreSnapshot>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One hook record (`state/stage/hooks.json`, written by shellbridge).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookRecord {
    #[serde(rename = "sessionId", default)]
    pub session_id: String,
    #[serde(default)]
    pub phase: String,
    #[serde(rename = "updatedAt", default)]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `projects.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectsFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub projects: Vec<Project>,
}

/// `sessions.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionsFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
}

/// `hooks.json` container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HooksFile {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: String,
    #[serde(default)]
    pub hooks: Vec<HookRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_record_workspace_round_trips_and_stays_absent_when_unset() {
        // serde: `workspace` serialises as an integer when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.workspace = Some(2);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"workspace\":2"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workspace, Some(2));

        // A record without a workspace omits the key entirely (no null noise) and
        // a legacy record with no `workspace` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("workspace"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.workspace, None);
    }
    #[test]
    fn session_record_hook_ancestry_round_trips_and_stays_empty_when_unset() {
        // serde: `hookAncestry` serialises as an int array when non-empty, and
        // is skipped (skip_serializing_if = "Vec::is_empty") when empty —
        // additive/v0-safe on the wire, same contract as `workspace`/
        // `needsSudo` above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.hook_ancestry = vec![111, 22, 3];
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"hookAncestry\":[111,22,3]"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hook_ancestry, vec![111, 22, 3]);

        // A record with no ancestry omits the key entirely (no `[]` noise) and
        // a legacy record with no `hookAncestry` field parses to an empty vec.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("hookAncestry"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert!(legacy.hook_ancestry.is_empty());
    }
    #[test]
    fn session_record_headless_round_trips_and_stays_absent_when_unset() {
        // serde: `headless` serialises as `true` only when set — the common
        // `false` case is skipped entirely (skip_serializing_if = "is_false"),
        // keeping every ordinary interactive record's wire form unchanged.
        // This is the PERMANENT registration-fact flag (task #89 review round
        // 2) that lets `windowless_by_lineage` answer true for a headless
        // conducted wrap's OWN record, not just its descendants' parent chain.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.headless = true;
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"headless\":true"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert!(back.headless);

        // The default/unset case omits the key entirely (no `false` noise)
        // and a legacy record with no `headless` field parses to `false`.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("headless"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert!(!legacy.headless);
    }
    #[test]
    fn project_auto_resume_round_trips_and_stays_absent_when_unset() {
        // serde: `autoResume` serialises as `true` only when set — the
        // common `false`/unset case is skipped entirely (skip_serializing_if
        // = "is_false"), the same additive-bool contract `SessionRecord.
        // headless` set the precedent for (P-D8). Default is `false`: a
        // project registered before this field existed, or one never opted
        // in, never trips the daemon's boot-time auto-resume trigger.
        let mut proj = Project { name: "aoide".into(), path: "/home/x/Aoide".into(), ..Default::default() };
        assert!(!proj.auto_resume, "default is off");
        let bare_json = serde_json::to_string(&proj).unwrap();
        assert!(!bare_json.contains("autoResume"), "serialised: {bare_json}");
        let legacy: Project = serde_json::from_str(r#"{ "name": "aoide", "path": "/home/x/Aoide" }"#).unwrap();
        assert!(!legacy.auto_resume, "a legacy project with no autoResume key defaults to off");

        proj.auto_resume = true;
        let json = serde_json::to_string(&proj).unwrap();
        assert!(json.contains("\"autoResume\":true"), "serialised: {json}");
        let back: Project = serde_json::from_str(&json).unwrap();
        assert!(back.auto_resume, "a set autoResume persists through the round trip");
    }
    #[test]
    fn a_projects_root_list_puts_path_first_and_dedupes() {
        let p = Project { path: "/a".into(), roots: vec!["/b".into()], ..Default::default() };
        assert_eq!(p.roots(), vec!["/a", "/b"]);

        let p = Project { path: "/a".into(), roots: vec![], ..Default::default() };
        assert_eq!(p.roots(), vec!["/a"]);

        let p = Project {
            path: "/a".into(),
            roots: vec!["/a".into(), "/b".into(), "/b".into()],
            ..Default::default()
        };
        assert_eq!(p.roots(), vec!["/a", "/b"]);

        let p = Project { path: String::new(), roots: vec!["/b".into()], ..Default::default() };
        assert_eq!(p.roots(), vec!["/b"]);
    }
    #[test]
    fn a_project_with_extra_roots_round_trips_the_full_list_always_on_the_wire() {
        // ROOTS SERIALIZED COMPLETE: `roots` has no `skip_serializing_if`
        // any more, and the new-code shape is the FULL ordered root list
        // with `path` mirrored at `roots[0]` — never "extras only."
        let one_root = Project {
            name: "aoide".into(),
            path: "/a".into(),
            roots: vec!["/a".into()],
            ..Default::default()
        };
        let one_root_json = serde_json::to_string(&one_root).unwrap();
        assert!(one_root_json.contains("\"roots\":[\"/a\"]"), "serialised: {one_root_json}");

        let populated = Project {
            name: "aoide".into(),
            path: "/a".into(),
            roots: vec!["/a".into(), "/b".into()],
            ..Default::default()
        };
        let json = serde_json::to_string(&populated).unwrap();
        assert!(json.contains("\"roots\":[\"/a\",\"/b\"]"), "serialised: {json}");

        let back_one_root: Project = serde_json::from_str(&one_root_json).unwrap();
        let back_populated: Project = serde_json::from_str(&json).unwrap();
        assert_eq!(back_one_root.roots(), vec!["/a"]);
        assert_eq!(back_one_root.path, back_one_root.roots()[0]);
        assert_eq!(back_populated.roots(), vec!["/a", "/b"]);
        assert_eq!(back_populated.path, back_populated.roots()[0]);
    }
    #[test]
    fn a_legacy_project_without_roots_reads_as_one_root() {
        let p: Project =
            serde_json::from_str(r#"{"name":"aoide","path":"/home/x/Aoide"}"#).unwrap();
        assert!(p.roots.is_empty());
        assert_eq!(p.roots(), vec!["/home/x/Aoide"]);
    }
    #[test]
    fn a_hand_edited_project_whose_first_root_differs_from_path_is_read_not_rewritten() {
        let p: Project =
            serde_json::from_str(r#"{"name":"a","path":"/a","roots":["/b","/a"]}"#).unwrap();
        assert_eq!(p.roots(), vec!["/a", "/b"]);
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"roots\":[\"/b\",\"/a\"]"), "serialised: {json}");
    }
    #[test]
    fn session_record_harness_session_id_round_trips_and_stays_absent_when_unset() {
        // serde: `harnessSessionId` serialises as a string when Some, and is
        // skipped (skip_serializing_if) when None — additive/v0-safe on the
        // wire, matching `workspace`/`needsSudo`'s contract above (P-D7).
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.harness_session_id = Some("claude-uuid-123".into());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            json.contains("\"harnessSessionId\":\"claude-uuid-123\""),
            "serialised: {json}"
        );
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.harness_session_id.as_deref(), Some("claude-uuid-123"));

        // The default/unset case omits the key entirely (no null noise), and
        // a LEGACY record predating this field (no `harnessSessionId` key at
        // all) parses to None rather than failing — the whole point of an
        // additive field is that an old record round-trips untouched.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("harnessSessionId"), "serialised: {bare_json}");
        let legacy: SessionRecord = serde_json::from_str(
            r#"{ "sessionId": "s", "windowAddress": "0x1", "agent": "claude" }"#,
        )
        .unwrap();
        assert_eq!(legacy.harness_session_id, None);
        assert_eq!(legacy.session_id, "s", "the rest of a legacy record is unaffected");
        assert_eq!(legacy.agent, "claude");
    }
    #[test]
    fn session_record_needs_sudo_round_trips_and_stays_absent_when_unset() {
        // serde: `needsSudo` serialises as a bool when Some(true), and is
        // skipped (skip_serializing_if) when None — additive/v0-safe on the
        // wire, matching the `workspace` field's contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.needs_sudo = Some(true);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"needsSudo\":true"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.needs_sudo, Some(true));

        // A record with no needsSudo omits the key entirely (no null/false
        // noise) and a legacy record with no `needsSudo` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("needsSudo"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.needs_sudo, None);
    }
    #[test]
    fn session_record_context_tokens_round_trips_and_stays_absent_when_unset() {
        // serde: `contextTokens` serialises as an integer when Some, and is
        // skipped (skip_serializing_if) when None — additive/v0-safe on the
        // wire, matching the `needsSudo`/`workspace` fields' contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.context_tokens = Some(361_416);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"contextTokens\":361416"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.context_tokens, Some(361_416));

        // A record with no contextTokens omits the key entirely (no null
        // noise) and a legacy record with no `contextTokens` field parses to
        // None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("contextTokens"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.context_tokens, None);
    }
    #[test]
    fn session_record_context_ceiling_round_trips_and_stays_absent_when_unset() {
        // serde: `contextCeiling` serialises as an integer when Some, and is
        // skipped (skip_serializing_if) when None — same additive/v0-safe wire
        // contract as `contextTokens` above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.context_ceiling = Some(1_000_000);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"contextCeiling\":1000000"), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.context_ceiling, Some(1_000_000));

        // A record with no contextCeiling omits the key entirely (no null
        // noise) and a legacy record with no `contextCeiling` field parses to
        // None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("contextCeiling"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.context_ceiling, None);
    }
    #[test]
    fn session_records_round_trip_unknown_fields() {
        // shellbridge may grow fields this version does not know; a graph
        // rewrite (link/prune) must not drop them.
        let raw = r#"{ "sessionId": "s", "agent": "claude", "windowAddress": "0x1",
                       "cwd": "/x", "state": "running", "startedAt": "t",
                       "futureField": 42 }"#;
        let rec: SessionRecord = serde_json::from_str(raw).unwrap();
        let back = serde_json::to_value(&rec).unwrap();
        assert_eq!(back["futureField"], 42);
        assert!(back.get("parentSessionId").is_none());
        // A record with no pid serialises WITHOUT the key (additive/v0-safe).
        assert!(back.get("pid").is_none());
    }
    #[test]
    fn session_record_log_path_round_trips_and_stays_absent_when_unset() {
        // serde: `logPath` serialises as a string when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire,
        // matching the `needsSudo`/`workspace` fields' contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.log_path = Some("/home/khoa/Aoide/state/sessions/s.log".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            json.contains("\"logPath\":\"/home/khoa/Aoide/state/sessions/s.log\""),
            "serialised: {json}"
        );
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.log_path, rec.log_path);

        // A record with no logPath omits the key entirely (no null noise) and
        // a legacy record with no `logPath` field parses to None — a record
        // WITHOUT the key serialises byte-identical to before this field
        // existed.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("logPath"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.log_path, None);
    }
    #[test]
    fn session_record_seal_round_trips_and_stays_absent_when_unset() {
        // LANE IDENTITY P-ID1: `seal` serialises as a plain string when set,
        // and is skipped (skip_serializing_if) when None — the same
        // additive/v0-safe wire contract every other v0-safe field on this
        // struct holds (`logPath`/`petname`/`origin` above).
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.seal = Some("deadbeef".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"seal\":\"deadbeef\""), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seal, rec.seal);

        // A record with no seal omits the key entirely (no null noise) and a
        // legacy record with no `seal` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("\"seal\""), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.seal, None);
    }
    #[test]
    fn session_record_petname_round_trips_and_stays_absent_when_unset() {
        // serde: `petname` serialises as a string when set, and is skipped
        // (skip_serializing_if) when None — additive/v0-safe on the wire,
        // matching the `logPath`/`needsSudo`/`workspace` fields' contract
        // above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.petname = Some("brave-otter".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"petname\":\"brave-otter\""), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.petname, rec.petname);

        // A record with no petname omits the key entirely (no null noise) and
        // a legacy record with no `petname` field parses to None — never
        // backfilled just by round-tripping.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("petname"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.petname, None);
    }
    #[test]
    fn session_record_restore_round_trips_and_stays_absent_when_unset() {
        // serde: `restore` serialises as a nested object when Some, and is
        // skipped (skip_serializing_if) when None — additive/v0-safe on the
        // wire, matching the `petname`/`logPath` fields' contract above.
        let mut rec = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        rec.restore = Some(RestoreSnapshot {
            cwd: Some("/home/khoa/Aoide".into()),
            idle: true,
            argv: None,
            typed: Some("cargo test -p aoide-conduct".into()),
        });
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"restore\":{"), "serialised: {json}");
        assert!(json.contains("\"typed\":\"cargo test -p aoide-conduct\""), "serialised: {json}");
        let back: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.restore, rec.restore);

        // A record with no restore omits the key entirely (no null noise) and
        // a legacy record with no `restore` field parses to None.
        let bare = SessionRecord {
            session_id: "s".into(),
            ..Default::default()
        };
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("restore"), "serialised: {bare_json}");
        let legacy: SessionRecord =
            serde_json::from_str(r#"{ "sessionId": "s", "windowAddress": "0x1" }"#).unwrap();
        assert_eq!(legacy.restore, None);
    }
}
