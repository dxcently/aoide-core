//! `resurrect --project <x>` — revive a project's most recently-ended
//! resumable session off the durable ledger (P-D8, `docs/architecture/
//! AOIDED.md`'s "L5 — harness summoning" section). The same command core
//! also backs the daemon's own boot-time auto-resume trigger
//! (`aoide-server`'s `daemon.rs`, called in-process the same way
//! `run_internal_reap` calls `crate::reap::reap_and_announce`).
//!
//! Selection: resolve `--project <x>` against `projects.json` by exact name,
//! read every ledger line whose `cwd` anchors to it (the SAME longest-
//! path-prefix rule bare `graph`'s `anchor_for` uses — reused, never
//! re-derived), then pick candidates. `--all` widens to every anchored
//! entry; `--id` narrows to one specific ledger `sessionId`; bare (neither
//! flag) resumes the project's WHOLE undying set (`state/undying.json`,
//! durable-sessions plan P-C4) — every anchored entry currently marked
//! durable, minus any id already alive in `sessions.json`, deduped by
//! `sessionId` keeping the newest `endedAt` (an append-only ledger can hold
//! more than one exit for the same undying id once it has been resurrected
//! and exited again). `--all` and `--id` are unchanged escapes: both widen
//! or narrow past the undying set regardless of the mark. Each candidate is
//! filtered through its harness's `AgentProfile.resume_args`
//! (`aoide_protocol::agents`): `None` (an unregistered agent, or a harness
//! whose resume argv has never been verified) skips that candidate with a
//! taught message naming the harness, never a guessed invocation.
//!
//! A resurrected session is ALWAYS a fresh `sessionId` — ids are never
//! recycled — spawned via the windowed path ([`super::spawn::session_spawn`]
//! with `--windowed --cwd <the ledger entry's own cwd>`, P-D7/P-D8) so it
//! reopens in a real terminal, in its original project directory. On success
//! the new record is stamped `resumedFrom` (`stamp_resumed_from`), naming the
//! ledger entry's own `sessionId` — `build_graph` projects that as a
//! `resumed` edge beside `spawned`/`anchors` (CONTRACTS.md §4). If the old id
//! was undying (`state/undying.json`, durable-sessions plan P-C3), the mark
//! transfers onto the new id in the same step — never left on the now-dead
//! old id, which would double-resurrect on the next sweep.
//!
//! Never a hard `Outcome::error` over a per-candidate spawn failure (a
//! headless host has no `$AOIDE_TERMINAL`/display — `session_spawn`'s own
//! taught error): every candidate's outcome is folded into
//! `resurrected`/`skipped`/`failed` and the command itself stays `Ok`, so a
//! `--all` batch keeps going past one bad candidate and the daemon's
//! boot-time trigger degrades gracefully (log the skip, never crash the
//! tick) instead of treating a headless box as a command failure. Only
//! genuine USAGE problems (`--project` missing, an unknown project name, an
//! `--id` that names no anchored ledger entry) are `Outcome::usage`/`error`.
//!
//! **Candidate resolution, two arms (P-C6, durable-sessions plan):**
//! [`resolve_candidate`] tries the harness arm FIRST —
//! `AgentProfile.resume_args` off `aoide_protocol::agents` — and only when
//! that yields nothing does it try the TERMINAL arm: a ledger entry carrying
//! a `restore` snapshot (P-C5) is a conducted shell, not a harness, so it
//! reopens as `[<login shell>, "-l"]` — the exact argv `kitty.nix`'s own
//! wrapper execs — rather than a `--resume <id>` nobody could ever verify. A
//! candidate with neither hits the pre-existing taught skip.
//!
//! **Post-spawn delivery into a resurrected terminal (decision 8):** once a
//! terminal candidate's spawn actually registers, its `restore` snapshot
//! decides what — if anything — lands in the new pty, through
//! [`super::send::session_send`], never a direct socket write:
//! - **not idle, with a foreground `argv`** — the session was demonstrably
//!   RUNNING something when it left. Re-exec it, `--yes --submit` and all:
//!   the never-auto-run rule below covers the typed-but-unsubmitted case,
//!   not a command already in flight. EXCEPT when `argv[0]`'s basename is
//!   `sudo` (orchestrator ruling, open knob 5 — asked twice, unanswered,
//!   default taken and flagged): a privileged foreground command is never
//!   re-exec'd unattended — at best it hangs on a password prompt nobody is
//!   watching, at worst it silently re-runs something destructive. The cwd
//!   still restores; nothing is delivered.
//! - **idle, with a clean `typed` line** — preload it with `--yes` and,
//!   deliberately, NEVER `--submit`. The text sits in the new prompt until a
//!   human presses Enter. **This is the whole safety invariant this phase
//!   exists to hold: the no-submit path must never grow a `--submit`, and
//!   the two branches above must never be unified behind a shared boolean
//!   parameter** — [`restore_delivery`] hardcodes each branch's flag map
//!   inline rather than threading a `submit: bool` through one "deliver"
//!   helper, precisely so a later refactor can't flip one into the other by
//!   accident. A stale `rm -rf` sitting in `typed` and firing itself at boot
//!   is the failure this shape prevents.
//! - **idle, with no `typed`** — nothing is delivered. A terminal reopened
//!   at its own cwd is already the correct, complete answer.
//!
//! **Bare-manifest mode (U2, command-defrag lane U).** `resurrect` with
//! NONE of `--project`/`--all`/`--id` given walks UP from cwd
//! (`aoide_storage::manifest::walk_up`) for the nearest `.aoide/
//! project.json` and, if found, revives THAT manifest's specs directly —
//! [`resurrect_from_manifest`] — instead of the flag-mode selection above.
//! The manifest is SELF-SUFFICIENT: no `projects.json` registration is
//! read or required. Not found — genuinely bare, no flag given either —
//! the command falls through to the ordinary `--project`-required check,
//! whose usage error then names both misses (no manifest above cwd, no
//! flag given). `--project`/`--all`/`--id` are UNCHANGED escapes that
//! ignore the manifest entirely — mutually exclusive with bare-manifest
//! mode by construction, since any one of them present routes straight to
//! the pre-existing flag-mode path AND skips the manifest walk altogether,
//! so a flag-mode invocation missing `--project` (`--id X` alone, say)
//! gets `require_flag`'s own ORIGINAL, accurate usage error — never the
//! both-misses wording, which would lie twice over (a flag WAS given; no
//! walk was ever attempted). A review fix (U2 round 1) closed exactly this
//! bug: the both-misses message used to fire unconditionally on any
//! `require_flag` failure.
//!
//! Each manifest spec (`{host, dir, agent, command?}`,
//! `aoide_storage::manifest::SessionSpec`) resolves independently, same
//! per-candidate isolation the flag-mode loop already holds: a spec whose
//! `host` is not this host's own name
//! (`aoide_storage::display::local_host_name`) is [`summon_remote`]'s job
//! (U4, command-defrag lane U) — summoned through the peer door rather than
//! skipped, see that function's own doc for the local refusal shapes, the
//! reused signed-spawn wire, and the cwd limitation this phase lands with.
//! A local spec's `dir` resolves through `aoide_storage::manifest::
//! resolve_spec_dir` (the containment guard — a `..`-laden `dir` is
//! refused, never silently resolved outside the project root).
//!
//! **The enrichment rule (the User's design decision, U2): the manifest
//! decides WHAT exists; the ledger decides HOW.** The newest entry in THIS
//! HOST's own `state/session-ledger.jsonl` whose `cwd`/`agent` match the
//! resolved `dir`/the spec's `agent` (host is implicit — the ledger is
//! host-local state, never synced, and only a same-host spec reaches this
//! match at all) is revived through the exact SAME [`resolve_candidate`]/
//! [`resurrect_one`] path `--id` drives — its harness resume args or
//! terminal restore snapshot, exactly as if the operator had named that
//! ledger entry directly. No match — the ordinary case for a spec this
//! host has never actually run, e.g. straight off a fresh checkout — falls
//! to a CLEAN windowed spawn instead ([`clean_spawn_from_spec`]): the
//! spec's own `command` when given, else the agent's registered
//! `AgentProfile::launch` default (`aoide_protocol::agents::agent_profile`)
//! — the SAME windowed [`session_spawn`] path every other resurrect
//! candidate spawns through, never a forked launch mechanism. An agent
//! with neither a `command` nor a registered profile is a taught
//! `failed[]` entry, never a guessed argv. A spec whose `host` names a
//! DIFFERENT box is [`summon_remote`]'s job (U4) rather than this loop's
//! own local match — see that function's doc. Every row of the outcome —
//! both buckets [`resurrect_one`] can push into as well as this loop's own
//! `summoned-remote`/`failed`/`clean-spawned` rows — carries a
//! `disposition` key, stamped after the fact where `resurrect_one` itself
//! doesn't know it is being called from manifest mode.
//!
//! **Manifest-revived sessions are marked undying (orchestrator design
//! ruling, U2 review round 1) — LOCAL revivals only.** [`summon_remote`]'s
//! own rows never reach this: the resurrected id lives on the PEER, and
//! `state/undying.json` is host-local runtime state naming ids that live on
//! THIS host (the same reasoning U3's picker already holds toward a peer
//! row's mark — it writes a manifest spec, never touches `undying.json`
//! for an id it doesn't own). Once a spawn from EITHER local path actually
//! lands a row in `resurrected` (which only happens past `Status::Ok`, the
//! same gate `resurrect_one`'s own pre-existing undying TRANSFER block
//! reads off, never `registered` — a live terminal registering is a fact
//! this crate's own tests never exercise end-to-end, `spawn.rs`'s own
//! module doc draws that exact line), [`mark_manifest_revival_undying`]
//! marks that new id undying directly: one `load_undying`/`set_undying`/
//! `save_undying`, right here in [`resurrect_from_manifest`] — conceptually
//! the same idea `aoide spawn --undying` marks a fresh spawn with, but its
//! own separate call, not a flag threaded into the shared `spawn`
//! invocation. The manifest spec IS the durable declaration of what should
//! exist, so marking its revived session undying means a LATER bare
//! `resurrect --project <name>` (or the daemon's boot sweep) finds it in
//! the undying set without re-walking or re-consulting the manifest —
//! flag-mode and manifest-mode revival converge on ONE durable set instead
//! of tracking two independent notions of "what this project wants
//! running." This is deliberately unconditional, unlike flag-mode's own
//! undying TRANSFER a few paragraphs up (which only ever marks a new id
//! when the OLD ledger id it replaces was already undying): there is no
//! ordinary-revive case to protect here, every manifest-mode spawn already
//! came from an explicit, operator-authored declaration.

use super::common::{require_flag, stage_error};
use super::model::{load_stage, projects_path, sessions_path, ProjectsFile, SessionsFile};
use super::send::session_send;
use super::session_store::{stamp_origin, stamp_resumed_from};
use super::spawn::session_spawn;
use aoide_protocol::agents::agent_profile;
use aoide_protocol::output::{Outcome, Status};
use aoide_protocol::Invocation;
use aoide_storage::records::RestoreSnapshot;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

/// Mint a fresh session id for a resurrected session — never the ledger
/// entry's own id (ids are never recycled, `docs/architecture/AOIDED.md`'s
/// invariant list, item 5). Same `<command>-<pid>-<unixts>` shape `spawn`
/// mints with (`spawn.rs::unix_ts`, reused rather than re-derived).
fn mint_resurrected_id() -> String {
    format!("resurrect-{}-{}", std::process::id(), super::conduct::unix_ts())
}

/// One selected, resumable ledger candidate, resolved down to what
/// [`resurrect_one`] needs — the harness profile lookup and `harnessSessionId`
/// fallback already done, so the spawn/skip decision below never re-derives
/// them.
struct Candidate {
    entry: aoide_storage::ledger::LedgerEntry,
    resume_argv: Option<Vec<String>>,
}

fn resolve_candidate(entry: aoide_storage::ledger::LedgerEntry) -> Candidate {
    let harness_argv = agent_profile(&entry.agent).and_then(|p| p.resume_args).map(|f| {
        let harness_id = entry.harness_session_id.as_deref().unwrap_or(&entry.session_id);
        f(harness_id)
    });
    if harness_argv.is_some() {
        return Candidate { entry, resume_argv: harness_argv };
    }
    // Harness arm found nothing — try the TERMINAL arm (P-C6, durable-
    // sessions plan). `agent == "shell"` is never a harness — it has no
    // session id to `--resume` and no profile row (`agents.rs`'s own module
    // doc refuses a guessed `SHELL_PROFILE` for exactly this reason) — what
    // it carries instead is a `restore` snapshot (P-C5). `Some(restore)` is
    // the whole test for "is this even a terminal candidate"; a `restore`
    // -less entry (predating P-C5, or a harness this box has never
    // verified) falls through to the pre-existing taught skip below.
    let resume_argv = entry.restore.is_some().then(|| vec![login_shell(), "-l".to_string()]);
    Candidate { entry, resume_argv }
}

/// The login shell a resurrected terminal candidate re-opens with `-l` —
/// reconstructing exactly what `modules/dendrites/kitty.nix`'s own wrapper
/// execs (`:70,72`, `<login_shell> -l`), same three-step resolution order
/// (`kitty.nix:49-55`): `$SHELL` if set and executable, else the passwd
/// entry for this uid if executable, else `/bin/sh`. Not a pure function —
/// it reads the environment, the passwd database, and the filesystem — so
/// it stays a thin, unmocked helper the same way `spawn.rs`'s own
/// `terminal_template`/`require_display` do; nothing downstream needs to
/// know WHY a shell was chosen, only which one.
fn login_shell() -> String {
    if let Ok(shell) = std::env::var("SHELL") {
        if is_executable_file(&shell) {
            return shell;
        }
    }
    if let Some(shell) = passwd_login_shell() {
        if is_executable_file(&shell) {
            return shell;
        }
    }
    "/bin/sh".to_string()
}

fn is_executable_file(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// The shell field of this uid's own passwd entry, via `getent` — the same
/// lookup `kitty.nix`'s `getent passwd "$(id -u)" | cut -d: -f7` performs.
fn passwd_login_shell() -> Option<String> {
    let uid = unsafe { libc::getuid() };
    let out = std::process::Command::new("getent").arg("passwd").arg(uid.to_string()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()?.trim_end().split(':').nth(6).map(str::to_string)
}

/// The narrow, named check behind the sudo refusal (orchestrator ruling,
/// durable-sessions plan open knob 5): match ONLY `argv[0]`'s basename being
/// exactly `sudo`, nothing cleverer — no `doas`/`pkexec` guessing, no
/// argument inspection.
fn is_sudo_argv(argv: &[String]) -> bool {
    argv.first()
        .and_then(|a| std::path::Path::new(a).file_name())
        .and_then(|n| n.to_str())
        == Some("sudo")
}

/// What, if anything, to deliver into a freshly-resurrected terminal once it
/// registers — pure, no process, no socket, so this decision and its exact
/// `Invocation` flag map are directly unit-testable apart from
/// `resurrect_one`'s real spawn. See the module doc's safety-invariant
/// paragraph: the two branches below are never unified behind a shared
/// boolean parameter — each hardcodes its own flag map inline.
fn restore_delivery(door: aoide_protocol::Door, new_id: &str, restore: &RestoreSnapshot) -> Option<Invocation> {
    if !restore.idle {
        // Branch one — demonstrably RUNNING something when the session
        // left. Re-exec it, Enter and all: never for `sudo` (`is_sudo_argv`)
        // — an unattended password prompt in a terminal nobody is watching
        // is not a restore.
        let argv = restore.argv.as_ref()?;
        if is_sudo_argv(argv) {
            return None;
        }
        let mut flags = BTreeMap::new();
        flags.insert("id".to_string(), new_id.to_string());
        // Attributed to the target ITSELF: these are the session's own prior
        // bytes going back to its own prompt, and send's self-attribution
        // rule delivers them verbatim — a provenance prefix would turn the
        // re-exec into a shell syntax error (live P-C7 finding).
        flags.insert("from".to_string(), new_id.to_string());
        flags.insert("yes".to_string(), "true".to_string());
        flags.insert("submit".to_string(), "true".to_string());
        return Some(Invocation {
            path: vec!["send".to_string()],
            args: vec![argv.join(" ")],
            flags,
            door,
        });
    }
    // Branch two — idle, with a clean, unpoisoned typed line. Preload it and
    // NOTHING else: `--yes`, and — permanently — no `--submit`. This flag
    // map must never gain a `submit` key; that omission is the entire
    // mechanism behind "preload, never auto-run".
    let typed = restore.typed.as_ref()?;
    let mut flags = BTreeMap::new();
    flags.insert("id".to_string(), new_id.to_string());
    // Self-attributed for the same verbatim-bytes reason as the re-exec
    // branch above: the preloaded line must be exactly what the operator
    // typed, or Enter runs something else.
    flags.insert("from".to_string(), new_id.to_string());
    flags.insert("yes".to_string(), "true".to_string());
    Some(Invocation {
        path: vec!["send".to_string()],
        args: vec![typed.clone()],
        flags,
        door,
    })
}

/// Spawn one candidate via the windowed path and fold the outcome into
/// `resurrected`/`skipped`/`failed`. Never returns an error — every failure
/// mode is data, per the module doc.
fn resurrect_one(
    door: aoide_protocol::Door,
    c: Candidate,
    resurrected: &mut Vec<serde_json::Value>,
    skipped: &mut Vec<serde_json::Value>,
    failed: &mut Vec<serde_json::Value>,
    changed: &mut Vec<String>,
) {
    let Some(argv) = c.resume_argv else {
        skipped.push(json!({
            "sessionId": c.entry.session_id,
            "agent": c.entry.agent,
            "reason": format!(
                "harness `{}` has no verified resume argv — skipped rather than typing a guessed invocation",
                c.entry.agent
            ),
        }));
        return;
    };
    let new_id = mint_resurrected_id();
    let mut flags = BTreeMap::new();
    flags.insert("agent".to_string(), c.entry.agent.clone());
    flags.insert("id".to_string(), new_id.clone());
    flags.insert("windowed".to_string(), "true".to_string());
    if !c.entry.cwd.is_empty() {
        flags.insert("cwd".to_string(), c.entry.cwd.clone());
    }
    let spawn_inv = Invocation {
        path: vec!["spawn".to_string()],
        args: argv,
        flags,
        door,
    };
    let out = session_spawn(&spawn_inv);
    if out.status != aoide_protocol::output::Status::Ok {
        failed.push(json!({
            "sessionId": c.entry.session_id,
            "agent": c.entry.agent,
            "reason": out.message,
        }));
        return;
    }
    let registered = out
        .data
        .as_ref()
        .and_then(|d| d.get("registered"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // Safe no-op if the record has not landed yet (an honest `registered:
    // false` on a slow terminal open) — never a second wait loop here;
    // `session_spawn` already spent its own registration budget.
    stamp_resumed_from(&new_id, &c.entry.session_id);

    // Carry the ledger entry's own `origin` forward onto the revived record
    // (LANE IDENTITY P-ID0, G6): `ledger_session_exit` writes `origin` on
    // every exit, but nothing read it back until now — a revived
    // peer-origin session silently became origin-less, losing its
    // provenance on every resurrection. Change-only/no-op-safe exactly like
    // `stamp_resumed_from` above (an unknown id or empty origin is a silent
    // no-op); absent on the ledger entry (a locally-registered session
    // never had one) means nothing to carry, same as before.
    if let Some(origin) = c.entry.origin.as_deref() {
        stamp_origin(&new_id, origin);
    }

    // Undying transfer (P-C3, durable-sessions plan): if the OLD id was
    // durable, move the mark onto the fresh one rather than leaving it
    // behind — a mark left on a ledger id would double-resurrect on the next
    // sweep once P-C4 selects off the undying set. A no-op when the old id
    // was never undying at all (this resurrect did not originate from the
    // undying set), so an ordinary `--all`/`--id` revive never starts
    // marking sessions undying that nobody marked.
    //
    // Both mutations land in ONE in-memory vector before the SINGLE
    // `save_undying` write below — mark the new id BEFORE dropping the old
    // one, so a crash between the two in-memory edits and the write is
    // impossible, and a crash right before the write leaves the OLD id
    // still undying (retry-safe) rather than neither (silent loss). Also
    // idempotent: re-running this on an already-transferred pair finds the
    // old id no longer undying and writes nothing.
    let mut undying = aoide_storage::undying::load_undying();
    if aoide_storage::undying::is_undying(&undying, &c.entry.session_id) {
        aoide_storage::undying::set_undying(&mut undying, &new_id, true);
        aoide_storage::undying::set_undying(&mut undying, &c.entry.session_id, false);
        let _ = aoide_storage::undying::save_undying(&undying);
    }

    // Post-spawn restore delivery (P-C6, durable-sessions plan) — only for a
    // TERMINAL candidate (a `restore` snapshot present) whose spawn actually
    // registered: an unregistered session has no live pty to deliver into,
    // the same posture `spawn --prompt` already takes toward its own
    // injection. `restore_delivery` is pure and decides the whole shape; the
    // `submit` key on its returned flags (never present on the preload
    // shape) is what this reads back to report which branch fired.
    let restore_result = if !registered {
        "skipped-unregistered".to_string()
    } else {
        match c.entry.restore.as_ref().and_then(|r| restore_delivery(door, &new_id, r)) {
            None => "none".to_string(),
            Some(inv) => {
                let submit = inv.flags.contains_key("submit");
                let inner = session_send(&inv);
                if inner.status == Status::Ok {
                    if submit { "reexec".to_string() } else { "preload".to_string() }
                } else {
                    format!("failed: {}", inner.message)
                }
            }
        }
    };

    changed.push(format!(
        "session {new_id}: resurrected from {} ({}){}",
        c.entry.session_id,
        c.entry.agent,
        if registered { "" } else { " (not yet registered)" }
    ));
    if restore_result == "reexec" || restore_result == "preload" {
        changed.push(format!("session {new_id}: restore {restore_result}"));
    }
    resurrected.push(json!({
        "sessionId": new_id,
        "resumedFrom": c.entry.session_id,
        "agent": c.entry.agent,
        "registered": registered,
        "restoreDelivery": restore_result,
    }));
}

/// Bare-mode selection (no `--all`/`--id`, decision 6 of the durable-sessions
/// plan): `anchored` narrowed to the project's WHOLE undying set, not just
/// its single most recent entry. Three steps, in order:
///
/// 1. keep only entries whose `sessionId` is in `state/undying.json`
///    (`aoide_storage::undying::is_undying`);
/// 2. drop any id that is already alive (non-`done`) in `sessions.json` —
///    the daemon's old `has_live` skip moves HERE, per-id instead of
///    per-project, so one live terminal no longer suppresses the rest of a
///    multi-session undying set (`server/src/daemon.rs`'s
///    `run_boot_auto_resume`, which now calls this unconditionally);
/// 3. dedup by `sessionId`, keeping the entry with the latest `endedAt` — a
///    undying id that was resurrected and exited again appears twice in the
///    append-only ledger.
fn undying_selection(
    anchored: Vec<aoide_storage::ledger::LedgerEntry>,
) -> Vec<aoide_storage::ledger::LedgerEntry> {
    let undying = aoide_storage::undying::load_undying();
    let sessions: SessionsFile = load_stage(&sessions_path()).unwrap_or_default();
    let live: std::collections::HashSet<&str> = sessions
        .sessions
        .iter()
        .filter(|s| s.state != "done")
        .map(|s| s.session_id.as_str())
        .collect();

    let mut newest: BTreeMap<String, aoide_storage::ledger::LedgerEntry> = BTreeMap::new();
    for e in anchored {
        if !aoide_storage::undying::is_undying(&undying, &e.session_id) {
            continue;
        }
        if live.contains(e.session_id.as_str()) {
            continue;
        }
        let ended = aoide_storage::time::parse_iso_utc(&e.ended_at).unwrap_or(0);
        let keep = match newest.get(&e.session_id) {
            Some(existing) => ended > aoide_storage::time::parse_iso_utc(&existing.ended_at).unwrap_or(0),
            None => true,
        };
        if keep {
            newest.insert(e.session_id.clone(), e);
        }
    }
    newest.into_values().collect()
}

/// One audit line per `resurrect` invocation, carrying the decision's own
/// counts/message — the boot-sweep postmortem's own finding (gate-6): an
/// early empty-selection return must audit exactly like a full run does,
/// never silently skip it. Mirrors `send.rs`'s `audit_send`/`pending.rs`'s
/// `audit_pending` shape, minus `untrusted_data` (a resurrect decision
/// carries no forwarded text to wrap). Deliberately NOT called from a pure
/// usage/stage-file miss (a missing flag, an unreadable `projects.json`/
/// ledger) — the same posture `audit_send` already holds toward its own
/// `require_flag`/`stage_error` early exits; this covers every point past
/// that where `resurrect` has actually made — or attempted — a revival
/// decision.
fn audit_resurrect(inv: &Invocation, status: &str, message: &str) {
    let log = aoide_protocol::audit_log_path(inv);
    let _ = aoide_protocol::append_audit(
        &log,
        &aoide_protocol::AuditRecord {
            ts: aoide_protocol::audit::now_secs(),
            door: inv.door,
            class: aoide_protocol::EventClass::Audit,
            command: "resurrect".to_string(),
            status: status.to_string(),
            message: message.to_string(),
            untrusted_data: None,
        },
    );
}

/// `aoide resurrect [--project <name> [--all | --id <ledgerSessionId>]]`.
///
/// Bare (none of the three flags): try the manifest first
/// ([`resurrect_from_manifest`], U2's own module-doc paragraph) — found, it
/// owns the whole outcome; not found, falls through to the flag-mode path
/// below, whose `require_flag` miss now teaches both misses at once. Any of
/// `--project`/`--all`/`--id` present routes straight past the manifest
/// check to the pre-existing flag-mode selection, unchanged.
pub fn session_resurrect(inv: &Invocation) -> Outcome {
    let cmd = "resurrect";
    let flag_mode = inv.flags.contains_key("project") || inv.flags.contains_key("id") || inv.flag_present("all");
    if !flag_mode {
        let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
        if let Some((root, manifest)) = aoide_storage::manifest::walk_up(&cwd) {
            return resurrect_from_manifest(inv, &root, &manifest);
        }
    }

    let name = match require_flag(inv, "project") {
        Ok(v) => v,
        Err(o) => {
            // The manifest-miss wording is honest ONLY when a manifest walk
            // was actually attempted — that happened above iff `!flag_mode`.
            // `flag_mode == true` here means one of `--all`/`--id` was given
            // without `--project` (no walk was ever tried, and one of the
            // three flags WAS given) — `require_flag`'s own original error
            // is the true one in that case (review fix, U2 round 1: this
            // branch used to return the manifest-miss message unconditionally,
            // which lied on both counts for e.g. a bare `--id` invocation).
            if flag_mode {
                return o;
            }
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".to_string());
            return Outcome::usage(
                cmd,
                format!(
                    "no .aoide/project.json above `{cwd}` and no --project/--all/--id given — \
                     run inside a project with a manifest, or pass --project <name>"
                ),
            );
        }
    };

    let projects: ProjectsFile = match load_stage(&projects_path()) {
        Ok(f) => f,
        Err(e) => return stage_error(cmd, e),
    };
    let Some(target_idx) = projects.projects.iter().position(|p| p.name == name) else {
        let out = Outcome::error(cmd, format!("no project named `{name}` — register it first with `project add`"))
            .with_data(json!({ "reason": "unknown-project", "project": name }));
        audit_resurrect(inv, "error", &out.message);
        return out;
    };

    let ledger = match aoide_storage::ledger::read_ledger() {
        Ok(v) => v,
        Err(e) => return stage_error(cmd, e.to_string()),
    };
    let anchored: Vec<aoide_storage::ledger::LedgerEntry> = ledger
        .into_iter()
        .filter(|e| super::model::anchor_for(&e.cwd, &projects.projects) == Some(target_idx))
        .collect();

    let selected: Vec<aoide_storage::ledger::LedgerEntry> = if let Some(id) = inv.flags.get("id") {
        match anchored.into_iter().find(|e| &e.session_id == id) {
            Some(e) => vec![e],
            None => {
                let out = Outcome::error(
                    cmd,
                    format!("no ledger entry `{id}` anchored to project `{name}`"),
                )
                .with_data(json!({ "reason": "unknown-ledger-id", "project": name, "id": id }));
                audit_resurrect(inv, "error", &out.message);
                return out;
            }
        }
    } else if inv.flag_present("all") {
        let mut v = anchored;
        v.sort_by(|a, b| {
            let ea = aoide_storage::time::parse_iso_utc(&a.ended_at).unwrap_or(0);
            let eb = aoide_storage::time::parse_iso_utc(&b.ended_at).unwrap_or(0);
            eb.cmp(&ea)
        });
        v
    } else {
        undying_selection(anchored)
    };

    if selected.is_empty() {
        let bare = inv.flags.get("id").is_none() && !inv.flag_present("all");
        let msg = if bare {
            format!("undying set is empty for project `{name}` — nothing to resurrect")
        } else {
            format!("no resumable session found for project `{name}`")
        };
        audit_resurrect(inv, "ok", &msg);
        return Outcome::ok(cmd, msg)
            .with_data(json!({ "project": name, "resurrected": [], "skipped": [], "failed": [] }));
    }

    let mut resurrected: Vec<serde_json::Value> = Vec::new();
    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut failed: Vec<serde_json::Value> = Vec::new();
    let mut changed: Vec<String> = Vec::new();
    for e in selected {
        resurrect_one(inv.door, resolve_candidate(e), &mut resurrected, &mut skipped, &mut failed, &mut changed);
    }

    let out = Outcome::ok(
        cmd,
        format!(
            "project `{name}`: resurrected {}, skipped {}, failed {}",
            resurrected.len(),
            skipped.len(),
            failed.len(),
        ),
    )
    .changed(changed)
    .with_data(json!({
        "project": name,
        "resurrected": resurrected,
        "skipped": skipped,
        "failed": failed,
        "sessionsFile": sessions_path().to_string_lossy(),
    }));
    audit_resurrect(inv, "ok", &out.message);
    out
}

/// Mark a manifest-revived session's OWN new id undying (orchestrator
/// design ruling, U2 review round 1) — `entry` is a `resurrected[]` row
/// (either shape: `resurrect_one`'s own, or `clean_spawn_from_spec`'s),
/// read back for its `sessionId` rather than threading one down through
/// another parameter. One `load_undying`/`set_undying`/`save_undying`,
/// gated on nothing but the row already being IN `resurrected` — which by
/// construction only happens once the underlying spawn reached
/// `Status::Ok` (never on `registered`: this crate's own tests never open
/// a real terminal end-to-end, the same line `spawn.rs`'s module doc
/// draws, so gating on live registration would make this unconditionally
/// untestable here). The rationale for marking unconditionally rather than
/// only transferring a PRE-existing mark (`resurrect_one`'s own transfer
/// block, a few paragraphs up, untouched by this function): the manifest
/// spec IS the durable declaration of what should exist, so its revived
/// session belongs in the undying set regardless of whether the ledger
/// entry that enriched it (if any) happened to be marked — a later bare
/// `resurrect --project <name>` or the daemon's boot sweep then finds it
/// without ever re-walking or re-consulting the manifest.
fn mark_manifest_revival_undying(entry: &serde_json::Value) {
    let Some(id) = entry.get("sessionId").and_then(serde_json::Value::as_str) else {
        return;
    };
    let mut undying = aoide_storage::undying::load_undying();
    aoide_storage::undying::set_undying(&mut undying, id, true);
    let _ = aoide_storage::undying::save_undying(&undying);
}

/// U2's bare-manifest mode: `resurrect` with no `--project`/`--all`/`--id`
/// found `.aoide/project.json` walking up from cwd — revive its specs
/// directly. See this module's own doc for the enrichment rule and the
/// remote-skip/containment-guard steps; this function is the loop that
/// applies them per spec, one failure never aborting the rest (same
/// posture the flag-mode candidate loop above already holds).
fn resurrect_from_manifest(
    inv: &Invocation,
    root: &Path,
    manifest: &aoide_storage::manifest::Manifest,
) -> Outcome {
    let cmd = "resurrect";
    let this_host = aoide_storage::display::local_host_name();
    let ledger = match aoide_storage::ledger::read_ledger() {
        Ok(v) => v,
        Err(e) => return stage_error(cmd, e.to_string()),
    };

    let mut resurrected: Vec<serde_json::Value> = Vec::new();
    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut failed: Vec<serde_json::Value> = Vec::new();
    let mut changed: Vec<String> = Vec::new();

    for spec in &manifest.sessions {
        if spec.host != this_host {
            summon_remote(spec, &mut resurrected, &mut failed, &mut changed);
            continue;
        }

        let dir = match aoide_storage::manifest::resolve_spec_dir(root, &spec.dir) {
            Ok(p) => p,
            Err(e) => {
                failed.push(json!({
                    "host": spec.host, "dir": spec.dir, "agent": spec.agent,
                    "disposition": "failed", "reason": e,
                }));
                continue;
            }
        };
        let dir_str = dir.to_string_lossy().into_owned();

        // Enrichment (the module doc's own rule): the newest ledger entry
        // whose cwd/agent match this spec — host is implicit, a spec whose
        // host didn't match this one already skipped above, and the ledger
        // itself is host-local state that is never synced.
        let matched = ledger
            .iter()
            .filter(|e| e.cwd == dir_str && e.agent == spec.agent)
            .max_by_key(|e| aoide_storage::time::parse_iso_utc(&e.ended_at).unwrap_or(0));

        match matched {
            Some(entry) => {
                // `resurrect_one` is the flag-mode function, reused
                // VERBATIM — it pushes into exactly ONE of the three
                // buckets per call, none of its own pushes carrying a
                // `disposition` key (that's a manifest-mode-only concept).
                // Track each bucket's length so whichever one grew gets
                // stamped after the fact — every row this loop's own
                // outcome carries MUST have a `disposition`, so a consumer
                // filtering by it never silently drops a row that fell
                // through `resurrect_one`'s own skip/fail shapes (review
                // fix, U2 round 1).
                let (before_r, before_s, before_f) = (resurrected.len(), skipped.len(), failed.len());
                resurrect_one(inv.door, resolve_candidate(entry.clone()), &mut resurrected, &mut skipped, &mut failed, &mut changed);
                if resurrected.len() > before_r {
                    if let Some(last) = resurrected.last_mut() {
                        last["disposition"] = json!("revived-from-ledger");
                    }
                    mark_manifest_revival_undying(&resurrected[resurrected.len() - 1]);
                } else if skipped.len() > before_s {
                    if let Some(last) = skipped.last_mut() {
                        last["disposition"] = json!("skipped");
                    }
                } else if failed.len() > before_f {
                    if let Some(last) = failed.last_mut() {
                        last["disposition"] = json!("failed");
                    }
                }
            }
            None => {
                let before_r = resurrected.len();
                clean_spawn_from_spec(inv.door, spec, &dir_str, &mut resurrected, &mut failed, &mut changed);
                if resurrected.len() > before_r {
                    mark_manifest_revival_undying(&resurrected[resurrected.len() - 1]);
                }
            }
        }
    }

    let out = Outcome::ok(
        cmd,
        format!(
            "manifest at `{}`: resurrected {}, skipped {}, failed {}",
            root.display(),
            resurrected.len(),
            skipped.len(),
            failed.len(),
        ),
    )
    .changed(changed)
    .with_data(json!({
        "manifestRoot": root.to_string_lossy(),
        "resurrected": resurrected,
        "skipped": skipped,
        "failed": failed,
        "sessionsFile": sessions_path().to_string_lossy(),
    }));
    audit_resurrect(inv, "ok", &out.message);
    out
}

/// A manifest spec whose `host` names a DIFFERENT box: summoned through the
/// peer door rather than skipped (U4, command-defrag lane U — landing the
/// U2/U3 module doc's own "remote summoning is a later phase" note).
/// `spec.host` resolves against `state/peers.json` the exact same way U3's
/// picker WRITES it (`{host: <peer name>, dir, agent}`, `CONTRACTS.md`'s
/// `.aoide/project.json` section) — a peer NICKNAME, not a literal DNS/OS
/// hostname. Three local refusals, all landing in `failed[]` — never
/// `skipped[]`, since this spec was tried and refused, not given up on —
/// before the wire is ever touched:
/// - no peer named `spec.host` at all — taught, names `peer add`;
/// - a registered but UNVERIFIED peer — the same local-only refusal
///   `aoide-client::commands::handle_peer_spawn` already holds (an
///   unsigned request can never satisfy the remote door's `Signature`-rung
///   spawn gate, P-P4/PAIRING.md decision 6): refused HERE rather than
///   earning a doomed round trip;
/// - neither a `command` nor a registered `AgentProfile::launch` default
///   for `spec.agent` ([`summon_text`]) — the same taught gap
///   [`clean_spawn_from_spec`] refuses locally, mirrored here since there
///   is no argv to build a prompt from either.
///
/// Past those three, this reuses [`aoide_client::commands::spawn_on_peer`]
/// VERBATIM — the identical signed spawn-shaped `message/send`
/// (`context_id: None`) `aoide peer spawn` drives (the `conduct` → `client`
/// edge this crate's `Cargo.toml` already documents for `who`, extended to
/// this tenant) — never a re-implementation of the wire, never a shell-out
/// to the `aoide` CLI. No confirm prompt: unlike `peer spawn`'s interactive
/// `--yes` gate, a manifest spec IS the operator's own standing
/// declaration — the identical posture U2's local clean-spawn already
/// takes toward a spec's own `command`, never re-asked at revival time.
/// **Which AGENT actually runs is the PEER's own configured
/// `aoide.a2a.spawnAgent`, never chosen here** — [`summon_text`]'s result
/// only ever becomes that agent's first typed turn
/// (`aoide-server::a2a::do_spawn`'s `spawn_inject_prompt`), the same
/// security model `handle_peer_spawn`'s own doc states; `spec.agent` is
/// informational on the remote leg, unlike the local leg where it picks
/// the actual harness. Every remaining refusal — unreachable peer, the
/// remote door's own gate/autogate/allow-set refusal — surfaces VERBATIM
/// into `failed[]` as `spawn_on_peer`'s own `Err` text; per-spec isolation
/// holds exactly as every other row in this loop already does.
///
/// **The cwd limitation (design note, U4).** The spawn wire carries NO
/// working-directory field at all — `decide_send_action`/`do_spawn`
/// (`aoide-server::a2a`) take only a prompt and the pre-configured
/// `spawn_agent` executable, nothing else — so `spec.dir` cannot be pushed
/// onto the peer through this call; it is not silently dropped so much as
/// never representable on this wire version. A spec wanting a specific
/// directory on the peer must say so inside its own `command`
/// (`git -C <absolute path on the peer> …`) — an honest limitation, never
/// a guessed `--cwd` the wire has nowhere to carry. Adding a wire field is
/// a LATER phase's job: the fleet's doors run older binaries this phase
/// must stay compatible with, so the wire itself is never touched here.
fn summon_remote(
    spec: &aoide_storage::manifest::SessionSpec,
    resurrected: &mut Vec<serde_json::Value>,
    failed: &mut Vec<serde_json::Value>,
    changed: &mut Vec<String>,
) {
    let peers = aoide_storage::peer_store::load_peers();
    let peer = match peers.iter().find(|p| p.name == spec.host) {
        Some(p) if p.verified => p.clone(),
        Some(_) => {
            failed.push(json!({
                "host": spec.host, "dir": spec.dir, "agent": spec.agent,
                "disposition": "failed",
                "reason": format!(
                    "peer `{}` is registered but not paired — summoning requires a signed \
                     request from a VERIFIED peer; pair first with `aoide peer pair request \
                     <url> --name {}`",
                    spec.host, spec.host
                ),
            }));
            return;
        }
        None => {
            failed.push(json!({
                "host": spec.host, "dir": spec.dir, "agent": spec.agent,
                "disposition": "failed",
                "reason": format!(
                    "host `{}` is not a registered peer — `aoide peer add {} <url>` (then pair it) first",
                    spec.host, spec.host
                ),
            }));
            return;
        }
    };

    let Some(text) = summon_text(spec) else {
        failed.push(json!({
            "host": spec.host, "dir": spec.dir, "agent": spec.agent,
            "disposition": "failed",
            "reason": format!(
                "no `command` given and no registered default launch for agent `{}` — add a `command` to the spec",
                spec.agent
            ),
        }));
        return;
    };

    match aoide_client::commands::spawn_on_peer(&peer, &text) {
        Ok(resp) => {
            let session_id = resp
                .get("result")
                .and_then(|r| r.get("id"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            changed.push(format!(
                "session {session_id}: summoned on peer `{}` (manifest spec, agent {})",
                spec.host, spec.agent
            ));
            resurrected.push(json!({
                "sessionId": session_id,
                "host": spec.host,
                "agent": spec.agent,
                "disposition": "summoned-remote",
                "response": resp,
            }));
        }
        Err(e) => {
            failed.push(json!({
                "host": spec.host, "dir": spec.dir, "agent": spec.agent,
                "disposition": "failed",
                "reason": format!("summoning on peer `{}`: {e}", spec.host),
            }));
        }
    }
}

/// The text a remote summon injects as the peer's newly spawned session's
/// first turn — the spec's own `command` VERBATIM when given (unlike
/// [`clean_spawn_from_spec`]'s LOCAL argv, this never whitespace-splits it:
/// there is no argv on this wire, only one prompt string, so splitting and
/// rejoining would only risk collapsing whitespace the operator wrote on
/// purpose), else the agent's registered
/// [`aoide_protocol::agents::AgentProfile::launch`] default joined back
/// into one line (the same fallback U2's local clean-spawn already
/// applies, mirrored here since the wire wants a string, not a `Vec`).
/// `None` when neither exists — the caller turns that into a taught
/// `failed[]` entry, never a guessed prompt.
fn summon_text(spec: &aoide_storage::manifest::SessionSpec) -> Option<String> {
    // A whitespace-only command is no command — treated as absent so the
    // agent default (or the taught None) applies instead of summoning a
    // blank prompt: the string-form twin of clean_spawn's empty-argv guard.
    if let Some(command) = spec.command.as_deref().filter(|c| !c.trim().is_empty()) {
        return Some(command.to_string());
    }
    let profile = agent_profile(&spec.agent)?;
    if profile.launch.is_empty() {
        return None;
    }
    Some(profile.launch.join(" "))
}

/// A manifest spec with no enriching ledger match: clean-spawn it windowed
/// — the spec's own `command` when given (whitespace-split into argv; no
/// shell-quote awareness, the same naive tokenizing `spawn.rs`'s own
/// `build_terminal_argv` already uses for `$AOIDE_TERMINAL`), else the
/// agent's registered [`aoide_protocol::agents::AgentProfile::launch`]
/// default. An agent with neither is a `failed[]` entry naming the gap,
/// never a guessed invocation. Reuses [`session_spawn`]'s own windowed
/// path — never a forked launch mechanism.
fn clean_spawn_from_spec(
    door: aoide_protocol::Door,
    spec: &aoide_storage::manifest::SessionSpec,
    dir: &str,
    resurrected: &mut Vec<serde_json::Value>,
    failed: &mut Vec<serde_json::Value>,
    changed: &mut Vec<String>,
) {
    let argv: Vec<String> = match &spec.command {
        Some(command) => command.split_whitespace().map(str::to_string).collect(),
        None => match agent_profile(&spec.agent) {
            Some(p) if !p.launch.is_empty() => p.launch.iter().map(|s| s.to_string()).collect(),
            _ => {
                failed.push(json!({
                    "host": spec.host, "dir": spec.dir, "agent": spec.agent,
                    "disposition": "failed",
                    "reason": format!(
                        "no `command` given and no registered default launch for agent `{}` — add a `command` to the spec",
                        spec.agent
                    ),
                }));
                return;
            }
        },
    };
    if argv.is_empty() {
        failed.push(json!({
            "host": spec.host, "dir": spec.dir, "agent": spec.agent,
            "disposition": "failed", "reason": "spec's `command` is empty after whitespace-splitting",
        }));
        return;
    }

    let mut flags = BTreeMap::new();
    flags.insert("agent".to_string(), spec.agent.clone());
    flags.insert("windowed".to_string(), "true".to_string());
    flags.insert("cwd".to_string(), dir.to_string());
    let out = session_spawn(&Invocation { path: vec!["spawn".to_string()], args: argv, flags, door });
    if out.status != Status::Ok {
        failed.push(json!({
            "host": spec.host, "dir": spec.dir, "agent": spec.agent,
            "disposition": "failed", "reason": out.message,
        }));
        return;
    }
    let session_id = out
        .data
        .as_ref()
        .and_then(|d| d.get("sessionId"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let registered = out
        .data
        .as_ref()
        .and_then(|d| d.get("registered"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    changed.push(format!(
        "session {session_id}: clean-spawned from manifest spec ({}){}",
        spec.agent,
        if registered { "" } else { " (not yet registered)" }
    ));
    resurrected.push(json!({
        "sessionId": session_id,
        "agent": spec.agent,
        "registered": registered,
        "disposition": "clean-spawned",
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::*;
    use super::super::model::write_stage;

    fn set_ledger(entries: &[aoide_storage::ledger::LedgerEntry]) {
        for e in entries {
            aoide_storage::ledger::append_ledger_entry(e).unwrap();
        }
    }

    /// A peer registered via the legacy `peer add` escape, never paired —
    /// same `verified: false` shape `send.rs`'s own `test_peer` fixture
    /// uses, named here for the summon tests' own local-refusal case.
    fn unpaired_peer(name: &str) -> aoide_storage::peer_store::Peer {
        aoide_storage::peer_store::Peer {
            name: name.to_string(),
            url: "http://127.0.0.1:9/".to_string(),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-08-27T00:00:00Z".to_string(),
        }
    }

    /// A `verified: true` peer at the given `url` — enough for
    /// `summon_remote`'s local gate to pass and `spawn_on_peer`'s own
    /// signing to proceed (signing only needs THIS instance's own identity,
    /// never the peer's `pubkey` — `sign_headers_for_peer`'s own doc), so
    /// no real pairing ceremony is needed to exercise the wire.
    fn verified_peer(name: &str, url: &str) -> aoide_storage::peer_store::Peer {
        aoide_storage::peer_store::Peer {
            verified: true,
            url: url.to_string(),
            ..unpaired_peer(name)
        }
    }

    /// Count audit-log lines whose `command` tag is `"resurrect"` — the
    /// EXACT check the headline invariant needs ("exactly one line per
    /// invocation", review round 1), not a `contains()` scan that would
    /// also pass on a log carrying two lines, or a stray substring inside
    /// some OTHER command's own message.
    fn count_resurrect_audit_lines(log_path: &std::path::Path) -> usize {
        std::fs::read_to_string(log_path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v.get("command").and_then(serde_json::Value::as_str) == Some("resurrect"))
            .count()
    }

    fn ledger_entry(
        session_id: &str,
        agent: &str,
        cwd: &str,
        ended_at: &str,
    ) -> aoide_storage::ledger::LedgerEntry {
        aoide_storage::ledger::LedgerEntry {
            v: 0,
            session_id: session_id.to_string(),
            agent: agent.to_string(),
            harness_session_id: Some(session_id.to_string()),
            cwd: cwd.to_string(),
            title: None,
            petname: None,
            started_at: "2026-08-20T00:00:00Z".to_string(),
            ended_at: ended_at.to_string(),
            resumed_from: None,
            origin: None,
            restore: None,
        }
    }

    /// Same fixture as `ledger_entry`, with an explicit `restore` block —
    /// the terminal-arm tests need to control it directly rather than
    /// always getting `None`.
    fn ledger_entry_with_restore(
        session_id: &str,
        agent: &str,
        cwd: &str,
        ended_at: &str,
        restore: Option<RestoreSnapshot>,
    ) -> aoide_storage::ledger::LedgerEntry {
        aoide_storage::ledger::LedgerEntry { restore, ..ledger_entry(session_id, agent, cwd, ended_at) }
    }

    /// Common env scaffolding every test below needs: an isolated stage +
    /// state dir, a registered project anchored at that dir. Returns the
    /// project's own absolute path (also the anchor every ledger fixture
    /// entry's `cwd` should use).
    fn setup(tag: &str) -> (std::path::PathBuf, String) {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));
        let proj_path = root.to_str().unwrap().to_string();
        let out = crate::graph::project_add(&invocation(
            &["project", "add"],
            &["proj", &proj_path],
        ));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        (root, proj_path)
    }

    // A full windowed-spawn SUCCESS (a real `conduct` registering a real
    // agent under a real-if-nulled pty) is deliberately NOT exercised here —
    // `spawn.rs`'s own module doc draws this exact line: "the LIVE gate (a
    // real terminal opening under the compositor) is the orchestrator's and
    // the User's, never this crate's tests." What IS this crate's job —
    // that a resurrected session always mints a FRESH id, and that
    // `resumedFrom` actually lands on the record once one exists — is
    // covered directly below and in `session_store.rs`'s own
    // `stamp_resumed_from` tests, with no process ever spawned.

    #[test]
    fn mint_resurrected_id_never_reuses_the_ledger_id() {
        // Same `<command>-<pid>-<unixts>` shape (and the same second-granularity
        // caveat) as `spawn`'s/`conduct`'s own id minting — this only
        // asserts what P-D8 actually needs: it is never the OLD ledger id.
        for old_id in ["ledger-old-1", "resurrect-1-1"] {
            let minted = mint_resurrected_id();
            assert_ne!(minted, old_id, "a resurrected session must never reuse the ledger id");
            assert!(minted.starts_with("resurrect-"), "id: {minted}");
        }
    }

    /// The terminal arm (P-C6): a `restore`-bearing `shell` entry has no
    /// harness profile at all (`agent_profile("shell")` is `None`, same as
    /// any unregistered name) — the harness arm skips it exactly like
    /// `a_no_resume_args_harness_is_skipped_with_a_taught_message` proves for
    /// an unknown harness, but the terminal arm picks it up right after,
    /// resolving `[<login shell>, "-l"]` rather than leaving it skipped.
    #[test]
    fn resolve_candidate_terminal_arm_resolves_a_restore_bearing_shell_entry_the_harness_arm_skips() {
        let entry = ledger_entry_with_restore(
            "ledger-terminal",
            "shell",
            "/home/khoa/Aoide",
            "2026-08-20T01:00:00Z",
            Some(RestoreSnapshot { cwd: Some("/home/khoa/Aoide".into()), idle: true, argv: None, typed: None }),
        );
        let candidate = resolve_candidate(entry);
        let argv = candidate.resume_argv.expect("the terminal arm must resolve a restore-bearing shell entry");
        assert_eq!(argv.len(), 2, "argv: {argv:?}");
        assert_eq!(argv[1], "-l", "argv: {argv:?}");
        assert!(!argv[0].is_empty(), "the login shell must not resolve to an empty string");
    }

    /// A `shell` entry with NO `restore` block (predating P-C5, or a harness
    /// this box has never verified) must still hit the pre-existing taught
    /// skip — the terminal arm's whole gate is `Some(restore)`, never bare
    /// `agent == "shell"`.
    #[test]
    fn resolve_candidate_restore_less_shell_entry_still_hits_the_taught_skip() {
        let entry = ledger_entry_with_restore("ledger-no-restore", "shell", "/home/khoa/Aoide", "2026-08-20T01:00:00Z", None);
        let candidate = resolve_candidate(entry);
        assert!(candidate.resume_argv.is_none(), "a restore-less shell entry must still be skipped");
    }

    /// The preload path's flag map, pinned directly — no process, no socket.
    /// `--yes` is present; `--submit` must NEVER be, on pain of violating
    /// the whole "preload, never auto-run" invariant this phase exists for.
    #[test]
    fn preload_delivery_carries_yes_and_never_submit() {
        let restore = RestoreSnapshot {
            cwd: Some("/home/khoa/Aoide".into()),
            idle: true,
            argv: None,
            typed: Some("echo hello".to_string()),
        };
        let inv = restore_delivery(aoide_protocol::Door::Daemon, "new-id", &restore)
            .expect("an idle restore with a typed line must construct a send");
        assert_eq!(inv.flags.get("yes").map(String::as_str), Some("true"));
        assert!(!inv.flags.contains_key("submit"), "the no-submit path must never carry `submit`: {:?}", inv.flags);
        // Self-attributed (`--from <new-id>`): send's self-attribution rule
        // then delivers the bytes verbatim — without this, the preload came
        // back as `from <sender>: echo hello`, a line no human typed
        // (live P-C7 finding).
        assert_eq!(inv.flags.get("from").map(String::as_str), Some("new-id"));
        assert_eq!(inv.args, vec!["echo hello".to_string()]);
    }

    /// The re-exec path's flag map, pinned directly — no process, no socket.
    /// It carries BOTH `--yes` and `--submit`: the session was demonstrably
    /// running this when it left, which is a different case from a typed
    /// -but-unsubmitted line.
    #[test]
    fn reexec_delivery_carries_yes_and_submit() {
        let restore = RestoreSnapshot {
            cwd: Some("/home/khoa/Aoide".into()),
            idle: false,
            argv: Some(vec!["nvim".to_string(), "notes.md".to_string()]),
            typed: None,
        };
        let inv = restore_delivery(aoide_protocol::Door::Daemon, "new-id", &restore)
            .expect("a working restore with argv must construct a send");
        assert_eq!(inv.flags.get("yes").map(String::as_str), Some("true"));
        assert_eq!(inv.flags.get("submit").map(String::as_str), Some("true"));
        // Self-attributed for the same verbatim-bytes reason as the preload
        // pin above — a prefixed re-exec is a shell syntax error.
        assert_eq!(inv.flags.get("from").map(String::as_str), Some("new-id"));
        assert_eq!(inv.args, vec!["nvim notes.md".to_string()]);
    }

    /// Idle with a null `typed` (a poisoned or never-populated line) must
    /// construct no send at all — a bare cwd restore is already the correct,
    /// complete answer, never a guess.
    #[test]
    fn idle_with_null_typed_constructs_no_send_at_all() {
        let restore = RestoreSnapshot { cwd: Some("/home/khoa/Aoide".into()), idle: true, argv: None, typed: None };
        assert!(restore_delivery(aoide_protocol::Door::Daemon, "new-id", &restore).is_none());
    }

    /// The orchestrator ruling (open knob 5): a recorded foreground of
    /// `sudo …` re-execs nothing and delivers nothing — only the cwd
    /// restores. Covers both the narrow named check directly and the
    /// delivery decision that consults it.
    #[test]
    fn sudo_foreground_is_never_reexeced() {
        assert!(is_sudo_argv(&["sudo".to_string(), "reboot".to_string()]));
        assert!(is_sudo_argv(&["/usr/bin/sudo".to_string(), "-i".to_string()]), "basename match must see through a full path");
        assert!(!is_sudo_argv(&["sudo-ish".to_string()]), "must match the exact basename, nothing cleverer");
        assert!(!is_sudo_argv(&[]));

        let restore = RestoreSnapshot {
            cwd: Some("/home/khoa/Aoide".into()),
            idle: false,
            argv: Some(vec!["sudo".to_string(), "systemctl".to_string(), "restart".to_string(), "aoided".to_string()]),
            typed: None,
        };
        assert!(
            restore_delivery(aoide_protocol::Door::Daemon, "new-id", &restore).is_none(),
            "a recorded sudo foreground must never be re-exec'd"
        );
    }

    #[test]
    fn a_no_resume_args_harness_is_skipped_with_a_taught_message() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-skip");

        set_ledger(&[ledger_entry(
            "ledger-unknown-harness",
            "no-such-harness",
            &proj_path,
            "2026-08-20T01:00:00Z",
        )]);
        // Bare selection is undying-set-driven (P-C4) — mark the entry so it
        // is even a candidate; the point of this test is the harness skip,
        // not the selection width.
        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "ledger-unknown-harness", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 0);
        let skipped = data["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1, "data: {data}");
        assert!(
            skipped[0]["reason"].as_str().unwrap().contains("no-such-harness"),
            "the skip reason must name the harness: {}",
            skipped[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_windowed_spawn_failure_degrades_gracefully_instead_of_erroring_the_command() {
        // The headless-host case (P-D8's decided trigger): no $AOIDE_TERMINAL
        // set. `session_spawn`'s own taught error fires — this proves it is
        // folded into `failed`, never turned into a hard `Outcome::error`, so
        // the daemon's boot-time trigger can call this in a loop without ever
        // treating a display-less box as a failure worth crashing a tick over.
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-headless");
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        set_ledger(&[ledger_entry("ledger-old-2", "claude", &proj_path, "2026-08-20T01:00:00Z")]);
        // Bare selection is undying-set-driven (P-C4) — mark the entry so it
        // is even a candidate; the point of this test is the failure
        // handling, not the selection width.
        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "ledger-old-2", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(
            out.status,
            aoide_protocol::output::Status::Ok,
            "a per-candidate spawn failure must degrade gracefully, never error the command: {}",
            out.message
        );
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 0);
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert!(
            failed[0]["reason"].as_str().unwrap().contains("AOIDE_TERMINAL"),
            "reason: {}",
            failed[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A successful resurrect of a UNDYING old id transfers the mark: the
    /// new id ends up undying, the old id does not, and an unrelated undying
    /// id already in the set is left exactly as it was (P-C3, durable-
    /// sessions plan). `AOIDE_TERMINAL=true` is enough to make the windowed
    /// spawn itself succeed (`Status::Ok`) without a real terminal — `true`
    /// exits 0 the instant it's exec'd; the point of this test is the undying
    /// transfer, not registration, which `resurrect_one` never gates it on.
    #[test]
    fn a_successful_resurrect_transfers_the_undying_mark_from_old_to_new() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-undying-transfer");
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        set_ledger(&[ledger_entry("ledger-undying", "claude", &proj_path, "2026-08-20T01:00:00Z")]);

        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "ledger-undying", true);
        aoide_storage::undying::set_undying(&mut undying, "unrelated-id", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");
        let new_id = resurrected[0]["sessionId"].as_str().unwrap().to_string();

        let undying = aoide_storage::undying::load_undying();
        assert!(aoide_storage::undying::is_undying(&undying, &new_id), "the new id must be undying");
        assert!(
            !aoide_storage::undying::is_undying(&undying, "ledger-undying"),
            "the old id must no longer be undying"
        );
        assert!(
            aoide_storage::undying::is_undying(&undying, "unrelated-id"),
            "an unrelated undying id must be left untouched"
        );
        assert_eq!(undying.len(), 2, "exactly one id moves — the set's size is unchanged");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// G6 (LANE IDENTITY P-ID0), data-integrity half: `resurrect_one` reads
    /// `c.entry.origin` straight off the resolved candidate to carry it
    /// forward onto the revived record — this pins that `resolve_candidate`
    /// (the harness-arm/terminal-arm dispatcher every mode routes through)
    /// carries the ledger entry's `origin` into the `Candidate` unmodified,
    /// the exact value the carry-forward line at the bottom of
    /// `resurrect_one` consumes. Pure, no env, no spawn.
    #[test]
    fn resolve_candidate_preserves_the_ledger_entrys_origin() {
        let entry = aoide_storage::ledger::LedgerEntry {
            origin: Some("peer:yomi-strix".to_string()),
            ..ledger_entry("ledger-peer-origin", "claude", "/home/khoa/Aoide", "2026-08-20T01:00:00Z")
        };
        let candidate = resolve_candidate(entry);
        assert_eq!(candidate.entry.origin.as_deref(), Some("peer:yomi-strix"));
    }

    /// G6 (LANE IDENTITY P-ID0), wiring half: a peer-origin ledger entry must
    /// not derail an otherwise-ordinary resurrect — `resurrect_one`'s new
    /// `stamp_origin` call sits right after `stamp_resumed_from`, on the
    /// SAME `AOIDE_TERMINAL=true` fixture that never actually registers a
    /// record (see the undying-transfer test above), so this proves the new
    /// call is a safe no-op in exactly that shape (an unknown id, same as
    /// `stamp_resumed_from` already tolerates) rather than a panic or an
    /// error status. Whether the value actually LANDS on a real record is
    /// `stamp_origin`'s own contract, proven directly in
    /// `session_store.rs`'s `stamp_origin_lands_the_field_and_never_
    /// restages_graph_json` — a real registered windowed spawn is the live
    /// gate's job, per this module's own doc (top of file), never this
    /// crate's.
    #[test]
    fn a_peer_origin_ledger_entry_never_derails_an_ordinary_resurrect() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-origin-carry");
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let entry = aoide_storage::ledger::LedgerEntry {
            origin: Some("peer:yomi-strix".to_string()),
            ..ledger_entry("ledger-peer-origin", "claude", &proj_path, "2026-08-20T01:00:00Z")
        };
        set_ledger(&[entry]);

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj"), ("all", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The failure half of the same rule: a spawn that never even reaches
    /// `Status::Ok` (the headless-host taught error, no `$AOIDE_TERMINAL`)
    /// must leave the old id undying, so the next sweep retries it.
    #[test]
    fn a_failed_resurrect_leaves_the_old_id_undying() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-undying-failed");
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        set_ledger(&[ledger_entry("ledger-undying-fail", "claude", &proj_path, "2026-08-20T01:00:00Z")]);

        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "ledger-undying-fail", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["failed"].as_array().unwrap().len(), 1);

        let undying = aoide_storage::undying::load_undying();
        assert!(
            aoide_storage::undying::is_undying(&undying, "ledger-undying-fail"),
            "a failed resurrect must leave the old id undying so the next sweep retries it"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Re-running a resurrect against the same (append-only, so still
    /// selectable) ledger entry after it has already transferred must not
    /// mark the SECOND new id undying or touch the set again — the transfer step
    /// only fires when the old id is currently undying, and by the second
    /// call it no longer is.
    #[test]
    fn transfer_is_idempotent_when_the_pair_has_already_transferred() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "XDG_RUNTIME_DIR",
            "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL",
            "WAYLAND_DISPLAY",
            "DISPLAY",
        ]);
        let (root, proj_path) = setup("resurrect-undying-idempotent");
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        set_ledger(&[ledger_entry("ledger-idem", "claude", &proj_path, "2026-08-20T01:00:00Z")]);

        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "ledger-idem", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        let first = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(first.status, aoide_protocol::output::Status::Ok, "msg: {}", first.message);
        let first_new_id =
            first.data.as_ref().unwrap()["resurrected"][0]["sessionId"].as_str().unwrap().to_string();
        let after_first = aoide_storage::undying::load_undying();
        assert!(aoide_storage::undying::is_undying(&after_first, &first_new_id));
        assert!(!aoide_storage::undying::is_undying(&after_first, "ledger-idem"));

        // Bare selection no longer re-picks `ledger-idem` (P-C4): its mark
        // already moved to `first_new_id` above. `--id` is the unchanged
        // escape that narrows to one entry regardless of the mark (the
        // append-only ledger still holds the line), so it is what re-drives
        // the same candidate a second time here — the point of THIS test is
        // `resurrect_one`'s transfer idempotency, not bare-mode selection.
        let second = session_resurrect(&flag_invocation(
            &["resurrect"],
            &[("project", "proj"), ("id", "ledger-idem")],
        ));
        assert_eq!(second.status, aoide_protocol::output::Status::Ok, "msg: {}", second.message);
        let second_new_id =
            second.data.as_ref().unwrap()["resurrected"][0]["sessionId"].as_str().unwrap().to_string();

        let after_second = aoide_storage::undying::load_undying();
        assert!(
            !aoide_storage::undying::is_undying(&after_second, &second_new_id),
            "the old id was no longer undying, so nothing transfers to the second new id"
        );
        assert_eq!(
            after_second, after_first,
            "a re-run transfer on an already-transferred pair changes nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_ledger_history_for_the_project_is_an_ok_no_op() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, _proj_path) = setup("resurrect-empty");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["resurrected"].as_array().unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_project_is_an_error() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, _proj_path) = setup("resurrect-unknown-project");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "nope")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Error);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_project_flag_is_a_usage_error() {
        // Bare mode (no flags at all) now tries a manifest walk-up FIRST
        // (U2) — chdir into a fresh, manifest-free scratch dir so this
        // stays deterministic regardless of where `cargo test` happens to
        // run from, rather than depending on the real ambient cwd's own
        // ancestry having no `.aoide/project.json` (every real ancestor of
        // a fresh temp dir is guaranteed manifest-free, the same
        // assumption `aoide_storage::manifest`'s own walk-up-none test
        // already leans on).
        let _guard = crate::env_lock().lock().unwrap();
        let scratch = unique_stage("resurrect-no-manifest-no-flags");
        let _cwd = CwdGuard::enter(&scratch);

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(
            out.message.contains("--project") && out.message.contains("project.json"),
            "the taught error must name both misses: {}",
            out.message
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// The review-round-1 fix: `--id` given WITHOUT `--project` is
    /// flag-mode (one of the three flags is present), so it must NEVER
    /// attempt a manifest walk and must NEVER get the bare-mode's
    /// both-misses wording — only `require_flag`'s own, accurate
    /// `--project`-missing usage error, exactly as it was before U2 ever
    /// touched this function. No cwd/env setup needed at all: proving this
    /// doesn't even reach the manifest-walk branch is the whole point.
    #[test]
    fn id_without_project_is_the_ordinary_missing_flag_error_not_the_manifest_message() {
        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("id", "some-ledger-id")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("--project"), "message: {}", out.message);
        assert!(
            !out.message.contains("project.json"),
            "an --id-given invocation must get the ORDINARY missing-flag error, never the \
             manifest-miss wording (which would lie: a flag WAS given, no walk was attempted): {}",
            out.message
        );
    }

    /// Same fix, the `--all` half.
    #[test]
    fn all_without_project_is_the_ordinary_missing_flag_error_not_the_manifest_message() {
        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("all", "true")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("--project"), "message: {}", out.message);
        assert!(!out.message.contains("project.json"), "message: {}", out.message);
    }

    /// `--all` and `--id` are unchanged escapes (P-C4's own scope line): both
    /// widen or narrow past the undying set regardless of the mark — neither
    /// entry below is ever undying, and both still resolve.
    #[test]
    fn all_widens_to_every_anchored_entry_and_id_narrows_to_one_regardless_of_the_mark() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-all-id");

        // Two resumable-shaped entries (unresolved harness, so both land in
        // `skipped` rather than needing a real spawn) — proves the SELECTION
        // width, independent of the spawn mechanics already covered above.
        // Neither is undying: --all and --id must not care.
        set_ledger(&[
            ledger_entry("ledger-a", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("ledger-b", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
        ]);

        // --all: both, undying or not.
        let out = session_resurrect(&flag_invocation(
            &["resurrect"],
            &[("project", "proj"), ("all", "true")],
        ));
        assert_eq!(out.data.as_ref().unwrap()["skipped"].as_array().unwrap().len(), 2);

        // --id: exactly the named one, not undying and not the newest.
        let out = session_resurrect(&flag_invocation(
            &["resurrect"],
            &[("project", "proj"), ("id", "ledger-a")],
        ));
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["sessionId"], "ledger-a");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── P-C4: bare selection drives off the undying set ─────────────────────

    /// The headline case: three undying, two not undying, all five anchored to
    /// the same project — bare `--project` resurrects exactly the three.
    #[test]
    fn bare_default_resurrects_exactly_the_undying_set() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-undying-set");

        set_ledger(&[
            ledger_entry("undying-1", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("undying-2", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
            ledger_entry("undying-3", "no-such-harness", &proj_path, "2026-08-20T03:00:00Z"),
            ledger_entry("not-undying-1", "no-such-harness", &proj_path, "2026-08-20T04:00:00Z"),
            ledger_entry("not-undying-2", "no-such-harness", &proj_path, "2026-08-20T05:00:00Z"),
        ]);
        let mut undying = Vec::new();
        for id in ["undying-1", "undying-2", "undying-3"] {
            aoide_storage::undying::set_undying(&mut undying, id, true);
        }
        aoide_storage::undying::save_undying(&undying).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        let mut ids: Vec<&str> = skipped.iter().map(|s| s["sessionId"].as_str().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, vec!["undying-1", "undying-2", "undying-3"], "skipped: {skipped:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A undying id still live in `sessions.json` (non-`done`) is excluded —
    /// the daemon's old per-project `has_live` skip moved down to here,
    /// per-id (P-C4's own scope line).
    #[test]
    fn bare_default_excludes_an_undying_id_still_live_in_the_roster() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-undying-live");

        set_ledger(&[
            ledger_entry("undying-alive", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("undying-dead", "no-such-harness", &proj_path, "2026-08-20T02:00:00Z"),
        ]);
        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "undying-alive", true);
        aoide_storage::undying::set_undying(&mut undying, "undying-dead", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        // `undying-alive` is still in the roster, non-`done`.
        write_stage(
            &sessions_path(),
            &SessionsFile {
                schema_version: "0".into(),
                sessions: vec![session("undying-alive", &proj_path, "working", "2026-08-20T01:00:00Z", None)],
            },
        )
        .unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1, "skipped: {skipped:?}");
        assert_eq!(skipped[0]["sessionId"], "undying-dead");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty undying set is an `ok` no-op with an honest message — never
    /// silently treated as "nothing to do" without saying why.
    #[test]
    fn bare_default_is_an_ok_no_op_when_the_undying_set_is_empty() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-undying-empty");

        // An anchored entry exists, but nothing is undying.
        set_ledger(&[ledger_entry("not-undying-only", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z")]);

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        assert_eq!(out.data.as_ref().unwrap()["resurrected"].as_array().unwrap().len(), 0);
        assert!(
            out.message.contains("undying set is empty"),
            "message must say WHY, not just no-op silently: {}",
            out.message
        );

        // The gate-6 fix (U2): an empty-selection early return must still
        // write the ONE audit line every resurrect invocation gets, never
        // silently skip it because nothing was selected — exactly one line,
        // never zero, never two (review round 1: `contains()` alone would
        // also pass on a duplicated line).
        let log = root.join("log");
        assert_eq!(count_resurrect_audit_lines(&log), 1, "log: {}", std::fs::read_to_string(&log).unwrap_or_default());
        let raw = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(raw.contains("undying set is empty"), "the one line must carry the real message: {raw}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A undying id that exited, was resurrected, and exited again appears
    /// twice in the append-only ledger — the dedup keeps the newest
    /// `endedAt`, so only one candidate is ever selected.
    #[test]
    fn bare_default_dedups_a_repeated_undying_id_keeping_the_newest_ended_at() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, proj_path) = setup("resurrect-undying-dedup");

        // Same sessionId, two ledger lines (append-only, both legal): an
        // earlier exit and a later re-exit.
        set_ledger(&[
            ledger_entry("repeated-id", "no-such-harness", &proj_path, "2026-08-20T01:00:00Z"),
            ledger_entry("repeated-id", "no-such-harness", &proj_path, "2026-08-20T09:00:00Z"),
        ]);
        let mut undying = Vec::new();
        aoide_storage::undying::set_undying(&mut undying, "repeated-id", true);
        aoide_storage::undying::save_undying(&undying).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[("project", "proj")]));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let skipped = out.data.as_ref().unwrap()["skipped"].as_array().unwrap().clone();
        assert_eq!(skipped.len(), 1, "the repeated id must be deduped to one candidate: {skipped:?}");

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── U2: bare-manifest mode ───────────────────────────────────────────

    /// Restores the real process cwd on drop, even if the test body panics
    /// mid-assertion — without this, a panicking test would leave every
    /// LATER test in this same process running from the wrong directory
    /// (tests share one OS process; `--test-threads=1` plus `env_lock`
    /// serializes access, but only a `Drop` guard protects against a panic
    /// skipping the restore).
    struct CwdGuard {
        prev: std::path::PathBuf,
    }
    impl CwdGuard {
        fn enter(dir: &std::path::Path) -> Self {
            let prev = std::env::current_dir().expect("current_dir must resolve in a test");
            std::env::set_current_dir(dir).expect("chdir into the scratch dir must succeed");
            CwdGuard { prev }
        }
    }
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }

    /// Build a manifest at `root` (also this test's `AOIDE_STATE_DIR`/
    /// `AOIDE_STAGE_DIR` root — no collision, `.aoide/` sits beside, never
    /// inside, `state/`/`stage/`) with the given specs, chdir into
    /// `root/work` (proving the walk actually climbs, not just checks
    /// cwd itself), and return `(root, CwdGuard)` — the guard must outlive
    /// the call that exercises `session_resurrect`.
    fn setup_manifest(tag: &str, specs: Vec<aoide_storage::manifest::SessionSpec>) -> (std::path::PathBuf, CwdGuard) {
        let root = unique_stage(tag);
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        std::env::set_var("XDG_RUNTIME_DIR", &root);
        std::env::set_var("AOIDE_AUDIT_LOG", root.join("log"));

        aoide_storage::manifest::save_manifest(
            &root,
            &aoide_storage::manifest::Manifest { version: aoide_storage::manifest::MANIFEST_VERSION, sessions: specs },
        )
        .unwrap();

        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let guard = CwdGuard::enter(&work);
        (root, guard)
    }

    fn manifest_spec(host: &str, dir: &str, agent: &str, command: Option<&str>) -> aoide_storage::manifest::SessionSpec {
        aoide_storage::manifest::SessionSpec {
            host: host.to_string(),
            dir: dir.to_string(),
            agent: agent.to_string(),
            command: command.map(str::to_string),
        }
    }

    /// The headline case: bare `resurrect`, no flags, cwd nested under a
    /// project with a manifest but no matching ledger history — the spec
    /// clean-spawns (windowed, `AOIDE_TERMINAL=true` for a real-but-inert
    /// child, same fixture `a_successful_resurrect_transfers_the_undying_
    /// mark_from_old_to_new` already uses) rather than needing any
    /// `projects.json` registration at all.
    #[test]
    fn bare_mode_finds_the_manifest_and_clean_spawns_an_unmatched_spec() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-clean-spawn",
            vec![manifest_spec(&this_host, ".", "claude", None)],
        );
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["manifestRoot"], root.to_string_lossy().to_string());
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");
        assert_eq!(resurrected[0]["disposition"], "clean-spawned");
        assert_eq!(resurrected[0]["agent"], "claude");

        // Bare-manifest mode audits too, EXACTLY once, same as flag mode.
        let log = root.join("log");
        assert_eq!(
            count_resurrect_audit_lines(&log), 1,
            "log: {}", std::fs::read_to_string(&log).unwrap_or_default()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A spec whose `command` is given wins over the agent's registered
    /// default — proven indirectly: an agent with NO registered profile
    /// (`no-such-harness`) would otherwise fail with no default launch, but
    /// a `command` on the spec still clean-spawns it.
    #[test]
    fn bare_mode_clean_spawn_prefers_the_specs_own_command_over_a_default_launch() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-own-command",
            vec![manifest_spec(&this_host, ".", "no-such-harness", Some("watch -n1 true"))],
        );
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["failed"].as_array().unwrap().len(), 0, "data: {data}");
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");
        assert_eq!(resurrected[0]["disposition"], "clean-spawned");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// An agent with neither a `command` nor a registered profile is a
    /// taught `failed[]` entry, never a guessed argv.
    #[test]
    fn bare_mode_clean_spawn_fails_taught_when_neither_command_nor_default_launch_exists() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-no-default",
            vec![manifest_spec(&this_host, ".", "no-such-harness", None)],
        );

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert_eq!(failed[0]["disposition"], "failed");
        assert!(
            failed[0]["reason"].as_str().unwrap().contains("no-such-harness"),
            "reason must name the agent: {}",
            failed[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// U4: a spec whose `host` is not this host's own name is SUMMONED, not
    /// skipped — but "no peer named that host at all" is the first local
    /// refusal `summon_remote` holds, before the wire is ever touched. Lands
    /// in `failed[]` (never `skipped[]` — this spec was tried and refused),
    /// taught to name `peer add`.
    #[test]
    fn bare_mode_remote_summon_fails_taught_against_an_unregistered_host() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-remote-unknown",
            vec![manifest_spec("some-other-host", ".", "claude", None)],
        );

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["skipped"].as_array().unwrap().len(), 0, "an unknown-host remote spec is FAILED, not skipped: {data}");
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert_eq!(failed[0]["disposition"], "failed");
        assert_eq!(failed[0]["host"], "some-other-host");
        assert!(
            failed[0]["reason"].as_str().unwrap().contains("peer add"),
            "reason must teach `peer add`: {}",
            failed[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The second local refusal: a peer registered via the legacy `peer
    /// add` escape but never paired (`verified: false`) can never satisfy
    /// the remote door's `Signature`-rung spawn gate — refused LOCALLY,
    /// same posture `aoide-client::commands::handle_peer_spawn` already
    /// holds toward its own CLI callers.
    #[test]
    fn bare_mode_remote_summon_fails_taught_against_an_unverified_peer() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-remote-unverified",
            vec![manifest_spec("sakaki", ".", "claude", None)],
        );
        aoide_storage::peer_store::save_peers(&[unpaired_peer("sakaki")]).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert_eq!(failed[0]["disposition"], "failed");
        assert!(
            failed[0]["reason"].as_str().unwrap().contains("peer pair request"),
            "reason must teach the pairing ceremony: {}",
            failed[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The third local refusal: a verified peer, but nothing to summon it
    /// WITH — no `command` and no registered default launch for the spec's
    /// agent. Proven with a genuinely unreachable peer URL (port 9, the
    /// same discard-port fixture `send.rs`'s own remote-delivery tests use)
    /// to prove the wire is never even touched — the refusal must fire
    /// before `spawn_on_peer` gets a chance to fail for a DIFFERENT reason.
    #[test]
    fn bare_mode_remote_summon_fails_taught_with_nothing_to_summon() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-remote-no-command",
            vec![manifest_spec("sakaki", ".", "no-such-harness", None)],
        );
        aoide_storage::peer_store::save_peers(&[verified_peer("sakaki", "http://127.0.0.1:9/")]).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert!(
            failed[0]["reason"].as_str().unwrap().contains("no-such-harness"),
            "reason must name the agent: {}",
            failed[0]["reason"]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A verified, reachable-address peer with nothing listening at all
    /// (port 9, same discard-port fixture `send.rs`'s remote-delivery
    /// tests already rely on) — `spawn_on_peer`'s own connection failure
    /// surfaces VERBATIM into `failed[]`, never turned into a hard
    /// `Outcome::error` (per-spec isolation holds even past the local
    /// refusals).
    #[test]
    fn bare_mode_remote_summon_fails_taught_when_the_peer_is_unreachable() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-remote-unreachable",
            vec![manifest_spec("sakaki", ".", "claude", Some("git -C /home/khoa/Aoide pull --ff-only"))],
        );
        aoide_storage::peer_store::save_peers(&[verified_peer("sakaki", "http://127.0.0.1:9/")]).unwrap();

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 0, "data: {data}");
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "the closed loopback port refuses the POST: {data}");
        assert_eq!(failed[0]["disposition"], "failed");
        assert_eq!(failed[0]["host"], "sakaki");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Local and remote specs in ONE manifest resolve independently — a
    /// remote spec refused locally (unknown host) never poisons a sibling
    /// LOCAL spec's own clean-spawn in the same invocation, the same
    /// per-spec isolation every other row in this loop already holds.
    #[test]
    fn bare_mode_local_and_remote_specs_isolate_in_one_manifest() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-mixed",
            vec![
                manifest_spec("some-other-host", ".", "claude", None),
                manifest_spec(&this_host, ".", "claude", None),
            ],
        );
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert_eq!(failed[0]["host"], "some-other-host");
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "the LOCAL spec must still clean-spawn: {data}");
        assert_eq!(resurrected[0]["disposition"], "clean-spawned");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// [`summon_text`] pinned directly, no I/O: a spec's own `command`
    /// wins verbatim (never whitespace-split — there is no argv on the
    /// remote wire, only one prompt string), a `command`-less spec falls to
    /// the agent's registered default launch joined back into one line, and
    /// an agent with neither yields `None` rather than a guessed prompt.
    #[test]
    fn summon_text_prefers_the_specs_own_command_verbatim_over_a_default_launch() {
        let spec = manifest_spec("sakaki", ".", "claude", Some("echo  two  spaces"));
        assert_eq!(summon_text(&spec).as_deref(), Some("echo  two  spaces"));
    }

    #[test]
    fn summon_text_falls_to_the_agents_default_launch_joined_into_one_line() {
        let spec = manifest_spec("sakaki", ".", "claude", None);
        let text = summon_text(&spec).expect("a registered agent must fall to its default launch");
        assert!(!text.is_empty());
        assert!(!text.contains('\u{0}'), "sanity: a real command string");
    }

    #[test]
    fn summon_text_is_none_for_an_unregistered_agent_with_no_command() {
        let spec = manifest_spec("sakaki", ".", "no-such-harness", None);
        assert!(summon_text(&spec).is_none());
    }

    /// A `dir` that normalizes outside the project root is rejected into
    /// `failed[]`, never resolved to some path outside the project the
    /// manifest lives in.
    #[test]
    fn bare_mode_rejects_a_dir_that_escapes_the_project_root() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-escape",
            vec![manifest_spec(&this_host, "../../etc", "claude", None)],
        );

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert_eq!(failed[0]["disposition"], "failed");
        assert!(failed[0]["reason"].as_str().unwrap().contains("escapes"), "reason: {}", failed[0]["reason"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// One spec's containment rejection never aborts a sibling spec's own
    /// resolution — the same per-candidate isolation the flag-mode loop
    /// already holds, now proven at the per-SPEC level.
    #[test]
    fn bare_mode_one_failing_spec_never_aborts_the_rest() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-isolation",
            vec![
                manifest_spec(&this_host, "../escape", "claude", None),
                manifest_spec(&this_host, ".", "claude", None),
            ],
        );
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        assert_eq!(data["failed"].as_array().unwrap().len(), 1, "data: {data}");
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 1, "data: {data}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The enrichment rule: a matching ledger entry revives through the
    /// SAME `resolve_candidate`/`resurrect_one` path `--id` drives, and
    /// when more than one entry matches, the NEWEST `endedAt` wins — proven
    /// via the harness-skip taught message (cheap: no windowed spawn), same
    /// as the flag-mode `--id`/`--all` tests above prove selection width
    /// without needing a real spawn either.
    #[test]
    fn bare_mode_enrichment_picks_the_newest_matching_ledger_entry() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG"]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-enrich-newest",
            vec![manifest_spec(&this_host, ".", "no-such-harness", None)],
        );
        let root_str = root.to_str().unwrap().to_string();
        set_ledger(&[
            ledger_entry("ledger-older", "no-such-harness", &root_str, "2026-08-20T01:00:00Z"),
            ledger_entry("ledger-newer", "no-such-harness", &root_str, "2026-08-20T09:00:00Z"),
        ]);

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let skipped = data["skipped"].as_array().unwrap();
        assert_eq!(skipped.len(), 1, "exactly one ledger entry must be selected for enrichment: {data}");
        assert_eq!(skipped[0]["sessionId"], "ledger-newer", "the NEWEST matching entry must win: {data}");
        // Review round 1: a row `resurrect_one` itself pushed into `skipped`
        // (no `disposition` of its own — that's a manifest-mode concept)
        // must still carry one once it lands in THIS loop's own outcome,
        // so a consumer filtering by `disposition` never drops it.
        assert_eq!(skipped[0]["disposition"], "skipped", "data: {data}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The same uniform-disposition fix, the `failed` bucket half: a
    /// MATCHED entry (terminal arm resolves — a `restore` snapshot is
    /// present) whose spawn then fails outright (no `$AOIDE_TERMINAL`, the
    /// same headless taught error `a_windowed_spawn_failure_degrades_
    /// gracefully_instead_of_erroring_the_command` proves in flag mode)
    /// must land in `failed` with `disposition: "failed"`, not a bare
    /// `resurrect_one`-shaped row missing the key entirely.
    #[test]
    fn bare_mode_enrichment_spawn_failure_gets_a_failed_disposition_too() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-enrich-failed",
            vec![manifest_spec(&this_host, ".", "shell", None)],
        );
        let root_str = root.to_str().unwrap().to_string();
        set_ledger(&[ledger_entry_with_restore(
            "ledger-shell-fail",
            "shell",
            &root_str,
            "2026-08-20T01:00:00Z",
            Some(RestoreSnapshot { cwd: Some(root_str.clone()), idle: true, argv: None, typed: None }),
        )]);
        std::env::remove_var("AOIDE_TERMINAL");
        std::env::remove_var("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let failed = data["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 1, "data: {data}");
        assert_eq!(failed[0]["disposition"], "failed", "data: {data}");
        assert_eq!(data["resurrected"].as_array().unwrap().len(), 0);

        // A failed spawn never reaches the undying mark either — nothing
        // to mark, the session never came into being.
        let undying = aoide_storage::undying::load_undying();
        assert!(!aoide_storage::undying::is_undying(&undying, "ledger-shell-fail"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The enrichment path is not just "some ledger match" — it reuses
    /// `resolve_candidate`/`resurrect_one` verbatim, so a MATCHED entry with
    /// a `restore` snapshot resolves through the terminal arm exactly like
    /// `--id` would, and the resulting `resurrected` entry carries
    /// `disposition: "revived-from-ledger"` (never `"clean-spawned"`,
    /// proving enrichment — not a fresh launch — is what actually fired).
    #[test]
    fn bare_mode_enrichment_revives_a_matched_restore_bearing_entry_via_the_terminal_arm() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-enrich-terminal",
            vec![manifest_spec(&this_host, ".", "shell", None)],
        );
        let root_str = root.to_str().unwrap().to_string();
        set_ledger(&[ledger_entry_with_restore(
            "ledger-shell",
            "shell",
            &root_str,
            "2026-08-20T01:00:00Z",
            Some(RestoreSnapshot { cwd: Some(root_str.clone()), idle: true, argv: None, typed: None }),
        )]);
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");
        assert_eq!(resurrected[0]["disposition"], "revived-from-ledger");
        assert_eq!(resurrected[0]["resumedFrom"], "ledger-shell");

        // Design ruling (U2 review round 1): a manifest-enriched revival
        // marks its NEW session id undying, gated on Status::Ok alone
        // (this spawn reached it — "true" launches successfully even
        // though it never registers).
        let new_id = resurrected[0]["sessionId"].as_str().unwrap().to_string();
        let undying = aoide_storage::undying::load_undying();
        assert!(
            aoide_storage::undying::is_undying(&undying, &new_id),
            "a manifest-enriched revival must mark its new session undying"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The design ruling's clean-spawn half: an UNMATCHED spec (no ledger
    /// enrichment at all — the ordinary fresh-checkout case) still marks
    /// its freshly clean-spawned session undying, same as the enriched
    /// path above.
    #[test]
    fn bare_mode_clean_spawn_marks_the_new_session_undying() {
        let _guard = crate::env_lock().lock().unwrap();
        let _env = EnvVars::save(&[
            "AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "XDG_RUNTIME_DIR", "AOIDE_AUDIT_LOG",
            "AOIDE_TERMINAL", "WAYLAND_DISPLAY", "DISPLAY",
        ]);
        let this_host = aoide_storage::display::local_host_name();
        let (root, cwd) = setup_manifest(
            "resurrect-manifest-clean-spawn-undying",
            vec![manifest_spec(&this_host, ".", "claude", None)],
        );
        std::env::set_var("AOIDE_TERMINAL", "true");
        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");

        let out = session_resurrect(&flag_invocation(&["resurrect"], &[]));
        drop(cwd);
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "msg: {}", out.message);
        let data = out.data.as_ref().unwrap();
        let resurrected = data["resurrected"].as_array().unwrap();
        assert_eq!(resurrected.len(), 1, "data: {data}");
        assert_eq!(resurrected[0]["disposition"], "clean-spawned");
        let new_id = resurrected[0]["sessionId"].as_str().unwrap().to_string();

        let undying = aoide_storage::undying::load_undying();
        assert!(
            aoide_storage::undying::is_undying(&undying, &new_id),
            "a manifest clean-spawn must mark its new session undying"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
