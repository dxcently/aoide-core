//! `session grant <kind> [on|off] [--id <id> | --self]` — the GRANT family
//! (session-surface redesign, command-defrag lane X, 2026-08-28). A
//! POSITIONAL `<kind>` grammar, matching `secrets automate <name> on|off`
//! (`crates/secrets/src/commands.rs`) rather than growing a second flag on
//! bare `session` — which no longer picks anything: it renders the roster
//! instead (`who.rs`'s module doc, "The roster core"). Two kinds exist today
//! — [`GRANTABLE_KINDS`]:
//!
//! - `session grant undying` (bare, no state) opens the interactive
//!   PICKER — [`undying_picker`], U3's exact body, only relocated. A
//!   multi-select over every session this conductor can see (this box's
//!   own roster, plus every registered node's CACHED graph — no live
//!   pulls, see below), each row pre-checked by its CURRENT undying state,
//!   confirmed in one Enter.
//! - `session grant undying on|off [--self | --id <id>]` is the SCRIPTED
//!   mark — [`super::undying::undying_grant`], U1's exact body, relocated
//!   from the standalone `session undying` command, which this absorbs and
//!   retires (hard cutover, no alias: `session undying` is now unknown,
//!   same as a typo).
//! - `session grant exempt on|off [--self | --id <id>]` (task #20) is the
//!   OTHER scripted mark — [`exempt_grant`] — vetoing the reaper's
//!   staleness judgments for a LIVE session (`reap.rs`'s `is_session_dead`
//!   third signal and its `abandoned_spawned_shells` arm), never its
//!   window-gone/pid-gone/ghost/orphan signals. This kind has NO picker:
//!   bare `session grant exempt` is a taught refusal naming the scripted
//!   form, since the motivating caller is a script (`--self`/`--id`), not
//!   an interactive session at a tty. Unlike `undying`, its mark lives on
//!   `SessionRecord::exempt` — a stage-tree field, not a durable state
//!   file — because an exemption's meaning ENDS at death (a resurrected
//!   session mints a fresh id) where undying's begins there; see
//!   `exempt_grant`'s own doc for the full contrast.
//! - `session grant` (no kind at all) teaches the grantable set; an
//!   unknown kind is a taught refusal. The dispatch in [`session_grant`] is
//!   a plain match arm — a future kind (#127, secret grants is the next one
//!   named, not yet built) adds one arm, and if it wants a picker too,
//!   reuses [`undying_picker`]'s own CLI+tty gate shape
//!   ([`require_cli_tty`]) rather than re-deriving it — there is still only
//!   one multi-select primitive in this crate.
//!
//! **CLI-only, tty-only — the picker branch only.** [`undying_picker`]
//! gates on [`aoide_protocol::Door::Cli`] FIRST (the same `require_cli`
//! shape `secrets`' admin quartet holds — `crates/secrets/src/
//! commands.rs`), then on [`aoide_protocol::pick::interactive`] (door + a
//! real stdin/stdout tty) — `--json` also steers to the taught
//! non-interactive path, since a picker's prompts would otherwise corrupt a
//! machine-readable stream. Every non-interactive reach lands on the exact
//! same taught usage error naming the scripted form. The SCRIPTED branch
//! (`undying_grant`) carries no such gate — unchanged from `session
//! undying`'s own reach from any door, since a script/daemon needs it too.
//!
//! **The seam: `aoide_protocol::pick::choose_many`, reached directly — no
//! new seam.** `pick.rs`'s own module doc already frames the picker as door
//! behavior living in `aoide-protocol` because every domain crate already
//! depends on it; `aoide-conduct` is one of those crates (`Invocation`/
//! `Outcome` already come from there), and `choose_many` already supports
//! everything this picker needs — pre-checked defaults (`default: &[usize]`,
//! widened for exactly this shape of caller, ONBOARD.md decision 7) and a
//! clean `None` on Esc/EOF. `song::commands::take`'s `prune_picker` is the
//! existing in-tree caller this mirrors; there was no missing primitive to
//! add.
//!
//! **Rows.** [`build_rows`] is pure: local rows come from `merged_sessions`
//! (already `pub`, `model.rs`) the same way `who.rs`'s own `build_local_node`
//! computes its local node, never re-derived; node rows come from
//! [`super::who::sessions_from_graph`] (widened `pub(super)` this phase) fed
//! each registered node's `node_store::load_node_cache` entry — no
//! `who::probe_nodes`/live pull anywhere in this module, per the brief's own
//! "no live pulls in the picker." A `done` session is omitted from either
//! side, mirroring `who`'s own default (un-`--all`) listing — there is no
//! `--all` here; this picker offers a mark/unmark surface, not a full roster
//! view, and `who`/`who --all` already own that job.
//!
//! **Local marks** toggle through `aoide_storage::undying`'s existing CRUD —
//! one `load_undying`, N `set_undying` mutations, one `save_undying`, the
//! same "one load, one save" discipline `session_undying` (U1) already holds
//! for its own single-id case, widened here to cover every local row the
//! confirm touched at once.
//!
//! **Node marks write a manifest spec, never `undying.json`** — the id lives
//! on the node, so this conductor can't write ITS store. Per the locked
//! design (task brief, U3), marking a node session undying instead appends a
//! `{host, dir, agent}` [`aoide_storage::manifest::SessionSpec`] into the
//! CURRENT project's `.aoide/project.json` (`aoide_storage::manifest::
//! walk_up` from cwd, the exact discovery `resurrect`'s own bare-manifest
//! mode already uses, U2). No manifest above cwd: the node marks in the same
//! confirm are reported `skipped[]` with a taught reason — this command does
//! NOT create one (a manifest is a deliberate per-project decision, not a
//! side effect of a picker), the local marks in the same confirm still
//! apply. [`node_spec_dir`] resolves the spec's `dir`: LEXICALLY relative to
//! the CURRENT project's own root when the node session's cwd literally
//! starts with that same root string (the plausible real case — the same
//! project checked out at the same path on more than one host, e.g. every
//! `~/Aoide` box already named in the fleet); a cwd that does NOT lie under
//! the root has no savable spec at all — `aoide_storage::manifest::
//! save_manifest` refuses the WHOLE batch on any absolute `dir`, so a raw-cwd
//! fallback would not merely write an inferior spec, it would silently drop
//! every OTHER legitimate node change in the same confirm (review round 1's
//! finding). That row is therefore REJECTED before it ever reaches
//! `manifest.sessions` — `skipped[]` with a taught reason, same as the
//! no-manifest-at-all case — never a guessed cross-host relativization.
//! `resolve_spec_dir` (U2) is the read-side containment guard for whatever
//! ends up here; this function only ever computes a `dir` to WRITE, purely
//! lexical, no filesystem access. An identical spec already present is a
//! no-op, reported as such ([`manifest_has_spec`]); unmarking removes EVERY
//! spec matching `{host, dir, agent}` (`Vec::retain`, not a first-match
//! removal — a hand-duplicated entry is cleaned up in one unmark, not one
//! per copy), otherwise a no-op the same way. The manifest write itself is
//! ALL-OR-NOTHING per confirm: `changed[]` only ever names what
//! `save_manifest` actually persisted — a failed save (the validation
//! refusal above, or a plain I/O error) folds every pending node change for
//! that confirm into `skipped[]` instead, never a false `changed` entry.

use super::common::stage_error;
use super::doc::restage_graph;
use super::model::{
    load_stage, merged_sessions, resolved_parent, sessions_path, write_stage, HookRecord,
    SessionRecord, SessionsFile,
};
use super::who::{sessions_from_graph, SessionView};
use aoide_protocol::output::Outcome;
use aoide_protocol::{pick, Door, Invocation};
use aoide_storage::fs::with_stage_lock;
use aoide_storage::manifest::{self, Manifest, SessionSpec};
use aoide_storage::node_store::{self, Node};
use aoide_storage::undying::{self, UndyingSession};
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Where one picker row's mark lives — a local session id (the undying
/// store) or a node-cached session (a manifest spec, since the id itself
/// lives on the node). Pure data; no I/O anywhere on this type.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum RowTarget {
    Local { session_id: String },
    Node { node: String, cwd: String, agent: String },
}

/// One picker row: a display label (host/role/petname + agent + state, the
/// same grammar `who.rs`'s own render uses) and its CURRENT undying state —
/// the exact set [`choose_many`]'s own `default` slice is built from.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PickerRow {
    pub(super) label: String,
    pub(super) target: RowTarget,
    pub(super) undying: bool,
}

/// Is `{host, dir, agent}` already present in `manifest`? The dedupe key for
/// both directions (mark = no-op if already there, unmark = remove the
/// match) — pure equality over the three fields `SessionSpec` carries that
/// matter for identity (never `command`, which the picker never sets).
fn manifest_has_spec(manifest: &Manifest, host: &str, dir: &str, agent: &str) -> bool {
    manifest.sessions.iter().any(|s| s.host == host && s.dir == dir && s.agent == agent)
}

/// Resolve a node spec's `dir` — see the module doc's "Node marks" section.
/// `None` when `node_cwd` does not lie under `project_root` at all: there is
/// no savable spec for it (`save_manifest` refuses the WHOLE batch on any
/// absolute `dir`), so the caller MUST reject that row before it ever
/// touches `manifest.sessions` — never fall back to the raw cwd (review
/// round 1's finding: a raw-cwd fallback here would silently sink every
/// OTHER legitimate node change queued in the same confirm). Purely lexical
/// (`Path::strip_prefix`, a string-prefix operation over `Path` components)
/// — no filesystem access, no realpath, matching `resolve_spec_dir`/
/// `walk_up`'s own "LEXICAL, not realpath" discipline
/// (`aoide_storage::manifest`).
fn node_spec_dir(project_root: &Path, node_cwd: &str) -> Option<String> {
    match Path::new(node_cwd).strip_prefix(project_root) {
        Ok(rel) if rel.as_os_str().is_empty() => Some(".".to_string()),
        Ok(rel) => Some(rel.to_string_lossy().into_owned()),
        Err(_) => None,
    }
}

/// The taught reason a node row's cwd cannot be resolved into a savable
/// manifest `dir` — shared by [`build_rows`]'s pre-check (silently, via
/// `None`) and [`apply_diff`]'s own reject-before-push (out loud, via
/// `skipped[]`), so the wording lives in exactly one place.
fn node_cwd_unsavable_reason(node: &str, cwd: &str, action: &str) -> String {
    format!(
        "{node}: cannot {action} — node cwd `{cwd}` is not under the local project root — \
         write the spec by hand with a project-relative dir, or wait for the remote mapping (U4)"
    )
}

/// Build every picker row — pure, given already-loaded inputs (module doc's
/// "Rows" section). `locals`/`hooks` are this box's own stage files;
/// `nodes` is `(registered node, that node's cached sessions)` — the caller
/// derives the second element via [`sessions_from_graph`] over
/// `node_store::load_node_cache`, never a live probe; `undying` is
/// `aoide_storage::undying::load_undying`'s result; `project` is the
/// CURRENT project's root + manifest, if `walk_up` found one (`None` when it
/// didn't — every node row's `undying` then reads `false`, since there is
/// nowhere for a node mark to have been recorded). A node row's pre-check
/// goes through the SAME [`node_spec_dir`] relativization [`apply_diff`]
/// uses to WRITE — a raw absolute cwd never matches a manifest spec (specs
/// are always project-relative), so comparing the unrelativized cwd against
/// `spec.dir` would silently under-report an already-undying node session as
/// unmarked; a cwd `node_spec_dir` can't place under the root reads `false`
/// here too, the same as no manifest at all.
pub(super) fn build_rows(
    host: &str,
    locals: &[SessionRecord],
    hooks: &[HookRecord],
    undying: &[UndyingSession],
    nodes: &[(Node, Vec<SessionView>)],
    project: Option<(&Path, &Manifest)>,
) -> Vec<PickerRow> {
    let merged = merged_sessions(locals, hooks);
    let ids: HashSet<&str> = merged.iter().map(|s| s.session_id.as_str()).collect();

    let mut rows: Vec<PickerRow> = merged
        .iter()
        .filter(|s| s.state != "done")
        .map(|s| {
            let role = if resolved_parent(s, &ids).is_some() { "child" } else { "root" };
            let label = aoide_storage::display::session_label(s, host, role);
            let on = undying::is_undying(undying, &s.session_id);
            PickerRow {
                label: format!("{label}  {}  {}{}", s.agent, s.state, if on { "  [undying]" } else { "" }),
                target: RowTarget::Local { session_id: s.session_id.clone() },
                undying: on,
            }
        })
        .collect();

    for (node, sessions) in nodes {
        for sv in sessions {
            if sv.state == "done" {
                continue;
            }
            let on = project.is_some_and(|(root, m)| {
                node_spec_dir(root, &sv.cwd).is_some_and(|dir| manifest_has_spec(m, &node.name, &dir, &sv.agent))
            });
            rows.push(PickerRow {
                label: format!("{}  {}  {}{}", sv.label, sv.agent, sv.state, if on { "  [undying]" } else { "" }),
                target: RowTarget::Node { node: node.name.clone(), cwd: sv.cwd.clone(), agent: sv.agent.clone() },
                undying: on,
            });
        }
    }
    rows
}

/// Diff the picker's final selection against each row's CURRENT undying
/// state — pure, index-based (matching what [`choose_many`] hands back).
/// Returns `(to_mark, to_unmark)`, both row indices; a row absent from both
/// is untouched — the confirm's "no changes" case is simply both empty.
pub(super) fn diff_selection(rows: &[PickerRow], selected: &[usize]) -> (Vec<usize>, Vec<usize>) {
    let selected: HashSet<usize> = selected.iter().copied().collect();
    let mut to_mark = Vec::new();
    let mut to_unmark = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let now_on = selected.contains(&i);
        if now_on && !row.undying {
            to_mark.push(i);
        } else if !now_on && row.undying {
            to_unmark.push(i);
        }
    }
    (to_mark, to_unmark)
}

/// What applying a diff actually did — `changed`/`skipped` in the same
/// human-line shape `Outcome::changed` already carries elsewhere in this
/// crate.
pub(super) struct ApplyResult {
    pub(super) changed: Vec<String>,
    pub(super) skipped: Vec<String>,
}

/// Apply `to_mark`/`to_unmark` (row indices into `rows`) — local rows
/// through ONE load/save of the undying store, node rows through ONE
/// load/save of `project_root`'s manifest (`None` when `walk_up` found
/// none: every node row touched is folded into `skipped[]` instead, the
/// local rows in the SAME confirm still applying). Pure with respect to
/// nothing — this is the one impure function in the module, kept this
/// small and this separated so [`build_rows`]/[`diff_selection`]/
/// [`node_spec_dir`]/[`manifest_has_spec`] stay unit-testable without a
/// temp dir.
pub(super) fn apply_diff(
    rows: &[PickerRow],
    to_mark: &[usize],
    to_unmark: &[usize],
    project_root: Option<&(PathBuf, Manifest)>,
) -> ApplyResult {
    let mut changed = Vec::new();
    let mut skipped = Vec::new();

    let touched: Vec<(usize, bool)> =
        to_mark.iter().map(|&i| (i, true)).chain(to_unmark.iter().map(|&i| (i, false))).collect();

    let local_touched: Vec<(usize, bool)> =
        touched.iter().copied().filter(|(i, _)| matches!(rows[*i].target, RowTarget::Local { .. })).collect();
    if !local_touched.is_empty() {
        let mut undying = undying::load_undying();
        for (i, on) in &local_touched {
            if let RowTarget::Local { session_id } = &rows[*i].target {
                if undying::set_undying(&mut undying, session_id, *on) {
                    changed.push(format!("{session_id}: {}", if *on { "undying" } else { "not undying" }));
                }
            }
        }
        if let Err(e) = undying::save_undying(&undying) {
            skipped.push(format!("local undying write failed: {e}"));
        }
    }

    let node_touched: Vec<(usize, bool)> =
        touched.into_iter().filter(|(i, _)| matches!(rows[*i].target, RowTarget::Node { .. })).collect();
    if !node_touched.is_empty() {
        match project_root {
            None => {
                for (i, on) in &node_touched {
                    if let RowTarget::Node { node, .. } = &rows[*i].target {
                        let action = if *on { "mark" } else { "unmark" };
                        skipped.push(format!(
                            "{node}: cannot {action} — no project manifest above cwd; run from a project root (or create .aoide/project.json first)"
                        ));
                    }
                }
            }
            Some((root, base_manifest)) => {
                let mut manifest = base_manifest.clone();
                // (node, dir, on) for every row that actually MUTATED
                // `manifest.sessions` in-memory below — recorded as
                // `changed` only once `save_manifest` (below) confirms the
                // write actually landed; a no-op (already present / already
                // absent) or a rejected cwd never enters this list at all.
                let mut pending: Vec<(String, String, bool)> = Vec::new();

                for (i, on) in &node_touched {
                    if let RowTarget::Node { node, cwd, agent } = &rows[*i].target {
                        let dir = match node_spec_dir(root, cwd) {
                            Some(d) => d,
                            None => {
                                let action = if *on { "mark" } else { "unmark" };
                                skipped.push(node_cwd_unsavable_reason(node, cwd, action));
                                continue;
                            }
                        };
                        if *on {
                            if manifest_has_spec(&manifest, node, &dir, agent) {
                                skipped.push(format!("{node}/{dir}: already undying (no-op)"));
                            } else {
                                manifest.sessions.push(SessionSpec {
                                    host: node.clone(),
                                    dir: dir.clone(),
                                    agent: agent.clone(),
                                    command: None,
                                });
                                pending.push((node.clone(), dir, true));
                            }
                        } else {
                            let before = manifest.sessions.len();
                            // `retain` drops EVERY entry matching
                            // `{host, dir, agent}`, not just the first — a
                            // hand-duplicated spec is cleaned up in one
                            // unmark, never left with a surviving copy.
                            manifest.sessions.retain(|s| !(s.host == *node && s.dir == dir && s.agent == *agent));
                            if manifest.sessions.len() < before {
                                pending.push((node.clone(), dir, false));
                            } else {
                                skipped.push(format!("{node}/{dir}: not undying already (no-op)"));
                            }
                        }
                    }
                }

                if !pending.is_empty() {
                    match manifest::save_manifest(root, &manifest) {
                        Ok(()) => {
                            for (node, dir, on) in pending {
                                changed.push(format!("{node}/{dir}: {} (manifest)", if on { "undying" } else { "not undying" }));
                            }
                        }
                        Err(e) => {
                            // The whole batch failed together (`save_manifest`
                            // validates before writing anything) — every
                            // pending change reports as skipped, never a
                            // false `changed` entry for a write that never
                            // landed.
                            for (node, dir, on) in pending {
                                let action = if on { "mark" } else { "unmark" };
                                skipped.push(format!("{node}/{dir}: {action} not saved — manifest write failed: {e}"));
                            }
                        }
                    }
                }
            }
        }
    }

    ApplyResult { changed, skipped }
}

/// `Door::Cli`, real-tty gate — the taught non-interactive path the picker
/// branch holds (module doc's "CLI-only, tty-only — the picker branch
/// only"). `--json` steers here too, even on a real tty: a picker's prompts
/// have no business interleaving with a machine-readable stream a caller
/// explicitly asked for.
fn require_cli_tty(inv: &Invocation, cmd: &str) -> Option<Outcome> {
    let taught = "bare `session grant undying` opens an interactive picker on a real CLI \
                  terminal; script the mark directly instead: \
                  `session grant undying on|off --id <id>`";
    if inv.door != Door::Cli {
        return Some(Outcome::usage(cmd, format!("{taught} (this door is not the CLI)")));
    }
    if inv.flag_present("json") || !pick::interactive(inv.door) {
        return Some(Outcome::usage(cmd, taught));
    }
    None
}

/// Grantable kinds. A future kind (#127, secret grants) is one more entry
/// here plus one more `match` arm in [`session_grant`].
const GRANTABLE_KINDS: &[&str] = &["undying", "exempt"];

/// `session grant <kind> [on|off] [--id <id> | --self]` — the registered
/// entry point (module doc has the full grammar). Bare (no `<kind>`) teaches
/// the grantable set; an unknown kind is a taught refusal; `undying` with no
/// state dispatches to [`undying_picker`], with a state to
/// [`super::undying::undying_grant`].
pub fn session_grant(inv: &Invocation) -> Outcome {
    let cmd = "session.grant";
    let usage = format!(
        "usage: aoide session grant <kind> [on|off] [--id <id> | --self] — grantable kinds: {}",
        GRANTABLE_KINDS.join(", ")
    );
    let Some(kind) = inv.args.first().map(String::as_str) else {
        return Outcome::usage(cmd, usage);
    };
    match kind {
        "undying" => match inv.args.get(1).map(String::as_str) {
            None => undying_picker(inv, cmd),
            Some(state) => super::undying::undying_grant(inv, cmd, state),
        },
        // No picker for this kind (module doc's "Fork 1" — the design record
        // this landed under, task #20): bare `session grant exempt` is a
        // taught refusal naming the scripted form, never a multi-select.
        "exempt" => match inv.args.get(1).map(String::as_str) {
            None => Outcome::usage(
                cmd,
                format!("`exempt` takes a state — `on` or `off` (no picker for this kind)\n{usage}"),
            ),
            Some(state) => exempt_grant(inv, cmd, state),
        },
        other => Outcome::usage(
            cmd,
            format!("`{other}` is not a grantable kind — grantable: {}\n{usage}", GRANTABLE_KINDS.join(", ")),
        ),
    }
}

/// `session grant exempt (on|off) [--self | --id <id>] [--json]` — the
/// SCRIPTED exempt mark (task #20's design record). Mirrors [`super::
/// undying::undying_grant`]'s on/off/`--self`/`--id` shape, but the
/// lifecycle runs the OPPOSITE direction: an exemption's meaning ENDS at
/// death (a resurrected session mints a fresh id), so it lives on
/// `SessionRecord::exempt` — a stage-tree field — rather than a durable
/// state file, and it MUST route through `aoide_client::daemon::
/// daemon_dispatch` first, the same L4 dual-writer discipline every other
/// stage-writing `session *` handler in this crate holds
/// (`session_store.rs`'s `session_start`/`session_phase`/`session_end`,
/// `reap.rs`'s `reap_and_announce`). `undying_grant` is this file's one
/// exception to that discipline, and stays one — `undying.json` sits
/// outside the stage tree entirely; this function is not that case.
///
/// Unlike `undying_grant`, `--id`/`--self` MUST resolve to a session
/// CURRENTLY on the roster: an exemption vetoes a LIVE reap judgment, so a
/// mark with no record to carry it means nothing — deliberately the
/// opposite of undying's own post-mortem posture (module doc's "Fork 2").
fn exempt_grant(inv: &Invocation, cmd: &str, state: &str) -> Outcome {
    if let Some(outcome) = aoide_client::daemon::daemon_dispatch(inv) {
        return outcome;
    }
    let usage = "usage: aoide session grant exempt (on|off) [--self | --id <id>] [--json]";

    let on = match state {
        "on" => true,
        "off" => false,
        other => {
            return Outcome::usage(
                cmd,
                format!("`{other}` is not an exempt state — the only two are `on` and `off`\n{usage}"),
            );
        }
    };

    let self_flag = inv.flag_present("self");
    let id_flag = inv
        .flags
        .get("id")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if self_flag && id_flag.is_some() {
        return Outcome::usage(cmd, format!("--self and --id are mutually exclusive\n{usage}"));
    }

    let id = match id_flag {
        Some(id) => id,
        None => match std::env::var("AOIDE_SESSION_ID").ok().filter(|s| !s.is_empty()) {
            Some(id) => id,
            None => {
                return Outcome::usage(
                    cmd,
                    format!(
                        "no session to mark exempt: pass --self (reads $AOIDE_SESSION_ID) or \
                         --id <id> — neither was given and $AOIDE_SESSION_ID is unset\n{usage}"
                    ),
                );
            }
        },
    };

    with_stage_lock(|| {
        let mut s_file: SessionsFile = match load_stage(&sessions_path()) {
            Ok(f) => f,
            Err(e) => return stage_error(cmd, e),
        };
        let Some(idx) = s_file.sessions.iter().position(|s| s.session_id == id) else {
            return Outcome::usage(
                cmd,
                format!("`{id}` is not on the roster — an exemption lives on a live session's record"),
            );
        };
        let message = if on {
            format!("`{id}` is now exempt from the reaper's staleness sweep")
        } else {
            format!("`{id}` is no longer exempt")
        };
        if s_file.sessions[idx].exempt == on {
            // Idempotent — the same "a re-mark is not a transition" contract
            // `undying_grant` holds: nothing to persist or restage.
            return Outcome::ok(cmd, message).with_data(json!({ "sessionId": id, "exempt": on }));
        }
        s_file.sessions[idx].exempt = on;
        if let Err(e) = write_stage(&sessions_path(), &s_file) {
            return stage_error(cmd, e);
        }
        let mut changed = vec![format!("{id}: {}", if on { "exempt" } else { "not exempt" })];
        match restage_graph() {
            Ok(g) => changed.push(g.to_string_lossy().into_owned()),
            Err(e) => return stage_error(cmd, e),
        }
        Outcome::ok(cmd, message)
            .changed(changed)
            .with_data(json!({ "sessionId": id, "exempt": on }))
    })
}

/// `session grant undying` (bare, no state) — the interactive picker, U3's
/// body relocated verbatim. See the module doc for the full design; this
/// function is the thin impure shell around
/// [`build_rows`]/[`diff_selection`]/[`apply_diff`], loading local stage
/// state, every registered node's CACHED graph (no live probe), and the
/// current project's manifest (`walk_up` from cwd, `None` if none exists
/// above it — never created here).
fn undying_picker(inv: &Invocation, cmd: &str) -> Outcome {
    if let Some(hint) = require_cli_tty(inv, cmd) {
        return hint;
    }

    let (_, s, h) = match super::common::load_inputs(cmd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let host = aoide_storage::display::local_host_name();
    let undying = undying::load_undying();

    let nodes = node_store::load_nodes();
    let node_sessions: Vec<(Node, Vec<SessionView>)> = nodes
        .into_iter()
        .map(|p| {
            let sessions = node_store::load_node_cache(&p.name)
                .and_then(|c| c.graph)
                .map(|g| sessions_from_graph(&g, &p.name))
                .unwrap_or_default();
            (p, sessions)
        })
        .collect();

    let cwd = std::env::current_dir().unwrap_or_default();
    let manifest_hit = manifest::walk_up(&cwd);
    let project_ref = manifest_hit.as_ref().map(|(root, m)| (root.as_path(), m));

    let rows = build_rows(&host, &s.sessions, &h.hooks, &undying, &node_sessions, project_ref);
    if rows.is_empty() {
        return Outcome::ok(cmd, "no sessions to pick from — nothing local, no node-cached sessions");
    }

    let labels: Vec<String> = rows.iter().map(|r| r.label.clone()).collect();
    let default: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| r.undying).map(|(i, _)| i).collect();

    match pick::choose_many("toggle undying — space to select, enter to confirm", &labels, &default) {
        None => Outcome::ok(cmd, "no changes"),
        Some(selected) => {
            let (to_mark, to_unmark) = diff_selection(&rows, &selected);
            if to_mark.is_empty() && to_unmark.is_empty() {
                return Outcome::ok(cmd, "no changes");
            }
            let result = apply_diff(&rows, &to_mark, &to_unmark, manifest_hit.as_ref());
            let mut out = Outcome::ok(
                cmd,
                format!("{} changed, {} skipped", result.changed.len(), result.skipped.len()),
            );
            if !result.changed.is_empty() {
                out = out.changed(result.changed.clone());
            }
            out.with_data(json!({ "changed": result.changed, "skipped": result.skipped }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::testutil::session;

    fn spec(host: &str, dir: &str, agent: &str) -> SessionSpec {
        SessionSpec { host: host.to_string(), dir: dir.to_string(), agent: agent.to_string(), command: None }
    }

    fn node(name: &str) -> Node {
        Node {
            name: name.to_string(),
            url: format!("http://{name}/"),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            via: None,
            added_at: "2026-08-14T00:00:00Z".to_string(),
        }
    }

    fn node_session(id: &str, state: &str, cwd: &str, agent: &str) -> SessionView {
        SessionView {
            session_id: id.to_string(),
            label: format!("node/root/{id}"),
            petname: None,
            agent: agent.to_string(),
            state: state.to_string(),
            presence: "online",
            cwd: cwd.to_string(),
            project: None,
            effective_project: None,
            exempt: false,
            title: None,
            model: None,
            kind: None,
            parent: None,
        }
    }

    // ── build_rows: local + node, done omitted, undying pre-checked ──────

    #[test]
    fn build_rows_marks_local_rows_currently_undying() {
        let locals = vec![session("s1", "/x", "working", "1", None), session("s2", "/x", "idle", "2", None)];
        let undying = vec![UndyingSession { session_id: "s1".to_string(), marked_at: "t".to_string() }];
        let rows = build_rows("sakaki", &locals, &[], &undying, &[], None);
        assert_eq!(rows.len(), 2);
        let s1 = rows.iter().find(|r| matches!(&r.target, RowTarget::Local { session_id } if session_id == "s1")).unwrap();
        assert!(s1.undying);
        assert!(s1.label.contains("[undying]"), "{}", s1.label);
        let s2 = rows.iter().find(|r| matches!(&r.target, RowTarget::Local { session_id } if session_id == "s2")).unwrap();
        assert!(!s2.undying);
        assert!(!s2.label.contains("[undying]"));
    }

    #[test]
    fn build_rows_omits_done_sessions_local_and_node() {
        let locals = vec![session("s1", "/x", "done", "1", None)];
        let nodes = vec![(node("yomi"), vec![node_session("p1", "done", "/y", "claude")])];
        let rows = build_rows("sakaki", &locals, &[], &[], &nodes, None);
        assert!(rows.is_empty());
    }

    #[test]
    fn build_rows_node_row_reads_undying_off_a_matching_manifest_spec() {
        // The manifest spec's `dir` is project-relative ("pkgs/aoide"), the
        // node row's cwd is the raw absolute path -- `build_rows` must
        // relativize the cwd through the SAME `node_spec_dir` `apply_diff`
        // writes through before comparing, or an already-undying node
        // session would never show pre-checked (the bug review round 1
        // caught: comparing the raw cwd straight against `spec.dir` can
        // never match, since specs are always project-relative).
        let root = PathBuf::from("/home/x/Aoide");
        let nodes = vec![(node("yomi"), vec![node_session("p1", "working", "/home/x/Aoide/pkgs/aoide", "claude")])];
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", "pkgs/aoide", "claude")] };
        let rows = build_rows("sakaki", &[], &[], &[], &nodes, Some((&root, &manifest)));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].undying, "the manifest spec's host/dir/agent match the node row exactly");
    }

    #[test]
    fn build_rows_node_row_is_not_undying_with_no_manifest_at_all() {
        let nodes = vec![(node("yomi"), vec![node_session("p1", "working", "/home/x/Aoide", "claude")])];
        let rows = build_rows("sakaki", &[], &[], &[], &nodes, None);
        assert!(!rows[0].undying);
    }

    #[test]
    fn build_rows_node_row_is_not_undying_when_its_cwd_falls_outside_the_project_root() {
        // A manifest exists, and even carries a spec for this node/agent --
        // but the row's cwd cannot be relativized under the local project
        // root at all, so there is no `dir` to compare against, and the row
        // must read `false` the same way a missing manifest does (never a
        // panic, never a raw-cwd comparison that happens to work by luck).
        let root = PathBuf::from("/home/x/Aoide");
        let nodes = vec![(node("yomi"), vec![node_session("p1", "working", "/home/alice/elsewhere", "claude")])];
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", ".", "claude")] };
        let rows = build_rows("sakaki", &[], &[], &[], &nodes, Some((&root, &manifest)));
        assert!(!rows[0].undying);
    }

    // ── build_rows: default-index alignment across local+node rows ───────

    #[test]
    fn build_rows_default_indices_align_across_local_and_node_concatenation() {
        // Locals come first, nodes after (module doc's "Rows" section) --
        // `session_pick`'s own `default` (fed to `choose_many`) is built by
        // filtering `rows.iter().enumerate()` AFTER this concatenation, so a
        // caller must be able to trust that a node row's position accounts
        // for every local row ahead of it. Two locals (one undying), one
        // node undying, one node not -- the undying set must land on
        // exactly the right indices in the FINAL four-row list.
        let root = PathBuf::from("/home/x/Aoide");
        let locals = vec![session("s1", "/x", "working", "1", None), session("s2", "/x", "working", "2", None)];
        let local_undying = vec![UndyingSession { session_id: "s1".to_string(), marked_at: "t".to_string() }];
        let nodes = vec![(
            node("yomi"),
            vec![
                node_session("p1", "working", "/home/x/Aoide/pkgs/aoide", "claude"),
                node_session("p2", "working", "/home/x/Aoide/pkgs/lyra", "codex"),
            ],
        )];
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", "pkgs/aoide", "claude")] };

        let rows = build_rows("sakaki", &locals, &[], &local_undying, &nodes, Some((&root, &manifest)));
        assert_eq!(rows.len(), 4);
        let default: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| r.undying).map(|(i, _)| i).collect();

        // s1 (index 0) and p1 (index 2, the first node row -- "pkgs/aoide"
        // matches the manifest spec) are undying; s2 (1) and p2 (3,
        // "pkgs/lyra", no matching spec) are not.
        assert_eq!(default, vec![0, 2]);
        assert!(matches!(&rows[0].target, RowTarget::Local { session_id } if session_id == "s1"));
        assert!(matches!(&rows[2].target, RowTarget::Node { cwd, .. } if cwd.ends_with("pkgs/aoide")));
        assert!(!rows[3].undying);
    }

    // ── diff_selection: pure index diff against current state ────────────

    #[test]
    fn diff_selection_finds_new_marks_and_new_unmarks() {
        let rows = vec![
            PickerRow { label: "a".into(), target: RowTarget::Local { session_id: "a".into() }, undying: false },
            PickerRow { label: "b".into(), target: RowTarget::Local { session_id: "b".into() }, undying: true },
            PickerRow { label: "c".into(), target: RowTarget::Local { session_id: "c".into() }, undying: false },
            PickerRow { label: "d".into(), target: RowTarget::Local { session_id: "d".into() }, undying: false },
        ];
        // Selection: a and c checked, b and d unchecked -- a and c are new
        // marks (were off, now checked), b is a new unmark (was on, now
        // unchecked), d stays untouched (was off, stays unchecked).
        let (mark, unmark) = diff_selection(&rows, &[0, 2]);
        assert_eq!(mark, vec![0, 2]);
        assert_eq!(unmark, vec![1]);
    }

    #[test]
    fn diff_selection_is_empty_when_selection_matches_current_state_exactly() {
        let rows = vec![
            PickerRow { label: "a".into(), target: RowTarget::Local { session_id: "a".into() }, undying: false },
            PickerRow { label: "b".into(), target: RowTarget::Local { session_id: "b".into() }, undying: true },
        ];
        let (mark, unmark) = diff_selection(&rows, &[1]);
        assert!(mark.is_empty());
        assert!(unmark.is_empty());
    }

    // ── node_spec_dir: lexical relativization, no unsavable fallback ─────

    #[test]
    fn node_spec_dir_relativizes_under_the_project_root() {
        let root = PathBuf::from("/home/khoa/Aoide");
        let dir = node_spec_dir(&root, "/home/khoa/Aoide/pkgs/aoide");
        assert_eq!(dir, Some("pkgs/aoide".to_string()));
    }

    #[test]
    fn node_spec_dir_is_dot_when_the_cwd_is_the_root_itself() {
        let root = PathBuf::from("/home/khoa/Aoide");
        let dir = node_spec_dir(&root, "/home/khoa/Aoide");
        assert_eq!(dir, Some(".".to_string()));
    }

    #[test]
    fn node_spec_dir_is_none_outside_the_root_never_a_raw_cwd_fallback() {
        // Review round 1's finding: a raw-cwd fallback here would produce a
        // spec `save_manifest` refuses on sight (absolute `dir`), sinking
        // every OTHER legitimate node change queued in the same confirm.
        // There is no savable fallback -- `None` is the whole answer.
        let root = PathBuf::from("/home/khoa/Aoide");
        let dir = node_spec_dir(&root, "/home/alice/dev/Aoide/pkgs/aoide");
        assert_eq!(dir, None);
    }

    // ── manifest_has_spec: the dedupe key ─────────────────────────────────

    #[test]
    fn manifest_has_spec_matches_on_host_dir_agent_only() {
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", "pkgs/aoide", "claude")] };
        assert!(manifest_has_spec(&manifest, "yomi", "pkgs/aoide", "claude"));
        assert!(!manifest_has_spec(&manifest, "yomi", "pkgs/aoide", "codex"), "agent differs");
        assert!(!manifest_has_spec(&manifest, "wraith", "pkgs/aoide", "claude"), "host differs");
    }

    // ── apply_diff: local (one load/save) + node (manifest, dedupe, no-manifest skip) ──

    fn with_temp_state_dir<T>(name: &str, f: impl FnOnce() -> T) -> T {
        let _g = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        let dir = std::env::temp_dir().join(format!("aoide-session-pick-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);

        let out = f();

        let _ = std::fs::remove_dir_all(&dir);
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        out
    }

    #[test]
    fn apply_diff_marks_and_unmarks_local_rows_through_one_load_one_save() {
        with_temp_state_dir("local", || {
            // `b` starts genuinely undying on disk -- a row's own `undying`
            // field is only a snapshot of what the store said when the rows
            // were built; `apply_diff` re-derives the real transition off
            // the store itself (`set_undying`'s own return), never off the
            // row's stale flag.
            undying::save_undying(&[UndyingSession { session_id: "b".to_string(), marked_at: "t".to_string() }]).unwrap();

            let rows = vec![
                PickerRow { label: "a".into(), target: RowTarget::Local { session_id: "a".into() }, undying: false },
                PickerRow { label: "b".into(), target: RowTarget::Local { session_id: "b".into() }, undying: true },
            ];
            let result = apply_diff(&rows, &[0], &[1], None);
            assert_eq!(result.changed.len(), 2, "{:?}", result.changed);
            assert!(undying::is_undying(&undying::load_undying(), "a"));
            assert!(!undying::is_undying(&undying::load_undying(), "b"));
        });
    }

    #[test]
    fn apply_diff_writes_a_new_node_spec_into_the_project_manifest() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Node { node: "yomi".to_string(), cwd: root.join("pkgs/aoide").to_string_lossy().into_owned(), agent: "claude".to_string() },
            undying: false,
        }];
        let base = Manifest::default();
        let result = apply_diff(&rows, &[0], &[], Some(&(root.clone(), base)));
        assert_eq!(result.changed.len(), 1, "{:?} / {:?}", result.changed, result.skipped);

        let loaded = manifest::load_manifest(&root).expect("manifest must now exist");
        assert!(manifest_has_spec(&loaded, "yomi", "pkgs/aoide", "claude"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_diff_marking_an_already_present_node_spec_is_a_no_op() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-noop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Node { node: "yomi".to_string(), cwd: root.to_string_lossy().into_owned(), agent: "claude".to_string() },
            undying: true,
        }];
        let base = Manifest { version: 0, sessions: vec![spec("yomi", ".", "claude")] };
        let result = apply_diff(&rows, &[0], &[], Some(&(root.clone(), base)));
        assert!(result.changed.is_empty(), "already-undying mark must not report a change: {:?}", result.changed);
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].contains("no-op"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_diff_unmark_removes_the_matching_node_spec() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-unmark-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Node { node: "yomi".to_string(), cwd: root.to_string_lossy().into_owned(), agent: "claude".to_string() },
            undying: true,
        }];
        let base = Manifest { version: 0, sessions: vec![spec("yomi", ".", "claude"), spec("wraith", "elsewhere", "codex")] };
        let result = apply_diff(&rows, &[], &[0], Some(&(root.clone(), base)));
        assert_eq!(result.changed.len(), 1, "{:?}", result.changed);

        let loaded = manifest::load_manifest(&root).expect("manifest still exists");
        assert!(!manifest_has_spec(&loaded, "yomi", ".", "claude"), "the matching spec must be gone");
        assert!(manifest_has_spec(&loaded, "wraith", "elsewhere", "codex"), "an unrelated spec survives");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_diff_unmarking_an_absent_node_spec_is_a_no_op() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-unmark-noop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Node { node: "yomi".to_string(), cwd: root.to_string_lossy().into_owned(), agent: "claude".to_string() },
            undying: false,
        }];
        let base = Manifest::default();
        let result = apply_diff(&rows, &[], &[0], Some(&(root.clone(), base)));
        assert!(result.changed.is_empty());
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].contains("no-op"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn apply_diff_node_mark_with_no_manifest_skips_with_a_taught_reason_but_local_marks_still_land() {
        with_temp_state_dir("no-manifest", || {
            let rows = vec![
                PickerRow { label: "local".into(), target: RowTarget::Local { session_id: "loc-1".into() }, undying: false },
                PickerRow {
                    label: "node".into(),
                    target: RowTarget::Node { node: "yomi".to_string(), cwd: "/somewhere".to_string(), agent: "claude".to_string() },
                    undying: false,
                },
            ];
            let result = apply_diff(&rows, &[0, 1], &[], None);
            assert!(undying::is_undying(&undying::load_undying(), "loc-1"), "the local mark must still land");
            assert_eq!(result.changed, vec!["loc-1: undying".to_string()]);
            assert_eq!(result.skipped.len(), 1);
            assert!(result.skipped[0].contains("no project manifest"), "{}", result.skipped[0]);
        });
    }

    /// The end-to-end mixed-batch proof (review round 1's own ask): one
    /// local toggle, one node row whose cwd relativizes cleanly, and one
    /// node row whose cwd falls outside the project root, all marked in the
    /// SAME confirm. The local mark and the valid node spec must both land;
    /// the invalid node row must be rejected BEFORE ever touching
    /// `manifest.sessions` (never a batch-wide `save_manifest` refusal that
    /// silently drops the valid spec too — the exact review-round-1 defect)
    /// — and `changed`/`skipped` must match disk state exactly, not merely
    /// look plausible.
    #[test]
    fn apply_diff_mixed_batch_local_plus_valid_node_plus_unsavable_node() {
        with_temp_state_dir("mixed-batch", || {
            let root = std::env::temp_dir().join(format!("aoide-session-pick-mixed-batch-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();

            let rows = vec![
                PickerRow { label: "local".into(), target: RowTarget::Local { session_id: "loc-1".into() }, undying: false },
                PickerRow {
                    label: "valid node".into(),
                    target: RowTarget::Node {
                        node: "yomi".to_string(),
                        cwd: root.join("pkgs/aoide").to_string_lossy().into_owned(),
                        agent: "claude".to_string(),
                    },
                    undying: false,
                },
                PickerRow {
                    label: "unsavable node".into(),
                    target: RowTarget::Node {
                        node: "yomi".to_string(),
                        cwd: "/home/alice/elsewhere".to_string(),
                        agent: "claude".to_string(),
                    },
                    undying: false,
                },
            ];
            let base = Manifest::default();
            let result = apply_diff(&rows, &[0, 1, 2], &[], Some(&(root.clone(), base)));

            // Disk state: the local mark landed, the valid node spec
            // persisted, and NOTHING from the unsavable row ever reached
            // the manifest.
            assert!(undying::is_undying(&undying::load_undying(), "loc-1"));
            let loaded = manifest::load_manifest(&root).expect("manifest must exist -- the valid spec persisted");
            assert_eq!(loaded.sessions.len(), 1, "only the valid node spec was ever written: {:?}", loaded.sessions);
            assert!(manifest_has_spec(&loaded, "yomi", "pkgs/aoide", "claude"));

            // Report state matches disk exactly.
            assert_eq!(
                result.changed,
                vec!["loc-1: undying".to_string(), "yomi/pkgs/aoide: undying (manifest)".to_string()],
                "{:?}",
                result.changed
            );
            assert_eq!(result.skipped.len(), 1, "{:?}", result.skipped);
            assert!(
                result.skipped[0].contains("is not under the local project root"),
                "{}",
                result.skipped[0]
            );

            let _ = std::fs::remove_dir_all(&root);
        });
    }

    // ── require_cli_tty: door + tty + --json gates ────────────────────────

    fn inv(door: Door, json: bool) -> Invocation {
        let mut flags = std::collections::BTreeMap::new();
        if json {
            flags.insert("json".to_string(), "true".to_string());
        }
        Invocation { path: vec!["session".into(), "grant".into()], args: vec!["undying".into()], flags, door }
    }

    #[test]
    fn require_cli_tty_refuses_every_non_cli_door() {
        for door in [Door::Mcp, Door::Daemon, Door::A2a] {
            let hint = require_cli_tty(&inv(door, false), "session.grant");
            assert!(hint.is_some());
        }
    }

    #[test]
    fn require_cli_tty_refuses_json_even_on_the_cli_door() {
        let hint = require_cli_tty(&inv(Door::Cli, true), "session.grant");
        assert!(hint.is_some(), "cargo test's own stdio is never a tty either, but --json must refuse regardless");
    }

    #[test]
    fn require_cli_tty_refuses_a_non_tty_cli_invocation() {
        // cargo test's stdin/stdout are never a real tty, so Door::Cli alone
        // (no --json) still refuses here -- the genuinely-interactive case
        // can only be proven by hand, same caveat pick.rs's own tests carry.
        let hint = require_cli_tty(&inv(Door::Cli, false), "session.grant");
        assert!(hint.is_some());
    }

    // ── session_grant: kind dispatch (bare/unknown/undying-picker-vs-scripted) ──

    fn grant_inv(args: &[&str]) -> Invocation {
        Invocation {
            path: vec!["session".into(), "grant".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: std::collections::BTreeMap::new(),
            door: Door::Cli,
        }
    }

    #[test]
    fn bare_grant_with_no_kind_teaches_the_grantable_set() {
        let out = session_grant(&grant_inv(&[]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("undying"), "msg: {}", out.message);
        assert!(out.message.contains("exempt"), "msg: {}", out.message);
    }

    #[test]
    fn an_unknown_kind_is_a_taught_refusal() {
        let out = session_grant(&grant_inv(&["secrets"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("not a grantable kind"), "msg: {}", out.message);
        assert!(out.message.contains("undying"), "msg: {}", out.message);
    }

    #[test]
    fn undying_kind_with_no_state_dispatches_to_the_picker_and_hits_its_tty_gate() {
        // Not a real tty under `cargo test`, so this proves routing (the
        // picker's own gate fires) rather than the picker's interactive body.
        let out = session_grant(&grant_inv(&["undying"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("interactive picker"), "msg: {}", out.message);
    }

    #[test]
    fn undying_kind_with_a_bogus_state_is_a_usage_error_from_the_scripted_path() {
        // Proves routing reaches `undying_grant`, not the picker (which
        // would refuse on the tty gate instead, a different message).
        let out = session_grant(&grant_inv(&["undying", "sideways"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("not an undying state"), "msg: {}", out.message);
    }

    // ── exempt kind (task #20): session grant exempt on|off [--self | --id] ──

    /// Isolated stage+state dir per test — the exact shape `undying.rs`'s own
    /// `setup` uses; unlike `undying_grant`, `exempt_grant` reads/writes
    /// `sessions.json` directly, so it needs the stage half too.
    fn setup(tag: &str) -> std::path::PathBuf {
        let root = crate::graph::testutil::unique_stage(tag);
        let stage = root.join("stage");
        let state = root.join("state");
        std::fs::create_dir_all(&stage).unwrap();
        std::env::set_var("AOIDE_STAGE_DIR", &stage);
        std::env::set_var("AOIDE_STATE_DIR", &state);
        root
    }

    fn exempt_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        Invocation {
            path: vec!["session".into(), "grant".into()],
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            door: Door::Cli,
        }
    }

    #[test]
    fn bare_exempt_kind_is_a_taught_refusal_naming_the_scripted_form() {
        // No picker for this kind (module doc's "Fork 1") — unlike
        // `undying`, a missing state is a usage error, not a picker dispatch.
        let out = session_grant(&grant_inv(&["exempt"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("takes a state"), "msg: {}", out.message);
        assert!(out.message.contains("no picker for this kind"), "msg: {}", out.message);
    }

    #[test]
    fn exempt_grant_on_then_off_round_trips_through_the_record() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = crate::graph::testutil::EnvVars::save(&[
            "AOIDE_STAGE_DIR",
            "AOIDE_STATE_DIR",
            "AOIDE_SESSION_ID",
        ]);
        let root = setup("exempt-roundtrip");
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions: vec![session("sess-1", "/x", "idle", "1", None)] },
        )
        .unwrap();

        let on = exempt_grant(&exempt_invocation(&[], &[("id", "sess-1")]), "session.grant", "on");
        assert_eq!(on.status, aoide_protocol::output::Status::Ok, "msg: {}", on.message);
        assert_eq!(on.data.as_ref().unwrap()["exempt"], true);
        // `changed` also carries the restage-graph path (`restage_graph`'s
        // own convention, same as `session_store.rs`'s other stage writers)
        // — the transition line is the part this test pins.
        assert!(on.changed.contains(&"sess-1: exempt".to_string()), "{:?}", on.changed);
        let f: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(f.sessions.iter().find(|s| s.session_id == "sess-1").unwrap().exempt);

        let off = exempt_grant(&exempt_invocation(&[], &[("id", "sess-1")]), "session.grant", "off");
        assert_eq!(off.status, aoide_protocol::output::Status::Ok, "msg: {}", off.message);
        assert_eq!(off.data.as_ref().unwrap()["exempt"], false);
        assert!(off.changed.contains(&"sess-1: not exempt".to_string()), "{:?}", off.changed);
        let f: SessionsFile = load_stage(&sessions_path()).unwrap();
        assert!(!f.sessions.iter().find(|s| s.session_id == "sess-1").unwrap().exempt);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exempt_grant_a_remark_is_ok_but_reports_no_transition() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = crate::graph::testutil::EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("exempt-remark");
        write_stage(
            &sessions_path(),
            &SessionsFile { schema_version: "0".into(), sessions: vec![session("sess-1", "/x", "idle", "1", None)] },
        )
        .unwrap();

        let first = exempt_grant(&exempt_invocation(&[], &[("id", "sess-1")]), "session.grant", "on");
        assert!(!first.changed.is_empty());
        let second = exempt_grant(&exempt_invocation(&[], &[("id", "sess-1")]), "session.grant", "on");
        assert_eq!(second.status, aoide_protocol::output::Status::Ok);
        assert!(second.changed.is_empty(), "a re-mark is not a transition: {:?}", second.changed);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exempt_grant_rejects_an_unknown_state() {
        // `exempt_grant` tries `daemon_dispatch` first (unlike
        // `undying_grant`) — the crate-wide `env_lock` guard is what floors
        // `AOIDE_DAEMON_SOCKET` to a path that can never have a real
        // listener (`lib.rs`'s own P-D6 safety net), so this test needs it
        // even though it never touches the stage tree.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let out = exempt_grant(&exempt_invocation(&[], &[("id", "sess-1")]), "session.grant", "maybe");
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("not an exempt state"), "msg: {}", out.message);
        assert!(out.message.contains("on"), "msg: {}", out.message);
        assert!(out.message.contains("off"), "msg: {}", out.message);
    }

    #[test]
    fn exempt_grant_rejects_self_and_id_together() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner()); // see the daemon-socket-floor note above
        let out = exempt_grant(&exempt_invocation(&[], &[("self", "true"), ("id", "sess-1")]), "session.grant", "on");
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("mutually exclusive"), "msg: {}", out.message);
    }

    #[test]
    fn exempt_grant_rejects_no_id_and_no_env() {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = crate::graph::testutil::EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("exempt-no-target");
        std::env::remove_var("AOIDE_SESSION_ID");

        let out = exempt_grant(&exempt_invocation(&[], &[]), "session.grant", "on");
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("--self"), "msg: {}", out.message);
        assert!(out.message.contains("--id"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exempt_grant_rejects_an_id_absent_from_the_roster() {
        // The one deliberate divergence from `undying_grant`'s post-mortem
        // posture (module doc's "Fork 2") — an exemption lives on a LIVE
        // record, so a dead/unknown id is a refusal here, never a valid
        // post-mortem target.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _env = crate::graph::testutil::EnvVars::save(&["AOIDE_STAGE_DIR", "AOIDE_STATE_DIR", "AOIDE_SESSION_ID"]);
        let root = setup("exempt-off-roster");
        // sessions.json stays empty -- "long-dead-id" is never in it.

        let out = exempt_grant(&exempt_invocation(&[], &[("id", "long-dead-id")]), "session.grant", "on");
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("is not on the roster"), "msg: {}", out.message);
        assert!(out.message.contains("live session's record"), "msg: {}", out.message);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exempt_kind_with_a_bogus_state_is_a_usage_error_from_the_scripted_path_not_a_picker() {
        // Routing proof through `session_grant` itself (mirrors the undying
        // dispatch test above) -- `exempt` has no picker branch to fall to.
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner()); // reaches exempt_grant -> daemon_dispatch
        let out = session_grant(&grant_inv(&["exempt", "sideways"]));
        assert_eq!(out.status, aoide_protocol::output::Status::Usage);
        assert!(out.message.contains("not an exempt state"), "msg: {}", out.message);
    }
}
