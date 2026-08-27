//! `aoide session` (bare) — the undying PICKER (U3, command-defrag lane U).
//!
//! `session undying on|off [--self | --id <id>]` (U1) is the scripted
//! spelling — one flag flips one id. This command is its tty sibling: a
//! multi-select over every session this conductor can see (this box's own
//! roster, plus every registered peer's CACHED graph — no live pulls, see
//! below), each row pre-checked by its CURRENT undying state, confirmed in
//! one Enter. There is deliberately no second scripted spelling here (no
//! `--undying` flag on bare `session`) — one spelling per capability, the
//! same "deletes more" rule `AGENTS.md`'s "Building" section states.
//!
//! **CLI-only, tty-only.** [`session_pick`] gates on [`aoide_protocol::Door::Cli`]
//! FIRST (the same `require_cli` shape `secrets`' admin quartet holds —
//! `crates/secrets/src/commands.rs`), then on [`aoide_protocol::pick::interactive`]
//! (door + a real stdin/stdout tty) — `--json` also steers to the taught
//! non-interactive path, since a picker's prompts would otherwise corrupt a
//! machine-readable stream. Every non-interactive reach lands on the exact
//! same taught usage error naming the scripted form: nothing here re-derives
//! `session undying`'s own usage text.
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
//! computes its local node, never re-derived; peer rows come from
//! [`super::who::sessions_from_graph`] (widened `pub(super)` this phase) fed
//! each registered peer's `peer_store::load_peer_cache` entry — no
//! `who::probe_peers`/live pull anywhere in this module, per the brief's own
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
//! **Peer marks write a manifest spec, never `undying.json`** — the id lives
//! on the peer, so this conductor can't write ITS store. Per the locked
//! design (task brief, U3), marking a peer session undying instead appends a
//! `{host, dir, agent}` [`aoide_storage::manifest::SessionSpec`] into the
//! CURRENT project's `.aoide/project.json` (`aoide_storage::manifest::
//! walk_up` from cwd, the exact discovery `resurrect`'s own bare-manifest
//! mode already uses, U2). No manifest above cwd: the peer marks in the same
//! confirm are reported `skipped[]` with a taught reason — this command does
//! NOT create one (a manifest is a deliberate per-project decision, not a
//! side effect of a picker), the local marks in the same confirm still
//! apply. [`peer_spec_dir`] resolves the spec's `dir`: LEXICALLY relative to
//! the CURRENT project's own root when the peer session's cwd literally
//! starts with that same root string (the plausible real case — the same
//! project checked out at the same path on more than one host, e.g. every
//! `~/Aoide` box already named in the fleet); a cwd that does NOT lie under
//! the root has no savable spec at all — `aoide_storage::manifest::
//! save_manifest` refuses the WHOLE batch on any absolute `dir`, so a raw-cwd
//! fallback would not merely write an inferior spec, it would silently drop
//! every OTHER legitimate peer change in the same confirm (review round 1's
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
//! refusal above, or a plain I/O error) folds every pending peer change for
//! that confirm into `skipped[]` instead, never a false `changed` entry.

use super::model::{merged_sessions, resolved_parent, HookRecord, SessionRecord};
use super::who::{sessions_from_graph, SessionView};
use aoide_protocol::output::Outcome;
use aoide_protocol::{pick, Door, Invocation};
use aoide_storage::manifest::{self, Manifest, SessionSpec};
use aoide_storage::peer_store::{self, Peer};
use aoide_storage::undying::{self, UndyingSession};
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Where one picker row's mark lives — a local session id (the undying
/// store) or a peer-cached session (a manifest spec, since the id itself
/// lives on the peer). Pure data; no I/O anywhere on this type.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum RowTarget {
    Local { session_id: String },
    Peer { peer: String, cwd: String, agent: String },
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

/// Resolve a peer spec's `dir` — see the module doc's "Peer marks" section.
/// `None` when `peer_cwd` does not lie under `project_root` at all: there is
/// no savable spec for it (`save_manifest` refuses the WHOLE batch on any
/// absolute `dir`), so the caller MUST reject that row before it ever
/// touches `manifest.sessions` — never fall back to the raw cwd (review
/// round 1's finding: a raw-cwd fallback here would silently sink every
/// OTHER legitimate peer change queued in the same confirm). Purely lexical
/// (`Path::strip_prefix`, a string-prefix operation over `Path` components)
/// — no filesystem access, no realpath, matching `resolve_spec_dir`/
/// `walk_up`'s own "LEXICAL, not realpath" discipline
/// (`aoide_storage::manifest`).
fn peer_spec_dir(project_root: &Path, peer_cwd: &str) -> Option<String> {
    match Path::new(peer_cwd).strip_prefix(project_root) {
        Ok(rel) if rel.as_os_str().is_empty() => Some(".".to_string()),
        Ok(rel) => Some(rel.to_string_lossy().into_owned()),
        Err(_) => None,
    }
}

/// The taught reason a peer row's cwd cannot be resolved into a savable
/// manifest `dir` — shared by [`build_rows`]'s pre-check (silently, via
/// `None`) and [`apply_diff`]'s own reject-before-push (out loud, via
/// `skipped[]`), so the wording lives in exactly one place.
fn peer_cwd_unsavable_reason(peer: &str, cwd: &str, verb: &str) -> String {
    format!(
        "{peer}: cannot {verb} — peer cwd `{cwd}` is not under the local project root — \
         write the spec by hand with a project-relative dir, or wait for the remote mapping (U4)"
    )
}

/// Build every picker row — pure, given already-loaded inputs (module doc's
/// "Rows" section). `locals`/`hooks` are this box's own stage files;
/// `peers` is `(registered peer, that peer's cached sessions)` — the caller
/// derives the second element via [`sessions_from_graph`] over
/// `peer_store::load_peer_cache`, never a live probe; `undying` is
/// `aoide_storage::undying::load_undying`'s result; `project` is the
/// CURRENT project's root + manifest, if `walk_up` found one (`None` when it
/// didn't — every peer row's `undying` then reads `false`, since there is
/// nowhere for a peer mark to have been recorded). A peer row's pre-check
/// goes through the SAME [`peer_spec_dir`] relativization [`apply_diff`]
/// uses to WRITE — a raw absolute cwd never matches a manifest spec (specs
/// are always project-relative), so comparing the unrelativized cwd against
/// `spec.dir` would silently under-report an already-undying peer session as
/// unmarked; a cwd `peer_spec_dir` can't place under the root reads `false`
/// here too, the same as no manifest at all.
pub(super) fn build_rows(
    host: &str,
    locals: &[SessionRecord],
    hooks: &[HookRecord],
    undying: &[UndyingSession],
    peers: &[(Peer, Vec<SessionView>)],
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

    for (peer, sessions) in peers {
        for sv in sessions {
            if sv.state == "done" {
                continue;
            }
            let on = project.is_some_and(|(root, m)| {
                peer_spec_dir(root, &sv.cwd).is_some_and(|dir| manifest_has_spec(m, &peer.name, &dir, &sv.agent))
            });
            rows.push(PickerRow {
                label: format!("{}  {}  {}{}", sv.label, sv.agent, sv.state, if on { "  [undying]" } else { "" }),
                target: RowTarget::Peer { peer: peer.name.clone(), cwd: sv.cwd.clone(), agent: sv.agent.clone() },
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
/// through ONE load/save of the undying store, peer rows through ONE
/// load/save of `project_root`'s manifest (`None` when `walk_up` found
/// none: every peer row touched is folded into `skipped[]` instead, the
/// local rows in the SAME confirm still applying). Pure with respect to
/// nothing — this is the one impure function in the module, kept this
/// small and this separated so [`build_rows`]/[`diff_selection`]/
/// [`peer_spec_dir`]/[`manifest_has_spec`] stay unit-testable without a
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

    let peer_touched: Vec<(usize, bool)> =
        touched.into_iter().filter(|(i, _)| matches!(rows[*i].target, RowTarget::Peer { .. })).collect();
    if !peer_touched.is_empty() {
        match project_root {
            None => {
                for (i, on) in &peer_touched {
                    if let RowTarget::Peer { peer, .. } = &rows[*i].target {
                        let verb = if *on { "mark" } else { "unmark" };
                        skipped.push(format!(
                            "{peer}: cannot {verb} — no project manifest above cwd; run from a project root (or create .aoide/project.json first)"
                        ));
                    }
                }
            }
            Some((root, base_manifest)) => {
                let mut manifest = base_manifest.clone();
                // (peer, dir, on) for every row that actually MUTATED
                // `manifest.sessions` in-memory below — recorded as
                // `changed` only once `save_manifest` (below) confirms the
                // write actually landed; a no-op (already present / already
                // absent) or a rejected cwd never enters this list at all.
                let mut pending: Vec<(String, String, bool)> = Vec::new();

                for (i, on) in &peer_touched {
                    if let RowTarget::Peer { peer, cwd, agent } = &rows[*i].target {
                        let dir = match peer_spec_dir(root, cwd) {
                            Some(d) => d,
                            None => {
                                let verb = if *on { "mark" } else { "unmark" };
                                skipped.push(peer_cwd_unsavable_reason(peer, cwd, verb));
                                continue;
                            }
                        };
                        if *on {
                            if manifest_has_spec(&manifest, peer, &dir, agent) {
                                skipped.push(format!("{peer}/{dir}: already undying (no-op)"));
                            } else {
                                manifest.sessions.push(SessionSpec {
                                    host: peer.clone(),
                                    dir: dir.clone(),
                                    agent: agent.clone(),
                                    command: None,
                                });
                                pending.push((peer.clone(), dir, true));
                            }
                        } else {
                            let before = manifest.sessions.len();
                            // `retain` drops EVERY entry matching
                            // `{host, dir, agent}`, not just the first — a
                            // hand-duplicated spec is cleaned up in one
                            // unmark, never left with a surviving copy.
                            manifest.sessions.retain(|s| !(s.host == *peer && s.dir == dir && s.agent == *agent));
                            if manifest.sessions.len() < before {
                                pending.push((peer.clone(), dir, false));
                            } else {
                                skipped.push(format!("{peer}/{dir}: not undying already (no-op)"));
                            }
                        }
                    }
                }

                if !pending.is_empty() {
                    match manifest::save_manifest(root, &manifest) {
                        Ok(()) => {
                            for (peer, dir, on) in pending {
                                changed.push(format!("{peer}/{dir}: {} (manifest)", if on { "undying" } else { "not undying" }));
                            }
                        }
                        Err(e) => {
                            // The whole batch failed together (`save_manifest`
                            // validates before writing anything) — every
                            // pending change reports as skipped, never a
                            // false `changed` entry for a write that never
                            // landed.
                            for (peer, dir, on) in pending {
                                let verb = if on { "mark" } else { "unmark" };
                                skipped.push(format!("{peer}/{dir}: {verb} not saved — manifest write failed: {e}"));
                            }
                        }
                    }
                }
            }
        }
    }

    ApplyResult { changed, skipped }
}

/// `Door::Cli`, real-tty gate — the taught non-interactive path both share
/// (module doc's "CLI-only, tty-only"). `--json` steers here too, even on a
/// real tty: a picker's prompts have no business interleaving with a
/// machine-readable stream a caller explicitly asked for.
fn require_cli_tty(inv: &Invocation, cmd: &str) -> Option<Outcome> {
    let taught = "bare `session` opens an interactive picker on a real CLI terminal; \
                  script the mark directly instead: `session undying on|off --id <id>`";
    if inv.door != Door::Cli {
        return Some(Outcome::usage(cmd, format!("{taught} (this door is not the CLI)")));
    }
    if inv.flag_present("json") || !pick::interactive(inv.door) {
        return Some(Outcome::usage(cmd, taught));
    }
    None
}

/// `aoide session` (bare, no subcommand) — the entry point. See the module
/// doc for the full design; this function is the thin impure shell around
/// [`build_rows`]/[`diff_selection`]/[`apply_diff`], loading local stage
/// state, every registered peer's CACHED graph (no live probe), and the
/// current project's manifest (`walk_up` from cwd, `None` if none exists
/// above it — never created here).
pub fn session_pick(inv: &Invocation) -> Outcome {
    let cmd = "session";
    if let Some(hint) = require_cli_tty(inv, cmd) {
        return hint;
    }

    let (_, s, h) = match super::common::load_inputs(cmd) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let host = aoide_storage::display::local_host_name();
    let undying = undying::load_undying();

    let peers = peer_store::load_peers();
    let peer_sessions: Vec<(Peer, Vec<SessionView>)> = peers
        .into_iter()
        .map(|p| {
            let sessions = peer_store::load_peer_cache(&p.name)
                .and_then(|c| c.graph)
                .map(|g| sessions_from_graph(&g, &p.name))
                .unwrap_or_default();
            (p, sessions)
        })
        .collect();

    let cwd = std::env::current_dir().unwrap_or_default();
    let manifest_hit = manifest::walk_up(&cwd);
    let project_ref = manifest_hit.as_ref().map(|(root, m)| (root.as_path(), m));

    let rows = build_rows(&host, &s.sessions, &h.hooks, &undying, &peer_sessions, project_ref);
    if rows.is_empty() {
        return Outcome::ok(cmd, "no sessions to pick from — nothing local, no peer-cached sessions");
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

    fn peer(name: &str) -> Peer {
        Peer {
            name: name.to_string(),
            url: format!("http://{name}/"),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified: false,
            allows: Vec::new(),
            added_at: "2026-08-14T00:00:00Z".to_string(),
        }
    }

    fn peer_session(id: &str, state: &str, cwd: &str, agent: &str) -> SessionView {
        SessionView {
            session_id: id.to_string(),
            label: format!("peer/root/{id}"),
            petname: None,
            agent: agent.to_string(),
            state: state.to_string(),
            presence: "online",
            cwd: cwd.to_string(),
        }
    }

    // ── build_rows: local + peer, done omitted, undying pre-checked ──────

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
    fn build_rows_omits_done_sessions_local_and_peer() {
        let locals = vec![session("s1", "/x", "done", "1", None)];
        let peers = vec![(peer("yomi"), vec![peer_session("p1", "done", "/y", "claude")])];
        let rows = build_rows("sakaki", &locals, &[], &[], &peers, None);
        assert!(rows.is_empty());
    }

    #[test]
    fn build_rows_peer_row_reads_undying_off_a_matching_manifest_spec() {
        // The manifest spec's `dir` is project-relative ("pkgs/aoide"), the
        // peer row's cwd is the raw absolute path -- `build_rows` must
        // relativize the cwd through the SAME `peer_spec_dir` `apply_diff`
        // writes through before comparing, or an already-undying peer
        // session would never show pre-checked (the bug review round 1
        // caught: comparing the raw cwd straight against `spec.dir` can
        // never match, since specs are always project-relative).
        let root = PathBuf::from("/home/x/Aoide");
        let peers = vec![(peer("yomi"), vec![peer_session("p1", "working", "/home/x/Aoide/pkgs/aoide", "claude")])];
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", "pkgs/aoide", "claude")] };
        let rows = build_rows("sakaki", &[], &[], &[], &peers, Some((&root, &manifest)));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].undying, "the manifest spec's host/dir/agent match the peer row exactly");
    }

    #[test]
    fn build_rows_peer_row_is_not_undying_with_no_manifest_at_all() {
        let peers = vec![(peer("yomi"), vec![peer_session("p1", "working", "/home/x/Aoide", "claude")])];
        let rows = build_rows("sakaki", &[], &[], &[], &peers, None);
        assert!(!rows[0].undying);
    }

    #[test]
    fn build_rows_peer_row_is_not_undying_when_its_cwd_falls_outside_the_project_root() {
        // A manifest exists, and even carries a spec for this peer/agent --
        // but the row's cwd cannot be relativized under the local project
        // root at all, so there is no `dir` to compare against, and the row
        // must read `false` the same way a missing manifest does (never a
        // panic, never a raw-cwd comparison that happens to work by luck).
        let root = PathBuf::from("/home/x/Aoide");
        let peers = vec![(peer("yomi"), vec![peer_session("p1", "working", "/home/alice/elsewhere", "claude")])];
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", ".", "claude")] };
        let rows = build_rows("sakaki", &[], &[], &[], &peers, Some((&root, &manifest)));
        assert!(!rows[0].undying);
    }

    // ── build_rows: default-index alignment across local+peer rows ───────

    #[test]
    fn build_rows_default_indices_align_across_local_and_peer_concatenation() {
        // Locals come first, peers after (module doc's "Rows" section) --
        // `session_pick`'s own `default` (fed to `choose_many`) is built by
        // filtering `rows.iter().enumerate()` AFTER this concatenation, so a
        // caller must be able to trust that a peer row's position accounts
        // for every local row ahead of it. Two locals (one undying), one
        // peer undying, one peer not -- the undying set must land on
        // exactly the right indices in the FINAL four-row list.
        let root = PathBuf::from("/home/x/Aoide");
        let locals = vec![session("s1", "/x", "working", "1", None), session("s2", "/x", "working", "2", None)];
        let local_undying = vec![UndyingSession { session_id: "s1".to_string(), marked_at: "t".to_string() }];
        let peers = vec![(
            peer("yomi"),
            vec![
                peer_session("p1", "working", "/home/x/Aoide/pkgs/aoide", "claude"),
                peer_session("p2", "working", "/home/x/Aoide/pkgs/lyra", "codex"),
            ],
        )];
        let manifest = Manifest { version: 0, sessions: vec![spec("yomi", "pkgs/aoide", "claude")] };

        let rows = build_rows("sakaki", &locals, &[], &local_undying, &peers, Some((&root, &manifest)));
        assert_eq!(rows.len(), 4);
        let default: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| r.undying).map(|(i, _)| i).collect();

        // s1 (index 0) and p1 (index 2, the first peer row -- "pkgs/aoide"
        // matches the manifest spec) are undying; s2 (1) and p2 (3,
        // "pkgs/lyra", no matching spec) are not.
        assert_eq!(default, vec![0, 2]);
        assert!(matches!(&rows[0].target, RowTarget::Local { session_id } if session_id == "s1"));
        assert!(matches!(&rows[2].target, RowTarget::Peer { cwd, .. } if cwd.ends_with("pkgs/aoide")));
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

    // ── peer_spec_dir: lexical relativization, no unsavable fallback ─────

    #[test]
    fn peer_spec_dir_relativizes_under_the_project_root() {
        let root = PathBuf::from("/home/khoa/Aoide");
        let dir = peer_spec_dir(&root, "/home/khoa/Aoide/pkgs/aoide");
        assert_eq!(dir, Some("pkgs/aoide".to_string()));
    }

    #[test]
    fn peer_spec_dir_is_dot_when_the_cwd_is_the_root_itself() {
        let root = PathBuf::from("/home/khoa/Aoide");
        let dir = peer_spec_dir(&root, "/home/khoa/Aoide");
        assert_eq!(dir, Some(".".to_string()));
    }

    #[test]
    fn peer_spec_dir_is_none_outside_the_root_never_a_raw_cwd_fallback() {
        // Review round 1's finding: a raw-cwd fallback here would produce a
        // spec `save_manifest` refuses on sight (absolute `dir`), sinking
        // every OTHER legitimate peer change queued in the same confirm.
        // There is no savable fallback -- `None` is the whole answer.
        let root = PathBuf::from("/home/khoa/Aoide");
        let dir = peer_spec_dir(&root, "/home/alice/dev/Aoide/pkgs/aoide");
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

    // ── apply_diff: local (one load/save) + peer (manifest, dedupe, no-manifest skip) ──

    fn with_temp_state_dir<T>(name: &str, f: impl FnOnce() -> T) -> T {
        let _g = crate::env_lock().lock().unwrap();
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
    fn apply_diff_writes_a_new_peer_spec_into_the_project_manifest() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Peer { peer: "yomi".to_string(), cwd: root.join("pkgs/aoide").to_string_lossy().into_owned(), agent: "claude".to_string() },
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
    fn apply_diff_marking_an_already_present_peer_spec_is_a_no_op() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-noop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Peer { peer: "yomi".to_string(), cwd: root.to_string_lossy().into_owned(), agent: "claude".to_string() },
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
    fn apply_diff_unmark_removes_the_matching_peer_spec() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-unmark-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Peer { peer: "yomi".to_string(), cwd: root.to_string_lossy().into_owned(), agent: "claude".to_string() },
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
    fn apply_diff_unmarking_an_absent_peer_spec_is_a_no_op() {
        let root = std::env::temp_dir().join(format!("aoide-session-pick-manifest-unmark-noop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let rows = vec![PickerRow {
            label: "yomi/root/x".into(),
            target: RowTarget::Peer { peer: "yomi".to_string(), cwd: root.to_string_lossy().into_owned(), agent: "claude".to_string() },
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
    fn apply_diff_peer_mark_with_no_manifest_skips_with_a_taught_reason_but_local_marks_still_land() {
        with_temp_state_dir("no-manifest", || {
            let rows = vec![
                PickerRow { label: "local".into(), target: RowTarget::Local { session_id: "loc-1".into() }, undying: false },
                PickerRow {
                    label: "peer".into(),
                    target: RowTarget::Peer { peer: "yomi".to_string(), cwd: "/somewhere".to_string(), agent: "claude".to_string() },
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
    /// local toggle, one peer row whose cwd relativizes cleanly, and one
    /// peer row whose cwd falls outside the project root, all marked in the
    /// SAME confirm. The local mark and the valid peer spec must both land;
    /// the invalid peer row must be rejected BEFORE ever touching
    /// `manifest.sessions` (never a batch-wide `save_manifest` refusal that
    /// silently drops the valid spec too — the exact review-round-1 defect)
    /// — and `changed`/`skipped` must match disk state exactly, not merely
    /// look plausible.
    #[test]
    fn apply_diff_mixed_batch_local_plus_valid_peer_plus_unsavable_peer() {
        with_temp_state_dir("mixed-batch", || {
            let root = std::env::temp_dir().join(format!("aoide-session-pick-mixed-batch-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();

            let rows = vec![
                PickerRow { label: "local".into(), target: RowTarget::Local { session_id: "loc-1".into() }, undying: false },
                PickerRow {
                    label: "valid peer".into(),
                    target: RowTarget::Peer {
                        peer: "yomi".to_string(),
                        cwd: root.join("pkgs/aoide").to_string_lossy().into_owned(),
                        agent: "claude".to_string(),
                    },
                    undying: false,
                },
                PickerRow {
                    label: "unsavable peer".into(),
                    target: RowTarget::Peer {
                        peer: "yomi".to_string(),
                        cwd: "/home/alice/elsewhere".to_string(),
                        agent: "claude".to_string(),
                    },
                    undying: false,
                },
            ];
            let base = Manifest::default();
            let result = apply_diff(&rows, &[0, 1, 2], &[], Some(&(root.clone(), base)));

            // Disk state: the local mark landed, the valid peer spec
            // persisted, and NOTHING from the unsavable row ever reached
            // the manifest.
            assert!(undying::is_undying(&undying::load_undying(), "loc-1"));
            let loaded = manifest::load_manifest(&root).expect("manifest must exist -- the valid spec persisted");
            assert_eq!(loaded.sessions.len(), 1, "only the valid peer spec was ever written: {:?}", loaded.sessions);
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
        Invocation { path: vec!["session".into()], args: vec![], flags, door }
    }

    #[test]
    fn require_cli_tty_refuses_every_non_cli_door() {
        for door in [Door::Mcp, Door::Daemon, Door::A2a] {
            let hint = require_cli_tty(&inv(door, false), "session");
            assert!(hint.is_some());
        }
    }

    #[test]
    fn require_cli_tty_refuses_json_even_on_the_cli_door() {
        let hint = require_cli_tty(&inv(Door::Cli, true), "session");
        assert!(hint.is_some(), "cargo test's own stdio is never a tty either, but --json must refuse regardless");
    }

    #[test]
    fn require_cli_tty_refuses_a_non_tty_cli_invocation() {
        // cargo test's stdin/stdout are never a real tty, so Door::Cli alone
        // (no --json) still refuses here -- the genuinely-interactive case
        // can only be proven by hand, same caveat pick.rs's own tests carry.
        let hint = require_cli_tty(&inv(Door::Cli, false), "session");
        assert!(hint.is_some());
    }
}
