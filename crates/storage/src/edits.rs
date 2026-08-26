//! The per-project edit journal (project-snapshot/per-session-revert plan,
//! §2): one append-only JSON-lines file naming every pre-image capture,
//! post-image fingerprint, and revert record an aoide session's edit tools
//! produced, across every registered project —
//! `~/Aoide/state/edits.jsonl` ([`edits_path`]).
//!
//! **R1 scope only.** This module is pure fs + serde, exactly the boundary
//! `takes.rs` already draws for its own store: no git (that is R2 — this
//! module never shells out, never hashes file content, never touches a
//! repo), no CLI (`Outcome`/`Invocation` belong to R4/R5), no domain
//! validation (a `project` string here is whatever the caller already
//! resolved via `graph project list` — validating that it names a real,
//! registered project is one layer up, same posture `takes.rs` leaves
//! song/draft-name checks to `compose::valid_song_name`).
//!
//! **One file for every project, not one per project** (plan §2.2): this
//! sidesteps the unvalidated-project-name-as-path-segment hazard a
//! per-project directory would reopen (`records.rs`'s `Project.name` has no
//! `valid_song_name` equivalent), and filtering by `project` on read is a
//! cold-path predicate, not a directory split.
//!
//! **Every fold below is pure and IO-free** — [`by_path`], [`session_plan`],
//! [`classify_file`], and [`movers_since`] all take a `&[EditLine]` slice a
//! caller already produced via [`read_all`], so the later commands (`graph
//! project edits`, `graph project back`, R4/R5) are unit-testable on a
//! literal `Vec<EditLine>` without ever touching a filesystem — the same
//! shape `takes::reparent`/`takes::ancestry` already establish for the
//! sibling store.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;

/// The journal's path: `~/Aoide/state/edits.jsonl`.
pub fn edits_path() -> PathBuf {
    crate::fs::state_dir().join("edits.jsonl")
}

/// One line of the journal: a `pre`-image capture, a `post`-image
/// fingerprint, or a `revert` record — one struct for all three kinds (the
/// `kind` field discriminates), rather than three, so [`append`]/[`read_all`]
/// stay single functions and a fold over the whole journal never juggles a
/// sum type. Every field beyond the four every line carries is `Option`
/// (or an empty `Vec`), additive and v0-safe — the same discipline
/// `records::SessionRecord`'s optional fields already establish for this
/// crate, applied here to a line shape instead of a long-lived record.
///
/// Present on every line: `at` (ISO-8601 UTC, `crate::time::now_iso_utc`),
/// `kind` (`"pre"` / `"post"` / `"revert"`), `project` (the registered
/// project name), `session` (the graph node id whose edit — or, on a
/// `revert` line, whose PAST edits — this line concerns; `sub:<id>` for a
/// subagent, matching the existing owner-derivation the hook door already
/// does, plan §1.3).
///
/// The rest vary by kind (worked examples in the plan's §2.2):
/// - `pre` / `post` carry `path` (project-root-relative) and `tool`
///   (`"Edit"`, `"Write"`, …). `sha` is the file's git blob hash at that
///   moment; on a `pre` line it is OMITTED — never written as a literal
///   JSON `null` (`TakeRecord.parent`'s own precedent: "no parent is
///   omitted, not null") — when the file did not exist yet. That omission
///   is exactly what answers "was this file MADE through aoide", the ask's
///   own third clause, and [`by_path`] reads it as such. A `pre` line alone
///   also carries `mode` (the octal file mode at capture, e.g. `"100644"`,
///   so a later restore never silently strips `+x`); a `post` line never
///   restamps it — nothing ever writes a `post` image back to disk (plan
///   §2.3), so a mode recorded against it would have no consumer.
/// - `revert` carries `by` (the session that PERFORMED the revert,
///   `AOIDE_SESSION_ID` when set) and `paths` (every path the revert
///   touched) instead of `path`/`tool`/`mode`/`sha`.
/// - `tuid` is the PostToolUse hook payload's `tool_use_id` — the
///   advisor's binding amendment D5. Without it, the plan's own R3 fallback
///   ("pair a `post` line with its `pre` by `tool_use_id` when one session
///   edits one file twice in flight, faster than either edit's `at`
///   ordering can disambiguate") has nothing to pair on: the originally
///   specced line shape carried no `tool_use_id` at all. Optional so a line
///   written before R3 wires it up (or a future writer that never has one)
///   still parses.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EditLine {
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuid: Option<String>,
}

/// Append one line to [`edits_path`], creating the file (and its parent
/// `state/` directory) on the first-ever write.
///
/// **No lock — deliberately, and not an oversight.**
/// [`crate::fs::with_stage_lock`] exists to serialize a load-modify-write
/// race over a shared file (`fs.rs:231`); a pure append is not that shape,
/// so wrapping this in it would only add contention with revert's own lock
/// (R5) for no correctness gain. Instead the handle is opened `O_APPEND`
/// (`OpenOptions::append(true)`), which POSIX guarantees seeks to
/// end-of-file and performs the `write(2)` atomically with respect to every
/// OTHER writer for any single write no larger than `PIPE_BUF` (4096 bytes
/// on Linux) — the same guarantee every `>>`-redirected shell append
/// leans on, and the one `aoide_protocol::audit::append_audit` already
/// leans on for this crate's sibling audit log.
///
/// That bound covers the lines this function is on the hot path for. A
/// `pre` or `post` line names ONE `path` and is on the order of 200-300
/// bytes even with every optional field populated — an order of magnitude
/// under `PIPE_BUF` — so the concurrent `append` calls that actually race,
/// separate hook processes across separate sessions, interleave correctly
/// at line granularity with no coordination whatsoever.
///
/// A `revert` line is the one shape that can exceed it: `paths` carries
/// every path the revert touched, so its size is `O(files_touched)` and
/// roughly a hundred paths already clears 4096 bytes. Past that bound
/// POSIX promises nothing, and the revert's own [`crate::fs::with_stage_lock`]
/// does not close the gap — that lock excludes other reverts and prunes,
/// never the lock-free hook appends this function is built for. So a large
/// enough `revert` line can in principle interleave with a concurrent
/// `pre`/`post` write and tear. It is accepted, not overlooked: the window
/// needs a revert of that size landing in the same instant as a hook write,
/// [`read_all`] already drops an unparseable line without taking its
/// neighbours with it, and the torn line is a journal record, never the
/// file content itself — the pre-images live in git, which this never
/// touches. Do not widen `paths` onto any hot path without revisiting this.
/// (NFS would break the small-write guarantee too; that risk is a
/// documented line in the plan, not something this function tries to
/// detect.)
pub fn append(line: &EditLine) -> io::Result<()> {
    let path = edits_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = serde_json::to_string(line)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialize edit line: {e}\"}}"));
    body.push('\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(body.as_bytes())
}

/// Read every line of the journal. A missing file reads as empty (the same
/// "absent means nothing yet" posture every other stage-adjacent store in
/// this crate takes), and a line that fails to parse as [`EditLine`] is
/// silently skipped rather than wedging every reader of the journal on one
/// bad line — the tolerate-corruption discipline `takes::list_takes`
/// already sets for its own store. A single small `O_APPEND` write cannot
/// itself land torn (see [`append`]'s doc), but a hand-edited or
/// truncated file is a realistic source of one bad line among many good
/// ones, and this keeps that line from poisoning its neighbours.
pub fn read_all() -> Vec<EditLine> {
    let Ok(raw) = std::fs::read_to_string(edits_path()) else {
        return Vec::new();
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<EditLine>(l).ok())
        .collect()
}

/// One row of [`by_path`]'s answer (plan §3, the provenance query): one
/// project-relative path, whether it was CREATED through aoide, which
/// sessions touched it, and its first/last activity timestamps. Field
/// names/casing match the `--json` shape §3 documents (the later CLI
/// layer's job is to hand this struct straight to `serde_json`, unchanged).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PathSummary {
    pub path: String,
    pub made: bool,
    pub sessions: Vec<String>,
    #[serde(rename = "firstAt")]
    pub first_at: String,
    #[serde(rename = "lastAt")]
    pub last_at: String,
    pub edits: usize,
}

/// Fold the journal into one summary row per project-relative path touched
/// inside `project`, sorted by path. Only `pre`/`post` lines carry a `path`
/// and count here; a `revert` line's own `paths` list feeds
/// [`session_plan`]'s `already_reverted` classification instead, not this
/// fold.
///
/// `made` reflects the EARLIEST `pre` line for that path (by `at`, not by
/// journal order — a caller's `Vec` is not required to be chronological):
/// its `sha` being omitted/`None` is exactly what "made through aoide"
/// means (see [`EditLine`]'s own doc), so a file's later edits (whose `pre`
/// lines necessarily carry a real `sha`, since the file exists by then)
/// never flip `made` back to `false`.
///
/// `edits` counts `pre` lines for the path (one per edit-tool invocation
/// this journal saw), not every line — counting `pre` AND `post` together
/// would double the number for a normal paired capture and misrepresent how
/// many times the file was actually touched.
pub fn by_path(lines: &[EditLine], project: &str) -> Vec<PathSummary> {
    struct Acc {
        made: bool,
        earliest_pre_at: Option<String>,
        sessions: Vec<String>,
        first_at: String,
        last_at: String,
        edits: usize,
    }

    let mut acc: Vec<(String, Acc)> = Vec::new();
    for line in lines {
        if line.project != project {
            continue;
        }
        let Some(path) = &line.path else { continue };
        if line.kind != "pre" && line.kind != "post" {
            continue;
        }
        let entry = match acc.iter_mut().find(|(p, _)| p == path) {
            Some((_, a)) => a,
            None => {
                acc.push((
                    path.clone(),
                    Acc {
                        made: false,
                        earliest_pre_at: None,
                        sessions: Vec::new(),
                        first_at: line.at.clone(),
                        last_at: line.at.clone(),
                        edits: 0,
                    },
                ));
                &mut acc.last_mut().unwrap().1
            }
        };

        if line.kind == "pre" {
            let is_earlier = entry
                .earliest_pre_at
                .as_deref()
                .map_or(true, |cur| line.at.as_str() < cur);
            if is_earlier {
                entry.earliest_pre_at = Some(line.at.clone());
                entry.made = line.sha.is_none();
            }
            entry.edits += 1;
        }
        if !entry.sessions.contains(&line.session) {
            entry.sessions.push(line.session.clone());
        }
        if line.at < entry.first_at {
            entry.first_at = line.at.clone();
        }
        if line.at > entry.last_at {
            entry.last_at = line.at.clone();
        }
    }

    let mut out: Vec<PathSummary> = acc
        .into_iter()
        .map(|(path, a)| PathSummary {
            path,
            made: a.made,
            sessions: a.sessions,
            first_at: a.first_at,
            last_at: a.last_at,
            edits: a.edits,
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// One file in a session's revert plan (plan §4.1 step 2): the EARLIEST
/// pre-image this session recorded for `path` (sha + mode), the LATEST
/// post-image fingerprint, and whether a `revert` line for this session
/// already names `path` as covered.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PlannedFile {
    pub path: String,
    #[serde(rename = "preSha", default, skip_serializing_if = "Option::is_none")]
    pub pre_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "postSha", default, skip_serializing_if = "Option::is_none")]
    pub post_sha: Option<String>,
    #[serde(rename = "alreadyReverted", default)]
    pub already_reverted: bool,
}

/// Fold the journal into `session`'s file plan inside `project`: one
/// [`PlannedFile`] per path it touched, sorted by path.
///
/// Mirrors [`by_path`]'s earliest/latest tracking, but keyed the other way
/// (`pre_sha`/`mode` from the EARLIEST `pre` line, `post_sha` from the
/// LATEST `post` line) — a revert restores what the session ORIGINALLY
/// found and checks against what it MOST RECENTLY left, which are the two
/// ends of its edit history for that file, not its middle.
///
/// `already_reverted` is set from any `revert` line in `lines` whose
/// `session` names this same session and whose `paths` names this path —
/// it does not matter whether that line was written by a prior COMPLETE
/// revert of this session, or by an earlier PARTIAL run this call is
/// re-planning after a crash (D1): either way, the path is done and a
/// planner must not ask a caller to restore it again.
pub fn session_plan(lines: &[EditLine], project: &str, session: &str) -> Vec<PlannedFile> {
    struct Acc {
        earliest_pre_at: Option<String>,
        pre_sha: Option<String>,
        mode: Option<String>,
        latest_post_at: Option<String>,
        post_sha: Option<String>,
    }

    let mut acc: Vec<(String, Acc)> = Vec::new();
    let mut reverted_paths: Vec<String> = Vec::new();

    for line in lines {
        if line.project != project || line.session != session {
            continue;
        }
        match line.kind.as_str() {
            "pre" | "post" => {
                let Some(path) = &line.path else { continue };
                let entry = match acc.iter_mut().find(|(p, _)| p == path) {
                    Some((_, a)) => a,
                    None => {
                        acc.push((
                            path.clone(),
                            Acc {
                                earliest_pre_at: None,
                                pre_sha: None,
                                mode: None,
                                latest_post_at: None,
                                post_sha: None,
                            },
                        ));
                        &mut acc.last_mut().unwrap().1
                    }
                };
                if line.kind == "pre" {
                    let is_earlier = entry
                        .earliest_pre_at
                        .as_deref()
                        .map_or(true, |cur| line.at.as_str() < cur);
                    if is_earlier {
                        entry.earliest_pre_at = Some(line.at.clone());
                        entry.pre_sha = line.sha.clone();
                        entry.mode = line.mode.clone();
                    }
                } else {
                    let is_later = entry
                        .latest_post_at
                        .as_deref()
                        .map_or(true, |cur| line.at.as_str() > cur);
                    if is_later {
                        entry.latest_post_at = Some(line.at.clone());
                        entry.post_sha = line.sha.clone();
                    }
                }
            }
            "revert" => {
                for p in &line.paths {
                    if !reverted_paths.contains(p) {
                        reverted_paths.push(p.clone());
                    }
                }
            }
            _ => {}
        }
    }

    let mut out: Vec<PlannedFile> = acc
        .into_iter()
        .map(|(path, a)| {
            let already_reverted = reverted_paths.contains(&path);
            PlannedFile {
                path,
                pre_sha: a.pre_sha,
                mode: a.mode,
                post_sha: a.post_sha,
                already_reverted,
            }
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The three-state classification a revert planner (R5) applies to each
/// [`PlannedFile`] against the file's CURRENT live content hash — binding
/// amendment D1 from the advisor's verdict, replacing the two-state
/// clean/moved-on test the plan originally specced.
///
/// The failure a two-state test cannot survive: a revert restores a
/// session's files one at a time and appends its own `revert` journal line
/// only at the very end (plan §4.1 steps 4-5). Crash after file 1 of 3
/// lands, then re-run: file 1's live hash now equals its OWN pre-image
/// (the revert already wrote it), not the session's recorded post-sha — a
/// two-state test calls that `moved-on` and the rail built to protect the
/// User refuses the whole revert, permanently, with no journal line ever
/// written to mark it done. Three states make the revert idempotent
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// The live hash equals the recorded post-sha: this session's edit is
    /// still standing, untouched since — restore it.
    Clean,
    /// The live hash equals the pre-image being restored (a prior, possibly
    /// crashed, run of THIS SAME revert already wrote it), OR the file is
    /// correctly ABSENT and `pre_sha` is `None` (a creation whose revert
    /// action is deletion, and the deletion already happened, or never
    /// needed to because the edit that would have created it never
    /// landed). Both cases fall out of the SAME equality check
    /// (`live_sha == planned.pre_sha`) because `hash_object` already
    /// represents "file absent" as `None` (R2) and a creation's `pre_sha`
    /// is `None` by construction (plan §2.2) — no special-casing needed.
    /// Counts as success, not a skip that needs explaining: a `PreToolUse`
    /// capture whose edit was denied or failed (a `pre` line, no matching
    /// `post`, file genuinely unchanged) also lands here, because a
    /// missing `post_sha` can never satisfy the `Clean` check above it.
    AlreadyRestored,
    /// Neither matches: something outside this revert changed the file
    /// since the session last left it (another session's edit, a hand
    /// edit, a Bash write) — the honest refusal case the whole
    /// all-or-nothing rail exists for.
    MovedOn,
}

/// Classify one [`PlannedFile`] against `live_sha` (the file's CURRENT git
/// blob hash, `None` when the file is absent — R2's `hash_object` shape).
/// Pure: the caller (R5) is the one that shells out to produce `live_sha`;
/// this function never touches a filesystem, so it stays testable exactly
/// like every other fold in this module.
///
/// `already_reverted` short-circuits to [`FileState::AlreadyRestored`]
/// before any hash comparison: once a `revert` line already names this
/// path for this session, the path is done regardless of what the live
/// file currently hashes to — re-checking its bytes against a stale
/// pre/post pair would be re-litigating a question the journal already
/// answered.
///
/// Order matters for the remaining two checks: a file whose `pre_sha`
/// happens to equal its `post_sha` (an edit that round-tripped to
/// identical bytes) reads as [`FileState::Clean`] because that check runs
/// first — restoring it is a no-op write, not wrong, just redundant, and
/// checking `Clean` first keeps this a single pass with no tie-break
/// needed.
pub fn classify_file(planned: &PlannedFile, live_sha: Option<&str>) -> FileState {
    if planned.already_reverted {
        return FileState::AlreadyRestored;
    }
    if planned.post_sha.is_some() && live_sha == planned.post_sha.as_deref() {
        return FileState::Clean;
    }
    if live_sha == planned.pre_sha.as_deref() {
        return FileState::AlreadyRestored;
    }
    FileState::MovedOn
}

/// The sessions whose `post` lines for `path` inside `project` are newer
/// than `after_at` — the LIFO hint (plan §2.4 rail 2): reverting the
/// sessions that moved on AFTER the one being reverted, newest first,
/// resolves the conflict, because each of THEIR reverts hands the file back
/// one step, eventually landing on exactly what the original session left.
///
/// A session that touched `path` more than once after `after_at` is named
/// ONCE — deduped to its own latest `post` — so the caller's message names
/// each mover a single time. Newest-first order: the caller's LIFO
/// instruction is "revert this one first", and that is always the head of
/// this list.
pub fn movers_since(
    lines: &[EditLine],
    project: &str,
    path: &str,
    after_at: &str,
) -> Vec<String> {
    let mut hits: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.project != project || line.kind != "post" {
            continue;
        }
        let Some(p) = &line.path else { continue };
        if p != path {
            continue;
        }
        if line.at.as_str() <= after_at {
            continue;
        }
        match hits.iter_mut().find(|(s, _)| s == &line.session) {
            Some(existing) => {
                if line.at > existing.1 {
                    existing.1 = line.at.clone();
                }
            }
            None => hits.push((line.session.clone(), line.at.clone())),
        }
    }
    hits.sort_by(|a, b| b.1.cmp(&a.1));
    hits.into_iter().map(|(s, _)| s).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────
//
// Every env-touching test takes the crate-wide `env_lock` AND an
// `EnvSaver`, exactly `takes.rs`'s own convention — `AOIDE_STATE_DIR` is
// process-global, same hazard as that module's `AOIDE_STAGE_DIR`.

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_test_support::{env_lock, unique_tmp, EnvSaver};

    /// Point `AOIDE_STATE_DIR` at a fresh scratch dir so `edits_path()`
    /// resolves under it — mirrors `takes.rs::tests::routed`'s shape, one
    /// env var lower in the stack ([`edits_path`] hangs off `state_dir()`,
    /// not `stage_dir()`).
    fn routed(tag: &str) {
        let dir = unique_tmp(tag);
        std::env::set_var("AOIDE_STATE_DIR", &dir);
    }

    fn pre(
        project: &str,
        session: &str,
        path: &str,
        at: &str,
        sha: Option<&str>,
        mode: Option<&str>,
    ) -> EditLine {
        EditLine {
            at: at.to_string(),
            kind: "pre".to_string(),
            project: project.to_string(),
            session: session.to_string(),
            path: Some(path.to_string()),
            tool: Some("Edit".to_string()),
            mode: mode.map(str::to_string),
            sha: sha.map(str::to_string),
            by: None,
            paths: Vec::new(),
            tuid: None,
        }
    }

    fn post(project: &str, session: &str, path: &str, at: &str, sha: &str) -> EditLine {
        EditLine {
            at: at.to_string(),
            kind: "post".to_string(),
            project: project.to_string(),
            session: session.to_string(),
            path: Some(path.to_string()),
            tool: Some("Edit".to_string()),
            mode: None,
            sha: Some(sha.to_string()),
            by: None,
            paths: Vec::new(),
            tuid: None,
        }
    }

    fn revert(project: &str, session: &str, by: &str, at: &str, paths: &[&str]) -> EditLine {
        EditLine {
            at: at.to_string(),
            kind: "revert".to_string(),
            project: project.to_string(),
            session: session.to_string(),
            path: None,
            tool: None,
            mode: None,
            sha: None,
            by: Some(by.to_string()),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            tuid: None,
        }
    }

    // ── append/read_all: round-trip + corruption tolerance ─────────────────

    #[test]
    fn one_line_round_trips_through_append_and_read_all() {
        let _g = env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        routed("edits-roundtrip");

        let line = pre(
            "aoide",
            "s_1",
            "crates/a.rs",
            "2026-08-18T09:00:00Z",
            Some("abc123"),
            Some("100644"),
        );
        append(&line).unwrap();

        let read = read_all();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0], line);
    }

    #[test]
    fn a_corrupt_line_is_skipped_without_losing_its_neighbours() {
        let _g = env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STATE_DIR"]);
        routed("edits-corrupt");

        append(&pre(
            "aoide",
            "s_1",
            "a.rs",
            "2026-08-18T09:00:00Z",
            None,
            Some("100644"),
        ))
        .unwrap();
        // Hand-append a garbage line between two good ones — never produced
        // by `append` itself, but a hand-edited or torn file is realistic.
        let mut f = OpenOptions::new().append(true).open(edits_path()).unwrap();
        f.write_all(b"not json at all\n").unwrap();
        drop(f);
        append(&post("aoide", "s_1", "a.rs", "2026-08-18T09:00:01Z", "def456")).unwrap();

        let read = read_all();
        assert_eq!(read.len(), 2, "the garbage line is dropped, both good lines survive");
        assert_eq!(read[0].kind, "pre");
        assert_eq!(read[1].kind, "post");
    }

    // ── by_path: made-through-aoide detection ───────────────────────────────

    #[test]
    fn by_path_marks_made_for_a_null_pre_sha_and_not_otherwise() {
        let lines = vec![
            pre("aoide", "s_1", "new.rs", "2026-08-18T09:00:00Z", None, Some("100644")),
            post("aoide", "s_1", "new.rs", "2026-08-18T09:00:01Z", "aaa"),
            pre(
                "aoide",
                "s_1",
                "existing.rs",
                "2026-08-18T09:00:02Z",
                Some("bbb"),
                Some("100644"),
            ),
            post("aoide", "s_1", "existing.rs", "2026-08-18T09:00:03Z", "ccc"),
        ];
        let summary = by_path(&lines, "aoide");
        let made = summary.iter().find(|s| s.path == "new.rs").unwrap();
        let not_made = summary.iter().find(|s| s.path == "existing.rs").unwrap();
        assert!(made.made, "a null/omitted pre sha means the file was made through aoide");
        assert!(!not_made.made, "a present pre sha means the file pre-existed");
        assert_eq!(made.edits, 1);
    }

    // ── session_plan: earliest pre, latest post ─────────────────────────────

    #[test]
    fn session_plan_picks_the_earliest_pre_and_latest_post_across_four_lines() {
        let lines = vec![
            pre(
                "aoide",
                "s_1",
                "f.rs",
                "2026-08-18T09:00:02Z",
                Some("second-pre"),
                Some("100644"),
            ),
            pre(
                "aoide",
                "s_1",
                "f.rs",
                "2026-08-18T09:00:00Z",
                Some("first-pre"),
                Some("100755"),
            ),
            post("aoide", "s_1", "f.rs", "2026-08-18T09:00:01Z", "earlier-post"),
            post("aoide", "s_1", "f.rs", "2026-08-18T09:00:03Z", "latest-post"),
        ];
        let plan = session_plan(&lines, "aoide", "s_1");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].pre_sha.as_deref(), Some("first-pre"));
        assert_eq!(plan[0].mode.as_deref(), Some("100755"), "mode travels with the earliest pre");
        assert_eq!(plan[0].post_sha.as_deref(), Some("latest-post"));
    }

    #[test]
    fn a_path_named_in_a_later_revert_line_is_classified_already_reverted() {
        let lines = vec![
            pre(
                "aoide",
                "s_1",
                "f.rs",
                "2026-08-18T09:00:00Z",
                Some("pre-sha"),
                Some("100644"),
            ),
            post("aoide", "s_1", "f.rs", "2026-08-18T09:00:01Z", "post-sha"),
            revert("aoide", "s_1", "s_2", "2026-08-18T10:00:00Z", &["f.rs"]),
        ];
        let plan = session_plan(&lines, "aoide", "s_1");
        assert_eq!(plan.len(), 1);
        assert!(plan[0].already_reverted);
        assert_eq!(
            classify_file(&plan[0], Some("anything-live")),
            FileState::AlreadyRestored,
            "an already_reverted plan entry is AlreadyRestored regardless of the live hash"
        );
    }

    // ── movers_since: the LIFO hint ──────────────────────────────────────────

    #[test]
    fn movers_since_returns_the_interleaving_sessions_newest_first() {
        let lines = vec![
            post("aoide", "s_1", "shared.rs", "2026-08-18T09:00:00Z", "s1-first"),
            post("aoide", "s_2", "shared.rs", "2026-08-18T09:05:00Z", "s2-post"),
            post("aoide", "s_3", "shared.rs", "2026-08-18T09:10:00Z", "s3-post"),
            post("aoide", "s_2", "shared.rs", "2026-08-18T09:12:00Z", "s2-again"),
        ];
        let movers = movers_since(&lines, "aoide", "shared.rs", "2026-08-18T09:01:00Z");
        assert_eq!(
            movers,
            vec!["s_2".to_string(), "s_3".to_string()],
            "s_1's post predates the cutoff so it is not a mover; \
             s_2 dedupes to its LATEST post, and the list is newest-first"
        );
    }

    // ── classify_file: the D1 three-state classification ────────────────────

    #[test]
    fn classify_file_is_clean_when_live_hash_matches_the_recorded_post() {
        let planned = PlannedFile {
            path: "f.rs".to_string(),
            pre_sha: Some("pre".to_string()),
            mode: Some("100644".to_string()),
            post_sha: Some("post".to_string()),
            already_reverted: false,
        };
        assert_eq!(classify_file(&planned, Some("post")), FileState::Clean);
    }

    #[test]
    fn classify_file_is_already_restored_when_live_hash_matches_the_pre_image() {
        let planned = PlannedFile {
            path: "f.rs".to_string(),
            pre_sha: Some("pre".to_string()),
            mode: Some("100644".to_string()),
            post_sha: Some("post".to_string()),
            already_reverted: false,
        };
        // A crashed revert already wrote the pre-image before it died;
        // re-running must see this as DONE, not as moved-on (D1).
        assert_eq!(classify_file(&planned, Some("pre")), FileState::AlreadyRestored);
    }

    #[test]
    fn classify_file_is_already_restored_when_a_null_pre_creation_is_correctly_absent() {
        let planned = PlannedFile {
            path: "created.rs".to_string(),
            pre_sha: None, // a creation: nothing existed before this session
            mode: None,
            post_sha: Some("post".to_string()),
            already_reverted: false,
        };
        // The revert action for a creation is deletion; the file is
        // correctly absent (the delete already ran, or the create never
        // landed) — `live_sha` is `None` too, same as `hash_object` of an
        // absent file (R2).
        assert_eq!(classify_file(&planned, None), FileState::AlreadyRestored);
    }

    #[test]
    fn classify_file_is_already_restored_for_a_denied_edit_with_no_post_line() {
        // A PreToolUse capture whose edit was denied/failed: a pre line, no
        // matching post, file genuinely unchanged (D1's bonus case).
        let planned = PlannedFile {
            path: "f.rs".to_string(),
            pre_sha: Some("unchanged".to_string()),
            mode: Some("100644".to_string()),
            post_sha: None,
            already_reverted: false,
        };
        assert_eq!(classify_file(&planned, Some("unchanged")), FileState::AlreadyRestored);
    }

    #[test]
    fn classify_file_is_moved_on_when_the_live_hash_matches_neither() {
        let planned = PlannedFile {
            path: "f.rs".to_string(),
            pre_sha: Some("pre".to_string()),
            mode: Some("100644".to_string()),
            post_sha: Some("post".to_string()),
            already_reverted: false,
        };
        assert_eq!(classify_file(&planned, Some("something-else")), FileState::MovedOn);
    }
}
