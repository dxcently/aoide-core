//! `aoide mesh` (task #135 P4) and `aoide mesh pair` (P5): compare every
//! declared `[mesh.<name>]` (`aoide_storage::config::Mesh`) against the live
//! peer registry (`aoide_storage::peer_store::load_peers`), report where
//! they diverge — and, on the converge, close that divergence by running
//! the ordinary pairing ceremony over it.
//!
//! **Declaration vs. registry — intent vs. state.** `config.toml`'s
//! `[mesh.*]` is INTENT: the operator's own roster of who SHOULD be paired,
//! written once and rarely touched. `state/peers.json` is STATE: the
//! product of actually running the pairing ceremony
//! (`docs/architecture/PAIRING.md`), rebuilt by that ceremony alone. This
//! module never writes either — it only reads both fresh on every call and
//! diffs them. No new persisted state, no field added to
//! [`aoide_storage::peer_store::Peer`]: a mesh's shape lives entirely in
//! `config.mesh`, recomputed from scratch each time rather than cached
//! anywhere a second copy could go stale.
//!
//! **[`drift`] is pure** — no I/O, no clock, no env — so every ruling below
//! is a plain unit test against in-memory values, never a fixture on disk.
//! [`handle_mesh`] is the only impure edge: it resolves
//! `aoide_storage::config::load()`,
//! `aoide_storage::peer_store::load_peers()`, and
//! `aoide_storage::display::local_host_name()`, then hands the three
//! results in.
//!
//! **Three drift classes**, checked in this order per declared peer:
//! - [`DriftClass::Missing`] — declared, but no peer record by that name
//!   exists at all.
//! - [`DriftClass::Unverified`] — a peer record exists, but the pairing
//!   ceremony never confirmed it (`Peer::verified == false`). Checked
//!   before via, since an unconfirmed peer's `via` is not yet meaningful.
//! - [`DriftClass::ViaMismatch`] — verified, but the live `via` does not
//!   match the mesh's declared hop. `recorded: None` is the severe case:
//!   a call with no `via` dials the peer's bare `url` directly, which for
//!   an already-paired peer is commonly a loopback address — so the call
//!   silently dials THIS box's own loopback instead of hopping anywhere.
//!
//! A peer that matches (verified, `via` equal to the declared hop) gets no
//! row at all — [`MeshSection::rows`] holds drift only, never a clean bill
//! of health per peer.
//!
//! **`allows` divergence is deliberately NOT a drift class.** A mesh's
//! `grant` is a default for the moment a pair is MINTED, never a continuous
//! invariant over it: [`handle_mesh_pair`] hands it to the ceremony, and
//! `peer_store::upsert_paired_peer` stamps a capability set only on a FIRST
//! verification, leaving an already-verified peer's `allows` exactly as it
//! was. A human then narrows or widens that set deliberately, one peer at a
//! time, with `peer allow`. Comparing the result back against the
//! declaration would report every one of those decisions as permanent drift
//! and invite the operator to "fix" his own revocation — so the comparison
//! is not made.
//!
//! **`paired-but-not-declared` is reported, never accused.** A verified
//! peer named in no mesh lands in [`MeshReport::undeclared`] — its own
//! section, no drift count, no suggested action. Plenty of legitimate
//! peers (anything paired before this feature existed, anything
//! deliberately kept outside every declared mesh) are undeclared forever;
//! this module states the fact and stops.
//!
//! **The local host is skipped silently.** A mesh declared identically
//! across every member box will list that box's own name among its peers
//! (the same file, deployed everywhere) — comparing a box against itself
//! is not a peer relationship, so [`drift`] drops that one entry before it
//! ever becomes a row, an undeclared entry, or anything else visible.
//!
//! **Drift is never itself a failure — bare `mesh` is [`Outcome::ok`]
//! whenever the config loads.** Like `config`/`peer list`, this is a
//! report of what's on disk, not a pass/fail gate — drift is surfaced in
//! the message and `data.report`, never turned into a non-zero exit by
//! itself. The one exception is a config that fails to load or validate at
//! all: that is [`Outcome::error`] (`reason: "config-unreadable"`, no
//! `data.report` — there is nothing to compare), the same shape `aoide
//! config` itself already uses for the same failure.
//!
//! **`mesh pair` is the converge, and it consumes exactly the [`drift`]
//! above.** There is no second comparison anywhere in the tree: [`plan`]
//! reads [`MeshSection::rows`] and selects `missing` + `unverified`, in
//! declared-name order; `via-mismatch` comes back `skipped`, naming `aoide
//! pair <name>` as the fix. That skip is a ruling, not an omission — a
//! converge NEVER modifies an existing verified peer, because re-pairing
//! rotates key material and because writing `via` outside a ceremony commit
//! would make this a second writer of a field
//! `peer_store::set_peer_via` reserves to that commit. It also makes a
//! converge idempotent by construction: run it twice and the second run is
//! all-`skipped`.
//!
//! Each selected peer goes through `commands::run_pair_request` and nothing
//! else — the ordinary two-POST ceremony, the ordinary park, the ordinary
//! blocking wait. **Zero ceremony logic lives here**; a duplicated poll loop
//! is the design error the `poll_outbound_once`/`commit_outbound` split
//! exists to prevent. What a converge adds over typing `aoide pair` N times
//! is the selection, one pre-flight confirm for the whole run, the mesh's
//! declared `grant`, and a report in one vocabulary — completed / parked /
//! UNREACHABLE / skipped ([`ConvergeOutcome`]).
//!
//! **`sameOperator` is declared and not acted on.** Whether a converge may
//! ever satisfy the far side's typed code on an operator's behalf is
//! undecided (`docs/architecture/PAIRING.md`'s "Mesh declaration" section),
//! so a mesh declaring it converges byte-identically to one that does not:
//! every peer paired with both codes typed. The report carries one note
//! saying the flag was seen and not acted on — a note, never a row, never a
//! status, never a refusal.

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use aoide_protocol::Invocation;
use aoide_storage::config::Mesh;
use aoide_storage::peer_store::Peer;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Why one declared peer diverges from the live registry. Internally
/// tagged (`class`) so [`MeshRow`]'s `#[serde(flatten)]` puts `class`
/// alongside `peer` in one flat JSON object, never a nested `class: {...}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "class", rename_all = "kebab-case")]
pub enum DriftClass {
    /// Declared, but no peer record by this name exists at all.
    Missing,
    /// A peer record exists, but pairing was never confirmed.
    Unverified,
    /// A peer record exists and is verified, but its live `via` does not
    /// match the mesh's declared hop. `recorded: None` is the severe case
    /// — see the module doc.
    ViaMismatch { declared: String, recorded: Option<String> },
}

/// One divergent peer inside one declared mesh. [`MeshSection::rows`]
/// holds these — never a row for a peer that matches.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MeshRow {
    pub peer: String,
    #[serde(flatten)]
    pub class: DriftClass,
}

/// One declared `[mesh.<name>]`, compared. `grant`/`same_operator` are
/// copied straight off the declaration for display — [`drift`] never
/// compares them against anything (see the module doc's note on `allows`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MeshSection {
    pub name: String,
    pub grant: Option<Vec<String>>,
    /// Renamed on the wire — matches `config::Mesh::same_operator`'s own
    /// `sameOperator`, the same declaration this field is copied from.
    #[serde(rename = "sameOperator")]
    pub same_operator: bool,
    /// How many of this mesh's declared peers were actually COMPARED — the
    /// local host's own entry (if declared) is excluded, the same as it is
    /// from `rows`, so `declared - rows.len()` (the "N/M ok" ratio) is never
    /// inflated by an entry that was never checked against anything. This
    /// is NOT the raw size of the mesh's `peers` map in `config.toml` — a
    /// mesh naming itself plus two others declares 3 but compares 2.
    pub declared: usize,
    /// Was this box's own name (`display::local_host_name()`) found among
    /// this mesh's declared peer keys? `false` means either this box
    /// genuinely isn't part of the mesh, or it's declared under the wrong
    /// key (a typo, an FQDN/uppercase hostname `peer_store::valid_peer_name`
    /// can never accept — see `CONTRACTS.md §4`) — the two are
    /// indistinguishable from here, so this is a note, never a drift row:
    /// it changes neither `rows` nor `declared`.
    #[serde(rename = "selfDeclared")]
    pub self_declared: bool,
    pub rows: Vec<MeshRow>,
}

/// The whole comparison, every declared mesh plus the separate
/// never-accused undeclared list. What [`handle_mesh`] renders and what
/// `--json` serializes under `data.report`.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct MeshReport {
    pub sections: Vec<MeshSection>,
    /// Verified peers named in no declared mesh. Reported, never accused
    /// — see the module doc.
    pub undeclared: Vec<String>,
}

/// Compare every declared mesh against the live peer registry. Pure — see
/// the module doc. `meshes`/`peers` come from
/// `aoide_storage::config::load()`/`aoide_storage::peer_store::load_peers()`
/// respectively; `local_name` from
/// `aoide_storage::display::local_host_name()`. Iteration follows each
/// input `BTreeMap`'s own sorted order, and `undeclared` is sorted
/// explicitly, so two calls over the same declarations and a differently
/// ordered `peers` slice render identically.
pub fn drift(meshes: &BTreeMap<String, Mesh>, peers: &[Peer], local_name: &str) -> MeshReport {
    let mut declared_names: BTreeSet<&str> = BTreeSet::new();
    let mut sections = Vec::with_capacity(meshes.len());

    for (name, mesh) in meshes {
        let mut rows = Vec::new();
        let mut compared = 0usize;
        for (peer_name, hop) in &mesh.peers {
            if peer_name == local_name {
                continue; // this box naming itself — not a peer, not an error
            }
            compared += 1;
            declared_names.insert(peer_name.as_str());
            let class = match peers.iter().find(|p| &p.name == peer_name) {
                None => DriftClass::Missing,
                Some(p) if !p.verified => DriftClass::Unverified,
                Some(p) if p.via.as_deref() != Some(hop.as_str()) => {
                    DriftClass::ViaMismatch { declared: hop.clone(), recorded: p.via.clone() }
                }
                Some(_) => continue, // matches — no row
            };
            rows.push(MeshRow { peer: peer_name.clone(), class });
        }
        sections.push(MeshSection {
            name: name.clone(),
            grant: mesh.grant.clone(),
            same_operator: mesh.same_operator,
            declared: compared,
            self_declared: mesh.peers.contains_key(local_name),
            rows,
        });
    }

    let mut undeclared: Vec<String> = peers
        .iter()
        .filter(|p| p.verified && p.name != local_name && !declared_names.contains(p.name.as_str()))
        .map(|p| p.name.clone())
        .collect();
    undeclared.sort();

    MeshReport { sections, undeclared }
}

/// The human-text rendering `aoide mesh`'s message carries — `--json`
/// serializes the same [`MeshReport`] structured instead, under
/// `data.report`. `local_name` is display-only here (it never changes what
/// was already decided in [`drift`]) — it lets the not-self-declared note
/// name the exact key a section is missing.
fn render_report(report: &MeshReport, local_name: &str) -> String {
    if report.sections.is_empty() {
        return if report.undeclared.is_empty() {
            "no mesh declared — see `aoide config` for [mesh.<name>]".to_string()
        } else {
            render_undeclared(&report.undeclared)
        };
    }
    let mut lines = Vec::new();
    for section in &report.sections {
        let clean = section.declared.saturating_sub(section.rows.len());
        lines.push(format!(
            "mesh.{}  {clean}/{} ok  sameOperator={}",
            section.name, section.declared, section.same_operator,
        ));
        for row in &section.rows {
            lines.push(format!("  {}", render_row(row)));
        }
        if !section.self_declared {
            lines.push(format!(
                "  note: this box is not named in mesh.{} — if it should be, \
                 the declared key must be exactly `{local_name}`",
                section.name
            ));
        }
    }
    if !report.undeclared.is_empty() {
        lines.push(String::new());
        lines.push(render_undeclared(&report.undeclared));
    }
    lines.join("\n")
}

fn render_row(row: &MeshRow) -> String {
    match &row.class {
        DriftClass::Missing => {
            format!("{} — missing (declared, no peer record by this name)", row.peer)
        }
        DriftClass::Unverified => {
            format!("{} — unverified (peer record exists, pairing never confirmed)", row.peer)
        }
        DriftClass::ViaMismatch { declared, recorded: None } => format!(
            "{} — SEVERE via-mismatch: declared {declared}, recorded none \
             (a call dials the bare url directly — likely this box's own loopback)",
            row.peer
        ),
        DriftClass::ViaMismatch { declared, recorded: Some(recorded) } => {
            format!("{} — via-mismatch: declared {declared}, recorded {recorded}", row.peer)
        }
    }
}

fn render_undeclared(names: &[String]) -> String {
    format!("undeclared (paired, named in no mesh — reported, not accused): {}", names.join(", "))
}

/// `aoide mesh [--json]` — `Outcome::ok` whenever the config loads;
/// `Outcome::error` (never a panic, never a swallowed failure) when it does
/// not. See the module doc.
fn handle_mesh(_inv: &Invocation) -> Outcome {
    let cmd = "mesh";
    let loaded = match aoide_storage::config::load() {
        Ok(l) => l,
        Err(e) => {
            return Outcome::error(cmd, e.to_string())
                .with_data(json!({ "reason": "config-unreadable", "path": e.path().to_string_lossy() }));
        }
    };
    let peers = aoide_storage::peer_store::load_peers();
    let local_name = aoide_storage::display::local_host_name();
    let report = drift(&loaded.config.mesh, &peers, &local_name);
    let text = render_report(&report, &local_name);
    Outcome::ok(cmd, text).with_data(json!({ "report": report }))
}

// ────────────────────────────────────────────────────────────────────────
// `mesh pair` — the converge (task #135 P5)
// ────────────────────────────────────────────────────────────────────────

/// What a converge does with one declared peer. Decided from [`drift`]'s
/// own classification and nothing else — a converge runs the SAME
/// comparison the read side does, never a second one.
#[derive(Debug, Clone, PartialEq)]
pub enum PlannedAction {
    /// [`DriftClass::Missing`] or [`DriftClass::Unverified`] — run the
    /// pairing ceremony through `hop`, the declared `ssh://` marker.
    Pair { hop: String },
    /// Reported, never attempted. `reason` is what the converge report
    /// carries and names the command that DOES fix it.
    Skip { reason: String },
}

/// One declared peer and what the converge will do with it.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedPeer {
    pub peer: String,
    pub action: PlannedAction,
}

/// What a converge over one declared mesh will attempt, and what it will
/// not. Pure, and the whole of the selection ruling:
///
/// - Only [`MeshSection::rows`] are considered, so a peer that already
///   matches is never touched and the local box (dropped inside [`drift`],
///   never here) is invisible.
/// - `missing` and `unverified` are paired. An `unverified` record is a
///   `peer add` row the ceremony never confirmed; `upsert_paired_peer`
///   updates it in place.
/// - **`via-mismatch` is skipped, always.** A converge NEVER modifies an
///   existing verified peer: re-pairing rotates key material,
///   `commands::confirm_repair_if_verified` already gates that behind a
///   human y/N, and writing `via` outside a ceremony commit would make this
///   a second writer of a field `peer_store::set_peer_via` reserves to the
///   ceremony. The fix is a human re-pair (`aoide pair <name>`), started
///   from whichever box holds the wrong record — and it is that skip which
///   makes a converge idempotent by construction: run it twice and the
///   second run is all-`skipped`.
///
/// Order is [`MeshSection::rows`]' own, which is `Mesh::peers`' `BTreeMap`
/// order — lexicographic by declared name, so the same declaration always
/// converges in the same sequence.
pub fn plan(section: &MeshSection, mesh: &Mesh) -> Vec<PlannedPeer> {
    section
        .rows
        .iter()
        .map(|row| {
            let action = match &row.class {
                DriftClass::Missing | DriftClass::Unverified => match mesh.peers.get(&row.peer) {
                    Some(hop) => PlannedAction::Pair { hop: hop.clone() },
                    // Unreachable by construction — `drift` builds every row
                    // out of this same map — so this arm exists to keep the
                    // match total rather than to guard anything.
                    None => PlannedAction::Skip { reason: format!("no hop declared for `{}`", row.peer) },
                },
                DriftClass::ViaMismatch { .. } => {
                    PlannedAction::Skip { reason: format!("via-mismatch; fix with `aoide pair {}`", row.peer) }
                }
            };
            PlannedPeer { peer: row.peer.clone(), action }
        })
        .collect()
}

/// How one selected peer's converge attempt came out, in the four words
/// this report is allowed (the pairing tombstone slice's locked vocabulary
/// — completed / parked / UNREACHABLE / skipped; a fifth word is a spec
/// change, not an implementation detail).
///
/// [`Unreachable`](ConvergeOutcome::Unreachable) carries NO id, structurally:
/// `pairing::park_outbound` runs only after BOTH ceremony POSTs succeed, so
/// a request to an offline box parks nothing at all and there is no entry a
/// later `aoide pair <id>` could resume. A report that handed one back would
/// be inviting the operator to resume something that does not exist.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ConvergeOutcome {
    /// The far operator typed the reply code and the peer record is
    /// verified — `commit_outbound`'s own success.
    Completed,
    /// The request is parked and resumable under `id`: `--wait 0`, a wait
    /// that ran out, an approval with no terminal to type the reply code
    /// into, or a declined confirm. `detail` is the ceremony's own message
    /// and rides the human line beside the resume: the id alone cannot say
    /// whether THIS run parked it or an older entry survived a request that
    /// never landed ([`parked_id_for`]), and that difference is the whole
    /// news when a box has gone offline.
    Parked { id: String, detail: String },
    /// The ceremony left nothing parked and nothing committed. `detail` is
    /// the ceremony's own message — the human line shows THIS half, since
    /// here it is the only half worth acting on.
    Unreachable { detail: String },
    /// Never attempted. See [`plan`].
    Skipped { reason: String },
}

/// One peer's converge result. `#[serde(flatten)]` for the same reason
/// [`MeshRow`] uses it — one flat `{"peer": …, "outcome": …}` object per
/// row, never a nested tag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConvergeRow {
    pub peer: String,
    #[serde(flatten)]
    pub outcome: ConvergeOutcome,
}

/// One converge, whole. What [`handle_mesh_pair`] renders and what `--json`
/// serializes under `data.report`.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct ConvergeReport {
    pub mesh: String,
    pub rows: Vec<ConvergeRow>,
    /// Present only when the mesh declares `sameOperator = true`. Its own
    /// field, deliberately outside [`rows`](ConvergeReport::rows): the flag
    /// changes no peer's status and no count, so folding it into a per-peer
    /// result would misreport what happened.
    #[serde(rename = "sameOperatorNote", skip_serializing_if = "Option::is_none")]
    pub same_operator_note: Option<String>,
}

/// What a declared `sameOperator = true` gets: a sentence, and nothing
/// else. Whether a converge may ever act on that claim — satisfying the far
/// side's typed code on an operator's behalf — is undecided
/// (`docs/architecture/PAIRING.md`'s "Mesh declaration" section), so the
/// converge runs the flag's `false` path exactly: every peer paired with
/// both codes typed, by two people or by one person at two screens. The
/// note says so rather than leaving the operator to wonder whether a
/// declared flag quietly did something.
const SAME_OPERATOR_NOTE: &str = "declares sameOperator = true, which is not yet ruled: a converge cannot act on it. \
                                  Peers were paired with both codes typed, as normal.";

/// Assemble one converge's report. Pure, so the `sameOperator` ruling above
/// is a unit test over in-memory values: the note's presence is the ONLY
/// thing `same_operator` changes about a report.
fn converge_report(mesh_name: &str, mesh: &Mesh, rows: Vec<ConvergeRow>) -> ConvergeReport {
    ConvergeReport {
        mesh: mesh_name.to_string(),
        rows,
        same_operator_note: mesh.same_operator.then(|| format!("mesh.{mesh_name} {SAME_OPERATOR_NOTE}")),
    }
}

/// Fold one peer's ceremony envelope into the locked vocabulary. Pure: both
/// facts it decides on are handed in — `out` is whatever
/// `commands::run_pair_request` returned, and `parked_id` is what
/// `pairing::list_outbound` says about that peer AFTERWARD (the only way
/// this module ever reads parked state, so a new optional field on a parked
/// entry stays invisible to it).
///
/// Keyed on those two facts and nothing else — never on a `data.reason`
/// string, which would make the vocabulary a hostage to every future
/// wording change inside the ceremony:
///
/// - `confirmed: true` on an Ok envelope is `commit_outbound`'s own success
///   shape, and the only thing that means a peer record was written.
/// - Otherwise, an entry parked under this peer's name is exactly what
///   "resume it later" needs, whatever the envelope's status was — a
///   mistyped reply code leaves the request parked and is reported as such,
///   not as an unreachable box.
/// - Nothing committed and nothing parked is [`ConvergeOutcome::Unreachable`],
///   which by construction cannot carry an id.
pub fn classify(out: &Outcome, parked_id: Option<String>) -> ConvergeOutcome {
    let confirmed = out
        .data
        .as_ref()
        .and_then(|d| d.get("confirmed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if out.status == aoide_protocol::output::Status::Ok && confirmed {
        return ConvergeOutcome::Completed;
    }
    match parked_id {
        Some(id) => ConvergeOutcome::Parked { id, detail: out.message.clone() },
        None => ConvergeOutcome::Unreachable { detail: out.message.clone() },
    }
}

/// Which declared mesh a converge runs over. A bare `mesh pair` with
/// exactly one declared mesh is unambiguous and takes it; anything else
/// names what it found rather than guessing.
fn resolve_section<'a>(cmd: &str, report: &'a MeshReport, arg: Option<&str>) -> Result<&'a MeshSection, Outcome> {
    let declared: Vec<&str> = report.sections.iter().map(|s| s.name.as_str()).collect();
    match arg {
        Some(name) => report.sections.iter().find(|s| s.name == name).ok_or_else(|| {
            Outcome::usage(
                cmd,
                format!(
                    "no `[mesh.{name}]` in config.toml — declared: {}",
                    if declared.is_empty() { "(none)".to_string() } else { declared.join(", ") }
                ),
            )
            .with_data(json!({ "reason": "unknown-mesh", "mesh": name, "declared": declared }))
        }),
        None if declared.is_empty() => Err(Outcome::error(
            cmd,
            "no mesh declared — add a `[mesh.<name>]` section to config.toml, then `aoide mesh` to see the drift this would converge",
        )
        .with_data(json!({ "reason": "no-mesh-declared" }))),
        None if declared.len() == 1 => Ok(&report.sections[0]),
        None => Err(Outcome::usage(
            cmd,
            format!("more than one mesh is declared — name the one to converge: {}", declared.join(", ")),
        )
        .with_data(json!({ "reason": "ambiguous-mesh", "declared": declared }))),
    }
}

/// The ceremony's post-request behaviour for a converge: `pair`'s OWN
/// `--wait`/`--yes` parse ([`crate::commands::pair_finish_from`] — one
/// parser and one taught error for a flag both commands spell the same),
/// with the grant taken from the MESH rather than from an `--allow` flag
/// `mesh pair` deliberately does not have. A declared grant is what a first
/// verification stamps; `None` (the mesh declares no override) falls
/// through to `commands::resolve_grant`, which reads `[pairing]
/// defaultGrant`. Never `Some(vec![])` for an absent declaration — the
/// empty list is the distinct, real "grant nothing" intent and must stay
/// distinguishable from "declared no override".
fn converge_finish(inv: &Invocation, mesh: &Mesh) -> Result<crate::commands::PairFinish, String> {
    let mut finish = crate::commands::pair_finish_from(inv)?;
    finish.grant = mesh.grant.clone();
    // `--yes` here buys the ONE pre-flight confirm below, never a code gate.
    // `commands::outbound_gate_from` reads `skip_confirm` ahead of the tty
    // test, so carrying it through would resolve every leg to
    // `CodeGate::Unavailable` and park the whole converge without committing
    // anything — N ids to type by hand, which is what this command exists to
    // replace. The converge replaces the N requests, not the N codes.
    finish.skip_confirm = false;
    Ok(finish)
}

/// How many of a plan's entries would actually send a request. Everything
/// that turns on "does this run do anything at all" — the pre-flight, the
/// detached-grant refusal — asks this one function, so the two can never
/// disagree about whether a converge is a no-op.
fn pairs_planned(plan: &[PlannedPeer]) -> usize {
    plan.iter().filter(|p| matches!(p.action, PlannedAction::Pair { .. })).count()
}

/// The whole converge, laid out for the one pre-flight confirm: which
/// peers, in what order, through which hops, at what grant, and how long
/// each will wait. Pure — the prompt is rendered here and only READ by the
/// confirm below.
fn render_preflight(mesh_name: &str, mesh: &Mesh, plan: &[PlannedPeer], wait_secs: u64) -> String {
    let mut lines = vec![format!("converge mesh.{mesh_name}:")];
    for planned in plan {
        if let PlannedAction::Pair { hop } = &planned.action {
            lines.push(format!("  pair {} via {hop}", planned.peer));
        }
    }
    for planned in plan {
        if let PlannedAction::Skip { reason } = &planned.action {
            lines.push(format!("  skip {} ({reason})", planned.peer));
        }
    }
    lines.push(match &mesh.grant {
        Some(g) if g.is_empty() => format!("grant: nothing (mesh.{mesh_name} declares an empty grant)"),
        Some(g) => format!("grant: {} (declared by mesh.{mesh_name})", g.join(", ")),
        None => "grant: config.toml's [pairing] defaultGrant".to_string(),
    });
    lines.push(match wait_secs {
        0 => "each request is parked and returns immediately (--wait 0)".to_string(),
        n => format!("each far operator types the pairing code and reads a reply code back; up to {n}s per peer"),
    });
    lines.join("\n")
}

/// ONE confirmation for the whole converge, before the loop (never one per
/// peer — N prompts for a single decision is friction, not safety).
/// `--yes` skips it exactly as it skips `pair`'s own sweep proceed-prompt:
/// nothing is bypassed by that, because every far operator still types a
/// code, and the pairing codes remain the gate that actually secures each
/// pair. `Err` is the finished [`Outcome`] to return — a decline is an Ok
/// "nothing sent", not a failure.
fn confirm_preflight(
    cmd: &str,
    inv: &Invocation,
    mesh_name: &str,
    mesh: &Mesh,
    plan: &[PlannedPeer],
    wait_secs: u64,
) -> Result<(), Outcome> {
    let to_pair = pairs_planned(plan);
    if to_pair == 0 || inv.flag_present("yes") {
        return Ok(());
    }
    let listing = render_preflight(mesh_name, mesh, plan, wait_secs);
    if !aoide_protocol::pick::interactive(inv.door) {
        return Err(Outcome::error(
            cmd,
            format!("{listing}\n— no terminal to confirm this on; re-run with --yes to proceed"),
        )
        .with_data(json!({ "reason": "no-preflight-confirm", "mesh": mesh_name, "toPair": to_pair })));
    }
    eprintln!("{listing}");
    match aoide_protocol::pick::confirm(&format!("proceed — pair {to_pair} peer(s) in mesh.{mesh_name}?")) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Outcome::ok(cmd, "not confirmed — nothing sent")
            .with_data(json!({ "confirmed": false, "mesh": mesh_name }))),
        Err(e) => Err(Outcome::error(cmd, e)),
    }
}

/// What `pairing::list_outbound` holds for `peer` at this moment — the id of
/// the entry a later `aoide pair <id>` would resume, or `None` when nothing
/// is parked under that name. The ONE way this module reads parked state:
/// never the file, never a second index.
///
/// It answers about the NAME, not about this run: `park_outbound` dedups by
/// pubkey, so an entry a previous converge left behind survives a request
/// that never reached the box, and this returns that older id. The row is
/// still true — that id really is resumable — but it is not evidence this
/// run made progress, which is why [`render_converge_outcome`] prints a
/// parked row's `detail` beside its id rather than the id alone.
fn parked_id_for(peer: &str) -> Option<String> {
    let now_epoch = aoide_storage::time::parse_iso_utc(&aoide_storage::time::now_iso_utc()).unwrap_or(0);
    aoide_storage::pairing::list_outbound(now_epoch).into_iter().find(|e| e.name == peer).map(|e| e.id)
}

/// Run the ceremony for one selected peer, through its declared hop. Every
/// line of ceremony logic lives in `commands::run_pair_request` — this
/// composes its arguments and nothing more. A duplicated poll loop is the
/// design error this whole split exists to prevent.
///
/// The dial url's HOST is irrelevant and deliberately loopback:
/// `commands::resolve_dial_url` discards a logical url's authority whenever
/// a `via` is set, rewriting the dial to the tunnel's own local end. So
/// `http://127.0.0.1:<default_a2a_port()>/` is both the correct logical url
/// and exactly the record shape a paired peer already carries.
fn converge_one(cmd: &str, peer: &str, hop: &str, finish: &crate::commands::PairFinish) -> ConvergeOutcome {
    let via = match aoide_storage::tunnel::parse_via(hop) {
        Ok(v) => v,
        // Unreachable through `config::load` (`validate_mesh` runs the same
        // parser), so this is the total-match arm, not a second validation.
        Err(e) => return ConvergeOutcome::Skipped { reason: format!("declared hop `{hop}` does not parse: {e}") },
    };
    let dial_url = format!("http://127.0.0.1:{}/", crate::commands::default_a2a_port());
    let self_url = crate::commands::default_self_url();
    let self_via = crate::commands::default_self_via(&via.host);
    let out = crate::commands::run_pair_request(
        cmd,
        &dial_url,
        peer,
        &self_url,
        self_via.as_deref(),
        Some(&via),
        Some(hop.to_string()),
        finish,
    );
    classify(&out, parked_id_for(peer))
}

/// The human-text rendering `aoide mesh pair`'s message carries — `--json`
/// serializes the same [`ConvergeReport`] under `data.report`, detail
/// included for every row.
fn render_converge(report: &ConvergeReport) -> String {
    let mut lines = Vec::new();
    if report.rows.is_empty() {
        lines.push(format!("mesh.{} — every declared peer is already paired at its declared hop", report.mesh));
    } else {
        let width = report.rows.iter().map(|r| r.peer.chars().count()).max().unwrap_or(0);
        for row in &report.rows {
            lines.push(format!("  {:width$} — {}", row.peer, render_converge_outcome(&row.outcome)));
        }
    }
    if let Some(note) = &report.same_operator_note {
        lines.push(String::new());
        lines.push(format!("  {note}"));
    }
    lines.join("\n")
}

/// One row's outcome word plus the half of its detail that is actionable —
/// the resume for a parked request, the failure for an unreachable one, the
/// fix for a skip. The other half is never lost: `--json` carries every
/// field of [`ConvergeOutcome`] verbatim.
fn render_converge_outcome(outcome: &ConvergeOutcome) -> String {
    match outcome {
        ConvergeOutcome::Completed => "completed   (far operator typed the reply code)".to_string(),
        ConvergeOutcome::Parked { id, detail } => {
            format!("parked      (resume with `aoide pair {id}` — {detail})")
        }
        ConvergeOutcome::Unreachable { detail } => format!("UNREACHABLE ({detail})"),
        ConvergeOutcome::Skipped { reason } => format!("skipped     ({reason})"),
    }
}

/// `aoide mesh pair [<mesh>] [--wait N] [--yes] [--json]` — make a declared
/// mesh true, one ordinary pairwise ceremony at a time. See the module doc.
fn handle_mesh_pair(inv: &Invocation) -> Outcome {
    let cmd = "mesh.pair";
    const USAGE: &str = "usage: aoide mesh pair [<mesh>] [--wait SECS] [--yes] [--json] — pairs every declared peer this box has no verified record of; the mesh may be omitted when exactly one is declared";
    if inv.args.len() > 1 {
        return Outcome::usage(cmd, USAGE);
    }
    let loaded = match aoide_storage::config::load() {
        Ok(l) => l,
        Err(e) => {
            return Outcome::error(cmd, e.to_string())
                .with_data(json!({ "reason": "config-unreadable", "path": e.path().to_string_lossy() }));
        }
    };
    let peers = aoide_storage::peer_store::load_peers();
    let local_name = aoide_storage::display::local_host_name();
    let report = drift(&loaded.config.mesh, &peers, &local_name);

    let arg = inv.args.first().map(|s| s.trim()).filter(|s| !s.is_empty());
    let section = match resolve_section(cmd, &report, arg) {
        Ok(s) => s,
        Err(out) => return out,
    };
    let Some(mesh) = loaded.config.mesh.get(&section.name) else {
        // `drift` builds a section per declared mesh, keyed by that same
        // map — the total-match arm, not a guard.
        return Outcome::error(cmd, format!("mesh.{} vanished between the read and the converge", section.name));
    };

    let plan = plan(section, mesh);
    let finish = match converge_finish(inv, mesh) {
        Ok(f) => f,
        Err(e) => return Outcome::usage(cmd, format!("{USAGE} — {e}")),
    };
    // The same refusal `pair --allow --wait 0` already gives, by the SAME
    // rule — `commands::refuse_detached_grant` is asked, so if `pair` ever
    // changes when a detached grant is refused this follows without a
    // second copy of the condition. Only the WORDING is replaced: that
    // message names `--allow`, and here the grant came from the
    // declaration, not from a flag anybody typed.
    //
    // Asked only when something would actually be sent, the same condition
    // the pre-flight uses. A converged mesh plans no request, so there is no
    // grant to detach and nothing to refuse — an all-`skipped` run stays Ok
    // whatever flags it carries, which is what makes the second run over a
    // converged mesh a usable scripted check.
    if pairs_planned(&plan) > 0 && crate::commands::refuse_detached_grant(cmd, &finish).is_some() {
        return Outcome::usage(
            cmd,
            format!(
                "mesh.{} declares a grant, and `--wait 0` parks every request before anything commits — \
                 a grant is never persisted on a parked entry, so this one would be silently dropped. \
                 Drop `--wait 0` so each pair finishes while its grant is still in hand.",
                section.name
            ),
        )
        .with_data(json!({ "reason": "detached-grant", "mesh": section.name }));
    }
    if let Err(out) = confirm_preflight(cmd, inv, &section.name, mesh, &plan, finish.wait_secs) {
        return out;
    }

    let mut rows = Vec::with_capacity(plan.len());
    for planned in &plan {
        let outcome = match &planned.action {
            PlannedAction::Skip { reason } => ConvergeOutcome::Skipped { reason: reason.clone() },
            PlannedAction::Pair { hop } => converge_one(cmd, &planned.peer, hop, &finish),
        };
        rows.push(ConvergeRow { peer: planned.peer.clone(), outcome });
    }

    let completed = rows.iter().any(|r| r.outcome == ConvergeOutcome::Completed);
    let converged = converge_report(&section.name, mesh, rows);
    let text = render_converge(&converged);
    let out = Outcome::ok(cmd, text).with_data(json!({ "report": converged }));
    if completed {
        out.changed(vec![aoide_storage::peer_store::peers_path().to_string_lossy().into_owned()])
    } else {
        out
    }
}

/// `mesh` then `mesh pair`, appended newest (Registry discipline,
/// `pkgs/aoide/crates/AGENTS.md`) into `cli`'s `commands::all()` — LAST,
/// after every other `register*` call.
///
/// **Neither is door-gated, and `mesh pair` is not gated for the same
/// reason `pair` is not.** Over any door but the CLI,
/// `aoide_protocol::pick::interactive` is false, so both legs' `CodeGate`
/// resolves to `Unavailable` (`commands::approve_inbound_leg`,
/// `commands::outbound_gate_from`): a remote caller can START requests and
/// can never COMMIT one. A converge is a loop over that same ceremony and
/// inherits that answer whole, so it needs no gate of its own — the
/// convention already answers. This says nothing about whether a converge
/// that could satisfy a far side's code mechanically would need one; no
/// such path exists, and if one is ever ruled in it brings its own gate and
/// its own reason.
pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["mesh"],
        summary: "Compare every declared [mesh.<name>] in config.toml against the live peer registry and report where they diverge (missing/unverified/via-mismatch), plus any paired peer named in no mesh. Drift is never itself a failure; a config that fails to load is.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_mesh,
        examples: ["mesh", "mesh --json"],
    ));
    r.insert(cmd!(
        path: ["mesh", "pair"],
        summary: "Converge a declared [mesh.<name>]: run the ordinary pairing ceremony against every declared peer this box has no verified record of (missing or unverified), in declared-name order, through each one's declared ssh hop, stamping the mesh's own grant. A verified peer is NEVER modified — a via-mismatch is reported as skipped and fixed by a human re-pair — so a second run is all-skipped. One pre-flight confirm for the whole converge (--yes skips it); every far operator still types a pairing code and reads a reply code back.",
        args: [arg!("mesh", "string", false, "Which declared mesh to converge. Omitted: the one declared mesh, when exactly one is declared.")],
        flags: [
            flag!("wait", "int", "Seconds to block per peer for the far operator (default 600). --wait 0 parks every request and returns immediately, to be finished later with `aoide pair <id>` or `aoide pair watch`. Refused when the mesh declares a grant and there is anything to pair: a parked entry carries no grant, so the declared one would be silently dropped."),
            flag!("yes", "bool", "Skip the pre-flight confirm. Never a bypass of the pairing codes: each peer's commit still needs a typed code on both sides."),
        ],
        gated: false,
        implemented: true,
        handler: handle_mesh_pair,
        examples: ["mesh pair", "mesh pair home", "mesh pair home --wait 0", "mesh pair home --yes --json"],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use aoide_protocol::Door;

    fn mesh(peers: &[(&str, &str)]) -> Mesh {
        Mesh {
            grant: None,
            same_operator: false,
            peers: peers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn peer(name: &str, verified: bool, via: Option<&str>) -> Peer {
        Peer {
            name: name.to_string(),
            url: format!("https://{name}.example/"),
            autogate: false,
            token_file: None,
            bearer_secret: None,
            hub: false,
            pubkey: None,
            verified,
            allows: Vec::new(),
            via: via.map(str::to_string),
            added_at: String::new(),
        }
    }

    fn cli_inv(path: &[&str]) -> Invocation {
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: Vec::new(),
            flags: BTreeMap::new(),
            door: Door::Cli,
        }
    }

    /// Sandboxes `handle_mesh`'s two real reads — `config::load()`
    /// (`AOIDE_ROOT`/`AOIDE_CONFIG`) and `peer_store::load_peers()`
    /// (`AOIDE_STATE_DIR`) — at one fresh scratch dir, so this module's
    /// handler test never reads the developer's own `~/.aoide` (mirrors
    /// `commands::tests::with_peer_state`). `EnvSaver` restores the three
    /// vars on drop even if `f` panics; the scratch dir itself is best-effort
    /// removed after `f` returns.
    fn with_config_root<T>(tag: &str, f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _saver = aoide_test_support::EnvSaver::capture(&["AOIDE_ROOT", "AOIDE_STATE_DIR", "AOIDE_CONFIG"]);
        let dir = aoide_test_support::unique_tmp(&format!("mesh-{tag}"));
        std::env::set_var("AOIDE_ROOT", &dir);
        std::env::set_var("AOIDE_STATE_DIR", &dir);
        std::env::remove_var("AOIDE_CONFIG");
        let out = f(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    // ── drift: matches produce nothing ──────────────────────────────────────

    #[test]
    fn a_verified_peer_whose_via_matches_the_declared_hop_produces_no_row() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("sakaki", "ssh://khoa@h")]))]);
        let peers = vec![peer("sakaki", true, Some("ssh://khoa@h"))];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(report.sections[0].rows, Vec::new());
        assert!(report.undeclared.is_empty());
    }

    // ── drift: the three classes ────────────────────────────────────────────

    #[test]
    fn a_declared_peer_with_no_record_at_all_is_missing() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("sakaki", "ssh://khoa@h")]))]);
        let report = drift(&meshes, &[], "this-box");
        assert_eq!(report.sections[0].rows, vec![MeshRow { peer: "sakaki".into(), class: DriftClass::Missing }]);
    }

    #[test]
    fn a_declared_peer_that_is_not_yet_verified_is_unverified_even_with_a_matching_via() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("sakaki", "ssh://khoa@h")]))]);
        let peers = vec![peer("sakaki", false, Some("ssh://khoa@h"))];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(report.sections[0].rows, vec![MeshRow { peer: "sakaki".into(), class: DriftClass::Unverified }]);
    }

    #[test]
    fn a_verified_peer_with_a_different_via_is_via_mismatch() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("sakaki", "ssh://khoa@h")]))]);
        let peers = vec![peer("sakaki", true, Some("ssh://khoa@other"))];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(
            report.sections[0].rows,
            vec![MeshRow {
                peer: "sakaki".into(),
                class: DriftClass::ViaMismatch {
                    declared: "ssh://khoa@h".into(),
                    recorded: Some("ssh://khoa@other".into())
                }
            }]
        );
    }

    #[test]
    fn a_verified_peer_with_no_recorded_via_is_via_mismatch_with_recorded_none() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("chiyo", "ssh://khoa@h")]))]);
        let peers = vec![peer("chiyo", true, None)];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(
            report.sections[0].rows,
            vec![MeshRow {
                peer: "chiyo".into(),
                class: DriftClass::ViaMismatch { declared: "ssh://khoa@h".into(), recorded: None }
            }]
        );
        // The severe case renders distinctly.
        let text = render_row(&report.sections[0].rows[0]);
        assert!(text.contains("SEVERE"), "{text}");
    }

    // ── undeclared: reported, never accused ─────────────────────────────────

    #[test]
    fn a_verified_peer_named_in_no_mesh_is_undeclared_not_a_drift_row() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[]))]);
        let peers = vec![peer("osaka", true, None)];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(report.sections[0].rows, Vec::new());
        assert_eq!(report.undeclared, vec!["osaka".to_string()]);
    }

    #[test]
    fn an_unverified_peer_named_in_no_mesh_is_not_undeclared() {
        let meshes = BTreeMap::new();
        let peers = vec![peer("osaka", false, None)];
        let report = drift(&meshes, &peers, "this-box");
        assert!(report.undeclared.is_empty(), "an unpaired peer has nothing to declare");
    }

    #[test]
    fn undeclared_is_sorted_regardless_of_input_order() {
        let meshes = BTreeMap::new();
        let peers = vec![peer("zeta", true, None), peer("alpha", true, None), peer("mu", true, None)];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(report.undeclared, vec!["alpha".to_string(), "mu".to_string(), "zeta".to_string()]);
    }

    // ── allows divergence is not drift ──────────────────────────────────────

    #[test]
    fn allows_divergent_from_grant_produces_no_row_and_is_never_inspected() {
        let mut m = mesh(&[("sakaki", "ssh://khoa@h")]);
        m.grant = Some(vec!["read".to_string()]);
        let meshes = BTreeMap::from([("home".to_string(), m)]);
        let mut p = peer("sakaki", true, Some("ssh://khoa@h"));
        p.allows = vec!["spawn".to_string()]; // deliberately NOT "read" — still no row
        let report = drift(&meshes, &[p], "this-box");
        assert_eq!(report.sections[0].rows, Vec::new());
    }

    // ── self-skip ────────────────────────────────────────────────────────────

    #[test]
    fn the_local_host_named_in_its_own_mesh_is_skipped_silently() {
        let meshes =
            BTreeMap::from([("home".to_string(), mesh(&[("this-box", "ssh://khoa@self"), ("sakaki", "ssh://khoa@h")]))]);
        let peers = vec![peer("sakaki", true, Some("ssh://khoa@h"))];
        let report = drift(&meshes, &peers, "this-box");
        assert_eq!(report.sections[0].rows, Vec::new(), "this-box's own entry must not surface as missing");
        assert!(report.sections[0].self_declared, "this-box's own key IS present in mesh.peers");
        assert_eq!(
            report.sections[0].declared, 1,
            "declared counts what was actually COMPARED — the self-entry is excluded, same as rows"
        );
    }

    #[test]
    fn a_mesh_missing_this_boxs_own_key_is_not_self_declared_and_its_other_peer_still_compares() {
        // Reproduces the false-accusation gap: the operator's config names
        // this box "yomi" but `local_host_name()` actually returns
        // "yomi-strix" (an FQDN/typo/rename mismatch). Nothing here special-
        // cases that — `sakaki` still compares normally — but the section
        // is flagged as not self-declared so the gap is discoverable.
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("sakaki", "ssh://khoa@h")]))]);
        let peers = vec![peer("sakaki", true, Some("ssh://khoa@h"))];
        let report = drift(&meshes, &peers, "yomi-strix");
        assert!(!report.sections[0].self_declared);
        assert_eq!(report.sections[0].rows, Vec::new(), "sakaki still compares cleanly regardless");
    }

    #[test]
    fn render_report_notes_a_mesh_that_does_not_self_declare_this_box() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("sakaki", "ssh://khoa@h")]))]);
        let peers = vec![peer("sakaki", true, Some("ssh://khoa@h"))];
        let report = drift(&meshes, &peers, "yomi-strix");
        let text = render_report(&report, "yomi-strix");
        assert!(text.contains("not named in mesh.home"), "{text}");
        assert!(text.contains("yomi-strix"), "{text}");
    }

    #[test]
    fn render_report_is_silent_when_this_box_is_self_declared() {
        let meshes = BTreeMap::from([("home".to_string(), mesh(&[("this-box", "ssh://khoa@self")]))]);
        let report = drift(&meshes, &[], "this-box");
        let text = render_report(&report, "this-box");
        assert!(!text.contains("note:"), "{text}");
    }

    // ── determinism ──────────────────────────────────────────────────────────

    #[test]
    fn two_shuffled_peer_orderings_render_an_identical_report() {
        let meshes = BTreeMap::from([(
            "home".to_string(),
            mesh(&[("sakaki", "ssh://khoa@h1"), ("chiyo", "ssh://khoa@h2"), ("osaka", "ssh://khoa@h3")]),
        )]);
        let a = vec![
            peer("sakaki", true, Some("ssh://khoa@h1")),
            peer("chiyo", false, None),
            peer("osaka", true, Some("ssh://khoa@wrong")),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(drift(&meshes, &a, "this-box"), drift(&meshes, &b, "this-box"));
    }

    #[test]
    fn bare_mesh_with_nothing_declared_and_nothing_paired_still_renders() {
        let report = drift(&BTreeMap::new(), &[], "this-box");
        assert_eq!(
            render_report(&report, "this-box"),
            "no mesh declared — see `aoide config` for [mesh.<name>]"
        );
    }

    // ── handler wiring ──────────────────────────────────────────────────────

    #[test]
    fn handle_mesh_is_ok_with_a_report_when_config_loads() {
        // A sandboxed root with no config.toml at all still loads (an absent
        // file is UNMANAGED-empty, not an error) — status is Ok and the
        // envelope carries a `report`, never a `reason`.
        let out = with_config_root("ok", |_dir| handle_mesh(&cli_inv(&["mesh"])));
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        let data = out.data.as_ref().expect("ok envelope carries data");
        assert!(data.get("report").is_some(), "{data:?}");
        assert!(data.get("reason").is_none(), "{data:?}");
    }

    #[test]
    fn handle_mesh_is_error_when_config_fails_to_load() {
        // `grant` values are validated against the closed capability
        // vocabulary at load time — "root" is not a member, so this file
        // never parses into a `Loaded`. The module doc's one carve-out:
        // drift itself never fails, but a config that won't load does.
        let out = with_config_root("error", |dir| {
            std::fs::write(dir.join("config.toml"), "[mesh.home]\ngrant = [\"root\"]\n").unwrap();
            handle_mesh(&cli_inv(&["mesh"]))
        });
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
        let data = out.data.as_ref().expect("error envelope carries data");
        assert_eq!(data.get("reason").and_then(|v| v.as_str()), Some("config-unreadable"), "{data:?}");
        assert!(data.get("report").is_none(), "{data:?}");
    }

    // ── mesh pair: selection ────────────────────────────────────────────────

    /// A mesh whose four declared peers cover every drift class plus this
    /// box itself — one fixture the selection rulings are all read off.
    fn converge_fixture() -> (BTreeMap<String, Mesh>, Vec<Peer>) {
        let mut m = mesh(&[
            ("this-box", "ssh://khoa@self"),
            ("sakaki", "ssh://khoa@h1"),
            ("chiyo", "ssh://khoa@h2"),
            ("osaka", "ssh://khoa@h3"),
            ("yuzu", "ssh://khoa@h4"),
        ]);
        m.grant = None;
        let peers = vec![
            // sakaki: no record at all -> missing
            peer("chiyo", false, None),                    // unverified
            peer("osaka", true, Some("ssh://khoa@h3")),     // matches -> no row
            peer("yuzu", true, Some("ssh://khoa@wrong")),   // via-mismatch
        ];
        (BTreeMap::from([("home".to_string(), m)]), peers)
    }

    #[test]
    fn a_converge_selects_exactly_the_missing_and_unverified_peers_in_declared_order() {
        let (meshes, peers) = converge_fixture();
        let report = drift(&meshes, &peers, "this-box");
        let plan = plan(&report.sections[0], &meshes["home"]);
        let paired: Vec<&str> = plan
            .iter()
            .filter(|p| matches!(p.action, PlannedAction::Pair { .. }))
            .map(|p| p.peer.as_str())
            .collect();
        // chiyo (unverified) before sakaki (missing) — lexicographic by
        // declared name, never by drift class.
        assert_eq!(paired, vec!["chiyo", "sakaki"]);
    }

    #[test]
    fn a_converge_never_touches_this_box_or_a_peer_that_already_matches() {
        let (meshes, peers) = converge_fixture();
        let report = drift(&meshes, &peers, "this-box");
        let plan = plan(&report.sections[0], &meshes["home"]);
        let named: Vec<&str> = plan.iter().map(|p| p.peer.as_str()).collect();
        assert!(!named.contains(&"this-box"), "the local box is invisible, not a skipped row: {named:?}");
        assert!(!named.contains(&"osaka"), "an already-matching peer is not a row at all: {named:?}");
    }

    #[test]
    fn a_via_mismatch_is_skipped_and_names_the_human_re_pair_as_the_fix() {
        let (meshes, peers) = converge_fixture();
        let report = drift(&meshes, &peers, "this-box");
        let plan = plan(&report.sections[0], &meshes["home"]);
        let yuzu = plan.iter().find(|p| p.peer == "yuzu").expect("yuzu is planned");
        match &yuzu.action {
            PlannedAction::Skip { reason } => assert_eq!(reason, "via-mismatch; fix with `aoide pair yuzu`"),
            other => panic!("a verified peer is never re-paired by a converge: {other:?}"),
        }
    }

    #[test]
    fn a_second_converge_over_a_converged_mesh_is_all_skipped() {
        // §2.2's payoff, stated as a test: once the missing/unverified peers
        // are paired at their declared hops, the only rows left are the
        // via-mismatches, and every one of them is a skip.
        let (meshes, _) = converge_fixture();
        let peers = vec![
            peer("sakaki", true, Some("ssh://khoa@h1")),
            peer("chiyo", true, Some("ssh://khoa@h2")),
            peer("osaka", true, Some("ssh://khoa@h3")),
            peer("yuzu", true, Some("ssh://khoa@wrong")),
        ];
        let report = drift(&meshes, &peers, "this-box");
        let plan = plan(&report.sections[0], &meshes["home"]);
        assert!(
            plan.iter().all(|p| matches!(p.action, PlannedAction::Skip { .. })),
            "a re-run converges nothing: {plan:?}"
        );
    }

    // ── mesh pair: the outcome fold ─────────────────────────────────────────

    #[test]
    fn a_committed_ceremony_folds_to_completed() {
        let out = Outcome::ok("pair", "paired with `sakaki` — verified, granted read")
            .with_data(json!({ "confirmed": true, "peer": "sakaki" }));
        assert_eq!(classify(&out, None), ConvergeOutcome::Completed);
    }

    #[test]
    fn a_ceremony_that_left_an_entry_parked_folds_to_parked_with_its_resumable_id() {
        let out = Outcome::ok("pair", "no answer from `osaka` within 600s")
            .with_data(json!({ "reason": "wait-timeout", "id": "4f2a91bc" }));
        assert_eq!(
            classify(&out, Some("4f2a91bc".to_string())),
            ConvergeOutcome::Parked { id: "4f2a91bc".into(), detail: "no answer from `osaka` within 600s".into() }
        );
    }

    #[test]
    fn a_mistyped_reply_code_is_parked_not_unreachable_because_the_entry_survives() {
        // An Error envelope whose entry is still parked is resumable, and
        // the fold says so — it keys on what the parked store holds, never
        // on the envelope's `data.reason` wording.
        let out = Outcome::error("pair", "reply-code mismatch — try 1 of 3")
            .with_data(json!({ "reason": "code-mismatch", "id": "4f2a91bc", "tries": 1 }));
        assert!(matches!(classify(&out, Some("4f2a91bc".to_string())), ConvergeOutcome::Parked { .. }));
    }

    #[test]
    fn an_offline_box_folds_to_unreachable_and_carries_no_resumable_id() {
        // `park_outbound` runs only after both ceremony POSTs succeed, so a
        // request to an offline box parks nothing — the variant has no id
        // field at all, so no report can imply a resume that would fail.
        let out = Outcome::error("pair", "sending the pairing request to http://127.0.0.1:8710/: connection refused")
            .with_data(json!({ "reason": "fetch-failed", "url": "http://127.0.0.1:8710/" }));
        let outcome = classify(&out, None);
        assert!(matches!(outcome, ConvergeOutcome::Unreachable { .. }), "{outcome:?}");
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json.get("outcome").and_then(|v| v.as_str()), Some("unreachable"));
        assert!(json.get("id").is_none(), "UNREACHABLE never carries a resumable id: {json}");
    }

    #[test]
    fn an_id_on_an_envelope_the_ceremony_never_parked_is_still_unreachable() {
        // A reveal that fails carries the APPROVER's id, but `park_outbound`
        // has not run yet — nothing on this side is resumable, and the fold
        // asks the parked store rather than trusting the envelope's `id`.
        let out = Outcome::error("pair", "revealing the nonce to http://127.0.0.1:8710/: HTTP 500")
            .with_data(json!({ "reason": "reveal-http-error", "id": "4f2a91bc" }));
        assert!(matches!(classify(&out, None), ConvergeOutcome::Unreachable { .. }));
    }

    // ── mesh pair: sameOperator is a note and nothing else ──────────────────

    fn one_row() -> Vec<ConvergeRow> {
        vec![ConvergeRow { peer: "sakaki".into(), outcome: ConvergeOutcome::Completed }]
    }

    #[test]
    fn same_operator_true_adds_a_note_and_changes_no_row_and_no_count() {
        let plain = mesh(&[("sakaki", "ssh://khoa@h")]);
        let mut claimed = plain.clone();
        claimed.same_operator = true;
        let a = converge_report("home", &plain, one_row());
        let b = converge_report("home", &claimed, one_row());
        assert_eq!(a.rows, b.rows, "the flag changes no per-peer result");
        assert_eq!(a.rows.len(), b.rows.len());
        assert!(a.same_operator_note.is_none());
        let note = b.same_operator_note.as_deref().expect("a declared sameOperator is noted");
        assert!(note.starts_with("mesh.home declares sameOperator = true"), "{note}");
        assert!(note.contains("not yet ruled"), "{note}");
        assert!(note.contains("both codes typed"), "{note}");
    }

    #[test]
    fn the_same_operator_note_is_its_own_json_field_never_a_per_peer_result() {
        let mut claimed = mesh(&[("sakaki", "ssh://khoa@h")]);
        claimed.same_operator = true;
        let json = serde_json::to_value(converge_report("home", &claimed, one_row())).unwrap();
        assert!(json.get("sameOperatorNote").is_some(), "{json}");
        let row = &json["rows"][0];
        assert_eq!(row.get("outcome").and_then(|v| v.as_str()), Some("completed"));
        assert!(row.get("sameOperatorNote").is_none(), "never folded into a row: {row}");
    }

    #[test]
    fn same_operator_true_selects_exactly_what_same_operator_false_selects() {
        let (mut meshes, peers) = converge_fixture();
        let report_false = drift(&meshes, &peers, "this-box");
        let plan_false = plan(&report_false.sections[0], &meshes["home"]);
        meshes.get_mut("home").unwrap().same_operator = true;
        let report_true = drift(&meshes, &peers, "this-box");
        let plan_true = plan(&report_true.sections[0], &meshes["home"]);
        assert_eq!(plan_false, plan_true, "the converge runs the flag's `false` path either way");
    }

    #[test]
    fn the_rendered_report_carries_the_note_below_the_rows_never_as_one() {
        let mut claimed = mesh(&[("sakaki", "ssh://khoa@h")]);
        claimed.same_operator = true;
        let text = render_converge(&converge_report("home", &claimed, one_row()));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].contains("sakaki") && lines[0].contains("completed"), "{text}");
        assert!(lines.last().unwrap().contains("sameOperator = true"), "{text}");
        assert_eq!(lines.iter().filter(|l| l.contains("sakaki")).count(), 1, "the note is not a row: {text}");
    }

    // ── mesh pair: the declared grant reaches the ceremony ──────────────────

    #[test]
    fn a_declared_grant_reaches_pair_finish_and_an_absent_one_is_none_never_empty() {
        let inv = cli_inv(&["mesh", "pair"]);
        let none = converge_finish(&inv, &mesh(&[])).expect("no flags, no parse failure");
        assert_eq!(none.grant, None, "an absent declaration falls through to resolve_grant, never to []");

        let mut declared = mesh(&[]);
        declared.grant = Some(vec!["read".to_string(), "spawn".to_string()]);
        let some = converge_finish(&inv, &declared).expect("no flags, no parse failure");
        assert_eq!(some.grant, Some(vec!["read".to_string(), "spawn".to_string()]));
        assert_ne!(none.grant, some.grant, "a mesh that declares a grant stamps a different one");

        let mut empty = mesh(&[]);
        empty.grant = Some(Vec::new());
        let nothing = converge_finish(&inv, &empty).expect("no flags, no parse failure");
        assert_eq!(nothing.grant, Some(Vec::new()), "`grant = []` is the real `grant nothing` intent");
        assert_ne!(nothing.grant, none.grant);
    }

    #[test]
    fn yes_buys_the_preflight_and_never_reaches_the_code_gate() {
        // `commands::outbound_gate_from` reads `skip_confirm` BEFORE it
        // tests for a tty, so a `--yes` carried into the finish would
        // resolve every leg to `CodeGate::Unavailable` — the whole converge
        // parks, nothing commits, and the operator types N ids by hand.
        // `--yes` buys exactly one thing here: the pre-flight, which
        // `the_preflight_is_refused_off_a_tty_without_yes_and_skipped_with_it`
        // pins separately off the invocation.
        let mut inv = cli_inv(&["mesh", "pair"]);
        inv.flags.insert("yes".to_string(), "true".to_string());
        let finish = converge_finish(&inv, &mesh(&[])).expect("--yes parses");
        assert!(!finish.skip_confirm, "--yes must not reach the ceremony's own gate: {finish:?}");
        assert!(inv.flag_present("yes"), "and it must still be readable for the pre-flight");
    }

    // ── mesh pair: which mesh, and the pre-flight ───────────────────────────

    #[test]
    fn a_bare_converge_takes_the_one_declared_mesh_and_names_them_when_there_are_several() {
        let one = drift(&BTreeMap::from([("home".to_string(), mesh(&[]))]), &[], "this-box");
        assert_eq!(resolve_section("mesh.pair", &one, None).unwrap().name, "home");

        let two = drift(
            &BTreeMap::from([("home".to_string(), mesh(&[])), ("lab".to_string(), mesh(&[]))]),
            &[],
            "this-box",
        );
        let err = resolve_section("mesh.pair", &two, None).unwrap_err();
        assert_eq!(err.status, aoide_protocol::output::Status::Usage, "{err:?}");
        assert!(err.message.contains("home, lab"), "{}", err.message);

        let none = drift(&BTreeMap::new(), &[], "this-box");
        let err = resolve_section("mesh.pair", &none, None).unwrap_err();
        assert_eq!(err.data.unwrap().get("reason").and_then(|v| v.as_str()), Some("no-mesh-declared"));
    }

    #[test]
    fn naming_a_mesh_that_is_not_declared_lists_the_ones_that_are() {
        let one = drift(&BTreeMap::from([("home".to_string(), mesh(&[]))]), &[], "this-box");
        let err = resolve_section("mesh.pair", &one, Some("lab")).unwrap_err();
        assert!(err.message.contains("no `[mesh.lab]`"), "{}", err.message);
        assert!(err.message.contains("declared: home"), "{}", err.message);
    }

    #[test]
    fn the_preflight_lists_every_peer_its_hop_the_grant_and_the_wait() {
        let (meshes, peers) = converge_fixture();
        let mut m = meshes["home"].clone();
        m.grant = Some(vec!["read".to_string()]);
        let report = drift(&meshes, &peers, "this-box");
        let plan = plan(&report.sections[0], &m);
        let text = render_preflight("home", &m, &plan, 600);
        assert!(text.contains("pair chiyo via ssh://khoa@h2"), "{text}");
        assert!(text.contains("pair sakaki via ssh://khoa@h1"), "{text}");
        assert!(text.contains("skip yuzu"), "{text}");
        assert!(text.contains("grant: read (declared by mesh.home)"), "{text}");
        assert!(text.contains("600s per peer"), "{text}");
    }

    #[test]
    fn the_preflight_is_refused_off_a_tty_without_yes_and_skipped_with_it() {
        let (meshes, peers) = converge_fixture();
        let m = &meshes["home"];
        let report = drift(&meshes, &peers, "this-box");
        let plan = plan(&report.sections[0], m);

        let mut inv = cli_inv(&["mesh", "pair"]);
        inv.door = Door::A2a; // never interactive
        let err = confirm_preflight("mesh.pair", &inv, "home", m, &plan, 600).unwrap_err();
        assert!(err.message.contains("re-run with --yes"), "{}", err.message);
        assert_eq!(err.data.unwrap().get("reason").and_then(|v| v.as_str()), Some("no-preflight-confirm"));

        inv.flags.insert("yes".to_string(), "true".to_string());
        assert!(confirm_preflight("mesh.pair", &inv, "home", m, &plan, 600).is_ok());
    }

    #[test]
    fn a_converge_with_nothing_to_pair_needs_no_confirmation_at_all() {
        // All-`skipped` (the idempotent second run) sends nothing, so there
        // is nothing to confirm — it must not refuse off a non-tty door.
        let (meshes, _) = converge_fixture();
        let peers = vec![peer("yuzu", true, Some("ssh://khoa@wrong"))];
        let report = drift(&meshes, &peers, "this-box");
        let plan: Vec<PlannedPeer> = plan(&report.sections[0], &meshes["home"])
            .into_iter()
            .filter(|p| matches!(p.action, PlannedAction::Skip { .. }))
            .collect();
        let mut inv = cli_inv(&["mesh", "pair"]);
        inv.door = Door::A2a;
        assert!(confirm_preflight("mesh.pair", &inv, "home", &meshes["home"], &plan, 600).is_ok());
    }

    // ── mesh pair: handler wiring ───────────────────────────────────────────

    #[test]
    fn handle_mesh_pair_with_no_mesh_declared_refuses_and_pairs_nothing() {
        let out = with_config_root("pair-nomesh", |_dir| handle_mesh_pair(&cli_inv(&["mesh", "pair"])));
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
        let data = out.data.as_ref().expect("error envelope carries data");
        assert_eq!(data.get("reason").and_then(|v| v.as_str()), Some("no-mesh-declared"), "{data:?}");
    }

    #[test]
    fn handle_mesh_pair_is_error_when_config_fails_to_load() {
        let out = with_config_root("pair-badconfig", |dir| {
            std::fs::write(dir.join("config.toml"), "[mesh.home]\ngrant = [\"root\"]\n").unwrap();
            handle_mesh_pair(&cli_inv(&["mesh", "pair"]))
        });
        assert_eq!(out.status, aoide_protocol::output::Status::Error, "{out:?}");
        let data = out.data.as_ref().expect("error envelope carries data");
        assert_eq!(data.get("reason").and_then(|v| v.as_str()), Some("config-unreadable"), "{data:?}");
    }

    #[test]
    fn handle_mesh_pair_over_an_all_skipped_mesh_dials_nothing_and_reports_every_skip() {
        // A declaration whose only drift is a via-mismatch: the converge
        // sends nothing (no tunnel, no POST, no confirm) and comes back with
        // one `skipped` row — the idempotent second run, end to end.
        let out = with_config_root("pair-skipped", |dir| {
            std::fs::write(
                dir.join("config.toml"),
                "[mesh.home.peers]\nyuzu = \"ssh://khoa@h4\"\n",
            )
            .unwrap();
            std::fs::create_dir_all(dir).unwrap();
            let peers = vec![peer("yuzu", true, Some("ssh://khoa@wrong"))];
            aoide_storage::peer_store::save_peers(&peers).unwrap();
            handle_mesh_pair(&cli_inv(&["mesh", "pair"]))
        });
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        assert!(out.changed.is_empty(), "nothing was written: {out:?}");
        assert!(out.message.contains("yuzu") && out.message.contains("skipped"), "{}", out.message);
        let report = out.data.as_ref().and_then(|d| d.get("report")).expect("ok envelope carries a report");
        assert_eq!(report["rows"].as_array().map(Vec::len), Some(1), "{report}");
        assert_eq!(report["rows"][0]["outcome"].as_str(), Some("skipped"), "{report}");
    }

    #[test]
    fn handle_mesh_pair_refuses_wait_zero_when_the_mesh_declares_a_grant() {
        // The same rule `pair --allow --wait 0` already holds: a parked
        // entry never carries a grant, so a declared one would be silently
        // dropped on the resume. Refused up front, nothing sent.
        let out = with_config_root("pair-detached-grant", |dir| {
            std::fs::write(
                dir.join("config.toml"),
                "[mesh.home]\ngrant = [\"read\"]\n\n[mesh.home.peers]\nsakaki = \"ssh://khoa@h1\"\n",
            )
            .unwrap();
            let mut inv = cli_inv(&["mesh", "pair"]);
            inv.flags.insert("wait".to_string(), "0".to_string());
            inv.flags.insert("yes".to_string(), "true".to_string());
            handle_mesh_pair(&inv)
        });
        assert_eq!(out.status, aoide_protocol::output::Status::Usage, "{out:?}");
        assert!(out.message.contains("mesh.home declares a grant"), "{}", out.message);
        assert!(out.message.contains("never persisted on a parked entry"), "{}", out.message);
        assert!(!out.message.contains("retype --allow"), "no flag was typed here: {}", out.message);
        let data = out.data.as_ref().expect("usage envelope carries data");
        assert_eq!(data.get("reason").and_then(|v| v.as_str()), Some("detached-grant"), "{data:?}");
    }

    #[test]
    fn wait_zero_over_a_converged_mesh_is_ok_even_when_a_grant_is_declared() {
        // The refusal above is about a grant that would be DROPPED, and a
        // converged mesh sends nothing to drop it from. Refusing here would
        // make `mesh pair --wait 0 --json` — the scripted drift check — fail
        // forever on any mesh that declares a grant, contradicting the
        // all-skipped second run the command promises.
        let out = with_config_root("pair-converged-grant", |dir| {
            std::fs::write(
                dir.join("config.toml"),
                "[mesh.home]\ngrant = [\"read\"]\n\n[mesh.home.peers]\nyuzu = \"ssh://khoa@h4\"\n",
            )
            .unwrap();
            let peers = vec![peer("yuzu", true, Some("ssh://khoa@wrong"))];
            aoide_storage::peer_store::save_peers(&peers).unwrap();
            let mut inv = cli_inv(&["mesh", "pair"]);
            inv.flags.insert("wait".to_string(), "0".to_string());
            handle_mesh_pair(&inv)
        });
        assert_eq!(out.status, aoide_protocol::output::Status::Ok, "{out:?}");
        assert!(out.changed.is_empty(), "nothing was written: {out:?}");
        let report = out.data.as_ref().and_then(|d| d.get("report")).expect("ok envelope carries a report");
        assert_eq!(report["rows"][0]["outcome"].as_str(), Some("skipped"), "{report}");
    }

    #[test]
    fn parked_id_for_answers_about_the_name_not_about_this_run() {
        // `park_outbound` dedups by pubkey, so an entry an earlier converge
        // left behind outlives a request that never reached the box. The id
        // it returns is genuinely resumable — it is simply not proof that
        // THIS run made progress, which is why a parked row prints its
        // detail beside the id.
        with_config_root("parked-id", |_dir| {
            assert_eq!(parked_id_for("sakaki"), None, "nothing parked yet");
            aoide_storage::pairing::park_outbound(aoide_storage::pairing::OutboundPairingRequest {
                id: "abc123".to_string(),
                url: "http://127.0.0.1:8710/".to_string(),
                name: "sakaki".to_string(),
                pubkey_hex: "aa".repeat(32),
                requester_nonce_hex: "bb".repeat(16),
                approver_nonce_hex: "cc".repeat(16),
                requested_at: "2026-09-03T00:00:00Z".to_string(),
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                state: aoide_storage::pairing::OutboundState::AwaitingApproval,
                tries: 0,
                via: Some("ssh://khoa@h1".to_string()),
            })
            .expect("parking writes to the scratch root");
            assert_eq!(parked_id_for("sakaki").as_deref(), Some("abc123"));
            assert_eq!(parked_id_for("osaka"), None, "another name is not this one's entry");
        });
    }
}
