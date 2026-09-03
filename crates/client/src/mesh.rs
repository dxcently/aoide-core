//! `aoide mesh` (task #135 P4): compare every declared `[mesh.<name>]`
//! (`aoide_storage::config::Mesh`) against the live peer registry
//! (`aoide_storage::peer_store::load_peers`) and report where they diverge.
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
//! `grant` DECLARES a capability set (`aoide_storage::config::Mesh::grant`'s
//! own doc) — nothing yet reads it to actually grant anything at
//! first-verify, and this module does not wait on that being decided: a
//! human may freely narrow or widen a live peer's `allows` via `peer
//! allow`, and comparing it against a mesh's `grant` would turn an
//! intentional, one-off admin action into permanent reported drift
//! regardless of whether `grant` ever becomes live. This module has no
//! standing to second-guess that decision on every subsequent `mesh` call.
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
//! P5 (`mesh pair`, not yet built — out of scope here) will consume this
//! same [`drift`] to decide what to converge; this module stops at
//! reporting.

use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{cmd, Registry};
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

/// `mesh`, appended newest (Registry discipline, `pkgs/aoide/crates/
/// AGENTS.md`) into `cli`'s `commands::all()` — LAST, after every other
/// `register*` call.
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
}
