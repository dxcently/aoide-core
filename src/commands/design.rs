//! `rice design status` — report the active design-mode marker
//! (`stage/design.json`) or that no design session is active.
//!
//! Phase A: read-only. `rice design enter`/`exit`/`sync` (which would WRITE
//! the marker) are later-phase work — see CONTRACTS.md §4's `design.json`
//! entry for the honest state of the lifecycle today.

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{cmd, Registry};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["rice", "design", "status"],
        summary: "Report the active design session (song, intent doc, sources) or that none is active.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_design_status,
    ));
}

/// `rice design status` — read `stage/design.json` via `aoide-storage` and
/// report it verbatim, or `{"active": false}` when no marker exists.
fn handle_design_status(_inv: &Invocation) -> Outcome {
    match aoide_storage::design::load_design_marker() {
        None => Outcome::ok("rice.design.status", "no design session active")
            .with_data(json!({ "active": false })),
        Some(marker) => Outcome::ok(
            "rice.design.status",
            format!("design session active for `{}`", marker.song),
        )
        .with_data(json!({
            "active": true,
            "song": marker.song,
            "enteredAt": marker.entered_at,
            "by": marker.by,
            "intent": marker.intent,
            "intentPresent": marker.intent_present,
            "sources": marker.sources,
            "carriedSlots": marker.carried_slots,
        })),
    }
}

// ── Tests (rice design status) ───────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::*;
    use crate::output::Status;
    use aoide_storage::design::{save_design_marker, DesignMarker};

    #[test]
    fn status_reports_inactive_when_no_marker_exists() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-status-none");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let out = handle_design_status(&inv(&["rice", "design", "status"], &[]));
        assert_eq!(out.status, Status::Ok);
        assert_eq!(out.data.unwrap()["active"], false);
        let _ = std::fs::remove_dir_all(&stage);
    }

    #[test]
    fn status_reports_the_marker_fields_when_one_exists() {
        let _g = crate::env_lock().lock().unwrap();
        let _s = EnvSaver::capture(&["AOIDE_STAGE_DIR"]);
        let stage = unique_tmp("design-status-active");
        std::env::set_var("AOIDE_STAGE_DIR", &stage);

        let marker = DesignMarker {
            song: "moonlight".to_string(),
            entered_at: "2026-08-02T00:00:00Z".to_string(),
            by: Some("khoa".to_string()),
            intent: "/home/khoa/Aoide/song/songbook/moonlight/design/intent.md".to_string(),
            intent_present: true,
            sources: vec!["stage/drachma.json".to_string()],
            carried_slots: vec![],
        };
        save_design_marker(&marker).unwrap();

        let out = handle_design_status(&inv(&["rice", "design", "status"], &[]));
        assert_eq!(out.status, Status::Ok);
        let data = out.data.unwrap();
        assert_eq!(data["active"], true);
        assert_eq!(data["song"], "moonlight");
        assert_eq!(data["enteredAt"], "2026-08-02T00:00:00Z");
        assert_eq!(data["by"], "khoa");
        assert_eq!(
            data["intent"],
            "/home/khoa/Aoide/song/songbook/moonlight/design/intent.md"
        );
        assert_eq!(data["intentPresent"], true);
        assert_eq!(data["sources"][0], "stage/drachma.json");
        assert!(data["carriedSlots"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&stage);
    }
}
