//! Integration test for `aoide conductor`'s core plumbing.
//!
//! We point `$AOIDE_STAGE_DIR` and `$AOIDE_AUDIT_LOG` at a tempdir, seed
//! fixture JSON, and drive the app-state layer end to end: load → recompute →
//! selection → a real `dispatch` (which writes the tempdir audit log, proving
//! the "every mutation is audited" seam works against the test rig). No
//! terminal is opened — the app core is headless by design.

use aoide::conductor::app::{App, Panel};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::Path;

/// A unique tempdir under the OS temp root (no external tempfile crate — the
/// lock stays lean). Returns the dir; the test process cleans it at the end.
fn make_stage(tag: &str) -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    let uniq = format!(
        "aoide-conductor-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    dir.push(uniq);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

fn seed(dir: &Path) {
    write(
        dir,
        "projects.json",
        r#"{ "schemaVersion":"0", "projects":[
              {"name":"aoide","path":"/home/k/Aoide"},
              {"name":"wiki","path":"/home/k/Wiki"} ] }"#,
    );
    write(
        dir,
        "sessions.json",
        r#"{ "schemaVersion":"0", "sessions":[
              {"sessionId":"a","agent":"claude","windowAddress":"0x1","cwd":"/home/k/Aoide","state":"running","startedAt":"1"},
              {"sessionId":"b","agent":"claude","windowAddress":"0x2","cwd":"/home/k/Aoide","state":"done","startedAt":"2"} ] }"#,
    );
    write(
        dir,
        "hooks.json",
        r#"{ "schemaVersion":"0", "hooks":[
              {"sessionId":"a","phase":"awaiting","updatedAt":"3"} ] }"#,
    );
    write(
        dir,
        "livery.json",
        r##"{ "palette": {"bg":"#1e1e2e","fg":"#cdd6f4","accent":"#89b4fa","urgent":"#f38ba8"} }"##,
    );
}

/// One serialised test: the app core reads env at call time, so we mustn't race
/// another env-mutating test. Rust runs integration test *files* each in their
/// own binary, and within this file the single `#[test]` runs alone — so no
/// in-file lock is needed.
#[test]
fn app_loads_recomputes_selects_and_dispatches_against_the_tempdir() {
    let stage = make_stage("core");
    let audit = stage.join("log");
    std::env::set_var("AOIDE_STAGE_DIR", &stage);
    std::env::set_var("AOIDE_AUDIT_LOG", &audit);
    seed(&stage);

    // ── load ──
    let mut app = App::load(aoide::dispatch::dispatch);
    assert_eq!(app.projects.len(), 2, "both projects loaded");
    assert_eq!(app.sessions.len(), 2, "both sessions loaded");

    // ── recompute: the hook phase overrides session `a`'s state ──
    // Roster `running` folds to canonical `working`; the later hook phase
    // `awaiting` overrides it, and both are rendered from the one vocabulary.
    let merged = app.merged();
    let a = merged.iter().find(|s| s.session_id == "a").unwrap();
    assert_eq!(
        a.state, "awaiting",
        "latest hook phase (canonical) merged into live state"
    );

    // ── palette parsed from livery.json ──
    assert!(
        app.palette.accent.is_some(),
        "accent colour mapped from livery.json"
    );

    // ── selection: j moves down over the flattened DAG rows (group headers
    // interleaved with session subtrees), clamped at the last row ──
    app.select_panel(Panel::Sessions);
    let n_rows = app.dag_rows().len();
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    assert_eq!(app.dag_sel, 1.min(n_rows - 1), "j advances one row");
    // Drive the cursor to the bottom and confirm it never runs off the end.
    for _ in 0..n_rows + 3 {
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    }
    assert_eq!(app.dag_sel, n_rows - 1, "selection clamps at the last row");
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
    assert!(app.dag_sel < n_rows, "selection stays in bounds");
    // ── dispatch: `session prune` drops the `done` session `b` and audits it ──
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    let outcome = app
        .last_outcome
        .as_ref()
        .expect("prune produced an outcome");
    assert_eq!(outcome.command, "session.prune");
    // state reloaded after dispatch: only session `a` remains.
    assert_eq!(app.sessions.len(), 1, "done session pruned");
    assert_eq!(app.sessions[0].session_id, "a");

    // ── the dispatch wrote an audit line into the tempdir log ──
    let log = std::fs::read_to_string(&audit).expect("audit log written to tempdir");
    assert!(
        log.contains("session.prune"),
        "prune recorded in the audit log"
    );

    // ── the LOG panel picks up the freshly-written audit line ──
    app.reload_all();
    assert!(
        app.log.iter().any(|l| l.command == "session.prune"),
        "LOG tail includes the prune record"
    );

    // ── project add via dispatch lands on disk + in state ──
    // (The path must be a real absolute dir — `project add` rejects
    // relative/nonexistent paths now — so a subdir of the tempdir stands in.)
    let newproj_dir = stage.join("newproj");
    std::fs::create_dir_all(&newproj_dir).unwrap();
    app.dispatch(
        &["project", "add"],
        &["newproj".to_string(), newproj_dir.to_string_lossy().into_owned()],
    );
    assert!(
        app.projects.iter().any(|p| p.name == "newproj"),
        "added project loaded"
    );
    let projects_json = std::fs::read_to_string(stage.join("projects.json")).unwrap();
    assert!(
        projects_json.contains("newproj"),
        "project persisted to stage file"
    );

    // ── a full frame renders through ratatui without panicking ──
    // The view layer is headless-testable: a TestBackend gives us the exact
    // buffer the tty would show, so we assert on the composed frame end to end.
    app.select_panel(Panel::Sessions);
    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| aoide::conductor::ui::draw(f, &app)).unwrap();
    let buf = term.backend().buffer();
    assert_eq!(buf.area.height, 30, "frame is exactly the terminal height");
    let joined: String = buf
        .content
        .chunks(buf.area.width.max(1) as usize)
        .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("aoide"), "SESSIONS panel shows a project");
    assert!(joined.contains("SESSIONS"), "active panel title rendered");

    // cleanup
    std::env::remove_var("AOIDE_STAGE_DIR");
    std::env::remove_var("AOIDE_AUDIT_LOG");
    let _ = std::fs::remove_dir_all(&stage);
}
