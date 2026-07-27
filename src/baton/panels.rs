//! The panels, the layout, and the help overlay.
//!
//! This frontend is built to conduct the running agent sessions, not to manage
//! files: its centre of gravity is those sessions, so the SESSIONS roster is the
//! hero
//! panel and takes the whole body, and the rest orbit it: PROJECTS anchors the
//! roots sessions hang under, LOG tails the audit feed those sessions emit,
//! STATUS reports the stage tree that carries the lot. Nothing here manages
//! anything that isn't an Aoide element — files, processes and logs already have
//! yazi, btop and journald.
//!
//! Every panel is a pure `App` → body-lines function; [`frame`] (components)
//! wraps the box-drawing chrome around what it returns, so the same state always
//! paints the same rows and a panel is unit-testable without a terminal. A panel
//! never runs a command — it reads the loaded stage data plus the flattened
//! [`DagRow`](crate::baton::app::DagRow) model the app already walked, and shows
//! the last dispatched [`Outcome`](crate::output::Outcome) on the status line.
//! Mutation lives entirely in [`App`]'s key handlers, which route through the one
//! dispatcher.
//!
//! Ornament discipline (borrowed wholesale from the chrome): the musical SMP
//! glyphs — the clef-tail end-cap, the stave-run divider, and the state glyphs
//! themselves — are the CONTENT, so they live on the brand header, the status
//! bar, and the roster rows, never inside the walled box math. Every rule that
//! has to line up with a `║` wall (the detail card, the legend row) is drawn in
//! width-1 ASCII so the right wall stays square.

use crate::baton::app::{is_done, App, DagRow, Palette, Panel};
use crate::baton::components as ui;
use crate::graph;

/// Compose the full screen — brand header, tab strip, the active panel filling
/// the body, and a status line — and hand back the visible rows; the caller pads
/// or truncates them to the terminal height. Whichever panel is active gets the
/// whole body, but SESSIONS is the one built to earn it.
pub fn layout(app: &App, cols: u16, rows: u16) -> Vec<String> {
    let pal = &app.palette;
    let mut out: Vec<String> = Vec::new();

    // Draw the brand header and the tab strip. Each takes one row.
    out.push(header(cols, pal));
    out.push(tab_strip(app.panel, cols, pal));

    // The body fills the height. Reserve 3 rows: header, tabs, status.
    let body_h = rows.saturating_sub(3).max(3);
    let body = match app.panel {
        Panel::Dag => dag_body(app, cols),
        Panel::Projects => projects_body(app, cols),
        Panel::Log => log_body(app, cols),
        Panel::Status => status_body(app, cols),
    };
    let framed = ui::frame(app.panel.title(), &body, cols, body_h, true, pal);
    out.extend(framed);

    // Draw the status line. Show an inline prompt when one is open. Else show
    // the last outcome message and the keymap hint.
    let hint = keymap_hint(app.panel);
    let msg = if let Some(input) = &app.input {
        format!("{}: {}▏", input.label, input.buffer)
    } else {
        app.status_message()
    };
    out.push(ui::status_bar(&msg, hint, cols, pal));

    out
}

/// The brand header — the clef-tail end-cap and the stave-run divider from the
/// ornament vocabulary, tinted with the palette accent, so the baton reads as a
/// sibling of the gadget dock the instant it opens. This is a non-walled seam,
/// so the SMP ornaments belong here.
fn header(cols: u16, pal: &Palette) -> String {
    let accent = pal.accent.map(ui::fg256).unwrap_or_default();
    let reset = if pal.accent.is_some() { ui::RESET } else { "" };
    let brand = format!(
        "{} aoide · baton {}  conduct the agent sessions",
        ui::END_CAP,
        ui::DIVIDER
    );
    format!("{accent}{}{}", ui::fit(&brand, cols as usize), reset)
}

/// The tab strip — the active panel in reverse video, the rest dimmed.
fn tab_strip(active: Panel, cols: u16, pal: &Palette) -> String {
    let accent = pal.accent.map(ui::fg256).unwrap_or_default();
    let mut s = String::new();
    for (i, p) in Panel::ALL.iter().enumerate() {
        let label = format!(" {} {} ", i + 1, p.title());
        if *p == active {
            s.push_str(&format!("{accent}{}{}{}", ui::REVERSE, label, ui::RESET));
        } else {
            s.push_str(&format!("{}{}{}", ui::DIM, label, ui::RESET));
        }
    }
    ui::fit(&s, cols as usize)
}

/// The status-line keymap hint for the active panel — Aoide cues only, since
/// those are the only verbs this frontend owns.
fn keymap_hint(panel: Panel) -> &'static str {
    match panel {
        Panel::Dag => {
            "j/k select · Enter jump/fold · h/l fold · L link · a add · d rm · p prune · e emit · ? help · q quit"
        }
        Panel::Projects => "j/k select · a add · d remove · Tab panel · ? help · q quit",
        Panel::Log => "Tab panel · ? help · q quit",
        Panel::Status => "Tab panel · ? help · q quit",
    }
}

// ── [1] SESSIONS — the roster the baton conducts (the heart of the app) ─────────

/// The agent-session roster — the view the baton conducts. It renders the app's
/// flattened [`DagRow`](crate::baton::app::DagRow) model directly: project group
/// headers (collapsible, `[live/total]` badge) interleaved with their session
/// subtrees, one selection index over the lot. Every session row carries the
/// agent, a musical state glyph, the state, the shortened cwd and the elapsed
/// clock; a fresh arrival wears an accent cue so the eye catches it; the selected
/// row inverts. Enter cues the selected session's window (or folds a group).
///
/// Order, grouping and the tree geometry are all pre-walked in `App::dag_rows`
/// from the graph pure functions — this panel re-derives nothing, so `j`/`k`
/// always tracks a real row and Enter never cues the wrong window.
pub fn dag_body(app: &App, cols: u16) -> Vec<String> {
    let rows = app.dag_rows();

    if rows.is_empty() {
        return empty_roster_art(cols);
    }

    let interior = (cols as usize).saturating_sub(2);
    let mut out: Vec<String> = Vec::new();

    // A glyph legend across the top — earns its keep twice, once as a key and
    // once as theme in the dead space above the roster. The musical glyphs ARE
    // the content here; the decorative DIVIDER ornament stays off this walled row
    // (its SMP cells would drift the right wall — legibility before flourish).
    out.push(ui::fit(
        &format!(
            "{DIM} ♪ working   𝄐 awaiting   𝄽 idle   𝄂 done   ◆ project (h/l fold){RST}",
            DIM = ui::DIM,
            RST = ui::RESET
        ),
        interior,
    ));

    for (i, row) in rows.iter().enumerate() {
        let selected = i == app.dag_sel;
        match row {
            DagRow::Group {
                name,
                path,
                live,
                total,
                folded,
            } => out.push(group_row(
                name, path, *live, *total, *folded, selected, interior,
            )),
            DagRow::Session { rec, prefix } => {
                let fresh = app.fresh.contains_key(&rec.session_id);
                out.push(session_row(
                    rec,
                    prefix,
                    fresh,
                    selected,
                    &app.palette,
                    interior,
                ));
            }
        }
    }

    // A live detail card for whatever session is selected — the rich per-session
    // read the operator owes themselves before cueing, tucked into the space
    // below the roster.
    if let Some(DagRow::Session { rec, .. }) = rows.get(app.dag_sel) {
        let merged = app.merged();
        out.push(String::new());
        out.extend(detail_card(rec, &merged, interior));
    }

    out
}

/// A collapsible project group header: the fold caret, a diamond anchor, the
/// name, its path, and the `[live/total]` session tally that hangs beneath it.
/// Folded groups swap the caret and drop everything below them.
fn group_row(
    name: &str,
    path: &str,
    live: usize,
    total: usize,
    folded: bool,
    selected: bool,
    interior: usize,
) -> String {
    let caret = if folded { "▸" } else { "▾" };
    let head = if path.is_empty() {
        format!("{caret} ◆ {name}  [{live}/{total}]")
    } else {
        format!(
            "{caret} ◆ {name}  {DIM}{path}{RST}  [{live}/{total}]",
            DIM = ui::DIM,
            RST = ui::RESET
        )
    };
    let styled = format!("{}{head}", ui::BOLD);
    if selected {
        format!("{}{}{}", ui::REVERSE, ui::fit(&styled, interior), ui::RESET)
    } else {
        ui::fit(&styled, interior)
    }
}

/// One session row: the pre-walked tree prefix, a fresh-arrival cue, a coloured
/// state glyph, id, agent, state, elapsed clock, and the shortened cwd — inverted
/// when it's the selected row. A session that appeared within the last few ticks
/// wears an accent `‣` marker (accent-tinted when a palette is present) so a new
/// arrival is impossible to miss.
fn session_row(
    s: &graph::SessionRecord,
    prefix: &str,
    fresh: bool,
    selected: bool,
    pal: &Palette,
    interior: usize,
) -> String {
    let glyph = state_glyph(&s.state);
    let color = state_color(&s.state, pal);
    let elapsed = elapsed_str(&s.started_at);
    let cwd = shorten_cwd(&s.cwd);
    // The fresh cue: an accent-tinted arrow in the gutter, or two spaces so the
    // columns still line up for the settled rows.
    let cue = if fresh {
        let accent = pal
            .accent
            .map(ui::fg256)
            .unwrap_or_else(|| ui::CYAN.to_string());
        format!("{accent}‣{RST}", RST = ui::RESET)
    } else {
        " ".to_string()
    };
    let row = format!(
        "{cue}{prefix}{color}{glyph}{RST} {id}  {DIM}{agent}{RST}  {color}{state}{RST}  {DIM}{elapsed}{RST}  {cwd}",
        RST = ui::RESET,
        DIM = ui::DIM,
        id = s.session_id,
        agent = s.agent,
        state = s.state,
    );
    if selected {
        format!("{}{}{}", ui::REVERSE, ui::fit(&row, interior), ui::RESET)
    } else {
        ui::fit(&row, interior)
    }
}

/// The detail card for the selected session — the who/where/when a conductor
/// needs before cueing, plus the parent chain walked back to the root, laid into
/// the dead space below the roster.
fn detail_card(
    s: &graph::SessionRecord,
    merged: &[graph::SessionRecord],
    interior: usize,
) -> Vec<String> {
    let color = state_color(&s.state, &Palette::default());
    let mut lines: Vec<String> = Vec::new();
    // A section rule in ASCII box-drawing (width-1 cells, so the wall stays
    // square) — the SMP ornaments live on the frame seams, not in this card.
    let label = " selected ";
    let rule_w = interior.saturating_sub(label.len());
    lines.push(ui::fit(
        &format!(
            "{DIM}─{label}{}{RST}",
            "─".repeat(rule_w),
            DIM = ui::DIM,
            RST = ui::RESET
        ),
        interior,
    ));
    lines.push(ui::fit(
        &format!(
            "  {color}{glyph}{RST} {id}   agent {agent}   state {color}{state}{RST}",
            color = color,
            glyph = state_glyph(&s.state),
            RST = ui::RESET,
            id = s.session_id,
            agent = if s.agent.is_empty() { "?" } else { &s.agent },
            state = s.state,
        ),
        interior,
    ));
    lines.push(ui::fit(&format!("  cwd     {}", s.cwd), interior));
    lines.push(ui::fit(
        &format!(
            "  window  {}   started {}",
            disp(&s.window_address),
            disp(&s.started_at)
        ),
        interior,
    ));
    // Parent chain, walked upward.
    let chain = parent_chain(s, merged);
    if !chain.is_empty() {
        lines.push(ui::fit(
            &format!("  chain   {}", chain.join(" ← ")),
            interior,
        ));
    }
    lines
}

/// Walk a session's parent chain upward, child-to-root — again cycle-guarded,
/// and returning empty for a lone session so the card omits the line entirely.
fn parent_chain(s: &graph::SessionRecord, merged: &[graph::SessionRecord]) -> Vec<String> {
    let by_id: std::collections::BTreeMap<&str, &graph::SessionRecord> =
        merged.iter().map(|r| (r.session_id.as_str(), r)).collect();
    let mut chain: Vec<String> = vec![s.session_id.clone()];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(s.session_id.clone());
    let mut cur = s.parent_session_id.clone();
    while let Some(p) = cur {
        if !seen.insert(p.clone()) {
            break;
        }
        chain.push(p.clone());
        cur = by_id
            .get(p.as_str())
            .and_then(|r| r.parent_session_id.clone());
    }
    if chain.len() <= 1 {
        return Vec::new();
    }
    chain
}

fn disp(s: &str) -> &str {
    if s.is_empty() {
        "—"
    } else {
        s
    }
}

/// A musical glyph for a session state — the roster read at a glance: working is
/// a note (♪), awaiting-input a fermata (𝄐, the "hold" sign — the session is held
/// pending its operator), idle a rest (𝄽), done the final barline (𝄂), and
/// anything we don't recognise a modest dot (·).
pub fn state_glyph(state: &str) -> &'static str {
    let l = state.to_ascii_lowercase();
    if is_done(state) {
        "𝄂"
    } else if l.contains("await") || l.contains("block") || l == "notification" {
        "𝄐"
    } else if l.contains("running")
        || l.contains("pretooluse")
        || l.contains("posttooluse")
        || l.contains("active")
    {
        "♪"
    } else if l.contains("idle") {
        "𝄽"
    } else {
        "·"
    }
}

/// The colour that partners the glyph — green for working, the palette's urgent
/// hue (yellow fallback) for an awaiting/blocked session that needs a human, cyan
/// for idle, dim for done, and no colour for the unknown.
fn state_color(state: &str, pal: &Palette) -> String {
    let l = state.to_ascii_lowercase();
    if is_done(state) {
        ui::DIM.to_string()
    } else if l.contains("await") || l.contains("block") || l == "notification" {
        // Awaiting a human is the one state worth an urgent tint.
        pal.urgent
            .map(ui::fg256)
            .unwrap_or_else(|| ui::YELLOW.to_string())
    } else if l.contains("running")
        || l.contains("pretooluse")
        || l.contains("posttooluse")
        || l.contains("active")
    {
        ui::GREEN.to_string()
    } else if l.contains("idle") {
        ui::CYAN.to_string()
    } else {
        String::new()
    }
}

/// Shorten a cwd to its last two components for the roster — the tail is what
/// tells sessions apart; the leading path is noise at a glance.
fn shorten_cwd(cwd: &str) -> String {
    let parts: Vec<&str> = cwd
        .trim_end_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    match parts.len() {
        0 => cwd.to_string(),
        1 => format!("/{}", parts[0]),
        n => format!("…/{}/{}", parts[n - 2], parts[n - 1]),
    }
}

/// A relative elapsed clock from an ISO-8601 `startedAt` (what a live
/// shellbridge writes) — mm:ss under the hour, `Hh MMm` under the day, whole
/// days beyond. An unparseable stamp or a start in the future yields the empty
/// string, and the row simply omits the clock rather than lie.
fn elapsed_str(started_at: &str) -> String {
    // Parse "YYYY-MM-DDTHH:MM:SS" to epoch seconds. Use a small UTC converter.
    let Some(epoch) = parse_iso_utc(started_at) else {
        return String::new();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = now - epoch;
    if secs < 0 {
        return String::new();
    }
    if secs < 3600 {
        format!("{:02}:{:02}", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SS` (a trailing `Z` tolerated) to UTC epoch seconds,
/// or `None` when the shape doesn't hold — a hand-rolled civil-days conversion
/// so the lock never grows a chrono just to subtract two timestamps.
fn parse_iso_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse().ok() };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let min = num(14, 16)?;
    let sec = num(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from the Unix epoch (1970-01-01) to this date. Use the civil algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// The empty-roster placeholder — shown only when there are neither sessions nor
/// projects to draw. House chrome in the void, and a nudge toward `seed.sh` so a
/// cold rig isn't a dead end.
fn empty_roster_art(cols: u16) -> Vec<String> {
    let interior = (cols as usize).saturating_sub(2);
    let art: &[&str] = &[
        "",
        "        ╭─────────────────────────╮",
        "        │   no agent sessions     │",
        "        │        𝄽  𝄽  𝄽          │",
        "        ╰─────────────────────────╯",
        "",
        "   Nothing to conduct — no terminals run agents.",
        "",
        "   Seed a stage tree to try the view:",
        "     pkgs/aoide/tests/fixtures/seed.sh $AOIDE_STAGE_DIR",
        "",
        "   Or register a project. Press a.",
    ];
    art.iter().map(|l| ui::fit(l, interior)).collect()
}

// ── [2] PROJECTS — anchor roots that sessions hang under ───────────────────────

/// The project roster — sorted by name (so the selection index maps stably),
/// each row a session-count meter and its anchor path. `a` opens the add prompt;
/// `d` removes the selected anchor — both through the one dispatcher.
pub fn projects_body(app: &App, cols: u16) -> Vec<String> {
    let projects = sorted_projects(&app.projects);
    let interior = (cols as usize).saturating_sub(2);

    if projects.is_empty() && app.input.is_none() {
        return vec![
            String::new(),
            "   No projects. Press a to add one.".to_string(),
            "".to_string(),
            "   A project anchors sessions by cwd prefix.".to_string(),
        ];
    }

    // Each row wears the count of sessions it anchors, meter and all.
    let merged = app.merged();
    let mut out: Vec<String> = Vec::new();
    out.push(format!(
        "{DIM} project        sessions  path{RST}",
        DIM = ui::DIM,
        RST = ui::RESET
    ));
    for (i, p) in projects.iter().enumerate() {
        let anchored = merged
            .iter()
            .filter(|s| {
                graph::anchor_for(&s.cwd, &projects)
                    .map(|idx| projects[idx].name == p.name)
                    .unwrap_or(false)
            })
            .count();
        let bar = ascii_bar(anchored, 6);
        let row = format!("◆ {:<12} {bar} {:>2}  {}", p.name, anchored, p.path);
        if i == app.proj_sel && app.input.is_none() {
            out.push(format!(
                "{}{}{}",
                ui::REVERSE,
                ui::fit(&row, interior),
                ui::RESET
            ));
        } else {
            out.push(ui::fit(&format!(" {row}"), interior));
        }
    }
    out
}

/// A `[▓░]` meter — `filled` shaded cells of `width`, the rest hollow — the same
/// bar vocabulary the gadget dock uses.
fn ascii_bar(filled: usize, width: usize) -> String {
    let f = filled.min(width);
    format!("[{}{}]", "▓".repeat(f), "░".repeat(width - f))
}

// ── [3] LOG — the audit tail (the event feed) ──────────────────────────────────

/// The audit-log tail — the flat event feed the baton reads to know what its
/// sessions did, newest at the bottom, each line coloured by class and status
/// and carrying the door it came through.
pub fn log_body(app: &App, cols: u16) -> Vec<String> {
    if app.log.is_empty() {
        return vec![String::new(), "   The audit log is empty.".to_string()];
    }
    let interior = (cols as usize).saturating_sub(2);
    let mut out: Vec<String> = Vec::new();
    for l in &app.log {
        let class_col = ui::fit(&l.class, 12);
        let door_col = ui::fit(&l.door, 6);
        let scolor = status_color(&l.status);
        let status_col = ui::fit(&l.status, 15);
        let cc = class_color(&l.class);
        let body = format!("{}: {}", l.command, l.message);
        let line = format!(
            "{cc}{class_col}{reset} {dim}{door_col}{reset} {scolor}{status_col}{reset} {body}",
            reset = ui::RESET,
            dim = ui::DIM,
        );
        out.push(ui::fit(&line, interior));
    }
    out
}

/// The colour an audit status wears — green for the many flavours of success,
/// red for error, yellow for usage, dim for the not-yet-built, cyan otherwise.
fn status_color(status: &str) -> &'static str {
    match status {
        "ok" | "started" | "proposed" | "forwarded" => ui::GREEN,
        "error" => ui::RED,
        "usage" => ui::YELLOW,
        "not-implemented" => ui::DIM,
        _ => ui::CYAN,
    }
}

/// The colour an event class wears — one hue per class in the neutral event
/// stream, so a scanning eye sorts audit from gate from rice without reading.
fn class_color(class: &str) -> &'static str {
    match class {
        "audit" => ui::CYAN,
        "gate" => ui::YELLOW,
        "rice" => ui::MAGENTA,
        "content" => ui::BLUE,
        "notification" => ui::RED,
        _ => "",
    }
}

// ── [4] STATUS — the stage tree health ─────────────────────────────────────────

/// The stage-tree health readout — where the stage dir lives, each stage file's
/// presence/mtime/count, whether the shellbridge socket is up, the audit tail's
/// summary, and the palette notes.json handed us. The panel that answers "is the
/// live data actually flowing?" when the roster looks suspiciously quiet.
pub fn status_body(app: &App, cols: u16) -> Vec<String> {
    let stage = crate::shellbridge::stage_dir();
    let sock = crate::shellbridge::socket_path();
    let audit = crate::daemon::default_audit_log();
    let interior = (cols as usize).saturating_sub(2);

    let mut out: Vec<String> = Vec::new();
    out.push(ui::fit(
        &format!(" stage dir   {}", stage.display()),
        interior,
    ));
    out.push(String::new());

    out.push(ui::fit(
        &format!(
            " {}",
            file_status(&stage.join("projects.json"), "projects", app.projects.len())
        ),
        interior,
    ));
    out.push(ui::fit(
        &format!(
            " {}",
            file_status(&stage.join("sessions.json"), "sessions", app.sessions.len())
        ),
        interior,
    ));
    out.push(ui::fit(
        &format!(
            " {}",
            file_status(&stage.join("hooks.json"), "hooks", app.hooks.len())
        ),
        interior,
    ));
    out.push(ui::fit(
        &format!(
            " {}",
            file_status(
                &stage.join("graph.json"),
                "graph",
                graph_node_count(&stage.join("graph.json"))
            )
        ),
        interior,
    ));
    out.push(ui::fit(
        &format!(
            " {}",
            file_status(&stage.join("notes.json"), "notes", palette_count(app))
        ),
        interior,
    ));
    out.push(String::new());

    let sock_present = sock.exists();
    out.push(ui::fit(
        &format!(
            " shellbridge sock  {}  {}",
            if sock_present { "●" } else { "○" },
            sock.display()
        ),
        interior,
    ));

    let last_ts = app.log.last().map(|l| l.ts).unwrap_or(0);
    out.push(ui::fit(
        &format!(
            " audit log         {}  ({} line(s), last ts {last_ts})",
            audit.display(),
            app.log.len()
        ),
        interior,
    ));
    out.push(String::new());

    out.push(palette_summary(app, interior));

    out
}

/// One stage-file status line — a filled/hollow dot for presence, the entry
/// count, and the mtime (or a plain "(absent)" when the file isn't there yet).
fn file_status(path: &std::path::Path, label: &str, count: usize) -> String {
    let (present, mtime) = match std::fs::metadata(path) {
        Ok(m) => (
            true,
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ),
        Err(_) => (false, 0),
    };
    let mark = if present { "●" } else { "○" };
    if present {
        format!("{mark} {label:<9} {count:>3} entr(y/ies)  mtime {mtime}")
    } else {
        format!("{mark} {label:<9} (absent)")
    }
}

/// The node tally in graph.json — 0 when the file is missing, which for the
/// status readout is a fact worth stating rather than an error.
fn graph_node_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("nodes").and_then(|n| n.as_array()).map(Vec::len))
        .unwrap_or(0)
}

/// How many palette keys actually mapped from notes.json — the count the status
/// panel reports and the swatch summary keys off.
fn palette_count(app: &App) -> usize {
    let p = &app.palette;
    [p.bg, p.fg, p.accent, p.urgent]
        .iter()
        .filter(|x| x.is_some())
        .count()
}

/// The palette summary — a swatch per key when notes.json carried one, or a
/// plain "terminal defaults" note when it didn't, since inheriting the terminal
/// theme is the honest default, not a failure.
fn palette_summary(app: &App, interior: usize) -> String {
    let p = &app.palette;
    if palette_count(app) == 0 {
        return ui::fit(" palette          (none — terminal defaults)", interior);
    }
    let swatch = |c: Option<u8>, name: &str| -> String {
        match c {
            Some(idx) => format!(
                "{}{} {}{} {name}",
                ui::bg256(idx),
                ui::fg256(idx),
                "██",
                ui::RESET
            ),
            None => format!("·· {name}"),
        }
    };
    let line = format!(
        " palette          {}  {}  {}  {}",
        swatch(p.bg, "bg"),
        swatch(p.fg, "fg"),
        swatch(p.accent, "accent"),
        swatch(p.urgent, "urgent"),
    );
    ui::fit(&line, interior)
}

// ── The help overlay ───────────────────────────────────────────────────────────

/// The help overlay — a centred, framed key list stamped over the composed
/// frame (a modal-overlay trick). It owns only the columns it covers; the
/// panel underneath survives everywhere the box doesn't reach.
pub fn overlay_help(lines: &mut [String], cols: u16, rows: u16, pal: &Palette) {
    let help: &[&str] = &[
        "aoide baton — keys",
        "",
        "  Tab / Shift-Tab   cycle panels",
        "  1 2 3 4           SESSIONS / PROJECTS / LOG / STATUS",
        "  j / k  ↓ / ↑      move selection",
        "",
        "  SESSIONS",
        "    Enter           cue: jump to the window (or fold a group)",
        "    h / -  l / +     fold / unfold the group under the cursor",
        "    L               link the session under a parent (id prompt)",
        "    a / d           add / remove a project anchor",
        "    p / e           prune done · emit the DAG",
        "    ‣               a fresh arrival (appeared in the last few ticks)",
        "    ♪ 𝄐 𝄽 𝄂          working · awaiting · idle · done",
        "",
        "  PROJECTS: a add · d remove",
        "",
        "  ?                 toggle this help",
        "  q / Ctrl-C        quit",
        "",
        "  Every cue runs through the one door.",
        "  The audit log records each action.",
    ];
    let box_w = (help
        .iter()
        .map(|l| ui::display_width(l))
        .max()
        .unwrap_or(20)
        + 4)
    .min(cols as usize - 2);
    let box_h = help.len() + 2;
    let top = (rows as usize).saturating_sub(box_h) / 2;
    let left = (cols as usize).saturating_sub(box_w) / 2;

    let framed = ui::frame(
        "HELP",
        &help.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        box_w as u16,
        box_h as u16,
        true,
        pal,
    );

    for (i, fl) in framed.iter().enumerate() {
        let row = top + i;
        if row >= lines.len() {
            break;
        }
        lines[row] = stamp(left, fl, cols as usize);
    }
}

/// Stamp a patch onto a row at a given column — left-padded and refit to width.
/// The modal rebuilds the whole row from its left pad rather than splicing, so
/// stray colour from the panel beneath can't bleed through the overlay.
fn stamp(col: usize, patch: &str, width: usize) -> String {
    let left_pad = " ".repeat(col.min(width));
    ui::fit(&format!("{left_pad}{patch}"), width)
}

/// Projects sorted by name (a fresh copy) — the one canonical order both the
/// roster render and the selection index agree on, so `d` removes what's lit.
fn sorted_projects(projects: &[graph::Project]) -> Vec<graph::Project> {
    let mut p = projects.to_vec();
    p.sort_by(|a, b| a.name.cmp(&b.name));
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baton::app::Panel;
    use crate::graph::{Project, SessionRecord};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use serde_json::Map;

    fn app_with(projects: Vec<Project>, sessions: Vec<SessionRecord>) -> App {
        App::for_test(projects, sessions, Vec::new())
    }

    fn session(id: &str, cwd: &str, state: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            agent: "claude".into(),
            window_address: format!("0x{id}"),
            cwd: cwd.into(),
            state: state.into(),
            started_at: "1".into(),
            parent_session_id: None,
            extra: Map::new(),
        }
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn dag_body_shows_group_roster_detail_and_state_glyph() {
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
            }],
            vec![session("s1", "/home/k/Aoide", "running")],
        );
        // Row 0 is the group header; land the cursor on the session row so the
        // detail card (only drawn for a selected Session) renders.
        let rows = app.dag_rows();
        app.dag_sel = rows
            .iter()
            .position(|r| matches!(r, DagRow::Session { rec, .. } if rec.session_id == "s1"))
            .expect("session present in the row model");
        let body = dag_body(&app, 90);
        let joined = body.join("\n");
        assert!(joined.contains("◆ aoide"), "project anchor present");
        assert!(joined.contains("[1/1]"), "live/total badge shown");
        assert!(joined.contains("s1"), "session id present");
        assert!(joined.contains("claude"), "agent name shown");
        assert!(
            joined.contains("♪"),
            "working session carries the active glyph"
        );
        assert!(joined.contains("selected"), "detail card present");
    }

    #[test]
    fn awaiting_session_uses_the_fermata_glyph() {
        assert_eq!(state_glyph("Notification"), "𝄐");
        assert_eq!(state_glyph("awaiting-input"), "𝄐");
        assert_eq!(state_glyph("running"), "♪");
        assert_eq!(state_glyph("idle"), "𝄽");
        assert_eq!(state_glyph("done"), "𝄂");
    }

    #[test]
    fn folded_group_hides_its_sessions_and_flips_the_caret() {
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
            }],
            vec![session("s1", "/home/k/Aoide", "running")],
        );
        // Unfolded: the session row is present, caret is open.
        let open = dag_body(&app, 90).join("\n");
        assert!(open.contains("▾"), "unfolded caret drawn");
        assert!(open.contains("s1"), "session visible when unfolded");
        // Fold the group via the app key handler (h on the header row).
        app.select_panel(Panel::Dag);
        app.dag_sel = 0;
        app.handle_key(key('h'));
        let folded = dag_body(&app, 90).join("\n");
        assert!(folded.contains("▸"), "folded caret drawn");
        assert!(!folded.contains(" s1 "), "session hidden when folded");
        assert!(
            folded.contains("[1/1]"),
            "badge still shown on folded header"
        );
    }

    #[test]
    fn fresh_session_wears_the_accent_cue() {
        let mut app = app_with(
            vec![Project {
                name: "aoide".into(),
                path: "/home/k/Aoide".into(),
            }],
            vec![session("s1", "/home/k/Aoide", "running")],
        );
        app.fresh.insert("s1".to_string(), 3);
        let joined = dag_body(&app, 90).join("\n");
        assert!(joined.contains("‣"), "fresh arrival marked with the cue");
    }

    #[test]
    fn dag_body_nests_spawned_children_and_shows_chain() {
        let mut child = session("child", "/home/k/Aoide/sub", "idle");
        child.parent_session_id = Some("root".into());
        child.started_at = "2".into();
        let app = {
            let mut a = app_with(
                vec![Project {
                    name: "aoide".into(),
                    path: "/home/k/Aoide".into(),
                }],
                vec![session("root", "/home/k/Aoide", "running"), child],
            );
            // Select the child row in the flattened DAG model.
            let rows = a.dag_rows();
            a.dag_sel = rows
                .iter()
                .position(|r| matches!(r, DagRow::Session { rec, .. } if rec.session_id == "child"))
                .expect("child present in the row model");
            a
        };
        let body = dag_body(&app, 90);
        let joined = body.join("\n");
        assert!(
            joined.contains("├─") || joined.contains("└─"),
            "tree branch drawn"
        );
        assert!(joined.contains("chain"), "parent chain shown for the child");
        assert!(joined.contains("root"), "chain names the parent");
    }

    #[test]
    fn empty_roster_shows_ascii_art() {
        let app = app_with(vec![], vec![]);
        let body = dag_body(&app, 80);
        let joined = body.join("\n");
        assert!(
            joined.contains("no agent sessions"),
            "empty-roster art present"
        );
        assert!(joined.contains("seed.sh"), "guidance to seed shown");
    }

    #[test]
    fn projects_body_lists_sorted_roster_with_meter() {
        let app = app_with(
            vec![
                Project {
                    name: "zeta".into(),
                    path: "/z".into(),
                },
                Project {
                    name: "alpha".into(),
                    path: "/a".into(),
                },
            ],
            vec![],
        );
        let body = projects_body(&app, 90);
        let joined = body.join("\n");
        let ai = joined.find("alpha").unwrap();
        let zi = joined.find("zeta").unwrap();
        assert!(ai < zi, "roster sorted by name");
        assert!(joined.contains("◆"));
        assert!(joined.contains("░"), "ascii meter drawn");
    }

    #[test]
    fn log_body_colours_by_status() {
        let mut app = app_with(vec![], vec![]);
        app.log = vec![
            crate::baton::app::LogLine {
                ts: 1,
                door: "cli".into(),
                class: "audit".into(),
                command: "graph.emit".into(),
                status: "ok".into(),
                message: "staged".into(),
            },
            crate::baton::app::LogLine {
                ts: 2,
                door: "cli".into(),
                class: "audit".into(),
                command: "graph.focus".into(),
                status: "error".into(),
                message: "gone".into(),
            },
        ];
        let body = log_body(&app, 100);
        let joined = body.join("\n");
        assert!(joined.contains(ui::GREEN), "ok line is green");
        assert!(joined.contains(ui::RED), "error line is red");
        assert!(joined.contains("graph.emit") && joined.contains("graph.focus"));
        assert!(joined.contains("cli"), "door column visible");
    }

    #[test]
    fn help_overlay_stamps_over_the_frame() {
        let mut lines: Vec<String> = (0..30).map(|i| format!("row {i}")).collect();
        overlay_help(&mut lines, 80, 30, &Palette::default());
        let joined = lines.join("\n");
        assert!(
            joined.contains("aoide baton — keys"),
            "overlay content present"
        );
        assert!(joined.contains("cycle panels"));
        assert!(joined.contains("link the session"), "link key documented");
    }

    #[test]
    fn iso_parse_and_elapsed() {
        assert_eq!(parse_iso_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso_utc("1970-01-02T00:00:00Z"), Some(86400));
        assert_eq!(parse_iso_utc("2026-07-26T00:00:00Z"), Some(1785024000));
        assert!(parse_iso_utc("not-a-date").is_none());
        assert_eq!(elapsed_str("2999-01-01T00:00:00Z"), "");
    }

    #[test]
    fn shorten_cwd_keeps_tail() {
        assert_eq!(shorten_cwd("/home/k/Aoide/pkgs/aoide"), "…/pkgs/aoide");
        assert_eq!(shorten_cwd("/tmp"), "/tmp");
    }
}
