//! Bounded audit history and a selectable, full-record detail view.

use crate::app::{App, LogLine};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_EVENTS: usize = 200;

/// Oldest first, so existing log consumers keep their chronological ordering.
pub fn read_history(path: &Path) -> Result<Vec<LogLine>, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot read audit log: {e}")),
    };
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let start = size.saturating_sub(MAX_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(size - start)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    decode_tail(&bytes, start > 0)
}

fn decode_tail(bytes: &[u8], clipped: bool) -> Result<Vec<LogLine>, String> {
    let end = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let begin = if clipped {
        bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(end, |i| i + 1)
    } else {
        0
    };
    let mut rows = Vec::new();
    for line in bytes[begin..end]
        .split(|b| *b == b'\n')
        .rev()
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
        .take(MAX_EVENTS)
    {
        let raw: serde_json::Value =
            serde_json::from_slice(line).map_err(|e| format!("Invalid audit record: {e}"))?;
        let field = |key: &str| {
            raw.get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        rows.push(LogLine {
            ts: raw.get("ts").and_then(|v| v.as_u64()).unwrap_or(0),
            door: field("door"),
            class: field("class"),
            command: field("command"),
            status: field("status"),
            message: field("message"),
            raw,
        });
    }
    rows.reverse();
    Ok(rows)
}

fn detail(row: &LogLine) -> String {
    let recorded = |key: &str| {
        row.raw
            .get(key)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| "(not recorded)".into())
    };
    format!("Time (recorded): {}\nDoor: {}\nClass: {}\nCommand: {}\nStatus: {}\n\nMessage\n{}\n\nComplete recorded event\n{}",
        recorded("ts"), recorded("door"), recorded("class"), recorded("command"), recorded("status"),
        recorded("message"), serde_json::to_string_pretty(&row.raw).unwrap_or_default())
}

pub fn parts(area: Rect) -> (Rect, Rect) {
    let wide = area.width >= 85;
    let p = Layout::default()
        .direction(if wide {
            Direction::Horizontal
        } else {
            Direction::Vertical
        })
        .constraints(if wide {
            vec![Constraint::Percentage(40), Constraint::Percentage(60)]
        } else {
            vec![
                Constraint::Length((area.height / 3).max(6).min(area.height)),
                Constraint::Min(0),
            ]
        })
        .split(area);
    (p[0], p[1])
}
pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    if app.log.is_empty() {
        f.render_widget(
            Paragraph::new("No recorded audit events.")
                .block(Block::default().borders(Borders::ALL).title(" Activity ")),
            area,
        );
        return;
    }
    let (list_area, detail_area) = parts(area);
    let selected = app.log_sel.min(app.log.len() - 1);
    let rows: Vec<ListItem> = app
        .log
        .iter()
        .map(|row| {
            let time = row
                .raw
                .get("ts")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into());
            ListItem::new(format!(
                "{} [{}] {}\n  {} / {}",
                time, row.status, row.command, row.door, row.class
            ))
        })
        .collect();
    let list = List::new(rows)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Recent events ({}/{}) ",
            selected + 1,
            app.log.len()
        )))
        .highlight_symbol("> ")
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut state = ListState::default().with_selected(Some(selected));
    f.render_stateful_widget(list, list_area, &mut state);
    f.render_widget(
        Paragraph::new(detail(&app.log[selected]))
            .wrap(Wrap { trim: false })
            .scroll((app.log_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Event detail ")
                    .title_bottom(" j/k select | PgUp/PgDn detail "),
            ),
        detail_area,
    );
    if let Some(error) = &app.log_error {
        f.render_widget(
            Paragraph::new(error.as_str()),
            Rect::new(area.x, area.y, area.width, 1),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_extra_fields_and_waits_for_complete_record() {
        let bytes = b"{\"ts\":1,\"command\":\"mail send\",\"changed\":[\"a\"],\"data\":{\"id\":\"letter\"}}\n{unfinished";
        let rows = decode_tail(bytes, false).unwrap();
        assert_eq!(rows.len(), 1);
        let text = detail(&rows[0]);
        assert!(text.contains("letter"));
        assert!(text.contains("changed"));
        assert!(text.contains("Door: (not recorded)"));
    }

    #[test]
    fn bounds_records_and_skips_clipped_prefix() {
        let body = "partial\n".to_string()
            + &(0..205)
                .map(|ts| format!("{{\"ts\":{ts}}}\n"))
                .collect::<String>();
        let rows = decode_tail(body.as_bytes(), true).unwrap();
        assert_eq!(rows.len(), MAX_EVENTS);
        assert_eq!(rows[0].ts, 5);
        assert_eq!(rows.last().unwrap().ts, 204);
        assert!(decode_tail(b"bad\n", false).is_err());
    }
}
