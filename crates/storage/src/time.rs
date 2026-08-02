//! ISO-8601 UTC time formatting/parsing (pure; hand-rolled civil-days
//! conversion so the offline lock never grows a chrono just to stamp/read one
//! timestamp).
//!
//! `now_iso_utc`/`iso_utc_from_epoch` moved from `graph/session_store.rs`;
//! `parse_iso_utc` (their exact inverse) moved from `conductor/theme.rs`
//! (Phase 3a restructure, docs/architecture/PACKAGE-LAYOUT.md). Both are
//! re-exported at their old paths so every existing caller is untouched.

/// UTC wall-clock now as ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The same `SystemTime`→epoch-seconds idiom daemon.rs stamps audit records
/// with, formatted for the `startedAt` field the stage shapes carry. The civil
/// date is hand-rolled (Howard Hinnant's `civil_from_days`, the exact inverse of
/// [`parse_iso_utc`], the reader) so the offline lock never grows a chrono just
/// to write one timestamp — and a stamp we write always round-trips back
/// through the reader `conductor/theme` ships.
pub fn now_iso_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    iso_utc_from_epoch(secs)
}

/// Format Unix epoch seconds as ISO-8601 UTC (pure; unit-tested).
pub fn iso_utc_from_epoch(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days: the inverse of parse_iso_utc's days computation.
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Parse `YYYY-MM-DDTHH:MM:SS` (a trailing `Z` tolerated) to UTC epoch seconds,
/// or `None` when the shape doesn't hold — a hand-rolled civil-days conversion
/// so the lock never grows a chrono just to subtract two timestamps.
pub fn parse_iso_utc(s: &str) -> Option<i64> {
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
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}
