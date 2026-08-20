//! Petname wordlist + mint (P1 of the petnames plan): a human-readable
//! `adjective-noun` DISPLAY handle for a session record — never an identity
//! key. `sessionId` stays the sole canonical identity everywhere (JSON
//! payloads, sockets, CONTRACTS keys, `Node::session_id`); this module only
//! ever hands back a string for a human to read.
//!
//! Pure and dependency-free: no rand crate, entropy comes from hashing
//! wall-clock nanos + the process id + a re-roll counter through
//! `std::hash::DefaultHasher`. [`mint_petname`] takes a `taken` PREDICATE
//! (not a slice) so it stays agnostic of `SessionRecord`; [`mint_for`] is
//! the one caller in this crate that wraps it against the live session
//! roster.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;

use crate::records::SessionRecord;

/// Adjective half of the `adjective-noun` pair: lowercase ASCII, 4-7 chars,
/// no hyphens, dup-free within and across [`NOUNS`] — 64 entries, paired
/// with 64 nouns for 4096 combined combos.
pub const ADJECTIVES: [&str; 64] = [
    "brave", "calm", "cozy", "crisp", "dainty", "dapper", "eager", "faint", "fond", "gentle",
    "giddy", "glossy", "golden", "grand", "hardy", "hasty", "honest", "humble", "jaunty", "jolly",
    "keen", "kind", "lively", "lucid", "lucky", "merry", "misty", "mossy", "muted", "nimble",
    "noble", "plucky", "quiet", "quirky", "rapid", "robust", "rosy", "rustic", "sandy", "shiny",
    "silent", "silky", "sleek", "sober", "solar", "sparse", "spry", "stark", "steady", "stout",
    "sturdy", "subtle", "sunny", "swift", "tidy", "timid", "tiny", "vivid", "warm", "wary",
    "wild", "windy", "witty", "zesty",
];

/// Noun half of the `adjective-noun` pair — see [`ADJECTIVES`].
pub const NOUNS: [&str; 64] = [
    "acorn", "alder", "amber", "antler", "apple", "thorn", "aspen", "badger", "basil", "beacon",
    "beech", "birch", "bison", "bloom", "boulder", "bramble", "breeze", "brook", "reed", "cactus",
    "canyon", "cedar", "cherry", "clover", "cloud", "comet", "coral", "crag", "creek", "crest",
    "dawn", "delta", "dune", "ember", "falcon", "fawn", "fern", "finch", "flame", "frost", "gale",
    "glade", "glen", "grove", "harbor", "hazel", "heron", "holly", "vine", "juniper", "kite",
    "lark", "lilac", "lotus", "maple", "marsh", "meadow", "mesa", "mist", "moth", "needle",
    "orchid", "otter", "pebble",
];

/// Roll one pseudo-random `adjective-noun` pair. Entropy: wall-clock nanos
/// (no unwrap — `SystemTime` failure falls back to `0`, same discipline
/// `time::now_iso_utc` uses) hashed together with the process id and
/// `attempt`, so a re-roll after a collision draws a different pair without
/// pulling in a rand dependency.
fn roll(attempt: u64) -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    nanos.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    attempt.hash(&mut hasher);
    let h = hasher.finish();
    let adj = ADJECTIVES[(h as usize) % ADJECTIVES.len()];
    let noun = NOUNS[((h >> 32) as usize) % NOUNS.len()];
    format!("{adj}-{noun}")
}

/// Mint a fresh petname `taken` reports as free. Re-rolls up to 16 times on
/// a collision; if every roll still collides (a near-full 4096-combo
/// space), falls back to `<word>-<word>-<n>` — an incrementing numeric
/// suffix on the last roll, tried until `taken` finally reports free — so
/// the function is TOTAL and never returns a name `taken` claims.
///
/// `taken` is a predicate, not a slice, so a caller can wrap any liveness
/// rule (see [`mint_for`]) without this module knowing about
/// `SessionRecord`.
pub fn mint_petname(taken: &dyn Fn(&str) -> bool) -> String {
    for attempt in 0..16u64 {
        let name = roll(attempt);
        if !taken(&name) {
            return name;
        }
    }
    let base = roll(16);
    let mut n: u64 = 2;
    loop {
        let name = format!("{base}-{n}");
        if !taken(&name) {
            return name;
        }
        n += 1;
    }
}

/// Mint against the live session roster: a record with `state == "done"` is
/// no longer live, so its petname is free to reuse — the predicate only
/// counts a name as taken when a still-live record holds it. Callers under
/// the stage lock pass the in-hand `Vec<SessionRecord>` straight through.
pub fn mint_for(sessions: &[SessionRecord]) -> String {
    mint_petname(&|name: &str| {
        sessions
            .iter()
            .any(|s| s.state != "done" && s.petname.as_deref() == Some(name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashSet;

    #[test]
    fn wordlists_are_shaped_and_dup_free() {
        let is_shaped = |w: &&str| w.len() >= 4 && w.len() <= 7 && w.bytes().all(|b| b.is_ascii_lowercase());
        assert!(ADJECTIVES.iter().all(is_shaped), "an adjective violates [a-z]{{4,7}}");
        assert!(NOUNS.iter().all(is_shaped), "a noun violates [a-z]{{4,7}}");

        let mut all: HashSet<&str> = HashSet::new();
        for w in ADJECTIVES.iter().chain(NOUNS.iter()) {
            assert!(all.insert(w), "duplicate word across the two lists: {w}");
        }
        assert_eq!(ADJECTIVES.len(), 64);
        assert_eq!(NOUNS.len(), 64);
    }

    #[test]
    fn mint_petname_has_adjective_noun_shape() {
        let name = mint_petname(&|_| false);
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 2, "expected adjective-noun, got {name}");
        assert!(ADJECTIVES.contains(&parts[0]), "{name}");
        assert!(NOUNS.contains(&parts[1]), "{name}");
    }

    #[test]
    fn mint_petname_avoids_a_200_name_taken_set() {
        // Seed a "taken" set wide enough to force multiple re-rolls on most
        // runs (200 of the 4096 combos), then prove mint never hands back
        // one of them — the collision-avoidance loop actually rerolls
        // rather than trusting the first draw.
        let mut taken: HashSet<String> = HashSet::new();
        while taken.len() < 200 {
            taken.insert(mint_petname(&|n| taken.contains(n)));
        }
        for _ in 0..50 {
            let name = mint_petname(&|n| taken.contains(n));
            assert!(!taken.contains(&name), "minted an already-taken name: {name}");
        }
    }

    #[test]
    fn mint_petname_exhausts_rerolls_then_falls_back_to_numeric_suffix() {
        // A predicate that stays "taken" for the first 19 calls (the 16
        // rerolls plus three numeric-suffix guesses) and frees up on the
        // 20th proves the fallback loop is actually reached and actually
        // terminates, without depending on the non-deterministic roll
        // output to construct a real collision.
        let calls = Cell::new(0u32);
        let name = mint_petname(&|_name: &str| {
            let n = calls.get();
            calls.set(n + 1);
            n < 19
        });
        assert!(calls.get() >= 19, "fallback path was not exercised");
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "expected <word>-<word>-<n> fallback, got {name}");
        assert!(
            parts[2].chars().all(|c| c.is_ascii_digit()) && !parts[2].is_empty(),
            "expected a numeric suffix, got {name}"
        );
    }

    #[test]
    fn mint_for_skips_done_records_and_avoids_live_petnames() {
        let sessions = vec![
            SessionRecord {
                session_id: "a".into(),
                state: "idle".into(),
                petname: Some("brave-otter".into()),
                ..Default::default()
            },
            SessionRecord {
                session_id: "b".into(),
                state: "done".into(),
                petname: Some("calm-thorn".into()),
                ..Default::default()
            },
        ];
        // The still-idle record's name must never come back out; a done
        // record's name is fair game (asserted structurally below via the
        // predicate itself, since the roll is non-deterministic).
        let name = mint_for(&sessions);
        assert_ne!(name, "brave-otter", "reused a still-live petname");
        let live_taken = |n: &str| {
            sessions
                .iter()
                .any(|s| s.state != "done" && s.petname.as_deref() == Some(n))
        };
        assert!(!live_taken(&name), "mint_for returned a name a live record already holds");
    }
}
