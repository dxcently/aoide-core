//! Single-use TOTP replay ledger — pure struct + (de)serialization, zero
//! clock reads. A code is single-use per `(consumer, timestep)`: within
//! a code's validity window (`totp::verify`'s `±window`), the SAME code
//! accepted twice for the same consumer is rejected the second time.
//!
//! Clock-as-parameter discipline (this crate's `AGENTS.md`): every
//! function here takes the timestep/cutoff as a parameter the caller
//! derived (typically from `totp::timestep(now)`); nothing in this
//! module reads `SystemTime::now()`. V2's broker wraps this with the
//! real clock and owns persisting it to vault home.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One consumed `(consumer, timestep)` pair. `consumer` is `None` for a
/// code accepted with no per-consumer scoping (a whole-vault standing
/// grant); `Some(name)` scopes single-use to that consumer only, so two
/// different consumers may each spend the same code once in the same
/// window without treating each other as a replay.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayKey {
    pub consumer: Option<String>,
    pub timestep: u64,
}

/// The ledger: an ordered set of consumed keys. `BTreeSet` gives a
/// deterministic iteration/serialization order for free — required for
/// the byte-stable round-trip this crate's types commit to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayLedger {
    consumed: BTreeSet<ReplayKey>,
}

impl ReplayLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if `(consumer, timestep)` has already been consumed.
    pub fn is_used(&self, consumer: Option<&str>, timestep: u64) -> bool {
        self.consumed.contains(&ReplayKey {
            consumer: consumer.map(str::to_owned),
            timestep,
        })
    }

    /// Record `(consumer, timestep)` as consumed. Returns `true` if this
    /// call is what consumed it, `false` if it was already used (the
    /// single-use gate: callers must check the return value, not just
    /// call this unconditionally).
    pub fn record(&mut self, consumer: Option<&str>, timestep: u64) -> bool {
        self.consumed.insert(ReplayKey {
            consumer: consumer.map(str::to_owned),
            timestep,
        })
    }

    /// Drop every entry older than `oldest_timestep_to_keep` — bounds
    /// ledger growth over time. The caller derives the cutoff from `now`
    /// (e.g. `totp::timestep(now) - retention_steps`); this function
    /// never reads a clock itself.
    pub fn prune_before(&mut self, oldest_timestep_to_keep: u64) {
        self.consumed.retain(|k| k.timestep >= oldest_timestep_to_keep);
    }

    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_ledger_is_empty() {
        let ledger = ReplayLedger::new();
        assert!(ledger.is_empty());
        assert!(!ledger.is_used(None, 12345));
    }

    #[test]
    fn record_then_is_used_reports_consumed() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(Some("m"), 100));
        assert!(ledger.is_used(Some("m"), 100));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn the_same_code_twice_is_rejected_the_second_time() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(Some("m"), 100), "first use accepted");
        assert!(
            !ledger.record(Some("m"), 100),
            "second use of the same (consumer, timestep) must be rejected"
        );
        assert_eq!(ledger.len(), 1, "replay must not double-record");
    }

    #[test]
    fn different_consumers_each_get_their_own_single_use() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(Some("a"), 100));
        assert!(
            ledger.record(Some("b"), 100),
            "a different consumer at the same timestep is not a replay"
        );
        assert!(!ledger.record(Some("a"), 100));
        assert!(!ledger.record(Some("b"), 100));
    }

    #[test]
    fn none_consumer_scopes_globally() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(None, 100));
        assert!(!ledger.record(None, 100));
        assert!(ledger.is_used(None, 100));
        assert!(!ledger.is_used(Some("m"), 100), "distinct key from None");
    }

    #[test]
    fn different_timesteps_do_not_collide() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(Some("m"), 100));
        assert!(ledger.record(Some("m"), 101));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn prune_before_drops_old_entries_only() {
        let mut ledger = ReplayLedger::new();
        ledger.record(Some("m"), 10);
        ledger.record(Some("m"), 20);
        ledger.record(Some("m"), 30);
        ledger.prune_before(20);
        assert!(!ledger.is_used(Some("m"), 10));
        assert!(ledger.is_used(Some("m"), 20));
        assert!(ledger.is_used(Some("m"), 30));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn serde_round_trip_is_byte_stable() {
        let mut ledger = ReplayLedger::new();
        ledger.record(Some("m"), 100);
        ledger.record(None, 200);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: ReplayLedger = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
        assert_eq!(ledger, back);
    }

    #[test]
    fn serde_round_trip_survives_a_real_file_in_a_tempdir() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-vault-replay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.json");

        let mut ledger = ReplayLedger::new();
        ledger.record(Some("m"), 4242);
        let bytes = serde_json::to_vec(&ledger).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(bytes, read_back, "file bytes must match what was written");
        let ledger2: ReplayLedger = serde_json::from_slice(&read_back).unwrap();
        assert_eq!(ledger, ledger2);

        std::fs::remove_dir_all(&dir).ok();
    }
}
