//! Single-use TOTP replay ledger — pure struct + (de)serialization, zero
//! clock reads. A code is single-use per TIMESTEP ALONE — never scoped by
//! consumer: within a code's validity window (`totp::verify`'s `±window`),
//! the same code accepted twice is rejected the second time, no matter
//! what consumer name rides either request.
//!
//! RULING (Fable, 2026-08-22, P-V1 review escalation — plan file's SECRETS
//! §Policy section carries the same text): the resolve wire's `consumer`
//! field is SELF-ASSERTED — a label the calling agent picks, not an
//! authenticated identity. A per-consumer ledger would let one
//! human-typed code redeem once per invented label, defeating single-use
//! entirely. "Single-use" means the host's one enrollment yields ONE
//! release per code, full stop; per-consumer replay semantics require
//! authenticated consumer identity first, which is out of scope
//! (#51-adjacent, not planned).
//!
//! Clock-as-parameter discipline (this crate's `AGENTS.md`): every
//! function here takes the timestep/cutoff as a parameter the caller
//! derived (typically from `totp::timestep(now)`); nothing in this
//! module reads `SystemTime::now()`. V2's broker wraps this with the
//! real clock and owns persisting it to secrets home.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The ledger: an ordered set of consumed timesteps. `BTreeSet` gives a
/// deterministic iteration/serialization order for free — required for
/// the byte-stable round-trip this crate's types commit to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayLedger {
    consumed: BTreeSet<u64>,
}

impl ReplayLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// True if `timestep` has already been consumed.
    pub fn is_used(&self, timestep: u64) -> bool {
        self.consumed.contains(&timestep)
    }

    /// Record `timestep` as consumed. Returns `true` if this call is what
    /// consumed it, `false` if it was already used (the single-use gate:
    /// callers must check the return value, not just call this
    /// unconditionally).
    pub fn record(&mut self, timestep: u64) -> bool {
        self.consumed.insert(timestep)
    }

    /// Drop every entry older than `oldest_timestep_to_keep` — bounds
    /// ledger growth over time. The caller derives the cutoff from `now`
    /// (e.g. `totp::timestep(now) - retention_steps`); this function
    /// never reads a clock itself.
    pub fn prune_before(&mut self, oldest_timestep_to_keep: u64) {
        self.consumed.retain(|&t| t >= oldest_timestep_to_keep);
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
        assert!(!ledger.is_used(12345));
    }

    #[test]
    fn record_then_is_used_reports_consumed() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(100));
        assert!(ledger.is_used(100));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn the_same_code_twice_is_rejected_the_second_time() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(100), "first use accepted");
        assert!(
            !ledger.record(100),
            "second use of the same timestep must be rejected"
        );
        assert_eq!(ledger.len(), 1, "replay must not double-record");
    }

    // Replaces the old `different_consumers_each_get_their_own_single_use`
    // test (P-V1 review fixes): the ruling is the opposite of what that
    // test asserted — a self-asserted consumer label must NOT buy a
    // second redemption of the same code.
    #[test]
    fn different_claimed_consumers_do_not_grant_a_second_redemption() {
        let mut ledger = ReplayLedger::new();
        // First caller claims consumer "a" — the ledger has no notion of
        // consumer at all, so this is just recording timestep 100.
        assert!(ledger.record(100), "first redemption accepted");
        // Second caller claims a DIFFERENT consumer "b" but the SAME
        // code/timestep — must still be rejected, because the consumer
        // field is self-asserted and the ledger keys on timestep alone.
        assert!(
            !ledger.record(100),
            "a second claimed consumer must not redeem the same timestep again"
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn different_timesteps_do_not_collide() {
        let mut ledger = ReplayLedger::new();
        assert!(ledger.record(100));
        assert!(ledger.record(101));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn prune_before_drops_old_entries_only() {
        let mut ledger = ReplayLedger::new();
        ledger.record(10);
        ledger.record(20);
        ledger.record(30);
        ledger.prune_before(20);
        assert!(!ledger.is_used(10));
        assert!(ledger.is_used(20));
        assert!(ledger.is_used(30));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn serde_round_trip_is_byte_stable() {
        let mut ledger = ReplayLedger::new();
        ledger.record(100);
        ledger.record(200);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: ReplayLedger = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
        assert_eq!(ledger, back);
    }

    #[test]
    fn serde_round_trip_survives_a_real_file_in_a_tempdir() {
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-replay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replay.json");

        let mut ledger = ReplayLedger::new();
        ledger.record(4242);
        let bytes = serde_json::to_vec(&ledger).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(bytes, read_back, "file bytes must match what was written");
        let ledger2: ReplayLedger = serde_json::from_slice(&read_back).unwrap();
        assert_eq!(ledger, ledger2);

        std::fs::remove_dir_all(&dir).ok();
    }
}
