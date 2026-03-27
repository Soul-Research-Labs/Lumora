//! Epoch-based nullifier partitioning.
//!
//! Inspired by ZASEON's CDNA epoch system: nullifiers are partitioned into
//! time-based epochs. Each epoch accumulates nullifiers and, when finalized,
//! produces a Merkle root over all nullifiers in that epoch. This enables:
//!
//! - **Efficient cross-chain sync**: Only epoch roots need to be shared, not
//!   individual nullifiers.
//! - **Bounded storage**: Old epoch data can be pruned while retaining the root
//!   as a commitment.
//! - **Temporal ordering**: Provides a coarse ordering of transactions without
//!   revealing exact timing.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_primitives::poseidon;

/// Default epoch duration in seconds (1 hour, matching ZASEON's default).
pub const DEFAULT_EPOCH_DURATION_SECS: u64 = 3600;

/// Maximum number of finalized epoch roots to retain.
pub const MAX_EPOCH_HISTORY: usize = 256;

/// An epoch identifier (monotonically increasing).
pub type EpochId = u64;

/// Manages epoch-based nullifier partitioning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochManager {
    /// Duration of each epoch in seconds.
    epoch_duration_secs: u64,
    /// The current (active) epoch ID.
    current_epoch: EpochId,
    /// Timestamp when the current epoch started (seconds since UNIX epoch).
    epoch_start_time: u64,
    /// Nullifiers accumulated in the current epoch (as field element bytes).
    #[serde(with = "lumora_primitives::serde_field::base_vec")]
    current_nullifiers: Vec<pallas::Base>,
    /// Finalized epoch roots: epoch_id → Merkle root over that epoch's nullifiers.
    #[serde(with = "epoch_roots_serde")]
    finalized_roots: HashMap<EpochId, pallas::Base>,
    /// Ordered list of finalized epoch IDs (for bounded history management).
    finalized_order: Vec<EpochId>,
}

impl EpochManager {
    /// Create a new epoch manager with the given epoch duration.
    ///
    /// # Panics
    /// Panics if `epoch_duration_secs` is zero.
    pub fn new(epoch_duration_secs: u64) -> Self {
        assert!(epoch_duration_secs > 0, "epoch duration must be > 0");
        let now = current_unix_secs();
        Self {
            epoch_duration_secs,
            current_epoch: now / epoch_duration_secs,
            epoch_start_time: (now / epoch_duration_secs) * epoch_duration_secs,
            current_nullifiers: Vec::new(),
            finalized_roots: HashMap::new(),
            finalized_order: Vec::new(),
        }
    }

    /// The current epoch ID.
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Number of nullifiers in the current (active) epoch.
    pub fn current_epoch_count(&self) -> usize {
        self.current_nullifiers.len()
    }

    /// Number of finalized epochs retained.
    pub fn finalized_epoch_count(&self) -> usize {
        self.finalized_roots.len()
    }

    /// Get the Merkle root for a finalized epoch.
    pub fn epoch_root(&self, epoch_id: EpochId) -> Option<pallas::Base> {
        self.finalized_roots.get(&epoch_id).copied()
    }

    /// Record a nullifier in the current epoch.
    ///
    /// Automatically advances the epoch if the current time has passed
    /// the epoch boundary.
    pub fn record_nullifier(&mut self, nullifier: pallas::Base) {
        self.maybe_advance_epoch();
        self.current_nullifiers.push(nullifier);
    }

    /// Force-finalize the current epoch and start a new one.
    ///
    /// Returns the finalized epoch's (id, root) if it contained any nullifiers,
    /// or `None` if the epoch was empty.
    pub fn finalize_current_epoch(&mut self) -> Option<(EpochId, pallas::Base)> {
        if self.current_nullifiers.is_empty() {
            return None;
        }

        let root = compute_nullifier_epoch_root(&self.current_nullifiers);
        let epoch_id = self.current_epoch;

        self.finalized_roots.insert(epoch_id, root);
        self.finalized_order.push(epoch_id);

        // Prune old epochs beyond the history limit.
        // Remove from the ordered Vec first, then from the HashMap, so that a
        // hypothetical interrupt between the two steps leaves finalized_order
        // as the authoritative list (the HashMap entry is unreachable anyway).
        while self.finalized_order.len() > MAX_EPOCH_HISTORY {
            let old_id = self.finalized_order.remove(0);
            self.finalized_roots.remove(&old_id);
        }

        // Reset current epoch.
        self.current_nullifiers.clear();
        self.current_epoch += 1;
        self.epoch_start_time += self.epoch_duration_secs;

        Some((epoch_id, root))
    }

    /// Check if the current epoch should be auto-advanced based on time.
    ///
    /// Uses `SystemTime` for wall-clock alignment. If the system clock
    /// jumps backward (NTP adjustment), we clamp to the current epoch to
    /// guarantee monotonic epoch progression — epochs never go backward.
    ///
    /// If multiple epoch boundaries have passed (e.g., node was offline),
    /// each skipped epoch is recorded with an empty/zero root so that sync
    /// peers can distinguish "no activity" epochs from missing data.
    fn maybe_advance_epoch(&mut self) {
        let now = current_unix_secs();
        let expected_epoch = now / self.epoch_duration_secs;
        // Only advance forward — never regress if wall clock jumps back.
        if expected_epoch > self.current_epoch {
            // Finalize the current epoch (even if empty, to avoid gaps).
            // For any fully-skipped intermediate epochs, insert a zero root.
            let old_epoch = self.current_epoch;
            let _ = self.finalize_current_epoch(); // finalizes old_epoch if non-empty
            // After finalize_current_epoch, self.current_epoch == old_epoch + 1.
            // For each remaining skipped epoch, record a zero root.
            while self.current_epoch < expected_epoch {
                let skip_id = self.current_epoch;
                self.finalized_roots.insert(skip_id, pallas::Base::zero());
                self.finalized_order.push(skip_id);
                // Prune if over limit.
                while self.finalized_order.len() > MAX_EPOCH_HISTORY {
                    let old_id = self.finalized_order.remove(0);
                    self.finalized_roots.remove(&old_id);
                }
                self.current_epoch += 1;
                self.epoch_start_time += self.epoch_duration_secs;
            }
            // current_epoch is now expected_epoch.
        }
    }

    /// Get all finalized epoch roots as a sorted list of (epoch_id, root).
    pub fn all_finalized_roots(&self) -> Vec<(EpochId, pallas::Base)> {
        self.finalized_order
            .iter()
            .filter_map(|id| self.finalized_roots.get(id).map(|r| (*id, *r)))
            .collect()
    }
}

impl Default for EpochManager {
    fn default() -> Self {
        Self::new(DEFAULT_EPOCH_DURATION_SECS)
    }
}

/// Compute a Merkle root over a list of nullifiers.
///
/// Uses a simple binary Poseidon hash tree. If the count is not a power of two,
/// we pad with zero to the next power of two.
fn compute_nullifier_epoch_root(nullifiers: &[pallas::Base]) -> pallas::Base {
    if nullifiers.is_empty() {
        return pallas::Base::zero();
    }
    if nullifiers.len() == 1 {
        return poseidon::hash_two(nullifiers[0], pallas::Base::zero());
    }

    // Pad to next power of two.
    let next_pow2 = nullifiers.len().next_power_of_two();
    let mut layer: Vec<pallas::Base> = Vec::with_capacity(next_pow2);
    layer.extend_from_slice(nullifiers);
    layer.resize(next_pow2, pallas::Base::zero());

    // Hash pairwise up to a single root.
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            next.push(poseidon::hash_two(chunk[0], chunk[1]));
        }
        layer = next;
    }

    layer[0]
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// Serde helper for HashMap<EpochId, pallas::Base>.
mod epoch_roots_serde {
    use super::*;
    use serde::ser::SerializeMap;

    pub fn serialize<S: serde::Serializer>(
        map: &HashMap<EpochId, pallas::Base>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use ff::PrimeField;
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(&k.to_string(), &hex::encode(v.to_repr()))?;
        }
        m.end()
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<EpochId, pallas::Base>, D::Error> {
        use ff::PrimeField;
        let raw: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v) in raw {
            let epoch_id: EpochId = k.parse().map_err(serde::de::Error::custom)?;
            let bytes = hex::decode(&v).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("expected 32-byte field element"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let field: Option<pallas::Base> = pallas::Base::from_repr(arr).into();
            let field = field.ok_or_else(|| serde::de::Error::custom("invalid field element"))?;
            out.insert(epoch_id, field);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_manager_basics() {
        let mut em = EpochManager::new(3600);
        assert_eq!(em.current_epoch_count(), 0);
        assert_eq!(em.finalized_epoch_count(), 0);

        // Record some nullifiers.
        em.record_nullifier(pallas::Base::from(1u64));
        em.record_nullifier(pallas::Base::from(2u64));
        em.record_nullifier(pallas::Base::from(3u64));
        assert_eq!(em.current_epoch_count(), 3);

        // Finalize.
        let result = em.finalize_current_epoch();
        assert!(result.is_some());
        let (epoch_id, root) = result.unwrap();
        assert_eq!(em.finalized_epoch_count(), 1);
        assert_eq!(em.current_epoch_count(), 0);
        assert_eq!(em.epoch_root(epoch_id), Some(root));
    }

    #[test]
    fn finalize_empty_epoch() {
        let mut em = EpochManager::new(3600);
        assert!(em.finalize_current_epoch().is_none());
    }

    #[test]
    fn epoch_root_deterministic() {
        let nfs = vec![
            pallas::Base::from(10u64),
            pallas::Base::from(20u64),
            pallas::Base::from(30u64),
        ];
        let r1 = compute_nullifier_epoch_root(&nfs);
        let r2 = compute_nullifier_epoch_root(&nfs);
        assert_eq!(r1, r2, "Epoch root must be deterministic");
    }

    #[test]
    fn different_nullifiers_different_roots() {
        let nfs_a = vec![pallas::Base::from(1u64), pallas::Base::from(2u64)];
        let nfs_b = vec![pallas::Base::from(3u64), pallas::Base::from(4u64)];
        let r_a = compute_nullifier_epoch_root(&nfs_a);
        let r_b = compute_nullifier_epoch_root(&nfs_b);
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn epoch_history_bounded() {
        let mut em = EpochManager::new(3600);
        for i in 0..(MAX_EPOCH_HISTORY as u64 + 10) {
            em.record_nullifier(pallas::Base::from(i));
            em.finalize_current_epoch();
        }
        assert!(em.finalized_epoch_count() <= MAX_EPOCH_HISTORY);
    }
}
