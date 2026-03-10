//! Batch Accumulator — metadata resistance via transaction batching.
//!
//! Inspired by ZASEON's BatchAccumulator: instead of processing transactions
//! immediately, they are collected into batches. Batches are released only when
//! both conditions are met:
//!
//! 1. **Minimum batch size** (default 4) is reached.
//! 2. **Minimum delay floor** has elapsed since the batch was created.
//!
//! If a batch has been waiting too long (max wait time) without reaching the
//! minimum size, it is padded with dummy entries and released anyway.
//!
//! This prevents:
//! - **Timing correlation**: Individual transaction timing is obscured.
//! - **Frequency inference**: Even the min-batch-reached event is delayed.
//! - **Size analysis**: Under-sized batches are padded to the minimum.

use std::time::{Duration, Instant};

use pasta_curves::pallas;

/// Configuration for batch accumulation behavior.
#[derive(Clone, Debug)]
pub struct BatchConfig {
    /// Minimum number of transactions before a batch can be released.
    pub min_batch_size: usize,
    /// Maximum number of transactions in a single batch.
    pub max_batch_size: usize,
    /// Minimum time a batch must wait before release (even if full).
    pub min_delay: Duration,
    /// Maximum time to wait before releasing an under-sized batch (with padding).
    pub max_wait: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            min_batch_size: 4,
            max_batch_size: 32,
            min_delay: Duration::from_secs(10),
            max_wait: Duration::from_secs(120),
        }
    }
}

/// A pending transaction in the batch accumulator.
#[derive(Clone, Debug)]
pub struct PendingTransaction {
    /// The proof data (opaque bytes).
    pub proof_bytes: Vec<u8>,
    /// Merkle root referenced by the proof.
    pub merkle_root: pallas::Base,
    /// Nullifiers revealed by this transaction.
    pub nullifiers: [pallas::Base; 2],
    /// Output commitments produced by this transaction.
    pub output_commitments: [pallas::Base; 2],
    /// Transaction fee.
    pub fee: u64,
    /// Whether this is a dummy padding transaction.
    pub is_dummy: bool,
}

/// The result of polling the accumulator.
#[derive(Debug)]
pub enum BatchPollResult {
    /// No batch ready yet.
    NotReady,
    /// A batch is ready for processing.
    Ready(Vec<PendingTransaction>),
}

/// Accumulates transactions for batched release.
pub struct BatchAccumulator {
    config: BatchConfig,
    pending: Vec<PendingTransaction>,
    batch_created: Option<Instant>,
}

impl BatchAccumulator {
    /// Create a new batch accumulator with the given configuration.
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            pending: Vec::new(),
            batch_created: None,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(BatchConfig::default())
    }

    /// Add a transaction to the current batch.
    ///
    /// Returns `true` if accepted, `false` if the batch is already at max capacity.
    pub fn submit(&mut self, tx: PendingTransaction) -> bool {
        if self.pending.len() >= self.config.max_batch_size {
            return false;
        }

        if self.batch_created.is_none() {
            self.batch_created = Some(Instant::now());
        }

        self.pending.push(tx);
        true
    }

    /// Number of pending transactions.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if a batch is ready to be released.
    ///
    /// A batch is ready when:
    /// - It has at least `min_batch_size` transactions AND `min_delay` has passed, OR
    /// - `max_wait` time has elapsed (releases with padding if under-sized).
    pub fn poll(&mut self) -> BatchPollResult {
        if self.pending.is_empty() {
            return BatchPollResult::NotReady;
        }

        let created = match self.batch_created {
            Some(t) => t,
            None => return BatchPollResult::NotReady,
        };

        let elapsed = created.elapsed();

        // Case 1: min batch size met AND min delay passed.
        if self.pending.len() >= self.config.min_batch_size
            && elapsed >= self.config.min_delay
        {
            return self.release_batch();
        }

        // Case 2: max wait exceeded — pad and release.
        if elapsed >= self.config.max_wait {
            self.pad_to_min_size();
            return self.release_batch();
        }

        BatchPollResult::NotReady
    }

    /// Pad the current batch with dummy transactions to reach `min_batch_size`.
    fn pad_to_min_size(&mut self) {
        while self.pending.len() < self.config.min_batch_size {
            self.pending.push(PendingTransaction {
                proof_bytes: vec![0u8; 32], // Minimal dummy proof
                merkle_root: pallas::Base::zero(),
                nullifiers: [pallas::Base::zero(); 2],
                output_commitments: [pallas::Base::zero(); 2],
                fee: 0,
                is_dummy: true,
            });
        }
    }

    /// Release the current batch, resetting the accumulator state.
    fn release_batch(&mut self) -> BatchPollResult {
        let batch = std::mem::take(&mut self.pending);
        self.batch_created = None;
        BatchPollResult::Ready(batch)
    }

    /// Force-release whatever is currently pending (for shutdown/flush).
    pub fn flush(&mut self) -> Vec<PendingTransaction> {
        let batch = std::mem::take(&mut self.pending);
        self.batch_created = None;
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(value: u64) -> PendingTransaction {
        PendingTransaction {
            proof_bytes: vec![value as u8; 32],
            merkle_root: pallas::Base::from(value),
            nullifiers: [pallas::Base::from(value * 10), pallas::Base::from(value * 10 + 1)],
            output_commitments: [pallas::Base::from(value * 20), pallas::Base::from(value * 20 + 1)],
            fee: value,
            is_dummy: false,
        }
    }

    #[test]
    fn empty_batch_not_ready() {
        let mut acc = BatchAccumulator::with_defaults();
        assert!(matches!(acc.poll(), BatchPollResult::NotReady));
    }

    #[test]
    fn under_min_batch_not_ready() {
        let config = BatchConfig {
            min_batch_size: 4,
            min_delay: Duration::from_millis(0),
            max_wait: Duration::from_secs(999),
            ..Default::default()
        };
        let mut acc = BatchAccumulator::new(config);
        acc.submit(make_tx(1));
        acc.submit(make_tx(2));
        // Only 2 of 4 — not ready.
        assert!(matches!(acc.poll(), BatchPollResult::NotReady));
    }

    #[test]
    fn min_size_met_with_zero_delay_releases() {
        let config = BatchConfig {
            min_batch_size: 2,
            min_delay: Duration::from_millis(0),
            max_wait: Duration::from_secs(999),
            ..Default::default()
        };
        let mut acc = BatchAccumulator::new(config);
        acc.submit(make_tx(1));
        acc.submit(make_tx(2));
        match acc.poll() {
            BatchPollResult::Ready(batch) => {
                assert_eq!(batch.len(), 2);
                assert!(!batch[0].is_dummy);
                assert!(!batch[1].is_dummy);
            }
            _ => panic!("batch should be ready"),
        }
        assert_eq!(acc.pending_count(), 0);
    }

    #[test]
    fn min_delay_prevents_early_release() {
        let config = BatchConfig {
            min_batch_size: 2,
            min_delay: Duration::from_secs(999), // Very long delay
            max_wait: Duration::from_secs(9999),
            ..Default::default()
        };
        let mut acc = BatchAccumulator::new(config);
        acc.submit(make_tx(1));
        acc.submit(make_tx(2));
        // Min size met but delay not passed.
        assert!(matches!(acc.poll(), BatchPollResult::NotReady));
    }

    #[test]
    fn max_wait_forces_release_with_padding() {
        let config = BatchConfig {
            min_batch_size: 4,
            min_delay: Duration::from_millis(0),
            max_wait: Duration::from_millis(0), // Instant max wait
            ..Default::default()
        };
        let mut acc = BatchAccumulator::new(config);
        acc.submit(make_tx(1)); // Only 1 tx, but max_wait=0
        match acc.poll() {
            BatchPollResult::Ready(batch) => {
                assert_eq!(batch.len(), 4); // Padded to min_batch_size
                assert!(!batch[0].is_dummy);
                assert!(batch[1].is_dummy);
                assert!(batch[2].is_dummy);
                assert!(batch[3].is_dummy);
            }
            _ => panic!("batch should be forced after max_wait"),
        }
    }

    #[test]
    fn max_capacity_rejects() {
        let config = BatchConfig {
            max_batch_size: 2,
            ..Default::default()
        };
        let mut acc = BatchAccumulator::new(config);
        assert!(acc.submit(make_tx(1)));
        assert!(acc.submit(make_tx(2)));
        assert!(!acc.submit(make_tx(3))); // Rejected — at capacity.
    }

    #[test]
    fn flush_returns_all_pending() {
        let mut acc = BatchAccumulator::with_defaults();
        acc.submit(make_tx(1));
        acc.submit(make_tx(2));
        let flushed = acc.flush();
        assert_eq!(flushed.len(), 2);
        assert_eq!(acc.pending_count(), 0);
    }
}
