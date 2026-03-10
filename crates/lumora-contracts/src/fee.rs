//! Dynamic fee estimation.
//!
//! Replaces the former hardcoded `TRANSFER_FEE = 10` / `WITHDRAW_FEE = 20`
//! with a congestion-aware model:
//!
//! ```text
//! effective_fee = base_fee * (1 + congestion_factor * (pending / capacity))
//! ```
//!
//! - `pending / capacity` is the mempool utilisation ratio (0.0 – 1.0).
//! - `congestion_factor` controls how aggressively fees rise under load.
//! - Fees are always clamped to `[min_fee, max_fee]`.

use serde::{Deserialize, Serialize};

/// Parameters for a single fee lane (transfer or withdraw).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeLaneConfig {
    /// Base fee when the mempool is empty.
    pub base_fee: u64,
    /// Minimum fee (floor).
    pub min_fee: u64,
    /// Maximum fee (ceiling).
    pub max_fee: u64,
    /// Multiplier applied to the congestion ratio.  A value of 10 means
    /// fees can grow up to `base_fee * 11` at full capacity.
    pub congestion_factor: u64,
}

/// Configuration for the dynamic fee estimator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicFeeConfig {
    pub transfer: FeeLaneConfig,
    pub withdraw: FeeLaneConfig,
    /// Mempool capacity used as the denominator in the congestion ratio.
    pub mempool_capacity: usize,
}

impl Default for DynamicFeeConfig {
    fn default() -> Self {
        Self {
            transfer: FeeLaneConfig {
                base_fee: 10,
                min_fee: 1,
                max_fee: 500,
                congestion_factor: 10,
            },
            withdraw: FeeLaneConfig {
                base_fee: 20,
                min_fee: 2,
                max_fee: 1000,
                congestion_factor: 10,
            },
            mempool_capacity: 256,
        }
    }
}

/// Dynamic fee estimator.
#[derive(Debug, Clone)]
pub struct DynamicFeeEstimator {
    config: DynamicFeeConfig,
}

impl DynamicFeeEstimator {
    pub fn new(config: DynamicFeeConfig) -> Self {
        Self { config }
    }

    /// Estimate the transfer fee given the current number of pending
    /// transactions in the mempool.
    pub fn transfer_fee(&self, pending_tx_count: usize) -> u64 {
        Self::compute(&self.config.transfer, pending_tx_count, self.config.mempool_capacity)
    }

    /// Estimate the withdrawal fee given the current pending count.
    pub fn withdraw_fee(&self, pending_tx_count: usize) -> u64 {
        Self::compute(&self.config.withdraw, pending_tx_count, self.config.mempool_capacity)
    }

    fn compute(lane: &FeeLaneConfig, pending: usize, capacity: usize) -> u64 {
        if capacity == 0 {
            return lane.base_fee.clamp(lane.min_fee, lane.max_fee);
        }
        // Ratio clamped to [0, 1] — pending can exceed capacity.
        let ratio_num = pending.min(capacity) as u128;
        let ratio_den = capacity as u128;

        // fee = base_fee + base_fee * congestion_factor * ratio
        let surge = (lane.base_fee as u128)
            .saturating_mul(lane.congestion_factor as u128)
            .saturating_mul(ratio_num)
            / ratio_den;
        let fee = (lane.base_fee as u128).saturating_add(surge);
        (fee as u64).clamp(lane.min_fee, lane.max_fee)
    }
}

impl Default for DynamicFeeEstimator {
    fn default() -> Self {
        Self::new(DynamicFeeConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mempool_returns_base_fee() {
        let est = DynamicFeeEstimator::default();
        assert_eq!(est.transfer_fee(0), 10);
        assert_eq!(est.withdraw_fee(0), 20);
    }

    #[test]
    fn full_mempool_returns_max_multiplier() {
        let est = DynamicFeeEstimator::default(); // capacity = 256
        // At full capacity: fee = 10 + 10*10*1 = 110 for transfer
        assert_eq!(est.transfer_fee(256), 110);
        // withdrawal: 20 + 20*10*1 = 220
        assert_eq!(est.withdraw_fee(256), 220);
    }

    #[test]
    fn half_mempool() {
        let est = DynamicFeeEstimator::default(); // capacity = 256
        // 128/256 = 0.5 → transfer: 10 + 10*10*0.5 = 60
        assert_eq!(est.transfer_fee(128), 60);
    }

    #[test]
    fn over_capacity_capped_at_max() {
        let est = DynamicFeeEstimator::default();
        // Even with 10× capacity, ratio capped at 1.
        assert_eq!(est.transfer_fee(2560), 110);
    }

    #[test]
    fn respects_min_max() {
        let config = DynamicFeeConfig {
            transfer: FeeLaneConfig {
                base_fee: 0,
                min_fee: 5,
                max_fee: 50,
                congestion_factor: 100,
            },
            withdraw: FeeLaneConfig {
                base_fee: 1000,
                min_fee: 10,
                max_fee: 100,
                congestion_factor: 10,
            },
            mempool_capacity: 100,
        };
        let est = DynamicFeeEstimator::new(config);
        // base=0, surge=0 → clamped to min=5
        assert_eq!(est.transfer_fee(0), 5);
        // base=1000 → clamped to max=100
        assert_eq!(est.withdraw_fee(0), 100);
    }
}
