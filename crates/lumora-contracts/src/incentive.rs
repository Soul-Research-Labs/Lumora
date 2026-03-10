//! Prover incentive mechanism — fee tracking and reward distribution.
//!
//! This module manages the application-layer fee model for provers:
//!
//! - Each transfer and withdrawal has an associated fee.
//! - Fees are accrued to the prover's account in a fee ledger.
//! - Provers can claim accumulated fees.
//!
//! **Note:** The current ZK circuits enforce strict value conservation
//! without a fee term. Until circuit-level fee support (#26) is added,
//! fees are tracked off-chain/application-layer only — they represent
//! a "service charge" that the submitting client agrees to pay the
//! prover, separate from the value-conservation constraint.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Fee schedule for different transaction types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Fee per private transfer (in base units).
    pub transfer_fee: u64,
    /// Fee per withdrawal (in base units).
    pub withdraw_fee: u64,
    /// Fee per deposit (typically 0 — deposits are free).
    pub deposit_fee: u64,
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            transfer_fee: 10,
            withdraw_fee: 20,
            deposit_fee: 0,
        }
    }
}

/// Identifies a prover for fee accounting.
pub type ProverId = String;

/// A record of a single fee event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRecord {
    /// Which prover earned the fee.
    pub prover: ProverId,
    /// Amount earned.
    pub amount: u64,
    /// Transaction type that generated the fee.
    pub tx_type: FeeType,
    /// Pool height at the time the fee was accrued.
    pub height: u64,
}

/// Transaction type for fee classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeType {
    Deposit,
    Transfer,
    Withdraw,
}

impl std::fmt::Display for FeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deposit => write!(f, "deposit"),
            Self::Transfer => write!(f, "transfer"),
            Self::Withdraw => write!(f, "withdraw"),
        }
    }
}

/// The prover fee ledger — tracks fee accruals and claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverFeeLedger {
    /// The active fee schedule.
    pub schedule: FeeSchedule,
    /// Accrued (unclaimed) balances per prover.
    balances: HashMap<ProverId, u64>,
    /// Total fees accrued across all provers.
    total_accrued: u64,
    /// Total fees claimed (paid out) across all provers.
    total_claimed: u64,
    /// Recent fee records (bounded, for auditing).
    records: Vec<FeeRecord>,
    /// Maximum number of records to retain.
    max_records: usize,
}

/// Default maximum fee records to keep.
const DEFAULT_MAX_RECORDS: usize = 10_000;

impl ProverFeeLedger {
    /// Create a new ledger with the default fee schedule.
    pub fn new() -> Self {
        Self {
            schedule: FeeSchedule::default(),
            balances: HashMap::new(),
            total_accrued: 0,
            total_claimed: 0,
            records: Vec::new(),
            max_records: DEFAULT_MAX_RECORDS,
        }
    }

    /// Create a new ledger with a custom fee schedule.
    pub fn with_schedule(schedule: FeeSchedule) -> Self {
        Self {
            schedule,
            ..Self::new()
        }
    }

    /// Accrue a fee for a prover based on the transaction type.
    pub fn accrue_fee(
        &mut self,
        prover: &str,
        tx_type: FeeType,
        height: u64,
    ) -> u64 {
        let amount = match tx_type {
            FeeType::Deposit => self.schedule.deposit_fee,
            FeeType::Transfer => self.schedule.transfer_fee,
            FeeType::Withdraw => self.schedule.withdraw_fee,
        };

        if amount == 0 {
            return 0;
        }

        *self.balances.entry(prover.to_string()).or_insert(0) += amount;
        self.total_accrued += amount;

        // Record for auditing.
        if self.records.len() >= self.max_records {
            self.records.remove(0);
        }
        self.records.push(FeeRecord {
            prover: prover.to_string(),
            amount,
            tx_type,
            height,
        });

        amount
    }

    /// Get a prover's unclaimed balance.
    pub fn balance(&self, prover: &str) -> u64 {
        self.balances.get(prover).copied().unwrap_or(0)
    }

    /// Claim (withdraw) all accrued fees for a prover.
    ///
    /// Returns the amount claimed, resetting the prover's balance to 0.
    pub fn claim(&mut self, prover: &str) -> u64 {
        let amount = self.balances.remove(prover).unwrap_or(0);
        self.total_claimed += amount;
        amount
    }

    /// Claim up to `max_amount` from a prover's balance.
    pub fn claim_partial(&mut self, prover: &str, max_amount: u64) -> u64 {
        let balance = self.balances.entry(prover.to_string()).or_insert(0);
        let claim = (*balance).min(max_amount);
        *balance -= claim;
        if *balance == 0 {
            self.balances.remove(prover);
        }
        self.total_claimed += claim;
        claim
    }

    /// Total fees accrued across all provers.
    pub fn total_accrued(&self) -> u64 {
        self.total_accrued
    }

    /// Total fees claimed (paid out).
    pub fn total_claimed(&self) -> u64 {
        self.total_claimed
    }

    /// Total unclaimed balance across all provers.
    pub fn total_unclaimed(&self) -> u64 {
        self.total_accrued.saturating_sub(self.total_claimed)
    }

    /// Number of provers with outstanding balances.
    pub fn active_prover_count(&self) -> usize {
        self.balances.len()
    }

    /// List all provers and their balances.
    pub fn all_balances(&self) -> Vec<(ProverId, u64)> {
        self.balances
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Recent fee records for auditing.
    pub fn recent_records(&self) -> &[FeeRecord] {
        &self.records
    }
}

impl Default for ProverFeeLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schedule() {
        let schedule = FeeSchedule::default();
        assert_eq!(schedule.transfer_fee, 10);
        assert_eq!(schedule.withdraw_fee, 20);
        assert_eq!(schedule.deposit_fee, 0);
    }

    #[test]
    fn accrue_and_claim() {
        let mut ledger = ProverFeeLedger::new();

        let fee = ledger.accrue_fee("prover-1", FeeType::Transfer, 100);
        assert_eq!(fee, 10);
        assert_eq!(ledger.balance("prover-1"), 10);

        ledger.accrue_fee("prover-1", FeeType::Withdraw, 101);
        assert_eq!(ledger.balance("prover-1"), 30); // 10 + 20

        let claimed = ledger.claim("prover-1");
        assert_eq!(claimed, 30);
        assert_eq!(ledger.balance("prover-1"), 0);
        assert_eq!(ledger.total_claimed(), 30);
    }

    #[test]
    fn deposit_fee_zero_by_default() {
        let mut ledger = ProverFeeLedger::new();
        let fee = ledger.accrue_fee("prover-1", FeeType::Deposit, 50);
        assert_eq!(fee, 0);
        assert_eq!(ledger.balance("prover-1"), 0);
    }

    #[test]
    fn partial_claim() {
        let mut ledger = ProverFeeLedger::new();
        ledger.accrue_fee("prover-1", FeeType::Transfer, 1);
        ledger.accrue_fee("prover-1", FeeType::Transfer, 2);
        assert_eq!(ledger.balance("prover-1"), 20);

        let claimed = ledger.claim_partial("prover-1", 15);
        assert_eq!(claimed, 15);
        assert_eq!(ledger.balance("prover-1"), 5);
    }

    #[test]
    fn multiple_provers() {
        let mut ledger = ProverFeeLedger::new();
        ledger.accrue_fee("prover-1", FeeType::Transfer, 1);
        ledger.accrue_fee("prover-2", FeeType::Withdraw, 2);

        assert_eq!(ledger.active_prover_count(), 2);
        assert_eq!(ledger.total_accrued(), 30); // 10 + 20
        assert_eq!(ledger.total_unclaimed(), 30);

        ledger.claim("prover-1");
        assert_eq!(ledger.active_prover_count(), 1);
        assert_eq!(ledger.total_unclaimed(), 20);
    }

    #[test]
    fn custom_schedule() {
        let schedule = FeeSchedule {
            transfer_fee: 50,
            withdraw_fee: 100,
            deposit_fee: 5,
        };
        let mut ledger = ProverFeeLedger::with_schedule(schedule);
        ledger.accrue_fee("p1", FeeType::Deposit, 1);
        assert_eq!(ledger.balance("p1"), 5);
    }
}
