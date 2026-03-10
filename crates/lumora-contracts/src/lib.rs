//! Lumora Contracts — on-chain state management and verification.
//!
//! This crate implements the contract-level logic for the Lumora privacy pool:
//!
//! - **Deposits**: Shield public funds into the privacy pool (no proof needed).
//! - **Transfers**: Private note-to-note transfers verified by Halo2 proof.
//! - **Withdrawals**: Unshield private notes back to public funds (proof required).
//!
//! The [`PrivacyPool`] struct is the main entry point, wrapping the on-chain state
//! and verifier parameters into a single interface.
//!
//! # Architecture
//!
//! ```text
//! User → deposit(amount, commitment) → [state: tree.insert(cm), balance += amount]
//! User → transfer(proof, nullifiers, new_cms) → [verify proof, mark nf spent, insert cms]
//! User → withdraw(proof, nullifiers, change_cms, amount) → [verify, mark nf, insert, balance -= amount]
//! ```

pub mod bridge;
pub mod compliance;
pub mod deposit;
pub mod epoch;
pub mod error;
pub mod events;
pub mod fee;
pub mod governance;
pub mod incentive;
pub mod migration;
pub mod rollup;
pub mod snapshot;
pub mod state;
pub mod transfer;
pub mod wal;
pub mod withdraw;

pub use bridge::{BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge, LocalBridge};
pub use epoch::{EpochManager, EpochId};
pub use deposit::{execute_deposit, DepositReceipt, DepositRequest, MIN_DEPOSIT_AMOUNT};
pub use error::ContractError;
pub use events::PoolEvent;
pub use events::TransparencyMemo;
pub use state::PrivacyPoolState;
pub use transfer::{execute_transfer, TransferReceipt, TransferRequest};
pub use withdraw::{execute_withdraw, WithdrawReceipt, WithdrawRequest, MIN_WITHDRAW_AMOUNT};

use lumora_prover::{VerifierParams, WithdrawVerifierParams};

/// High-level privacy pool interface.
///
/// Combines the on-chain state with verifier parameters for a complete
/// contract-like API.
pub struct PrivacyPool {
    pub state: PrivacyPoolState,
    pub verifier: VerifierParams,
    pub withdraw_verifier: WithdrawVerifierParams,
}

impl PrivacyPool {
    /// Create a new privacy pool with the given verifier params.
    pub fn new(verifier: VerifierParams, withdraw_verifier: WithdrawVerifierParams) -> Self {
        Self {
            state: PrivacyPoolState::new(),
            verifier,
            withdraw_verifier,
        }
    }

    /// Create a privacy pool with existing state and verifier params.
    pub fn new_with_state(
        state: PrivacyPoolState,
        verifier: VerifierParams,
        withdraw_verifier: WithdrawVerifierParams,
    ) -> Self {
        Self { state, verifier, withdraw_verifier }
    }

    /// Shield funds into the pool.
    pub fn deposit(&mut self, request: &DepositRequest) -> Result<DepositReceipt, ContractError> {
        execute_deposit(&mut self.state, request)
    }

    /// Execute a private transfer.
    pub fn transfer(
        &mut self,
        request: &TransferRequest,
    ) -> Result<TransferReceipt, ContractError> {
        execute_transfer(&mut self.state, &self.verifier, request)
    }

    /// Withdraw (unshield) funds from the pool.
    pub fn withdraw(
        &mut self,
        request: &WithdrawRequest,
    ) -> Result<WithdrawReceipt, ContractError> {
        execute_withdraw(&mut self.state, &self.withdraw_verifier, request)
    }
}
