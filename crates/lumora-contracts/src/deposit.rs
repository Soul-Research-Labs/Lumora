//! Deposit (shield) flow.
//!
//! A deposit takes public funds and creates a private note commitment
//! in the Merkle tree. No ZK proof is needed for deposits — the user
//! is simply converting public value to private value.

use pasta_curves::pallas;

use crate::error::ContractError;
use crate::events::PoolEvent;
use crate::state::PrivacyPoolState;

/// Minimum deposit amount (in base units) to prevent dust attacks.
pub const MIN_DEPOSIT_AMOUNT: u64 = 100;

/// A deposit request: shield `amount` into the privacy pool.
#[derive(Clone, Debug)]
pub struct DepositRequest {
    /// The note commitment for the newly created note.
    /// Computed off-chain as: `Poseidon(Poseidon(Poseidon(owner, value), asset), randomness)`
    pub commitment: pallas::Base,
    /// The amount being deposited (public, for balance tracking).
    pub amount: u64,
}

/// Receipt returned after a successful deposit.
#[derive(Clone, Debug)]
pub struct DepositReceipt {
    /// The index of the commitment in the Merkle tree.
    pub leaf_index: u64,
    /// The new Merkle root after insertion.
    pub new_root: pallas::Base,
}

/// Execute a deposit: insert the commitment into the tree, increase pool balance.
pub fn execute_deposit(
    state: &mut PrivacyPoolState,
    request: &DepositRequest,
) -> Result<DepositReceipt, ContractError> {
    if request.amount == 0 {
        return Err(ContractError::ZeroDeposit);
    }
    if request.amount < MIN_DEPOSIT_AMOUNT {
        return Err(ContractError::BelowMinimum {
            minimum: MIN_DEPOSIT_AMOUNT,
            actual: request.amount,
        });
    }

    // Track the pool balance (check before mutating the tree).
    state.pool_balance = state
        .pool_balance
        .checked_add(request.amount)
        .ok_or(ContractError::PoolBalanceOverflow)?;

    // Insert commitment into the Merkle tree.
    let leaf_index = state.insert_commitment(request.commitment)?;
    let new_root = state.current_root();

    state.emit_event(PoolEvent::Deposit {
        commitment: request.commitment,
        amount: request.amount,
        leaf_index,
    });

    Ok(DepositReceipt {
        leaf_index,
        new_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_basic() {
        let mut state = PrivacyPoolState::new();
        let cm = pallas::Base::from(42u64);
        let req = DepositRequest { commitment: cm, amount: 100 };
        let receipt = execute_deposit(&mut state, &req).unwrap();
        assert_eq!(receipt.leaf_index, 0);
        assert_eq!(state.pool_balance(), 100);
        assert_eq!(state.commitment_count(), 1);
    }

    #[test]
    fn deposit_zero_rejected() {
        let mut state = PrivacyPoolState::new();
        let cm = pallas::Base::from(1u64);
        let req = DepositRequest { commitment: cm, amount: 0 };
        assert_eq!(execute_deposit(&mut state, &req).unwrap_err(), ContractError::ZeroDeposit);
    }

    #[test]
    fn deposit_below_minimum_rejected() {
        let mut state = PrivacyPoolState::new();
        let cm = pallas::Base::from(1u64);
        let req = DepositRequest { commitment: cm, amount: MIN_DEPOSIT_AMOUNT - 1 };
        assert!(matches!(
            execute_deposit(&mut state, &req).unwrap_err(),
            ContractError::BelowMinimum { .. }
        ));
    }

    #[test]
    fn deposit_multiple_increments_balance() {
        let mut state = PrivacyPoolState::new();
        for i in 1..=3 {
            let cm = pallas::Base::from(i as u64);
            let req = DepositRequest { commitment: cm, amount: 500 };
            let receipt = execute_deposit(&mut state, &req).unwrap();
            assert_eq!(receipt.leaf_index, (i - 1) as u64);
        }
        assert_eq!(state.pool_balance(), 1500);
        assert_eq!(state.commitment_count(), 3);
    }

    #[test]
    fn deposit_emits_event() {
        let mut state = PrivacyPoolState::new();
        let cm = pallas::Base::from(7u64);
        let req = DepositRequest { commitment: cm, amount: 200 };
        execute_deposit(&mut state, &req).unwrap();
        assert_eq!(state.events().len(), 1);
        match &state.events()[0] {
            PoolEvent::Deposit { amount, leaf_index, .. } => {
                assert_eq!(*amount, 200);
                assert_eq!(*leaf_index, 0);
            }
            _ => panic!("expected Deposit event"),
        }
    }

    #[test]
    fn deposit_updates_root_history() {
        let mut state = PrivacyPoolState::new();
        let root_before = state.current_root();
        let req = DepositRequest { commitment: pallas::Base::from(1u64), amount: 100 };
        execute_deposit(&mut state, &req).unwrap();
        let root_after = state.current_root();
        assert_ne!(root_before, root_after);
        assert!(state.is_known_root(root_before));
        assert!(state.is_known_root(root_after));
    }
}
