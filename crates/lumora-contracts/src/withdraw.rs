//! Withdrawal (unshield) flow.
//!
//! A withdrawal converts private notes back into public funds.
//! The user proves ownership via a WithdrawCircuit ZK proof that enforces:
//!   sum(input values) == sum(output values) + exit_value
//!
//! The `exit_value` is a public input that becomes the withdrawal amount.

use pasta_curves::pallas;

use lumora_circuits::transfer::{NUM_INPUTS, NUM_OUTPUTS};

use crate::error::ContractError;
use crate::events::PoolEvent;
use crate::state::PrivacyPoolState;

/// Minimum withdrawal amount (in base units).
pub const MIN_WITHDRAW_AMOUNT: u64 = 100;

/// A withdrawal request: unshield funds from the privacy pool.
#[derive(Clone, Debug)]
pub struct WithdrawRequest {
    /// The serialized ZK proof (WithdrawCircuit).
    pub proof_bytes: Vec<u8>,
    /// The Merkle root the proof was generated against.
    pub merkle_root: pallas::Base,
    /// Nullifiers for the spent input notes.
    pub nullifiers: [pallas::Base; NUM_INPUTS],
    /// Output commitments (change note(s) — may include a zero-value dummy).
    pub output_commitments: [pallas::Base; NUM_OUTPUTS],
    /// The amount being withdrawn (public — must match the circuit's exit_value).
    pub amount: u64,
    /// Transaction fee (enforced by the circuit).
    pub fee: u64,
    /// Recipient address (opaque bytes — rollup-specific addressing).
    pub recipient: [u8; 32],
    /// Optional domain chain ID for V2 domain-separated nullifiers.
    pub domain_chain_id: Option<u64>,
    /// Optional domain application ID for V2 domain-separated nullifiers.
    pub domain_app_id: Option<u64>,
}

/// Receipt from a successful withdrawal.
#[derive(Clone, Debug)]
pub struct WithdrawReceipt {
    /// Change note leaf indices (if any change was returned to the pool).
    pub change_leaf_indices: [u64; NUM_OUTPUTS],
    /// The new Merkle root.
    pub new_root: pallas::Base,
    /// Amount released to recipient.
    pub amount: u64,
}

/// Execute a withdrawal: verify proof, register nullifiers, release funds.
///
/// The WithdrawCircuit proof enforces `sum(inputs) == sum(outputs) + exit_value`
/// where `exit_value` must equal `request.amount`.
pub fn execute_withdraw(
    state: &mut PrivacyPoolState,
    verifier: &lumora_prover::WithdrawVerifierParams,
    request: &WithdrawRequest,
) -> Result<WithdrawReceipt, ContractError> {
    if request.amount == 0 {
        return Err(ContractError::ZeroWithdrawal);
    }
    if request.amount < MIN_WITHDRAW_AMOUNT {
        return Err(ContractError::BelowMinimum {
            minimum: MIN_WITHDRAW_AMOUNT,
            actual: request.amount,
        });
    }

    // 1. Check the pool has sufficient balance.
    if request.amount > state.pool_balance {
        return Err(ContractError::InsufficientPoolBalance);
    }

    // 2. Check the Merkle root is known.
    if !state.is_known_root(request.merkle_root) {
        return Err(ContractError::UnknownMerkleRoot);
    }

    // 3. Check nullifiers are fresh.
    for nf in &request.nullifiers {
        if state.is_nullifier_spent(*nf) {
            return Err(ContractError::NullifierAlreadySpent);
        }
    }

    // 4. Verify the ZK proof (WithdrawCircuit — includes exit_value as public input).
    let valid = lumora_verifier::verify_withdraw(
        &verifier.params,
        &verifier.vk,
        &request.proof_bytes,
        request.merkle_root,
        &request.nullifiers,
        &request.output_commitments,
        request.amount,
        request.fee,
    );
    if valid.is_err() {
        return Err(ContractError::InvalidProof);
    }

    // 5. Register nullifiers.
    for nf in &request.nullifiers {
        let inserted = state.spend_nullifier(*nf);
        assert!(inserted, "nullifier was not spent despite passing check");
    }

    // 6. Insert change commitments.
    let mut change_leaf_indices = [0u64; NUM_OUTPUTS];
    for (i, cm) in request.output_commitments.iter().enumerate() {
        change_leaf_indices[i] = state.insert_commitment(*cm);
    }

    // 7. Decrease pool balance.
    state.pool_balance = state.pool_balance.checked_sub(request.amount)
        .ok_or(ContractError::InsufficientPoolBalance)?;

    let new_root = state.current_root();

    state.emit_event(PoolEvent::Withdraw {
        nullifiers: request.nullifiers,
        change_commitments: request.output_commitments,
        amount: request.amount,
        recipient: request.recipient,
        leaf_indices: change_leaf_indices,
        transparency_memo: None,
        domain_chain_id: request.domain_chain_id,
        domain_app_id: request.domain_app_id,
    });

    Ok(WithdrawReceipt {
        change_leaf_indices,
        new_root,
        amount: request.amount,
    })
}
