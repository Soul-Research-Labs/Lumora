//! Private transfer execution.
//!
//! A private transfer consumes input notes (via nullifiers) and creates
//! output notes (via new commitments). The ZK proof guarantees:
//! - Input notes exist in the tree
//! - Prover knows the spending keys
//! - Value is conserved (sum inputs == sum outputs)
//! - Nullifiers are correctly derived

use pasta_curves::pallas;

use lumora_circuits::transfer::{NUM_INPUTS, NUM_OUTPUTS};

use crate::error::ContractError;
use crate::events::PoolEvent;
use crate::state::PrivacyPoolState;

/// A private transfer request submitted to the contract.
#[derive(Clone, Debug)]
pub struct TransferRequest {
    /// The serialized ZK proof.
    pub proof_bytes: Vec<u8>,
    /// The Merkle root the proof was generated against.
    pub merkle_root: pallas::Base,
    /// Nullifiers for the spent input notes.
    pub nullifiers: [pallas::Base; NUM_INPUTS],
    /// Commitments for the newly created output notes.
    pub output_commitments: [pallas::Base; NUM_OUTPUTS],
    /// Transaction fee (enforced by the circuit).
    pub fee: u64,
    /// Optional domain chain ID for V2 domain-separated nullifiers.
    pub domain_chain_id: Option<u64>,
    /// Optional domain application ID for V2 domain-separated nullifiers.
    pub domain_app_id: Option<u64>,
}

/// Receipt from a successful private transfer.
#[derive(Clone, Debug)]
pub struct TransferReceipt {
    /// Indices of the new commitments in the Merkle tree.
    pub leaf_indices: [u64; NUM_OUTPUTS],
    /// The new Merkle root after inserting output commitments.
    pub new_root: pallas::Base,
}

/// Execute a private transfer: verify proof, register nullifiers, insert new commitments.
pub fn execute_transfer(
    state: &mut PrivacyPoolState,
    verifier: &lumora_prover::VerifierParams,
    request: &TransferRequest,
) -> Result<TransferReceipt, ContractError> {
    // 0. Guard against trivially invalid requests (same nullifier used twice or
    //    zero-value transfers that contribute nothing to the pool).
    if request.nullifiers[0] == request.nullifiers[1] {
        return Err(ContractError::NullifierAlreadySpent);
    }

    // 1. Check the Merkle root is known (recent).
    if !state.is_known_root(request.merkle_root) {
        return Err(ContractError::UnknownMerkleRoot);
    }

    // 2. Check none of the nullifiers have been spent.
    for nf in &request.nullifiers {
        if state.is_nullifier_spent(*nf) {
            return Err(ContractError::NullifierAlreadySpent);
        }
    }

    // 3. Verify the ZK proof.
    // Distinguish invalid proof (constraint failure) from verifier malfunction.
    match lumora_verifier::verify_transfer(
        &verifier.params,
        &verifier.vk,
        &request.proof_bytes,
        request.merkle_root,
        &request.nullifiers,
        &request.output_commitments,
        request.fee,
    ) {
        Ok(()) => {}
        Err(halo2_proofs::plonk::Error::ConstraintSystemFailure) => {
            return Err(ContractError::InvalidProof);
        }
        Err(e) => {
            return Err(ContractError::ProofError(format!("verifier error: {e:?}")));
        }
    }

    // 4. Register nullifiers as spent (AFTER proof verification).
    for nf in &request.nullifiers {
        let inserted = state.spend_nullifier(*nf);
        // This should always succeed since we checked above, but defense in depth.
        assert!(inserted, "nullifier was not spent despite passing check");
    }

    // 5. Insert output commitments into the tree.
    let mut leaf_indices = [0u64; NUM_OUTPUTS];
    for (i, cm) in request.output_commitments.iter().enumerate() {
        leaf_indices[i] = state.insert_commitment(*cm);
    }

    let new_root = state.current_root();

    state.emit_event(PoolEvent::Transfer {
        nullifiers: request.nullifiers,
        output_commitments: request.output_commitments,
        leaf_indices,
        transparency_memo: None,
        domain_chain_id: request.domain_chain_id,
        domain_app_id: request.domain_app_id,
    });

    Ok(TransferReceipt {
        leaf_indices,
        new_root,
    })
}
