//! LUMORA Verifier — proof verification for private transfers.
//!
//! Provides a standalone verification function that checks a Halo2 proof
//! against the transfer circuit's verifying key. This is the logic that
//! would run on-chain (or in a rollup's verification contract).

pub mod versioned;

use halo2_proofs::{
    plonk::{self, verify_proof, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{pallas, vesta};

use lumora_circuits::transfer::{transfer_public_inputs, NUM_INPUTS, NUM_OUTPUTS};
use lumora_circuits::withdraw::withdraw_public_inputs;

/// Verify a serialized transfer proof against public inputs.
///
/// # Arguments
/// - `params`: SRS parameters (same K used during proving).
/// - `vk`: verifying key (generated during setup).
/// - `proof_bytes`: the serialized proof.
/// - `merkle_root`: the Merkle root at the time of the transaction.
/// - `nullifiers`: the nullifiers for the spent notes.
/// - `output_commitments`: the commitments for the newly created notes.
pub fn verify_transfer(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    merkle_root: pallas::Base,
    nullifiers: &[pallas::Base; NUM_INPUTS],
    output_commitments: &[pallas::Base; NUM_OUTPUTS],
    fee: u64,
) -> Result<(), plonk::Error> {
    let public_inputs = transfer_public_inputs(merkle_root, nullifiers, output_commitments, fee);
    let strategy = halo2_proofs::plonk::SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(params, vk, strategy, &[&[&public_inputs]], &mut transcript)
}

/// Simplified verification using a `VerifierParams` bundle.
pub fn verify_transfer_proof(
    verifier: &lumora_prover::VerifierParams,
    proof_bytes: &[u8],
    merkle_root: pallas::Base,
    nullifiers: &[pallas::Base; NUM_INPUTS],
    output_commitments: &[pallas::Base; NUM_OUTPUTS],
    fee: u64,
) -> bool {
    verify_transfer(
        &verifier.params,
        &verifier.vk,
        proof_bytes,
        merkle_root,
        nullifiers,
        output_commitments,
        fee,
    )
    .is_ok()
}

// ============================================================================
// Withdrawal verification
// ============================================================================

/// Verify a serialized withdrawal proof against public inputs.
#[allow(clippy::too_many_arguments)]
pub fn verify_withdraw(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    merkle_root: pallas::Base,
    nullifiers: &[pallas::Base; NUM_INPUTS],
    output_commitments: &[pallas::Base; NUM_OUTPUTS],
    exit_value: u64,
    fee: u64,
) -> Result<(), plonk::Error> {
    let public_inputs = withdraw_public_inputs(merkle_root, nullifiers, output_commitments, exit_value, fee);
    let strategy = halo2_proofs::plonk::SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(params, vk, strategy, &[&[&public_inputs]], &mut transcript)
}

/// Simplified withdrawal verification using a `WithdrawVerifierParams` bundle.
pub fn verify_withdraw_proof(
    verifier: &lumora_prover::WithdrawVerifierParams,
    proof_bytes: &[u8],
    merkle_root: pallas::Base,
    nullifiers: &[pallas::Base; NUM_INPUTS],
    output_commitments: &[pallas::Base; NUM_OUTPUTS],
    exit_value: u64,
    fee: u64,
) -> bool {
    verify_withdraw(
        &verifier.params,
        &verifier.vk,
        proof_bytes,
        merkle_root,
        nullifiers,
        output_commitments,
        exit_value,
        fee,
    )
    .is_ok()
}

// ============================================================================
// Batch verification
// ============================================================================

use halo2_proofs::plonk::BatchVerifier;

/// Inputs for one transfer proof in a batch.
pub struct TransferBatchItem {
    pub proof_bytes: Vec<u8>,
    pub merkle_root: pallas::Base,
    pub nullifiers: [pallas::Base; NUM_INPUTS],
    pub output_commitments: [pallas::Base; NUM_OUTPUTS],
    pub fee: u64,
}

/// Verify multiple transfer proofs in a single batch.
///
/// Returns `true` if **all** proofs are valid. If any proof is invalid the
/// caller must re-verify individually to find the culprit.
pub fn batch_verify_transfers(
    verifier: &lumora_prover::VerifierParams,
    items: &[TransferBatchItem],
) -> bool {
    let mut batch = BatchVerifier::new();
    for item in items {
        let public_inputs = transfer_public_inputs(
            item.merkle_root,
            &item.nullifiers,
            &item.output_commitments,
            item.fee,
        );
        batch.add_proof(vec![vec![public_inputs]], item.proof_bytes.clone());
    }
    batch.finalize(&verifier.params, &verifier.vk)
}

/// Verify multiple transfer proofs and return the index of the first invalid proof,
/// or `Ok(())` if all proofs are valid.
///
/// Performs individual (sequential) verification so the specific failing proof
/// can be identified. Use `batch_verify_transfers` when you only need a pass/fail.
pub fn find_first_invalid_transfer(
    verifier: &lumora_prover::VerifierParams,
    items: &[TransferBatchItem],
) -> Result<(), usize> {
    for (i, item) in items.iter().enumerate() {
        if verify_transfer(
            &verifier.params,
            &verifier.vk,
            &item.proof_bytes,
            item.merkle_root,
            &item.nullifiers,
            &item.output_commitments,
            item.fee,
        ).is_err() {
            return Err(i);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumora_note::keys::scalar_to_base;
    use lumora_note::{Note, SpendingKey};
    use lumora_prover::{
        circuit_commitment, prove_transfer, prove_withdraw,
        setup, setup_withdraw, InputNote, OutputNote,
    };
    use lumora_tree::IncrementalMerkleTree;

    /// Build a minimal 2-in-2-out transfer scenario and return all components.
    fn build_transfer_fixture() -> (
        lumora_prover::ProverParams,
        lumora_prover::VerifierParams,
        lumora_prover::TransferProof,
    ) {
        let (prover, verifier) = setup().expect("transfer setup");

        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let sk_base = scalar_to_base(sk.inner());

        let r1 = scalar_to_base(pallas::Scalar::from(111u64));
        let r2 = scalar_to_base(pallas::Scalar::from(222u64));
        let r_out1 = pallas::Base::from(333u64);
        let r_out2 = pallas::Base::from(444u64);

        let cm1 = circuit_commitment(sk_base, 60, 0, r1);
        let cm2 = circuit_commitment(sk_base, 40, 0, r2);

        let mut tree = IncrementalMerkleTree::new();
        tree.insert(cm1);
        tree.insert(cm2);

        let inputs = [
            InputNote {
                spending_key: sk.clone(),
                note: Note { owner: sk_base, value: 60, asset: 0, randomness: pallas::Scalar::from(111u64) },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk.clone(),
                note: Note { owner: sk_base, value: 40, asset: 0, randomness: pallas::Scalar::from(222u64) },
                merkle_index: 1,
            },
        ];

        let recipient = pallas::Base::from(0xBEEFu64);
        let outputs = [
            OutputNote { owner_pubkey_field: recipient, value: 70, asset: 0, randomness: r_out1 },
            OutputNote { owner_pubkey_field: sk_base, value: 30, asset: 0, randomness: r_out2 },
        ];

        let proof = prove_transfer(&prover, &inputs, &outputs, &mut tree, 0).expect("prove should succeed");
        (prover, verifier, proof)
    }

    #[test]
    fn test_transfer_verify_roundtrip() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let ok = verify_transfer_proof(
            &verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(ok, "valid transfer proof should verify");
    }

    #[test]
    fn test_transfer_reject_tampered_proof() {
        let (_prover, verifier, mut proof) = build_transfer_fixture();

        // Flip a byte in the proof to corrupt it.
        if !proof.proof_bytes.is_empty() {
            proof.proof_bytes[0] ^= 0xFF;
        }

        let ok = verify_transfer_proof(
            &verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(!ok, "tampered proof should fail verification");
    }

    #[test]
    fn test_transfer_reject_wrong_nullifier() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let mut bad_nullifiers = proof.nullifiers;
        bad_nullifiers[0] = pallas::Base::from(999999u64);

        let ok = verify_transfer_proof(
            &verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &bad_nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(!ok, "wrong nullifier should fail");
    }

    #[test]
    fn test_withdraw_verify_roundtrip() {
        let (withdraw_prover, withdraw_verifier) = setup_withdraw().expect("withdraw setup");

        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let sk_base = scalar_to_base(sk.inner());

        let r1 = scalar_to_base(pallas::Scalar::from(111u64));
        let r2 = scalar_to_base(pallas::Scalar::from(222u64));

        let cm1 = circuit_commitment(sk_base, 60, 0, r1);
        let cm2 = circuit_commitment(sk_base, 40, 0, r2);

        let mut tree = IncrementalMerkleTree::new();
        tree.insert(cm1);
        tree.insert(cm2);

        let inputs = [
            InputNote {
                spending_key: sk.clone(),
                note: Note { owner: sk_base, value: 60, asset: 0, randomness: pallas::Scalar::from(111u64) },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk.clone(),
                note: Note { owner: sk_base, value: 40, asset: 0, randomness: pallas::Scalar::from(222u64) },
                merkle_index: 1,
            },
        ];

        let r_out1 = pallas::Base::from(333u64);
        let r_out2 = pallas::Base::from(444u64);
        let exit_value = 70u64;

        let outputs = [
            OutputNote { owner_pubkey_field: sk_base, value: 30, asset: 0, randomness: r_out1 },
            OutputNote { owner_pubkey_field: sk_base, value: 0, asset: 0, randomness: r_out2 },
        ];

        let proof = prove_withdraw(&withdraw_prover, &inputs, &outputs, &mut tree, exit_value, 0)
            .expect("prove_withdraw should succeed");

        let ok = verify_withdraw_proof(
            &withdraw_verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            exit_value,
            0,
        );
        assert!(ok, "valid withdraw proof should verify");

        // Wrong exit value should fail.
        let ok_wrong = verify_withdraw_proof(
            &withdraw_verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            exit_value + 1,
            0,
        );
        assert!(!ok_wrong, "wrong exit value should fail");
    }

    #[test]
    fn test_transfer_reject_wrong_root() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let bad_root = pallas::Base::from(0xDEADu64);
        let ok = verify_transfer_proof(
            &verifier,
            &proof.proof_bytes,
            bad_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(!ok, "wrong merkle root should fail");
    }

    #[test]
    fn test_transfer_reject_wrong_commitment() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let mut bad_cms = proof.output_commitments;
        bad_cms[0] = pallas::Base::from(0xBADu64);

        let ok = verify_transfer_proof(
            &verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &bad_cms,
            proof.fee,
        );
        assert!(!ok, "wrong output commitment should fail");
    }

    #[test]
    fn test_transfer_reject_wrong_fee() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let ok = verify_transfer_proof(
            &verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee + 1, // wrong fee
        );
        assert!(!ok, "wrong fee should fail");
    }

    #[test]
    fn test_transfer_empty_proof_fails() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let ok = verify_transfer_proof(
            &verifier,
            &[], // empty proof bytes
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(!ok, "empty proof should fail verification");
    }

    #[test]
    fn test_transfer_garbage_proof_fails() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let garbage = vec![0xAB; 256];
        let ok = verify_transfer_proof(
            &verifier,
            &garbage,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(!ok, "garbage proof should fail verification");
    }

    #[test]
    fn test_verify_transfer_raw_returns_error_for_bad_proof() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let result = verify_transfer(
            &verifier.params,
            &verifier.vk,
            &[],
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        );
        assert!(result.is_err(), "raw verify should return Err for empty proof");
    }

    #[test]
    fn test_batch_verify_single_valid() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let item = TransferBatchItem {
            proof_bytes: proof.proof_bytes.clone(),
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            fee: proof.fee,
        };

        let ok = batch_verify_transfers(&verifier, &[item]);
        assert!(ok, "batch of one valid proof should succeed");
    }

    #[test]
    fn test_batch_verify_empty_batch() {
        let (_prover, verifier, _proof) = build_transfer_fixture();

        let ok = batch_verify_transfers(&verifier, &[]);
        assert!(ok, "empty batch should verify");
    }

    #[test]
    fn test_batch_verify_with_invalid_rejects() {
        let (_prover, verifier, proof) = build_transfer_fixture();

        let good = TransferBatchItem {
            proof_bytes: proof.proof_bytes.clone(),
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            fee: proof.fee,
        };

        let bad = TransferBatchItem {
            proof_bytes: vec![0xFF; 100],
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            fee: proof.fee,
        };

        let ok = batch_verify_transfers(&verifier, &[good, bad]);
        assert!(!ok, "batch with one bad proof should fail");
    }
}
