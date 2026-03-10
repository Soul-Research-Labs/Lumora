//! Cross-crate integration tests exercising interactions between lumora-*
//! crates: batch verification, proof aggregation, note encryption, Merkle
//! tree serialisation, and dynamic fee estimation.

use std::sync::LazyLock;

use pasta_curves::pallas;
use pasta_curves::group::Group;
use ff::Field;
use rand::rngs::OsRng;

use lumora_circuits::aggregation::{AggregationBundle, SerializedProof, verify_and_aggregate};
use lumora_circuits::transfer::transfer_public_inputs;
use lumora_contracts::fee::DynamicFeeEstimator;
use lumora_note::encryption::{decrypt_note, encrypt_note};
use lumora_note::keys::scalar_to_base;
use lumora_note::SpendingKey;
use lumora_prover::{self, circuit_commitment, InputNote, OutputNote, ProverParams, VerifierParams};
use lumora_tree::IncrementalMerkleTree;
use lumora_verifier::{TransferBatchItem, batch_verify_transfers};

// ---------------------------------------------------------------------------
// Shared SRS (generated once across all tests in this file)
// ---------------------------------------------------------------------------

struct SharedSetup {
    prover: ProverParams,
    verifier: VerifierParams,
}

static SETUP: LazyLock<SharedSetup> = LazyLock::new(|| {
    let (prover, verifier) = lumora_prover::setup().expect("SRS generation");
    SharedSetup { prover, verifier }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_key() -> (SpendingKey, pallas::Base) {
    let sk = SpendingKey::random(&mut OsRng);
    let sk_base = scalar_to_base(sk.inner());
    (sk, sk_base)
}

/// Generate a valid transfer proof pair (Alice → Bob) and return everything
/// needed for downstream assertions.
struct ProofFixture {
    proof_bytes: Vec<u8>,
    merkle_root: pallas::Base,
    nullifiers: [pallas::Base; 2],
    output_commitments: [pallas::Base; 2],
}

fn make_transfer_proof(prover: &ProverParams, seed: u64) -> ProofFixture {
    let (sk, sk_base) = make_key();
    let (_, bob_base) = make_key();

    let r1 = pallas::Scalar::from(seed * 100 + 1);
    let r2 = pallas::Scalar::from(seed * 100 + 2);
    let r1_base = scalar_to_base(r1);
    let r2_base = scalar_to_base(r2);

    let cm1 = circuit_commitment(sk_base, 600, 0, r1_base);
    let cm2 = circuit_commitment(sk_base, 400, 0, r2_base);

    let mut tree = IncrementalMerkleTree::new();
    tree.insert(cm1);
    tree.insert(cm2);

    let inputs = [
        InputNote {
            spending_key: sk.clone(),
            note: lumora_note::Note { owner: sk_base, value: 600, asset: 0, randomness: r1 },
            merkle_index: 0,
        },
        InputNote {
            spending_key: sk,
            note: lumora_note::Note { owner: sk_base, value: 400, asset: 0, randomness: r2 },
            merkle_index: 1,
        },
    ];

    let r_out1 = pallas::Base::from(seed * 100 + 3);
    let r_out2 = pallas::Base::from(seed * 100 + 4);

    let outputs = [
        OutputNote { owner_pubkey_field: bob_base, value: 700, asset: 0, randomness: r_out1 },
        OutputNote { owner_pubkey_field: sk_base, value: 300, asset: 0, randomness: r_out2 },
    ];

    let proof = lumora_prover::prove_transfer(prover, &inputs, &outputs, &mut tree, 0)
        .expect("transfer proof");

    ProofFixture {
        proof_bytes: proof.proof_bytes,
        merkle_root: proof.merkle_root,
        nullifiers: proof.nullifiers,
        output_commitments: proof.output_commitments,
    }
}

// =========================================================================
// Tests
// =========================================================================

/// Batch-verify two independently generated transfer proofs.
#[test]
fn batch_verify_two_transfer_proofs() {
    let setup = &*SETUP;

    let p1 = make_transfer_proof(&setup.prover, 1);
    let p2 = make_transfer_proof(&setup.prover, 2);

    let items = vec![
        TransferBatchItem {
            proof_bytes: p1.proof_bytes,
            merkle_root: p1.merkle_root,
            nullifiers: p1.nullifiers,
            output_commitments: p1.output_commitments,
            fee: 0,
        },
        TransferBatchItem {
            proof_bytes: p2.proof_bytes,
            merkle_root: p2.merkle_root,
            nullifiers: p2.nullifiers,
            output_commitments: p2.output_commitments,
            fee: 0,
        },
    ];

    assert!(batch_verify_transfers(&setup.verifier, &items));
}

/// A tampered proof should fail batch verification.
#[test]
fn batch_verify_rejects_tampered_proof() {
    let setup = &*SETUP;

    let mut p = make_transfer_proof(&setup.prover, 10);
    // Flip a byte in the proof.
    if let Some(b) = p.proof_bytes.first_mut() {
        *b ^= 0xFF;
    }

    let items = vec![TransferBatchItem {
        proof_bytes: p.proof_bytes,
        merkle_root: p.merkle_root,
        nullifiers: p.nullifiers,
        output_commitments: p.output_commitments,
        fee: 0,
    }];

    assert!(!batch_verify_transfers(&setup.verifier, &items));
}

/// Aggregate real transfer proofs and verify the bundle.
#[test]
fn aggregation_with_real_proofs() {
    let setup = &*SETUP;

    let p1 = make_transfer_proof(&setup.prover, 20);
    let p2 = make_transfer_proof(&setup.prover, 21);

    let mut bundle = AggregationBundle::new();
    bundle.push(SerializedProof {
        bytes: p1.proof_bytes,
        public_inputs: transfer_public_inputs(
            p1.merkle_root,
            &p1.nullifiers,
            &p1.output_commitments,
            0,
        ),
    });
    bundle.push(SerializedProof {
        bytes: p2.proof_bytes,
        public_inputs: transfer_public_inputs(
            p2.merkle_root,
            &p2.nullifiers,
            &p2.output_commitments,
            0,
        ),
    });

    let result = verify_and_aggregate(&setup.verifier.params, &setup.verifier.vk, &bundle);

    assert!(result.verified, "aggregation should report all proofs valid");
    assert_eq!(result.proof_count, 2);
    assert!(result.individual_results.iter().all(|&ok| ok));
}

/// Encrypt a note for a recipient, then decrypt with spending key.
#[test]
fn note_encryption_decrypt_roundtrip() {
    let sk_scalar = pallas::Scalar::random(OsRng);
    let recipient_pk = pallas::Point::generator() * sk_scalar;

    let value = 500u64;
    let asset = 1u64;
    let randomness = pallas::Scalar::random(OsRng);

    let (eph_pk_bytes, ciphertext) = encrypt_note(recipient_pk, value, asset, randomness, OsRng);
    let decrypted = decrypt_note(sk_scalar, &eph_pk_bytes, &ciphertext);

    let (dec_value, dec_asset, dec_randomness) = decrypted.expect("decryption should succeed");
    assert_eq!(dec_value, value);
    assert_eq!(dec_asset, asset);
    assert_eq!(dec_randomness, randomness);
}

/// A wrong key cannot decrypt an encrypted note.
#[test]
fn note_encryption_wrong_key_fails() {
    let sk = pallas::Scalar::random(OsRng);
    let wrong_sk = pallas::Scalar::random(OsRng);
    let pk = pallas::Point::generator() * sk;

    let (eph, ct) = encrypt_note(pk, 42, 0, pallas::Scalar::random(OsRng), OsRng);
    assert!(decrypt_note(wrong_sk, &eph, &ct).is_none());
}

/// Merkle tree survives a JSON serialisation round-trip and remains functional.
#[test]
fn merkle_tree_serialization_roundtrip() {
    let mut tree = IncrementalMerkleTree::new();
    let leaf1 = pallas::Base::from(111u64);
    let leaf2 = pallas::Base::from(222u64);
    tree.insert(leaf1);
    tree.insert(leaf2);

    let root_before = tree.root();
    let json = serde_json::to_string(&tree).expect("serialize");

    let mut deserialized: IncrementalMerkleTree =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.root(), root_before);
    assert_eq!(deserialized.len(), 2);

    // Tree still works after deserialization.
    let leaf3 = pallas::Base::from(333u64);
    deserialized.insert(leaf3);
    assert_eq!(deserialized.len(), 3);
    assert_ne!(deserialized.root(), root_before);
}

/// Merkle witness paths remain valid after serialisation round-trip.
#[test]
fn merkle_witnesses_valid_after_roundtrip() {
    let mut tree = IncrementalMerkleTree::new();
    let leaves: Vec<pallas::Base> = (0..8).map(|i| pallas::Base::from(i * 7 + 13)).collect();
    for &l in &leaves {
        tree.insert(l);
    }

    let json = serde_json::to_string(&tree).expect("serialize");
    let mut restored: IncrementalMerkleTree =
        serde_json::from_str(&json).expect("deserialize");

    let root = restored.root();
    for (idx, &leaf) in leaves.iter().enumerate() {
        let path = restored.witness(idx as u64).expect("witness should exist");
        assert!(path.verify(root, leaf), "witness {} must verify", idx);
    }
}

/// DynamicFeeEstimator produces monotonically increasing fees as congestion rises.
#[test]
fn fee_estimator_monotonically_increases() {
    let estimator = DynamicFeeEstimator::default();

    let mut prev_fee = 0u64;
    for pending in [0, 32, 64, 128, 256, 512] {
        let fee = estimator.transfer_fee(pending);
        assert!(fee >= prev_fee, "fee should not decrease: {fee} < {prev_fee}");
        prev_fee = fee;
    }
}

/// DynamicFeeEstimator withdraw fees also scale with congestion.
#[test]
fn fee_estimator_withdraw_scales() {
    let estimator = DynamicFeeEstimator::default();

    let base = estimator.withdraw_fee(0);
    let loaded = estimator.withdraw_fee(256);

    assert_eq!(base, 20);
    assert!(loaded > base);
}
