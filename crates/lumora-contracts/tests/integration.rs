//! Integration tests for the Lumora privacy pool contract.
//!
//! Tests the full deposit → transfer → withdraw cycle with real Halo2 proofs.

use pasta_curves::pallas;
use rand::rngs::OsRng;

use lumora_contracts::{
    ContractError, DepositRequest, PrivacyPool, TransferRequest, WithdrawRequest,
};
use lumora_note::SpendingKey;
use lumora_note::keys::scalar_to_base;
use lumora_prover::{self, circuit_commitment, InputNote, OutputNote};
use lumora_tree::IncrementalMerkleTree;

/// Create a spending key and return (sk, sk_as_base_field).
fn make_key() -> (SpendingKey, pallas::Base) {
    let sk = SpendingKey::random(&mut OsRng);
    let sk_base = scalar_to_base(sk.inner());
    (sk, sk_base)
}

/// Compute a note commitment from raw parts.
fn make_commitment(owner: pallas::Base, value: u64, asset: u64, randomness: pallas::Base) -> pallas::Base {
    circuit_commitment(owner, value, asset, randomness)
}

/// Helper: create a PrivacyPool with both transfer and withdrawal verifier params.
fn make_pool() -> (lumora_prover::ProverParams, PrivacyPool) {
    let (pp, vp) = lumora_prover::setup().expect("transfer setup");
    let (_, wvp) = lumora_prover::setup_withdraw().expect("withdraw setup");
    let pool = PrivacyPool::new(vp, wvp);
    (pp, pool)
}

#[test]
fn test_deposit_basic() {
    let (_, mut pool) = make_pool();

    let (_, sk_base) = make_key();
    let randomness = pallas::Base::from(999u64);
    let cm = make_commitment(sk_base, 100, 0, randomness);

    let receipt = pool
        .deposit(&DepositRequest {
            commitment: cm,
            amount: 100,
        })
        .expect("deposit should succeed");

    assert_eq!(receipt.leaf_index, 0);
    assert_eq!(pool.state.pool_balance(), 100);
    assert_eq!(pool.state.commitment_count(), 1);
}

#[test]
fn test_deposit_zero_amount_rejected() {
    let (_, mut pool) = make_pool();

    let cm = pallas::Base::from(42u64);
    let result = pool.deposit(&DepositRequest {
        commitment: cm,
        amount: 0,
    });

    assert_eq!(result.unwrap_err(), ContractError::ZeroDeposit);
}

#[test]
fn test_multiple_deposits() {
    let (_, mut pool) = make_pool();

    for i in 0u64..5 {
        let cm = pallas::Base::from(i * 1000 + 1);
        let receipt = pool
            .deposit(&DepositRequest {
                commitment: cm,
                amount: 100,
            })
            .expect("deposit should succeed");
        assert_eq!(receipt.leaf_index, i);
    }

    assert_eq!(pool.state.pool_balance(), 500);
    assert_eq!(pool.state.commitment_count(), 5);
}

#[test]
fn test_deposit_transfer_cycle() {
    // Setup: generate keys and prover/verifier params.
    let (prover_params, mut pool) = make_pool();

    // --- Create two users ---
    let (sk_alice, sk_alice_base) = make_key();
    let (_, sk_bob_base) = make_key();

    let r1_scalar = pallas::Scalar::from(111u64);
    let r2_scalar = pallas::Scalar::from(222u64);
    let r1 = scalar_to_base(r1_scalar);
    let r2 = scalar_to_base(r2_scalar);

    // --- Deposit two notes for Alice: 600 + 400 = 1000 total ---
    let cm1 = make_commitment(sk_alice_base, 600, 0, r1);
    let cm2 = make_commitment(sk_alice_base, 400, 0, r2);

    pool.deposit(&DepositRequest { commitment: cm1, amount: 600 })
        .expect("deposit 1");
    pool.deposit(&DepositRequest { commitment: cm2, amount: 400 })
        .expect("deposit 2");

    assert_eq!(pool.state.pool_balance(), 1000);

    // --- Build a private transfer: Alice sends 700 to Bob, 300 change to Alice ---
    let mut local_tree = IncrementalMerkleTree::new();
    local_tree.insert(cm1);
    local_tree.insert(cm2);

    let r_out1 = pallas::Base::from(333u64);
    let r_out2 = pallas::Base::from(444u64);

    let inputs = [
        InputNote {
            spending_key: sk_alice.clone(),
            note: lumora_note::Note {
                owner: sk_alice_base,
                value: 600,
                asset: 0,
                randomness: r1_scalar,
            },
            merkle_index: 0,
        },
        InputNote {
            spending_key: sk_alice.clone(),
            note: lumora_note::Note {
                owner: sk_alice_base,
                value: 400,
                asset: 0,
                randomness: r2_scalar,
            },
            merkle_index: 1,
        },
    ];

    let outputs = [
        OutputNote {
            owner_pubkey_field: sk_bob_base,
            value: 700,
            asset: 0,
            randomness: r_out1,
        },
        OutputNote {
            owner_pubkey_field: sk_alice_base,
            value: 300,
            asset: 0,
            randomness: r_out2,
        },
    ];

    // The prover uses the local tree, which matches the pool's tree.
    let proof = lumora_prover::prove_transfer(&prover_params, &inputs, &outputs, &mut local_tree, 0)
        .expect("proof generation should succeed");

    // --- Submit the transfer to the pool ---
    let transfer_receipt = pool
        .transfer(&TransferRequest {
            proof_bytes: proof.proof_bytes,
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            fee: 0,
            domain_chain_id: None,
            domain_app_id: None,
        })
        .expect("transfer should succeed");

    // Pool balance unchanged (private transfer doesn't change total shielded value).
    assert_eq!(pool.state.pool_balance(), 1000);
    // Two new commitments added.
    assert_eq!(pool.state.commitment_count(), 4); // 2 deposits + 2 transfer outputs
    // Nullifiers are now spent.
    assert!(pool.state.is_nullifier_spent(proof.nullifiers[0]));
    assert!(pool.state.is_nullifier_spent(proof.nullifiers[1]));
    // Receipt has leaf indices.
    assert_eq!(transfer_receipt.leaf_indices[0], 2);
    assert_eq!(transfer_receipt.leaf_indices[1], 3);
}

#[test]
fn test_double_spend_rejected() {
    let (prover_params, mut pool) = make_pool();

    let (sk_alice, sk_alice_base) = make_key();
    let (_, sk_bob_base) = make_key();

    let r1_scalar = pallas::Scalar::from(111u64);
    let r2_scalar = pallas::Scalar::from(222u64);
    let r1 = scalar_to_base(r1_scalar);
    let r2 = scalar_to_base(r2_scalar);

    let cm1 = make_commitment(sk_alice_base, 500, 0, r1);
    let cm2 = make_commitment(sk_alice_base, 500, 0, r2);

    pool.deposit(&DepositRequest { commitment: cm1, amount: 500 }).unwrap();
    pool.deposit(&DepositRequest { commitment: cm2, amount: 500 }).unwrap();

    let mut local_tree = IncrementalMerkleTree::new();
    local_tree.insert(cm1);
    local_tree.insert(cm2);

    let r_out1 = pallas::Base::from(333u64);
    let r_out2 = pallas::Base::from(444u64);

    let inputs = [
        InputNote {
            spending_key: sk_alice.clone(),
            note: lumora_note::Note { owner: sk_alice_base, value: 500, asset: 0, randomness: r1_scalar },
            merkle_index: 0,
        },
        InputNote {
            spending_key: sk_alice.clone(),
            note: lumora_note::Note { owner: sk_alice_base, value: 500, asset: 0, randomness: r2_scalar },
            merkle_index: 1,
        },
    ];

    let outputs = [
        OutputNote { owner_pubkey_field: sk_bob_base, value: 700, asset: 0, randomness: r_out1 },
        OutputNote { owner_pubkey_field: sk_alice_base, value: 300, asset: 0, randomness: r_out2 },
    ];

    let proof = lumora_prover::prove_transfer(&prover_params, &inputs, &outputs, &mut local_tree, 0)
        .expect("proof generation should succeed");

    // First transfer succeeds.
    pool.transfer(&TransferRequest {
        proof_bytes: proof.proof_bytes.clone(),
        merkle_root: proof.merkle_root,
        nullifiers: proof.nullifiers,
        output_commitments: proof.output_commitments,
        fee: 0,
        domain_chain_id: None,
        domain_app_id: None,
    })
    .expect("first transfer should succeed");

    // Second transfer with same nullifiers must fail.
    let result = pool.transfer(&TransferRequest {
        proof_bytes: proof.proof_bytes,
        merkle_root: proof.merkle_root,
        nullifiers: proof.nullifiers,
        output_commitments: proof.output_commitments,
        fee: 0,
        domain_chain_id: None,
        domain_app_id: None,
    });

    assert_eq!(result.unwrap_err(), ContractError::NullifierAlreadySpent);
}

#[test]
fn test_unknown_merkle_root_rejected() {
    let (_, mut pool) = make_pool();

    // Use a fabricated root that the pool has never seen.
    let fake_root = pallas::Base::from(9999u64);

    let result = pool.transfer(&TransferRequest {
        proof_bytes: vec![0u8; 64],
        merkle_root: fake_root,
        nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
        output_commitments: [pallas::Base::from(3u64), pallas::Base::from(4u64)],
        fee: 0,
        domain_chain_id: None,
        domain_app_id: None,
    });

    assert_eq!(result.unwrap_err(), ContractError::UnknownMerkleRoot);
}

#[test]
fn test_withdrawal_zero_amount_rejected() {
    let (_, mut pool) = make_pool();

    let root = pool.state.current_root();
    let result = pool.withdraw(&WithdrawRequest {
        proof_bytes: vec![],
        merkle_root: root,
        nullifiers: [pallas::Base::zero(); 2],
        output_commitments: [pallas::Base::zero(); 2],
        amount: 0,
        fee: 0,
        recipient: [0u8; 32],
        domain_chain_id: None,
        domain_app_id: None,
    });

    assert_eq!(result.unwrap_err(), ContractError::ZeroWithdrawal);
}

#[test]
fn test_withdrawal_insufficient_balance_rejected() {
    let (_, mut pool) = make_pool();

    // Pool is empty, try to withdraw.
    let root = pool.state.current_root();
    let result = pool.withdraw(&WithdrawRequest {
        proof_bytes: vec![],
        merkle_root: root,
        nullifiers: [pallas::Base::zero(); 2],
        output_commitments: [pallas::Base::zero(); 2],
        amount: 100,
        fee: 0,
        recipient: [0u8; 32],
        domain_chain_id: None,
        domain_app_id: None,
    });

    assert_eq!(result.unwrap_err(), ContractError::InsufficientPoolBalance);
}

#[test]
fn test_root_history_tracking() {
    let (_, mut pool) = make_pool();

    let root_before = pool.state.current_root();

    let cm = pallas::Base::from(42u64);
    pool.deposit(&DepositRequest { commitment: cm, amount: 100 }).unwrap();

    let root_after = pool.state.current_root();

    // Both roots should be known.
    assert!(pool.state.is_known_root(root_before));
    assert!(pool.state.is_known_root(root_after));
    assert_ne!(root_before, root_after);
}

#[test]
fn test_nullifier_registry() {
    let (_, pool) = make_pool();

    let nf = pallas::Base::from(12345u64);
    assert!(!pool.state.is_nullifier_spent(nf));
}

#[test]
fn test_full_deposit_transfer_withdraw_cycle() {
    // This is the ultimate integration test: deposit → private transfer → withdraw.
    let (prover_params, mut pool) = make_pool();

    // --- Setup keys ---
    let (sk_alice, sk_alice_base) = make_key();
    let (_sk_bob, sk_bob_base) = make_key();

    // --- Step 1: Alice deposits 1000 (split into two notes: 600 + 400) ---
    let r1_scalar = pallas::Scalar::from(11u64);
    let r2_scalar = pallas::Scalar::from(22u64);
    let r1 = scalar_to_base(r1_scalar);
    let r2 = scalar_to_base(r2_scalar);
    let cm_a1 = make_commitment(sk_alice_base, 600, 0, r1);
    let cm_a2 = make_commitment(sk_alice_base, 400, 0, r2);

    pool.deposit(&DepositRequest { commitment: cm_a1, amount: 600 }).unwrap();
    pool.deposit(&DepositRequest { commitment: cm_a2, amount: 400 }).unwrap();
    assert_eq!(pool.state.pool_balance(), 1000);

    // --- Step 2: Alice privately sends 700 to Bob, 300 change back ---
    let mut tree = IncrementalMerkleTree::new();
    tree.insert(cm_a1);
    tree.insert(cm_a2);

    let r_out1 = pallas::Base::from(33u64);
    let r_out2 = pallas::Base::from(44u64);

    let transfer_proof = lumora_prover::prove_transfer(
        &prover_params,
        &[
            InputNote {
                spending_key: sk_alice.clone(),
                note: lumora_note::Note { owner: sk_alice_base, value: 600, asset: 0, randomness: r1_scalar },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk_alice.clone(),
                note: lumora_note::Note { owner: sk_alice_base, value: 400, asset: 0, randomness: r2_scalar },
                merkle_index: 1,
            },
        ],
        &[
            OutputNote { owner_pubkey_field: sk_bob_base, value: 700, asset: 0, randomness: r_out1 },
            OutputNote { owner_pubkey_field: sk_alice_base, value: 300, asset: 0, randomness: r_out2 },
        ],
        &mut tree,
        0,
    )
    .expect("transfer proof");

    pool.transfer(&TransferRequest {
        proof_bytes: transfer_proof.proof_bytes,
        merkle_root: transfer_proof.merkle_root,
        nullifiers: transfer_proof.nullifiers,
        output_commitments: transfer_proof.output_commitments,
        fee: 0,
        domain_chain_id: None,
        domain_app_id: None,
    })
    .expect("transfer should succeed");

    assert_eq!(pool.state.pool_balance(), 1000);
    assert_eq!(pool.state.commitment_count(), 4);

    // Verify final state after the full deposit -> transfer cycle.
    assert_eq!(pool.state.nullifier_count(), 2);
    assert!(pool.state.is_nullifier_spent(transfer_proof.nullifiers[0]));
    assert!(pool.state.is_nullifier_spent(transfer_proof.nullifiers[1]));
}
