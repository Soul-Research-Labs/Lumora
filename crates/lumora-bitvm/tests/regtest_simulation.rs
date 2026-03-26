//! Simulated regtest integration tests for BitVM2 transactions.
//!
//! These tests exercise the full transaction graph construction
//! (Assert → Challenge → Disprove/Timeout) with realistic parameters,
//! verifying script structure, witness stacks, and value flows.
//!
//! True on-chain testing requires a running Bitcoin Core regtest node;
//! these tests validate the transaction structures deterministically.

use lumora_bitvm::config::BitvmConfig;
use lumora_bitvm::protocol::Assertion;
use lumora_bitvm::script::{
    build_disprove_script, build_step_verifier_script, recompute_step_output,
    total_script_sizes,
};
use lumora_bitvm::trace::{
    compute_trace_merkle_root, merkle_proof_for_step, sha256, step_leaf_hash, verify_merkle_proof,
    StepKind, TraceStep, VerificationTrace,
};
use lumora_bitvm::transactions::{
    build_assert_tx, build_disprove_tx, build_timeout_tx, AssertTxParams, DisproveTxParams,
    OutPoint, TaprootLeaf, TaprootTree, TimeoutTxParams, TxId, XOnlyPubKey,
};

fn operator_key() -> XOnlyPubKey {
    XOnlyPubKey([0xAA; 32])
}

fn challenger_key() -> XOnlyPubKey {
    XOnlyPubKey([0xBB; 32])
}

fn realistic_trace() -> VerificationTrace {
    // Build a trace with all 6 step kinds, chained correctly
    let kinds = [
        StepKind::TranscriptInit,
        StepKind::CommitmentRead,
        StepKind::CommitmentRead,
        StepKind::ChallengeSqueeze,
        StepKind::ChallengeSqueeze,
        StepKind::MsmRound,
        StepKind::MsmRound,
        StepKind::MsmRound,
        StepKind::IpaRound,
        StepKind::IpaRound,
        StepKind::IpaRound,
        StepKind::FinalCheck,
    ];

    let mut steps = Vec::new();
    let mut prev_output = sha256(b"initial-state");

    for (i, kind) in kinds.iter().enumerate() {
        let witness = format!("witness-data-for-step-{i}").into_bytes();
        let output = recompute_step_output(*kind, &prev_output, &witness);

        steps.push(TraceStep {
            index: i as u32,
            kind: *kind,
            input_hash: prev_output,
            output_hash: output,
            witness,
        });

        prev_output = output;
    }

    let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
    VerificationTrace {
        steps,
        trace_root: compute_trace_merkle_root(&leaves),
        proof_hash: sha256(b"regtest-proof-bytes"),
        public_inputs_hash: sha256(b"regtest-public-inputs"),
        verification_result: true,
    }
}

// =========================================================================
// Assert TX construction
// =========================================================================

#[test]
fn test_assert_tx_structure() {
    let trace = realistic_trace();
    let assertion = Assertion::from_trace(&trace, 800_000, 10_000_000);

    let params = AssertTxParams {
        assertion: assertion.clone(),
        operator_pubkey: operator_key(),
        challenger_pubkey: challenger_key(),
        funding_outpoint: OutPoint {
            txid: TxId([0x11; 32]),
            vout: 0,
        },
        funding_value: 11_000_000,
        fee_sats: 1_000,
        timeout_blocks: 144,
    };

    let result = build_assert_tx(&params);

    // Verify TX structure
    assert_eq!(result.tx.version, 2);
    assert_eq!(result.tx.inputs.len(), 1);
    assert!(result.tx.outputs.len() >= 1);
    assert_eq!(result.assertion_id, assertion.id);

    // Verify the input references our funding UTXO
    assert_eq!(result.tx.inputs[0].previous_output.txid, TxId([0x11; 32]));
    assert_eq!(result.tx.inputs[0].previous_output.vout, 0);

    // Verify the Taproot tree is a Branch (timeout + challenge leaves)
    match &result.taproot_tree {
        lumora_bitvm::transactions::TaprootTree::Branch(_, _) => {} // expected
        _ => panic!("Taproot tree should be a branch with timeout + challenge leaves"),
    }
}

// =========================================================================
// Disprove TX construction
// =========================================================================

#[test]
fn test_disprove_tx_value_flow() {
    let params = DisproveTxParams {
        assert_outpoint: OutPoint {
            txid: TxId([0x22; 32]),
            vout: 0,
        },
        assert_value: 10_000_000,
        step_kind: StepKind::MsmRound,
        input_hash: [0xAA; 32],
        claimed_output_hash: [0xBB; 32],
        witness: vec![0x01, 0x02, 0x03],
        challenger_script_pubkey: {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[0xCC; 32]);
            s
        },
        fee_sats: 2_000,
        operator_pubkey: XOnlyPubKey([0xAA; 32]),
        taproot_tree: TaprootTree::Leaf(TaprootLeaf { version: 0xC0, script_bytes: vec![0x51] }),
    };

    let tx = build_disprove_tx(&params);

    assert_eq!(tx.version, 2);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.inputs[0].previous_output.txid, TxId([0x22; 32]));

    // Output value = assert_value - fee
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 10_000_000 - 2_000);
    assert_eq!(tx.outputs[0].script_pubkey, params.challenger_script_pubkey);

    // Witness should have script + data items
    assert!(!tx.inputs[0].witness.is_empty());
}

// =========================================================================
// Timeout TX construction
// =========================================================================

#[test]
fn test_timeout_tx_csv_locktime() {
    let params = TimeoutTxParams {
        assert_outpoint: OutPoint {
            txid: TxId([0x33; 32]),
            vout: 0,
        },
        assert_value: 10_000_000,
        operator_script_pubkey: {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[0xDD; 32]);
            s
        },
        fee_sats: 1_500,
        timeout_blocks: 144,
    };

    let tx = build_timeout_tx(&params);

    assert_eq!(tx.version, 2);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 10_000_000 - 1_500);

    // The input should have sequence set for OP_CSV
    // (sequence encoding: BIP 68 relative locktime)
    let seq = tx.inputs[0].sequence;
    assert!(
        seq > 0,
        "sequence should be set for OP_CSV relative timelock"
    );
}

// =========================================================================
// Script size estimation
// =========================================================================

#[test]
fn test_script_sizes_within_limits() {
    // Bitcoin consensus: max script size is 10,000 bytes
    // Tapscript: max is 10,000 bytes per leaf
    let max_script_size = 10_000;

    let sizes = total_script_sizes();
    println!("Script sizes by step kind:");
    for (kind, size) in &sizes {
        println!("  {:?}: size={}", kind, size);
        assert!(
            *size < max_script_size,
            "{:?} script too large: {}",
            kind,
            size
        );
    }
}

#[test]
fn test_all_step_kinds_have_scripts() {
    let kinds = [
        StepKind::TranscriptInit,
        StepKind::CommitmentRead,
        StepKind::ChallengeSqueeze,
        StepKind::MsmRound,
        StepKind::IpaRound,
        StepKind::FinalCheck,
    ];

    for kind in &kinds {
        let verifier = build_step_verifier_script(*kind);
        let disprove = build_disprove_script(*kind);
        assert!(!verifier.ops.is_empty(), "{:?} verifier script empty", kind);
        assert!(!disprove.ops.is_empty(), "{:?} disprove script empty", kind);
    }
}

// =========================================================================
// Merkle proof verification with realistic tree
// =========================================================================

#[test]
fn test_merkle_proofs_for_all_steps() {
    let trace = realistic_trace();
    let leaves: Vec<[u8; 32]> = trace.steps.iter().map(step_leaf_hash).collect();

    for (i, step) in trace.steps.iter().enumerate() {
        let proof = merkle_proof_for_step(&leaves, i);
        let leaf = step_leaf_hash(step);

        assert!(
            verify_merkle_proof(leaf, i, &proof, trace.trace_root),
            "Merkle proof failed for step {i} ({:?})",
            step.kind
        );

        // Verify proof fails with wrong leaf
        let wrong_leaf = [0xFF; 32];
        assert!(
            !verify_merkle_proof(wrong_leaf, i, &proof, trace.trace_root),
            "Merkle proof should fail for wrong leaf at step {i}"
        );
    }
}

// =========================================================================
// Full transaction graph: Assert → Disprove flow
// =========================================================================

#[test]
fn test_full_transaction_graph() {
    let trace = realistic_trace();
    let assertion = Assertion::from_trace(&trace, 800_000, 10_000_000);

    // 1. Build Assert TX
    let assert_tx = build_assert_tx(&AssertTxParams {
        assertion: assertion.clone(),
        operator_pubkey: operator_key(),
        challenger_pubkey: challenger_key(),
        funding_outpoint: OutPoint {
            txid: TxId([0x44; 32]),
            vout: 0,
        },
        funding_value: 11_000_000,
        fee_sats: 1_000,
        timeout_blocks: 144,
    });

    // 2. Simulate a dispute on step 5 (MsmRound)
    let disputed_step = &trace.steps[5];
    let disprove_tx = build_disprove_tx(&DisproveTxParams {
        assert_outpoint: OutPoint {
            txid: TxId([0x55; 32]), // would be assert TX's txid
            vout: 0,
        },
        assert_value: 10_000_000,
        step_kind: disputed_step.kind,
        input_hash: disputed_step.input_hash,
        claimed_output_hash: disputed_step.output_hash,
        witness: disputed_step.witness.clone(),
        challenger_script_pubkey: {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&challenger_key().0);
            s
        },
        fee_sats: 1_500,
        operator_pubkey: operator_key(),
        taproot_tree: TaprootTree::Leaf(TaprootLeaf { version: 0xC0, script_bytes: vec![0x51] }),
    });

    // 3. Also build the timeout path (for the honest case)
    let timeout_tx = build_timeout_tx(&TimeoutTxParams {
        assert_outpoint: OutPoint {
            txid: TxId([0x55; 32]),
            vout: 0,
        },
        assert_value: 10_000_000,
        operator_script_pubkey: {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&operator_key().0);
            s
        },
        fee_sats: 1_000,
        timeout_blocks: 144,
    });

    // Verify all TXs are structurally valid
    assert_eq!(assert_tx.tx.version, 2);
    assert_eq!(disprove_tx.version, 2);
    assert_eq!(timeout_tx.version, 2);

    // Value conservation: disprove pays challenger, timeout pays operator
    assert_eq!(disprove_tx.outputs[0].value, 10_000_000 - 1_500);
    assert_eq!(timeout_tx.outputs[0].value, 10_000_000 - 1_000);
}

// =========================================================================
// Config validation
// =========================================================================

#[test]
fn test_default_config_reasonable() {
    let config = BitvmConfig::default();

    // Bond should be meaningful (at least 0.01 BTC = 1M sats)
    assert!(config.bond_sats >= 1_000_000);

    // Timeout should be at least 1 hour (~6 blocks)
    assert!(config.challenge_timeout_blocks >= 6);

    // Min confirmations should be at least 1
    assert!(config.min_confirmations >= 1);

    // Max pending should be reasonable
    assert!(config.max_pending_assertions >= 1);
    assert!(config.max_pending_assertions <= 1024);
}
