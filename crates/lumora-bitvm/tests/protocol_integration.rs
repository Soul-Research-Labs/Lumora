//! End-to-end integration test for the BitVM2 challenge-response protocol.
//!
//! Tests the full lifecycle:
//! 1. Operator posts an honest assertion
//! 2. Challenger observes and verifies it's honest → no dispute → timeout
//! 3. Operator posts a dishonest assertion
//! 4. Challenger detects fraud and creates a challenge
//! 5. Operator responds
//! 6. Challenger verifies fraud and could build a disprove TX

use lumora_bitvm::challenger::{Challenger, VerifyOutcome};
use lumora_bitvm::config::{BitvmConfig, ChallengerConfig};
use lumora_bitvm::operator::Operator;
use lumora_bitvm::protocol::AssertionState;
use lumora_bitvm::script::recompute_step_output;
use lumora_bitvm::trace::{
    compute_trace_merkle_root, sha256, step_leaf_hash, StepKind, TraceStep, VerificationTrace,
};
use lumora_bitvm::transactions::{OutPoint, TxId, XOnlyPubKey};

fn operator_key() -> XOnlyPubKey {
    XOnlyPubKey([0xAA; 32])
}

fn challenger_key() -> XOnlyPubKey {
    XOnlyPubKey([0xBB; 32])
}

fn funding_utxo() -> (OutPoint, u64) {
    (
        OutPoint {
            txid: TxId([0xCC; 32]),
            vout: 0,
        },
        11_000_000,
    )
}

/// Build a valid, honestly computed trace.
fn honest_trace() -> VerificationTrace {
    let input0 = sha256(b"genesis-state");
    let w0 = b"transcript-init-data".to_vec();
    let output0 = recompute_step_output(StepKind::TranscriptInit, &input0, &w0);

    let w1 = b"commitment-group-1".to_vec();
    let output1 = recompute_step_output(StepKind::CommitmentRead, &output0, &w1);

    let w2 = b"challenge-squeeze-1".to_vec();
    let output2 = recompute_step_output(StepKind::ChallengeSqueeze, &output1, &w2);

    let w3 = b"msm-round-1".to_vec();
    let output3 = recompute_step_output(StepKind::MsmRound, &output2, &w3);

    let w4 = b"ipa-round-1".to_vec();
    let output4 = recompute_step_output(StepKind::IpaRound, &output3, &w4);

    let w5 = b"final-check-data".to_vec();
    let output5 = recompute_step_output(StepKind::FinalCheck, &output4, &w5);

    let steps = vec![
        TraceStep { index: 0, kind: StepKind::TranscriptInit, input_hash: input0, output_hash: output0, witness: w0 },
        TraceStep { index: 1, kind: StepKind::CommitmentRead, input_hash: output0, output_hash: output1, witness: w1 },
        TraceStep { index: 2, kind: StepKind::ChallengeSqueeze, input_hash: output1, output_hash: output2, witness: w2 },
        TraceStep { index: 3, kind: StepKind::MsmRound, input_hash: output2, output_hash: output3, witness: w3 },
        TraceStep { index: 4, kind: StepKind::IpaRound, input_hash: output3, output_hash: output4, witness: w4 },
        TraceStep { index: 5, kind: StepKind::FinalCheck, input_hash: output4, output_hash: output5, witness: w5 },
    ];

    let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
    VerificationTrace {
        steps,
        trace_root: compute_trace_merkle_root(&leaves),
        proof_hash: sha256(b"honest-proof"),
        public_inputs_hash: sha256(b"honest-pi"),
        verification_result: true,
    }
}

/// Build a trace where one step has an incorrect output hash (fraud).
fn dishonest_trace() -> VerificationTrace {
    let mut trace = honest_trace();

    // Corrupt step 3 (MsmRound): change the output hash so it doesn't match
    // the recomputed value, but keep the chain intact by also updating step 4's
    // input hash to match the corrupted output.
    let corrupted_output = sha256(b"CORRUPTED");
    trace.steps[3].output_hash = corrupted_output;
    trace.steps[4].input_hash = corrupted_output;

    // Recompute step 4 and 5 to keep the chain consistent
    let w4 = trace.steps[4].witness.clone();
    trace.steps[4].output_hash =
        recompute_step_output(StepKind::IpaRound, &corrupted_output, &w4);
    trace.steps[5].input_hash = trace.steps[4].output_hash;
    let w5 = trace.steps[5].witness.clone();
    trace.steps[5].output_hash =
        recompute_step_output(StepKind::FinalCheck, &trace.steps[5].input_hash, &w5);

    // Recompute Merkle root for the modified trace
    let leaves: Vec<[u8; 32]> = trace.steps.iter().map(step_leaf_hash).collect();
    trace.trace_root = compute_trace_merkle_root(&leaves);
    trace.proof_hash = sha256(b"dishonest-proof");
    trace
}

// =========================================================================
// Test: Honest operator → no challenge → timeout → finalization
// =========================================================================

#[test]
fn test_honest_operator_finalizes() {
    let config = BitvmConfig::default();
    let mut operator = Operator::new(config, operator_key(), challenger_key());

    let trace = honest_trace();
    let mut challenger = Challenger::new(ChallengerConfig::default(), challenger_key());

    // Operator posts assertion at height 100
    let (fund, val) = funding_utxo();
    let (assertion_id, _assert_tx) = operator
        .process_withdrawal(trace.clone(), 100, fund, val)
        .expect("operator should accept honest trace");

    // Challenger observes the assertion
    let assertion = lumora_bitvm::protocol::Assertion::from_trace(&trace, 100, 10_000_000);
    challenger.observe_assertion(
        assertion.clone(),
        OutPoint { txid: TxId([0xDD; 32]), vout: 0 },
    );

    // Challenger checks for fraud — should find none
    let fraud = challenger.find_fraud(&assertion, &trace.steps);
    assert!(
        fraud.is_none(),
        "honest trace should not trigger fraud detection"
    );

    // Time passes, no challenge arrives
    // At height 244 (100 + 144), timeout elapses
    let finalized = operator.finalize_expired(244);
    assert_eq!(finalized.len(), 1, "assertion should finalize after timeout");
    assert_eq!(finalized[0].0, assertion_id);

    // Operator assertion is now finalized
    assert!(matches!(
        operator.assertion_state(&assertion_id),
        Some(AssertionState::Finalized)
    ));
}

// =========================================================================
// Test: Dishonest operator → challenge → response → fraud detected
// =========================================================================

#[test]
fn test_dishonest_operator_caught() {
    let config = BitvmConfig::default();
    let mut operator = Operator::new(config, operator_key(), challenger_key());

    let trace = dishonest_trace();
    let mut challenger = Challenger::new(ChallengerConfig::default(), challenger_key());

    // Operator posts dishonest assertion at height 100
    let (fund, val) = funding_utxo();
    let (assertion_id, _) = operator
        .process_withdrawal(trace.clone(), 100, fund, val)
        .expect("operator can post any trace (verification is optimistic)");

    let assertion = lumora_bitvm::protocol::Assertion::from_trace(&trace, 100, 10_000_000);
    challenger.observe_assertion(
        assertion.clone(),
        OutPoint { txid: TxId([0xDD; 32]), vout: 0 },
    );

    // Challenger checks for fraud — should find step 3 is incorrect
    let fraud = challenger.find_fraud(&assertion, &trace.steps);
    assert_eq!(
        fraud,
        Some(3),
        "challenger should detect fraud at step 3 (MsmRound)"
    );

    // Challenger creates a challenge for step 3
    let challenge = challenger.create_challenge(
        assertion_id,
        3,
        trace.steps[3].output_hash,
        105,
    );
    assert_eq!(challenge.disputed_step, 3);

    // Operator responds to the challenge
    let response = operator
        .respond_to_challenge(&challenge)
        .expect("operator must respond");

    assert_eq!(response.disputed_step, 3);
    assert_eq!(response.step_kind, StepKind::MsmRound);

    // Challenger verifies the response
    let outcome = challenger.verify_response(&assertion, &response);

    // The response should reveal fraud because step 3's output_hash
    // doesn't match the recomputed output from input + witness + tag
    assert!(
        matches!(outcome, VerifyOutcome::Fraudulent { step_index: 3, .. }),
        "challenger should detect fraudulent step 3, got: {outcome:?}"
    );

    // Challenger can now build a Disprove TX
    let disprove_tx = challenger
        .build_disprove(&assertion_id, &response)
        .expect("should build disprove TX");

    assert!(!disprove_tx.outputs.is_empty(), "disprove TX should have outputs");
    assert_eq!(disprove_tx.version, 2);
}

// =========================================================================
// Test: Multiple assertions processed concurrently
// =========================================================================

#[test]
fn test_multiple_assertions() {
    let config = BitvmConfig::default();
    let mut operator = Operator::new(config, operator_key(), challenger_key());

    // Post three honest assertions at different heights
    let trace1 = honest_trace();
    let (f1, v1) = (OutPoint { txid: TxId([0x01; 32]), vout: 0 }, 11_000_000);
    let (id1, _) = operator.process_withdrawal(trace1, 100, f1, v1).unwrap();

    // Need different trace roots for different assertions
    let mut trace2 = honest_trace();
    trace2.proof_hash = sha256(b"proof-2");
    let leaves2: Vec<[u8; 32]> = trace2.steps.iter().map(step_leaf_hash).collect();
    trace2.trace_root = compute_trace_merkle_root(&leaves2);
    let (f2, v2) = (OutPoint { txid: TxId([0x02; 32]), vout: 0 }, 11_000_000);
    let (id2, _) = operator.process_withdrawal(trace2, 110, f2, v2).unwrap();

    let mut trace3 = honest_trace();
    trace3.proof_hash = sha256(b"proof-3");
    let leaves3: Vec<[u8; 32]> = trace3.steps.iter().map(step_leaf_hash).collect();
    trace3.trace_root = compute_trace_merkle_root(&leaves3);
    let (f3, v3) = (OutPoint { txid: TxId([0x03; 32]), vout: 0 }, 11_000_000);
    let (id3, _) = operator.process_withdrawal(trace3, 120, f3, v3).unwrap();

    assert_eq!(operator.active_count(), 3);

    // Finalize at height 244 — only assertion 1 should finalize
    let fin = operator.finalize_expired(244);
    assert_eq!(fin.len(), 1);
    assert_eq!(fin[0].0, id1);

    // Finalize at height 254 — assertion 2 should finalize
    let fin = operator.finalize_expired(254);
    assert_eq!(fin.len(), 1);
    assert_eq!(fin[0].0, id2);

    // Finalize at height 264 — assertion 3 should finalize
    let fin = operator.finalize_expired(264);
    assert_eq!(fin.len(), 1);
    assert_eq!(fin[0].0, id3);

    assert_eq!(operator.active_count(), 0);
}

// =========================================================================
// Test: Bridge + Verifier integration
// =========================================================================

#[test]
fn test_bridge_and_verifier_integration() {
    use lumora_bitvm::bridge::BitvmBridge;
    use lumora_bitvm::verifier::BitvmVerifier;
    use lumora_contracts::bridge::RollupBridge;

    let config = BitvmConfig::default();
    let bridge = BitvmBridge::new(config, operator_key());
    let mut verifier = BitvmVerifier::new(144);

    let trace = honest_trace();
    let assertion = lumora_bitvm::protocol::Assertion::from_trace(&trace, 100, 10_000_000);

    // Register assertion in both bridge and verifier
    bridge.set_height(100);
    let id = bridge
        .register_withdrawal_assertion(
            lumora_contracts::bridge::OutboundWithdrawal {
                amount: 50_000,
                recipient: [0xBB; 32],
                proof_bytes: b"honest-proof".to_vec(),
                nullifiers: [
                    pasta_curves::pallas::Base::from(1u64),
                    pasta_curves::pallas::Base::from(2u64),
                ],
            },
            assertion.clone(),
        )
        .expect("bridge should accept assertion");

    verifier.set_height(100);
    verifier
        .register_assertion(assertion)
        .expect("verifier should accept assertion");

    // Before timeout — bridge has pending, verifier has pending
    assert_eq!(bridge.active_assertions(), 1);
    assert!(!bridge.is_withdrawal_finalized(&id));

    // After timeout
    bridge.set_height(244);
    let finalized = bridge.finalize_expired();
    assert_eq!(finalized.len(), 1);
    assert!(bridge.is_withdrawal_finalized(&id));

    verifier.set_height(244);
    let v_finalized = verifier.finalize_expired();
    assert_eq!(v_finalized.len(), 1);

    // Bridge can still poll deposits (empty in test)
    let deposits = bridge.poll_deposits().unwrap();
    assert!(deposits.is_empty());

    // Bridge committed root tracking
    use pasta_curves::pallas;
    bridge.record_committed_root(pallas::Base::from(42u64));
    assert_eq!(bridge.committed_root_count(), 1);
}
