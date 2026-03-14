//! Challenger monitoring and response.
//!
//! Watches Bitcoin for operator assert transactions, re-executes
//! verification traces locally, and posts challenge/disprove transactions
//! when fraud is detected.
//!
//! The challenger is the honest watchdog — it earns the operator's bond
//! if it can prove a single trace step is incorrect.

use crate::config::ChallengerConfig;
use crate::protocol::{Assertion, AssertionId, Challenge, ChallengeResponse};
use crate::script::validate_step;
use crate::trace::{step_leaf_hash, verify_merkle_proof, StepKind, TraceStep};
use crate::transactions::{
    build_disprove_tx, DisproveTxParams, OutPoint, Transaction, XOnlyPubKey,
};

// ---------------------------------------------------------------------------
// Challenge outcome
// ---------------------------------------------------------------------------

/// Result of verifying an operator's challenge response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The operator's response is honest — step re-execution matches.
    Honest,
    /// The operator's step output is fraudulent. The disprove TX can be
    /// broadcast to claim the bond.
    Fraudulent {
        step_index: u32,
        expected_output: [u8; 32],
        actual_output: [u8; 32],
    },
    /// The Merkle proof is invalid — the step isn't in the committed trace.
    InvalidMerkleProof,
}

// ---------------------------------------------------------------------------
// Challenger
// ---------------------------------------------------------------------------

/// Challenger that monitors operator assertions and disputes fraud.
///
/// # Workflow
///
/// 1. Observe new `Assertion`s on Bitcoin (via `observe_assertion`)
/// 2. Re-verify each trace step locally
/// 3. If a step is dishonest, file a `Challenge`
/// 4. When the operator responds, verify the response
/// 5. If the response confirms fraud, broadcast a Disprove TX
pub struct Challenger {
    config: ChallengerConfig,
    challenger_pubkey: XOnlyPubKey,
    /// Observed assertions awaiting verification.
    observed: Vec<ObservedAssertion>,
}

/// An assertion the challenger is watching.
#[derive(Debug)]
struct ObservedAssertion {
    assertion: Assertion,
    assert_outpoint: OutPoint,
    /// Index of the disputed step, if any.
    disputed_step: Option<u32>,
}

impl Challenger {
    /// Create a new challenger.
    pub fn new(config: ChallengerConfig, challenger_pubkey: XOnlyPubKey) -> Self {
        Self {
            config,
            challenger_pubkey,
            observed: Vec::new(),
        }
    }

    /// Observe a new operator assertion on Bitcoin.
    pub fn observe_assertion(&mut self, assertion: Assertion, assert_outpoint: OutPoint) {
        self.observed.push(ObservedAssertion {
            assertion,
            assert_outpoint,
            disputed_step: None,
        });
    }

    /// Check a trace against an assertion and identify any fraudulent step.
    ///
    /// Returns the index of the first dishonest step, or `None` if the
    /// entire trace is consistent. This validates:
    /// 1. Step chain continuity (`output[i] == input[i+1]`)
    /// 2. Individual step re-execution via `validate_step`
    /// 3. The claimed verification result
    pub fn find_fraud(
        &self,
        assertion: &Assertion,
        steps: &[TraceStep],
    ) -> Option<u32> {
        if steps.is_empty() {
            return None;
        }

        // Check step chain continuity
        for i in 1..steps.len() {
            if steps[i].input_hash != steps[i - 1].output_hash {
                return Some(i as u32);
            }
        }

        // Validate each step independently
        for step in steps {
            if !validate_step(step.kind, &step.input_hash, &step.output_hash, &step.witness) {
                return Some(step.index);
            }
        }

        // Check the claimed result against what the final step implies
        let final_step = steps.last().unwrap();
        let expected_result = final_step.kind == StepKind::FinalCheck
            && final_step.output_hash != [0u8; 32];

        if assertion.claimed_result != expected_result {
            return Some(final_step.index);
        }

        None
    }

    /// Create a challenge for a specific step of an assertion.
    pub fn create_challenge(
        &mut self,
        assertion_id: AssertionId,
        disputed_step: u32,
        expected_output_hash: [u8; 32],
        current_height: u64,
    ) -> Challenge {
        // Track that we've disputed this assertion
        if let Some(obs) = self.observed.iter_mut().find(|o| o.assertion.id == assertion_id) {
            obs.disputed_step = Some(disputed_step);
        }

        Challenge {
            assertion_id,
            disputed_step,
            expected_output_hash,
            challenge_height: current_height,
        }
    }

    /// Verify an operator's challenge response.
    ///
    /// Checks:
    /// 1. The Merkle proof is valid (step belongs to the committed trace)
    /// 2. Re-executing the step with the revealed witness produces the
    ///    committed output hash
    pub fn verify_response(
        &self,
        assertion: &Assertion,
        response: &ChallengeResponse,
    ) -> VerifyOutcome {
        // Build a TraceStep from the response
        let step = TraceStep {
            index: response.disputed_step,
            kind: response.step_kind,
            input_hash: response.input_hash,
            output_hash: response.output_hash,
            witness: response.witness.clone(),
        };

        // Verify Merkle inclusion
        let leaf = step_leaf_hash(&step);
        if !verify_merkle_proof(
            leaf,
            response.disputed_step as usize,
            &response.merkle_proof,
            assertion.trace_root,
        ) {
            return VerifyOutcome::InvalidMerkleProof;
        }

        // Re-execute the step locally
        if !validate_step(step.kind, &step.input_hash, &step.output_hash, &step.witness) {
            let recomputed = crate::script::recompute_step_output(
                response.step_kind,
                &response.input_hash,
                &response.witness,
            );
            return VerifyOutcome::Fraudulent {
                step_index: response.disputed_step,
                expected_output: recomputed,
                actual_output: response.output_hash,
            };
        }

        VerifyOutcome::Honest
    }

    /// Build a Disprove TX to claim the operator's bond.
    ///
    /// This should only be called after `verify_response` returns
    /// `VerifyOutcome::Fraudulent`.
    pub fn build_disprove(
        &self,
        assertion_id: &AssertionId,
        response: &ChallengeResponse,
    ) -> Option<Transaction> {
        let obs = self
            .observed
            .iter()
            .find(|o| o.assertion.id == *assertion_id)?;

        // Build challenger's P2TR payout script
        let mut script_pubkey = vec![0x51, 0x20]; // OP_1 <32-byte key>
        script_pubkey.extend_from_slice(&self.challenger_pubkey.0);

        let disprove_tx = build_disprove_tx(&DisproveTxParams {
            assert_outpoint: obs.assert_outpoint,
            assert_value: obs.assertion.bond_sats,
            step_kind: response.step_kind,
            input_hash: response.input_hash,
            claimed_output_hash: response.output_hash,
            witness: response.witness.clone(),
            challenger_script_pubkey: script_pubkey,
            fee_sats: 1_000,
        });

        Some(disprove_tx)
    }

    /// Number of observed assertions.
    pub fn observed_count(&self) -> usize {
        self.observed.len()
    }

    /// Get challenger config.
    pub fn config(&self) -> &ChallengerConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChallengerConfig;
    use crate::protocol::Assertion;
    use crate::script::recompute_step_output;
    use crate::trace::{
        compute_trace_merkle_root, merkle_proof_for_step, sha256, step_leaf_hash, StepKind,
        TraceStep, VerificationTrace,
    };

    fn test_challenger() -> Challenger {
        let config = ChallengerConfig::default();
        let pubkey = XOnlyPubKey([0xCC; 32]);
        Challenger::new(config, pubkey)
    }

    fn honest_steps() -> Vec<TraceStep> {
        let input0 = sha256(b"init");
        let witness0 = vec![0x01];
        let output0 = recompute_step_output(StepKind::TranscriptInit, &input0, &witness0);

        let witness1 = vec![0x02];
        let output1 = recompute_step_output(StepKind::FinalCheck, &output0, &witness1);

        vec![
            TraceStep {
                index: 0,
                kind: StepKind::TranscriptInit,
                input_hash: input0,
                output_hash: output0,
                witness: witness0,
            },
            TraceStep {
                index: 1,
                kind: StepKind::FinalCheck,
                input_hash: output0,
                output_hash: output1,
                witness: witness1,
            },
        ]
    }

    fn honest_trace() -> VerificationTrace {
        let steps = honest_steps();
        let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
        VerificationTrace {
            steps,
            trace_root: compute_trace_merkle_root(&leaves),
            proof_hash: sha256(b"proof"),
            public_inputs_hash: sha256(b"pi"),
            verification_result: true,
        }
    }

    fn dishonest_steps() -> Vec<TraceStep> {
        let mut steps = honest_steps();
        // Break chain: step[1].input_hash != step[0].output_hash
        steps[1].input_hash = [0xFF; 32];
        steps
    }

    fn test_assertion(trace: &VerificationTrace) -> Assertion {
        Assertion::from_trace(trace, 100, 10_000_000)
    }

    fn test_outpoint() -> OutPoint {
        OutPoint {
            txid: crate::transactions::TxId([0xDD; 32]),
            vout: 0,
        }
    }

    #[test]
    fn test_challenger_creation() {
        let c = test_challenger();
        assert_eq!(c.observed_count(), 0);
    }

    #[test]
    fn test_observe_assertion() {
        let mut c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        c.observe_assertion(a, test_outpoint());
        assert_eq!(c.observed_count(), 1);
    }

    #[test]
    fn test_find_fraud_honest_trace() {
        let c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        assert!(c.find_fraud(&a, &trace.steps).is_none());
    }

    #[test]
    fn test_find_fraud_broken_chain() {
        let c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        let steps = dishonest_steps();
        // Chain break at step 1
        let fraud = c.find_fraud(&a, &steps);
        assert_eq!(fraud, Some(1));
    }

    #[test]
    fn test_create_challenge() {
        let mut c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        c.observe_assertion(a.clone(), test_outpoint());

        let challenge = c.create_challenge(a.id, 1, [0xFF; 32], 105);
        assert_eq!(challenge.assertion_id, a.id);
        assert_eq!(challenge.disputed_step, 1);
    }

    #[test]
    fn test_verify_response_honest() {
        let c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        let leaves: Vec<[u8; 32]> = trace.steps.iter().map(step_leaf_hash).collect();

        let step = &trace.steps[0];
        let proof = merkle_proof_for_step(&leaves, 0);

        let response = ChallengeResponse {
            assertion_id: a.id,
            disputed_step: 0,
            step_kind: step.kind,
            input_hash: step.input_hash,
            output_hash: step.output_hash,
            witness: step.witness.clone(),
            merkle_proof: proof,
        };

        assert_eq!(c.verify_response(&a, &response), VerifyOutcome::Honest);
    }

    #[test]
    fn test_verify_response_bad_merkle_proof() {
        let c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        let step = &trace.steps[0];

        let response = ChallengeResponse {
            assertion_id: a.id,
            disputed_step: 0,
            step_kind: step.kind,
            input_hash: step.input_hash,
            output_hash: step.output_hash,
            witness: step.witness.clone(),
            merkle_proof: vec![[0xFF; 32]], // bad proof
        };

        assert_eq!(
            c.verify_response(&a, &response),
            VerifyOutcome::InvalidMerkleProof
        );
    }

    #[test]
    fn test_build_disprove_tx() {
        let mut c = test_challenger();
        let trace = honest_trace();
        let a = test_assertion(&trace);
        c.observe_assertion(a.clone(), test_outpoint());
        let leaves: Vec<[u8; 32]> = trace.steps.iter().map(step_leaf_hash).collect();

        let response = ChallengeResponse {
            assertion_id: a.id,
            disputed_step: 0,
            step_kind: StepKind::TranscriptInit,
            input_hash: [0; 32],
            output_hash: [1; 32],
            witness: vec![0x01],
            merkle_proof: merkle_proof_for_step(&leaves, 0),
        };

        let tx = c.build_disprove(&a.id, &response);
        assert!(tx.is_some());
        let tx = tx.unwrap();
        assert_eq!(tx.outputs.len(), 1);
    }
}
