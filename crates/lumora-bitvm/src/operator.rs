//! Operator daemon logic for the BitVM bridge.
//!
//! Processes pending withdrawals, generates verification traces,
//! posts assert transactions, and handles incoming challenges.
//!
//! The operator is the party that posts assertions backed by a bond.
//! If the assertion is honest, the bond is reclaimed after the timeout.
//! If challenged successfully, the bond is slashed.

use lumora_contracts::bridge::BridgeError;

use crate::config::BitvmConfig;
use crate::protocol::{
    Assertion, AssertionId, AssertionState, Challenge, ChallengeResponse, ProtocolError,
    ProtocolManager,
};
use crate::trace::{
    merkle_proof_for_step, step_leaf_hash, VerificationTrace,
};
use crate::transactions::{
    build_assert_tx, AssertTxOutput, AssertTxParams, OutPoint, TimeoutTxParams, XOnlyPubKey,
};

// ---------------------------------------------------------------------------
// Operator
// ---------------------------------------------------------------------------

/// Pending assertion tracked by the operator.
#[derive(Debug)]
struct TrackedAssertion {
    assertion: Assertion,
    trace: VerificationTrace,
    assert_tx: AssertTxOutput,
}

/// Operator daemon managing BitVM2 assertions on Bitcoin.
///
/// Responsibilities:
/// - Accept withdrawal requests and generate verification traces
/// - Build and track Assert TXs
/// - Respond to challenges by revealing step witnesses
/// - Claim bonds via Timeout TXs after the challenge period
pub struct Operator {
    config: BitvmConfig,
    operator_pubkey: XOnlyPubKey,
    challenger_pubkey: XOnlyPubKey,
    protocol: ProtocolManager,
    tracked: Vec<TrackedAssertion>,
}

impl Operator {
    /// Create a new operator.
    pub fn new(
        config: BitvmConfig,
        operator_pubkey: XOnlyPubKey,
        challenger_pubkey: XOnlyPubKey,
    ) -> Self {
        let timeout = config.challenge_timeout_blocks;
        Self {
            config,
            operator_pubkey,
            challenger_pubkey,
            protocol: ProtocolManager::new(timeout),
            tracked: Vec::new(),
        }
    }

    /// Process a withdrawal by generating a trace and building an assert TX.
    ///
    /// Returns the assertion ID and serialized assert TX for broadcasting.
    pub fn process_withdrawal(
        &mut self,
        trace: VerificationTrace,
        current_height: u64,
        funding_outpoint: OutPoint,
        funding_value: u64,
    ) -> Result<(AssertionId, AssertTxOutput), BridgeError> {
        if !trace.verification_result {
            return Err(BridgeError::WithdrawFailed(
                "cannot assert a failing verification".into(),
            ));
        }

        // Create assertion
        let assertion =
            Assertion::from_trace(&trace, current_height, self.config.bond_sats);
        let id = assertion.id;

        // Build assert TX
        let assert_tx = build_assert_tx(&AssertTxParams {
            assertion: assertion.clone(),
            operator_pubkey: self.operator_pubkey,
            challenger_pubkey: self.challenger_pubkey,
            funding_outpoint,
            funding_value,
            fee_sats: 1_000,
            timeout_blocks: self.config.challenge_timeout_blocks,
        }).map_err(|e| BridgeError::CommitFailed(e.to_string()))?;

        // Register in protocol
        self.protocol
            .register_assertion(assertion.clone())
            .map_err(|e| BridgeError::CommitFailed(e.to_string()))?;

        self.tracked.push(TrackedAssertion {
            assertion,
            trace,
            assert_tx: assert_tx.clone(),
        });

        Ok((id, assert_tx))
    }

    /// Respond to a challenge by revealing the disputed step's witness.
    pub fn respond_to_challenge(
        &mut self,
        challenge: &Challenge,
        current_height: u64,
    ) -> Result<ChallengeResponse, ProtocolError> {
        // Process challenge in protocol state machine
        self.protocol.process_challenge(challenge)?;

        // Find the tracked assertion
        let tracked = self
            .tracked
            .iter()
            .find(|t| t.assertion.id == challenge.assertion_id)
            .ok_or(ProtocolError::AssertionNotFound(challenge.assertion_id))?;

        let step_idx = challenge.disputed_step as usize;
        let step = tracked
            .trace
            .steps
            .get(step_idx)
            .ok_or(ProtocolError::InvalidStepIndex(
                challenge.disputed_step,
                tracked.trace.steps.len() as u32,
            ))?;

        // Generate Merkle proof for this step
        let leaves: Vec<[u8; 32]> =
            tracked.trace.steps.iter().map(step_leaf_hash).collect();
        let merkle_proof = merkle_proof_for_step(&leaves, step_idx);

        let response = ChallengeResponse {
            assertion_id: challenge.assertion_id,
            disputed_step: challenge.disputed_step,
            step_kind: step.kind,
            input_hash: step.input_hash,
            output_hash: step.output_hash,
            witness: step.witness.clone(),
            merkle_proof,
            response_height: current_height,
        };

        // Process response in state machine
        self.protocol.process_response(&response)?;

        Ok(response)
    }

    /// Finalize assertions whose timeout has elapsed.
    ///
    /// Returns timeout TX params for each finalized assertion, allowing
    /// the operator to broadcast Timeout TXs and reclaim bonds.
    pub fn finalize_expired(
        &mut self,
        current_height: u64,
    ) -> Vec<(AssertionId, TimeoutTxParams)> {
        let finalized_ids = self.protocol.finalize_expired(current_height);

        finalized_ids
            .into_iter()
            .filter_map(|id| {
                let tracked = self.tracked.iter().find(|t| t.assertion.id == id)?;
                // Build P2TR script for operator's payout address
                let mut script_pubkey = vec![0x51, 0x20]; // OP_1 <32 bytes>
                script_pubkey.extend_from_slice(&self.operator_pubkey.0);
                let timeout_params = TimeoutTxParams {
                    assert_outpoint: OutPoint {
                        txid: crate::transactions::compute_txid(&tracked.assert_tx.tx),
                        vout: 0,
                    },
                    assert_value: tracked.assertion.bond_sats,
                    operator_script_pubkey: script_pubkey,
                    fee_sats: 1_000,
                    timeout_blocks: self.config.challenge_timeout_blocks,
                };
                Some((id, timeout_params))
            })
            .collect()
    }

    /// Number of active (in-flight) assertions.
    pub fn active_count(&self) -> usize {
        self.protocol.active_count()
    }

    /// Check the state of an assertion.
    pub fn assertion_state(&self, id: &AssertionId) -> Option<&AssertionState> {
        self.protocol.get_state(id)
    }

    /// Get operator configuration.
    pub fn config(&self) -> &BitvmConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Async daemon wrapper
// ---------------------------------------------------------------------------

/// Async operator daemon that polls for pending withdrawals and processes them.
///
/// Wraps the synchronous [`Operator`] and exposes a `run()` loop that can be
/// driven by a tokio runtime. The loop checks for finalized assertions each
/// tick and returns shutdown-safe state.
pub struct OperatorDaemon {
    operator: Operator,
    poll_interval: std::time::Duration,
}

impl OperatorDaemon {
    /// Create a new operator daemon.
    pub fn new(operator: Operator) -> Self {
        Self {
            operator,
            poll_interval: std::time::Duration::from_secs(30),
        }
    }

    /// Set the polling interval for the main loop.
    pub fn with_poll_interval(mut self, interval: std::time::Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Access the inner operator.
    pub fn operator(&self) -> &Operator {
        &self.operator
    }

    /// Mutable access to the inner operator.
    pub fn operator_mut(&mut self) -> &mut Operator {
        &mut self.operator
    }

    /// Run a single tick of the daemon loop:
    /// 1. Finalize any expired assertions
    /// 2. Return the finalized IDs and their timeout TX params
    ///
    /// In production, the caller would broadcast the Timeout TXs.
    pub fn tick(
        &mut self,
        current_height: u64,
    ) -> Vec<(AssertionId, crate::transactions::TimeoutTxParams)> {
        self.operator.finalize_expired(current_height)
    }

    /// Run the daemon loop until the cancellation token fires.
    ///
    /// `get_height` is called each tick to fetch the current Bitcoin height.
    /// `on_finalized` is called for each newly finalized assertion.
    pub async fn run<F, G>(
        &mut self,
        mut get_height: F,
        mut on_finalized: G,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) where
        F: FnMut() -> u64,
        G: FnMut(AssertionId, crate::transactions::TimeoutTxParams),
    {
        tracing::info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            "operator daemon started"
        );
        loop {
            if *cancel.borrow() {
                tracing::info!("operator daemon shutting down");
                break;
            }
            let height = get_height();
            let finalized = self.tick(height);
            for (id, params) in finalized {
                tracing::info!(?id, "assertion finalized, broadcasting timeout TX");
                on_finalized(id, params);
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BitvmConfig;
    use crate::trace::{
        compute_trace_merkle_root, sha256, step_leaf_hash, StepKind, TraceStep,
        VerificationTrace,
    };
    use crate::transactions::TxId;

    fn test_operator() -> Operator {
        let config = BitvmConfig::default();
        let pubkey = XOnlyPubKey([0xAA; 32]);
        let challenger = XOnlyPubKey([0xBB; 32]);
        Operator::new(config, pubkey, challenger)
    }

    fn valid_trace() -> VerificationTrace {
        let steps: Vec<TraceStep> = vec![
            TraceStep {
                index: 0,
                kind: StepKind::TranscriptInit,
                input_hash: [0u8; 32],
                output_hash: [1u8; 32],
                witness: vec![0x01, 0x02],
            },
            TraceStep {
                index: 1,
                kind: StepKind::MsmRound,
                input_hash: [1u8; 32],
                output_hash: [2u8; 32],
                witness: vec![0x03, 0x04],
            },
            TraceStep {
                index: 2,
                kind: StepKind::FinalCheck,
                input_hash: [2u8; 32],
                output_hash: [3u8; 32],
                witness: vec![0x05],
            },
        ];
        let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
        VerificationTrace {
            steps,
            trace_root: compute_trace_merkle_root(&leaves),
            proof_hash: sha256(b"test-proof"),
            public_inputs_hash: sha256(b"test-pi"),
            verification_result: true,
        }
    }

    fn failing_trace() -> VerificationTrace {
        let mut trace = valid_trace();
        trace.verification_result = false;
        trace
    }

    fn funding() -> (OutPoint, u64) {
        (OutPoint { txid: TxId([0xCC; 32]), vout: 0 }, 11_000_000)
    }

    #[test]
    fn test_operator_creation() {
        let op = test_operator();
        assert_eq!(op.active_count(), 0);
    }

    #[test]
    fn test_process_withdrawal() {
        let mut op = test_operator();
        let trace = valid_trace();
        let (fund, val) = funding();
        let (id, assert_tx) = op.process_withdrawal(trace, 100, fund, val).unwrap();
        assert_eq!(op.active_count(), 1);
        assert!(assert_tx.tx.inputs.len() > 0);
        assert!(matches!(
            op.assertion_state(&id),
            Some(AssertionState::Pending { .. })
        ));
    }

    #[test]
    fn test_reject_failing_trace() {
        let mut op = test_operator();
        let trace = failing_trace();
        let (fund, val) = funding();
        assert!(op.process_withdrawal(trace, 100, fund, val).is_err());
    }

    #[test]
    fn test_respond_to_challenge() {
        let mut op = test_operator();
        let trace = valid_trace();
        let (fund, val) = funding();
        let (id, _) = op.process_withdrawal(trace, 100, fund, val).unwrap();

        let challenge = Challenge {
            assertion_id: id,
            disputed_step: 1,
            expected_output_hash: [0xFF; 32],
            challenge_height: 105,
        };

        let response = op.respond_to_challenge(&challenge, 110).unwrap();
        assert_eq!(response.assertion_id, id);
        assert_eq!(response.disputed_step, 1);
        assert_eq!(response.step_kind, StepKind::MsmRound);
        assert_eq!(response.witness, vec![0x03, 0x04]);
    }

    #[test]
    fn test_challenge_invalid_step() {
        let mut op = test_operator();
        let trace = valid_trace();
        let (fund, val) = funding();
        let (id, _) = op.process_withdrawal(trace, 100, fund, val).unwrap();

        let challenge = Challenge {
            assertion_id: id,
            disputed_step: 99, // out of range
            expected_output_hash: [0xFF; 32],
            challenge_height: 105,
        };

        assert!(op.respond_to_challenge(&challenge, 110).is_err());
    }

    #[test]
    fn test_finalize_expired() {
        let mut op = test_operator();
        let trace = valid_trace();
        let (fund, val) = funding();
        let (id, _) = op.process_withdrawal(trace, 100, fund, val).unwrap();

        // Before timeout (default 144 blocks)
        let finalized = op.finalize_expired(200);
        assert!(finalized.is_empty());

        // After timeout
        let finalized = op.finalize_expired(244);
        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0].0, id);
    }

    #[test]
    fn test_duplicate_assertion_rejected() {
        let mut op = test_operator();
        let trace = valid_trace();
        let (fund, val) = funding();
        let _ = op.process_withdrawal(trace.clone(), 100, fund.clone(), val).unwrap();
        let (fund2, val2) = funding();
        assert!(op.process_withdrawal(trace, 100, fund2, val2).is_err());
    }
}