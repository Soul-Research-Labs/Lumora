//! BitVM2 bisection and challenge protocol.
//!
//! Defines the challenge-response data structures and state machine for
//! disputing an operator's verification trace.
//!
//! # Protocol overview
//!
//! 1. **Operator** publishes an **assertion**: the trace root (Merkle root
//!    over all step commitments) plus the claimed verification result.
//! 2. Any **challenger** can dispute by identifying a specific step they
//!    believe is fraudulent.
//! 3. The **operator** must respond by revealing the step's witness data
//!    and Merkle inclusion proof.
//! 4. A Bitcoin Script (Taproot leaf) re-executes the single step. If the
//!    operator's committed output doesn't match the recomputed output,
//!    the challenger claims the operator's bond.
//! 5. If no challenge arrives within the timeout window, the operator's
//!    assertion is considered valid.

use serde::{Deserialize, Serialize};

use crate::trace::{StepKind, VerificationTrace};

/// Number of blocks the operator has to respond after a challenge is filed.
const RESPONSE_WINDOW_BLOCKS: u64 = 10;

/// Number of blocks challengers have to verify a response and slash if fraudulent.
const VERIFICATION_WINDOW_BLOCKS: u64 = 10;

// ---------------------------------------------------------------------------
// Assertion — operator's on-chain claim
// ---------------------------------------------------------------------------

/// An operator's assertion posted on Bitcoin.
///
/// This claims that a specific Lumora proof verification succeeded (or
/// failed), committed via the trace Merkle root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    /// Unique identifier for this assertion.
    pub id: AssertionId,
    /// Merkle root over all trace step `(input_hash || output_hash)` pairs.
    pub trace_root: [u8; 32],
    /// SHA-256 hash of the proof bytes that were verified.
    pub proof_hash: [u8; 32],
    /// SHA-256 hash of the serialized public inputs.
    pub public_inputs_hash: [u8; 32],
    /// The claimed verification result (true = proof valid).
    pub claimed_result: bool,
    /// Total number of steps in the trace.
    pub num_steps: u32,
    /// Step kind for each step in the trace, used to validate challenge responses.
    pub step_kinds: Vec<StepKind>,
    /// Bitcoin block height at which the assertion was posted.
    pub assert_height: u64,
    /// Operator's bond amount in satoshis.
    pub bond_sats: u64,
}

/// Unique identifier for an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssertionId(pub [u8; 32]);

impl AssertionId {
    /// Derive an assertion ID from the trace root, proof hash, and public inputs hash.
    pub fn from_trace(trace_root: &[u8; 32], proof_hash: &[u8; 32], public_inputs_hash: &[u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"lumora-bitvm:assertion-id");
        h.update(trace_root);
        h.update(proof_hash);
        h.update(public_inputs_hash);
        Self(h.finalize().into())
    }
}

impl Assertion {
    /// Create an assertion from a completed verification trace.
    pub fn from_trace(
        trace: &VerificationTrace,
        assert_height: u64,
        bond_sats: u64,
    ) -> Self {
        let id = AssertionId::from_trace(&trace.trace_root, &trace.proof_hash, &trace.public_inputs_hash);
        Self {
            id,
            trace_root: trace.trace_root,
            proof_hash: trace.proof_hash,
            public_inputs_hash: trace.public_inputs_hash,
            claimed_result: trace.verification_result,
            num_steps: trace.steps.len() as u32,
            step_kinds: trace.steps.iter().map(|s| s.kind).collect(),
            assert_height,
            bond_sats,
        }
    }

    /// Check whether the challenge timeout has elapsed.
    pub fn is_finalized(&self, current_height: u64, timeout_blocks: u32) -> bool {
        current_height >= self.assert_height + timeout_blocks as u64
    }
}

// ---------------------------------------------------------------------------
// Challenge — challenger disputes a specific step
// ---------------------------------------------------------------------------

/// A challenge disputing a specific step in an operator's trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The assertion being challenged.
    pub assertion_id: AssertionId,
    /// The step index the challenger claims is fraudulent.
    pub disputed_step: u32,
    /// The challenger's recomputed output hash for the disputed step.
    /// If this differs from the operator's, the operator was dishonest.
    pub expected_output_hash: [u8; 32],
    /// Bitcoin block height at which the challenge was posted.
    pub challenge_height: u64,
}

// ---------------------------------------------------------------------------
// Response — operator reveals witness for the disputed step
// ---------------------------------------------------------------------------

/// The operator's response to a challenge, revealing the step witness
/// and Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The assertion being defended.
    pub assertion_id: AssertionId,
    /// The disputed step index.
    pub disputed_step: u32,
    /// The step's kind (determines which Script verifier to use).
    pub step_kind: StepKind,
    /// The step's input state hash.
    pub input_hash: [u8; 32],
    /// The step's output state hash (as claimed by the operator).
    pub output_hash: [u8; 32],
    /// The step's witness data for re-execution.
    pub witness: Vec<u8>,
    /// Merkle proof: sibling hashes from leaf to root.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Block height at which the operator submits this response.
    pub response_height: u64,
}

/// Maximum allowed witness size in bytes (1 MiB).
///
/// This prevents memory exhaustion from oversized challenge responses.
pub const MAX_WITNESS_SIZE: usize = 1 << 20;

/// Maximum Merkle proof depth (matching typical trace tree heights).
pub const MAX_MERKLE_PROOF_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Protocol state machine
// ---------------------------------------------------------------------------

/// The current state of an assertion in the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssertionState {
    /// Assertion posted, awaiting potential challenge.
    Pending {
        /// Block height at which the timeout expires.
        timeout_height: u64,
    },
    /// A challenge has been posted.
    Challenged {
        /// The disputed step index.
        disputed_step: u32,
        /// Block height by which the operator must respond.
        /// If not responded by this height, the assertion can be finalized as fraudulent.
        response_deadline: u64,
    },
    /// The operator has responded to the challenge.
    Responded {
        /// The disputed step index.
        disputed_step: u32,
        /// Block height at which the operator responded.
        response_height: u64,
    },
    /// The assertion was proven fraudulent (bond slashed).
    Slashed,
    /// The assertion was finalized successfully (no valid challenge).
    Finalized,
}

/// Manages the lifecycle of assertions in the BitVM2 protocol.
#[derive(Debug)]
pub struct ProtocolManager {
    /// Active assertions indexed by ID.
    assertions: std::collections::HashMap<AssertionId, (Assertion, AssertionState)>,
    /// Challenge timeout in blocks.
    timeout_blocks: u32,
}

impl ProtocolManager {
    /// Create a new protocol manager.
    pub fn new(timeout_blocks: u32) -> Self {
        Self {
            assertions: std::collections::HashMap::new(),
            timeout_blocks,
        }
    }

    /// Register a new assertion from the operator.
    pub fn register_assertion(&mut self, assertion: Assertion) -> Result<(), ProtocolError> {
        let id = assertion.id;
        if self.assertions.contains_key(&id) {
            return Err(ProtocolError::DuplicateAssertion(id));
        }
        // Validate the step_kinds vector length matches num_steps to prevent
        // step_kind validation bypass via truncated assertions.
        if assertion.step_kinds.len() != assertion.num_steps as usize {
            return Err(ProtocolError::InvalidStateTransition(
                format!(
                    "step_kinds length {} does not match num_steps {}",
                    assertion.step_kinds.len(),
                    assertion.num_steps
                ),
                "Pending".into(),
            ));
        }

        let timeout_height = assertion.assert_height.saturating_add(self.timeout_blocks as u64);
        let state = AssertionState::Pending { timeout_height };
        self.assertions.insert(id, (assertion, state));
        Ok(())
    }

    /// Process a challenge against an assertion.
    pub fn process_challenge(&mut self, challenge: &Challenge) -> Result<(), ProtocolError> {
        let (assertion, state) = self
            .assertions
            .get_mut(&challenge.assertion_id)
            .ok_or(ProtocolError::AssertionNotFound(challenge.assertion_id))?;

        match state {
            AssertionState::Pending { timeout_height } => {
                // Challenges must be strictly before the timeout height.
                if challenge.challenge_height >= *timeout_height {
                    return Err(ProtocolError::ChallengeAfterTimeout);
                }
                if challenge.disputed_step >= assertion.num_steps {
                    return Err(ProtocolError::InvalidStepIndex(
                        challenge.disputed_step,
                        assertion.num_steps,
                    ));
                }
                *state = AssertionState::Challenged {
                    disputed_step: challenge.disputed_step,
                    // Give the operator a window to respond after the challenge.
                    response_deadline: timeout_height.saturating_add(RESPONSE_WINDOW_BLOCKS),
                };
                Ok(())
            }
            _ => Err(ProtocolError::InvalidStateTransition(
                format!("{state:?}"),
                "Challenged".into(),
            )),
        }
    }

    /// Process an operator's response to a challenge.
    ///
    /// The caller is responsible for actually verifying the response
    /// (via Script or native re-execution).
    pub fn process_response(
        &mut self,
        response: &ChallengeResponse,
    ) -> Result<(), ProtocolError> {
        // Validate witness and proof sizes to prevent memory exhaustion.
        if response.witness.len() > MAX_WITNESS_SIZE {
            return Err(ProtocolError::InvalidStateTransition(
                format!("witness size {} exceeds max {MAX_WITNESS_SIZE}", response.witness.len()),
                "Responded".into(),
            ));
        }
        if response.merkle_proof.len() > MAX_MERKLE_PROOF_DEPTH {
            return Err(ProtocolError::InvalidStateTransition(
                format!("merkle proof depth {} exceeds max {MAX_MERKLE_PROOF_DEPTH}", response.merkle_proof.len()),
                "Responded".into(),
            ));
        }

        let (assertion, state) = self
            .assertions
            .get_mut(&response.assertion_id)
            .ok_or(ProtocolError::AssertionNotFound(response.assertion_id))?;

        match state {
            AssertionState::Challenged { disputed_step, .. } => {
                if response.disputed_step != *disputed_step {
                    return Err(ProtocolError::StepMismatch(
                        response.disputed_step,
                        *disputed_step,
                    ));
                }
                // Validate that the response's step_kind matches the registered trace.
                match assertion.step_kinds.get(*disputed_step as usize) {
                    Some(expected_kind) if response.step_kind != *expected_kind => {
                        return Err(ProtocolError::InvalidStateTransition(
                            format!(
                                "response step_kind {:?} does not match registered {:?} for step {}",
                                response.step_kind, expected_kind, disputed_step
                            ),
                            "Responded".into(),
                        ));
                    }
                    None => {
                        return Err(ProtocolError::InvalidStepIndex(
                            *disputed_step,
                            assertion.step_kinds.len() as u32,
                        ));
                    }
                    _ => {}
                }
                *state = AssertionState::Responded {
                    disputed_step: *disputed_step,
                    response_height: response.response_height,
                };
                Ok(())
            }
            _ => Err(ProtocolError::InvalidStateTransition(
                format!("{state:?}"),
                "Responded".into(),
            )),
        }
    }

    /// Mark an assertion as slashed (fraud proven).
    pub fn slash(&mut self, assertion_id: &AssertionId) -> Result<u64, ProtocolError> {
        let (assertion, state) = self
            .assertions
            .get_mut(assertion_id)
            .ok_or(ProtocolError::AssertionNotFound(*assertion_id))?;

        match state {
            AssertionState::Responded { .. } => {
                let bond = assertion.bond_sats;
                *state = AssertionState::Slashed;
                Ok(bond)
            }
            _ => Err(ProtocolError::InvalidStateTransition(
                format!("{state:?}"),
                "Slashed".into(),
            )),
        }
    }

    /// Finalize assertions whose timeout has elapsed without challenge.
    /// Also forfeits challenged assertions where the operator failed to respond in time.
    pub fn finalize_expired(&mut self, current_height: u64) -> Vec<AssertionId> {
        let mut finalized = Vec::new();

        for (id, (_, state)) in self.assertions.iter_mut() {
            match state {
                AssertionState::Pending { timeout_height } => {
                    if current_height >= *timeout_height {
                        *state = AssertionState::Finalized;
                        finalized.push(*id);
                    }
                }
                // Bug #20: Challenged state with expired response deadline → forfeit operator bond.
                AssertionState::Challenged { response_deadline, .. } => {
                    if current_height >= *response_deadline {
                        *state = AssertionState::Slashed;
                        finalized.push(*id);
                    }
                }
                // Responded: give challengers a verification window to slash.
                // If not slashed within the window, finalize as valid.
                AssertionState::Responded { response_height, .. } => {
                    if current_height >= response_height.saturating_add(VERIFICATION_WINDOW_BLOCKS) {
                        *state = AssertionState::Finalized;
                        finalized.push(*id);
                    }
                }
                _ => {}
            }
        }

        finalized
    }

    /// Get the state of an assertion.
    pub fn get_state(&self, id: &AssertionId) -> Option<&AssertionState> {
        self.assertions.get(id).map(|(_, s)| s)
    }

    /// Get the assertion details.
    pub fn get_assertion(&self, id: &AssertionId) -> Option<&Assertion> {
        self.assertions.get(id).map(|(a, _)| a)
    }

    /// Count of active (non-finalized, non-slashed) assertions.
    pub fn active_count(&self) -> usize {
        self.assertions
            .values()
            .filter(|(_, s)| {
                !matches!(s, AssertionState::Finalized | AssertionState::Slashed)
            })
            .count()
    }

    /// Iterate over all assertions and their states.
    pub fn iter_assertions(&self) -> impl Iterator<Item = (&Assertion, &AssertionState)> {
        self.assertions.values().map(|(a, s)| (a, s))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the protocol state machine.
#[derive(Debug)]
pub enum ProtocolError {
    DuplicateAssertion(AssertionId),
    AssertionNotFound(AssertionId),
    ChallengeAfterTimeout,
    InvalidStepIndex(u32, u32),
    InvalidStateTransition(String, String),
    StepMismatch(u32, u32),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::DuplicateAssertion(id) => {
                write!(f, "assertion {:?} already exists", id.0)
            }
            ProtocolError::AssertionNotFound(id) => {
                write!(f, "assertion {:?} not found", id.0)
            }
            ProtocolError::ChallengeAfterTimeout => {
                write!(f, "challenge submitted after timeout")
            }
            ProtocolError::InvalidStepIndex(got, max) => {
                write!(f, "step index {got} out of range (max {max})")
            }
            ProtocolError::InvalidStateTransition(from, to) => {
                write!(f, "invalid transition from {from} to {to}")
            }
            ProtocolError::StepMismatch(got, expected) => {
                write!(f, "response step {got} != challenged step {expected}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{sha256, VerificationTrace, TraceStep, StepKind,
                       step_leaf_hash, compute_trace_merkle_root};

    fn dummy_trace() -> VerificationTrace {
        let steps = vec![
            TraceStep {
                index: 0,
                kind: StepKind::TranscriptInit,
                input_hash: [0u8; 32],
                output_hash: [1u8; 32],
                witness: vec![],
            },
            TraceStep {
                index: 1,
                kind: StepKind::FinalCheck,
                input_hash: [1u8; 32],
                output_hash: [2u8; 32],
                witness: vec![],
            },
        ];
        let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
        let trace_root = compute_trace_merkle_root(&leaves);

        VerificationTrace {
            steps,
            trace_root,
            proof_hash: sha256(b"test-proof"),
            public_inputs_hash: sha256(b"test-pi"),
            verification_result: true,
        }
    }

    #[test]
    fn test_assertion_from_trace() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);

        assert_eq!(assertion.trace_root, trace.trace_root);
        assert!(assertion.claimed_result);
        assert_eq!(assertion.num_steps, 2);
        assert_eq!(assertion.assert_height, 100);
        assert_eq!(assertion.bond_sats, 10_000_000);
    }

    #[test]
    fn test_assertion_finalized_after_timeout() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);

        assert!(!assertion.is_finalized(200, 144));  // 100 + 144 = 244 > 200
        assert!(assertion.is_finalized(244, 144));   // 100 + 144 = 244 <= 244
        assert!(assertion.is_finalized(300, 144));   // 100 + 144 = 244 <= 300
    }

    #[test]
    fn test_protocol_happy_path() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);
        let assertion_id = assertion.id;

        let mut pm = ProtocolManager::new(144);
        pm.register_assertion(assertion).unwrap();

        assert_eq!(pm.active_count(), 1);

        // Before timeout: still pending
        let finalized = pm.finalize_expired(200);
        assert!(finalized.is_empty());
        assert_eq!(pm.active_count(), 1);

        // After timeout: finalized
        let finalized = pm.finalize_expired(244);
        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0], assertion_id);
        assert_eq!(
            pm.get_state(&assertion_id),
            Some(&AssertionState::Finalized)
        );
        assert_eq!(pm.active_count(), 0);
    }

    #[test]
    fn test_protocol_challenge_flow() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);
        let assertion_id = assertion.id;

        let mut pm = ProtocolManager::new(144);
        pm.register_assertion(assertion).unwrap();

        // Challenger disputes step 0
        let challenge = Challenge {
            assertion_id,
            disputed_step: 0,
            expected_output_hash: [0xFFu8; 32],
            challenge_height: 150,
        };
        pm.process_challenge(&challenge).unwrap();

        assert!(matches!(
            pm.get_state(&assertion_id),
            Some(&AssertionState::Challenged { disputed_step: 0, .. })
        ));

        // Operator responds
        let response = ChallengeResponse {
            assertion_id,
            disputed_step: 0,
            step_kind: StepKind::TranscriptInit,
            input_hash: [0u8; 32],
            output_hash: [1u8; 32],
            witness: vec![],
            merkle_proof: vec![],
            response_height: 160,
        };
        pm.process_response(&response).unwrap();

        assert_eq!(
            pm.get_state(&assertion_id),
            Some(&AssertionState::Responded { disputed_step: 0, response_height: 160 })
        );

        // Slash the operator (fraud proven after Script verification)
        let bond = pm.slash(&assertion_id).unwrap();
        assert_eq!(bond, 10_000_000);
        assert_eq!(
            pm.get_state(&assertion_id),
            Some(&AssertionState::Slashed)
        );
    }

    #[test]
    fn test_protocol_reject_duplicate_assertion() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);

        let mut pm = ProtocolManager::new(144);
        pm.register_assertion(assertion.clone()).unwrap();
        assert!(pm.register_assertion(assertion).is_err());
    }

    #[test]
    fn test_protocol_reject_late_challenge() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);
        let assertion_id = assertion.id;

        let mut pm = ProtocolManager::new(144);
        pm.register_assertion(assertion).unwrap();

        let challenge = Challenge {
            assertion_id,
            disputed_step: 0,
            expected_output_hash: [0xFFu8; 32],
            challenge_height: 300, // After timeout (100 + 144 = 244)
        };
        assert!(pm.process_challenge(&challenge).is_err());
    }

    #[test]
    fn test_protocol_reject_invalid_step_index() {
        let trace = dummy_trace();
        let assertion = Assertion::from_trace(&trace, 100, 10_000_000);
        let assertion_id = assertion.id;

        let mut pm = ProtocolManager::new(144);
        pm.register_assertion(assertion).unwrap();

        let challenge = Challenge {
            assertion_id,
            disputed_step: 99, // Only 2 steps
            expected_output_hash: [0xFFu8; 32],
            challenge_height: 150,
        };
        assert!(pm.process_challenge(&challenge).is_err());
    }

    #[test]
    fn test_assertion_id_deterministic() {
        let tr = [0xAAu8; 32];
        let ph = [0xBBu8; 32];
        let id1 = AssertionId::from_trace(&tr, &ph, &[0u8; 32]);
        let id2 = AssertionId::from_trace(&tr, &ph, &[0u8; 32]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_assertion_id_differs_for_different_inputs() {
        let tr1 = [0xAAu8; 32];
        let tr2 = [0xCCu8; 32];
        let ph = [0xBBu8; 32];
        let id1 = AssertionId::from_trace(&tr1, &ph, &[0u8; 32]);
        let id2 = AssertionId::from_trace(&tr2, &ph, &[0u8; 32]);
        assert_ne!(id1, id2);
    }
}
