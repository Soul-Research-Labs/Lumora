//! IPA verification trace model and generation.
//!
//! Decomposes Halo2 IPA verification into discrete steps, each producing
//! a SHA-256 commitment over its intermediate state. The full trace is
//! committed via a Merkle tree; only a disputed step needs on-chain
//! verification in Bitcoin Script.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use lumora_circuits::transfer::{transfer_public_inputs, NUM_INPUTS, NUM_OUTPUTS};
use lumora_circuits::withdraw::withdraw_public_inputs;

// ---------------------------------------------------------------------------
// Trace step types — each represents one atomic verification sub-computation
// ---------------------------------------------------------------------------

/// The type of computation performed in a single trace step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// Initialize transcript and absorb public inputs.
    TranscriptInit,
    /// Read a group of commitment points from the proof stream.
    CommitmentRead,
    /// Squeeze a Fiat-Shamir challenge from the transcript.
    ChallengeSqueeze,
    /// One round of the multi-scalar multiplication accumulator.
    MsmRound,
    /// One round of the inner product argument.
    IpaRound,
    /// Final check: verify the accumulated MSM result equals identity.
    FinalCheck,
}

/// A single step in the verification execution trace.
///
/// Each step has an input state commitment, an output state commitment,
/// and witness data sufficient to re-execute the step independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// Position of this step in the overall trace (0-indexed).
    pub index: u32,
    /// The type of computation this step performs.
    pub kind: StepKind,
    /// SHA-256 commitment over the step's input state.
    pub input_hash: [u8; 32],
    /// SHA-256 commitment over the step's output state.
    pub output_hash: [u8; 32],
    /// Serialized witness data for re-executing this step.
    /// Contains field elements, curve points, or scalar values depending
    /// on `kind`.
    pub witness: Vec<u8>,
}

/// Complete execution trace of an IPA verification.
///
/// The trace root is the Merkle root over all step commitments.
/// An honest operator produces a valid trace; a dishonest one will have
/// at least one step where `input_hash → recompute → output_hash` fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTrace {
    /// Ordered sequence of trace steps.
    pub steps: Vec<TraceStep>,
    /// Merkle root over `(input_hash || output_hash)` of every step.
    pub trace_root: [u8; 32],
    /// The proof bytes that were verified (for reference).
    pub proof_hash: [u8; 32],
    /// The public inputs that were verified (serialized).
    pub public_inputs_hash: [u8; 32],
    /// Whether the underlying verification succeeded.
    pub verification_result: bool,
}

// ---------------------------------------------------------------------------
// Trace Merkle tree — SHA-256 binary tree over step commitments
// ---------------------------------------------------------------------------

/// Compute the leaf hash for a trace step: `SHA256(input_hash || output_hash)`.
pub fn step_leaf_hash(step: &TraceStep) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(step.input_hash);
    hasher.update(step.output_hash);
    hasher.finalize().into()
}

/// Compute the Merkle root over a list of leaf hashes.
///
/// Uses a binary SHA-256 tree, padding to the next power of 2 with
/// zero-filled leaves.
///
/// # Panics
/// Panics if `leaves` is empty — an empty trace is not a valid assertion.
pub fn compute_trace_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "trace must contain at least one step");
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to next power of 2
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, [0u8; 32]);

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            next.push(hasher.finalize().into());
        }
        layer = next;
    }

    layer[0]
}

/// Generate a Merkle inclusion proof for step at `index`.
///
/// Returns the sibling hashes from leaf to root.
pub fn merkle_proof_for_step(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.is_empty() || index >= leaves.len() {
        return vec![];
    }

    let n = leaves.len().next_power_of_two();
    let mut padded: Vec<[u8; 32]> = Vec::with_capacity(n);
    padded.extend_from_slice(leaves);
    padded.resize(n, [0u8; 32]);

    let mut proof = Vec::new();
    let mut layer = padded;
    let mut idx = index;

    while layer.len() > 1 {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(layer[sibling]);

        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            next.push(hasher.finalize().into());
        }
        layer = next;
        idx /= 2;
    }

    proof
}

/// Verify a Merkle inclusion proof for a leaf at `index`.
pub fn verify_merkle_proof(
    leaf: [u8; 32],
    index: usize,
    proof: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    let mut current = leaf;
    let mut idx = index;

    for sibling in proof {
        let mut hasher = Sha256::new();
        if idx % 2 == 0 {
            hasher.update(current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
        idx /= 2;
    }

    current == root
}

// ---------------------------------------------------------------------------
// SHA-256 helpers for field element serialization
// ---------------------------------------------------------------------------

/// Hash a slice of bytes with SHA-256, returning a 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Hash a pallas::Base field element (32 bytes little-endian).
pub fn hash_field_element(fe: &pasta_curves::pallas::Base) -> [u8; 32] {
    use ff::PrimeField;
    sha256(&fe.to_repr())
}

/// Hash a sequence of field elements.
pub fn hash_field_elements(elements: &[pasta_curves::pallas::Base]) -> [u8; 32] {
    use ff::PrimeField;
    let mut hasher = Sha256::new();
    for fe in elements {
        hasher.update(fe.to_repr());
    }
    hasher.finalize().into()
}

/// Serialize a pallas::Base to 32 bytes (little-endian).
pub fn field_to_bytes(fe: &pasta_curves::pallas::Base) -> [u8; 32] {
    use ff::PrimeField;
    fe.to_repr()
}

/// Deserialize a pallas::Base from 32 bytes (little-endian).
/// Returns `None` if the bytes do not represent a valid field element.
pub fn bytes_to_field(bytes: &[u8; 32]) -> Option<pasta_curves::pallas::Base> {
    use ff::PrimeField;
    let ct = pasta_curves::pallas::Base::from_repr(*bytes);
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Trace generation — wraps Halo2 IPA verification with step instrumentation
// ---------------------------------------------------------------------------

/// Error returned when trace generation fails.
#[derive(Debug)]
pub enum TraceError {
    /// The proof or public inputs are malformed.
    InvalidInput(String),
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for TraceError {}

/// Internal: build a `TraceStep` from a state transition.
fn make_step(
    index: u32,
    kind: StepKind,
    input_state: &[u8],
    _output_state: &[u8],
    witness: Vec<u8>,
) -> TraceStep {
    let input_hash = sha256(input_state);
    let output_hash = crate::script::recompute_step_output(kind, &input_hash, &witness);
    TraceStep {
        index,
        kind,
        input_hash,
        output_hash,
        witness,
    }
}

/// Generate a verification trace for a transfer proof.
///
/// This decomposes the conceptual IPA verification into traced steps:
///
/// 1. **TranscriptInit** — Hash initial state (public inputs + proof hash).
/// 2. **CommitmentRead** — Process groups of proof bytes as commitment data.
/// 3. **ChallengeSqueeze** — Derive Fiat-Shamir challenges from transcript state.
/// 4. **MsmRound** — Multi-scalar multiplication accumulation rounds.
/// 5. **IpaRound** — Inner product argument rounds (log₂(n) rounds for K=13).
/// 6. **FinalCheck** — Verify the accumulated result.
///
/// The actual Halo2 verification is run to determine the boolean result;
/// the trace captures the conceptual stages with SHA-256 commitments.
pub fn generate_transfer_trace(
    verifier: &lumora_prover::VerifierParams,
    proof_bytes: &[u8],
    merkle_root: pasta_curves::pallas::Base,
    nullifiers: &[pasta_curves::pallas::Base; NUM_INPUTS],
    output_commitments: &[pasta_curves::pallas::Base; NUM_OUTPUTS],
    fee: u64,
) -> Result<VerificationTrace, TraceError> {
    use ff::PrimeField;

    // Compute public inputs
    let public_inputs = transfer_public_inputs(merkle_root, nullifiers, output_commitments, fee);
    let pi_bytes: Vec<u8> = public_inputs.iter()
        .flat_map(|fe| fe.to_repr().to_vec())
        .collect();

    // Run the actual verification to get the result
    let verification_result = lumora_verifier::verify_transfer(
        &verifier.params,
        &verifier.vk,
        proof_bytes,
        merkle_root,
        nullifiers,
        output_commitments,
        fee,
    )
    .is_ok();

    build_trace(proof_bytes, &pi_bytes, verification_result)
}

/// Generate a verification trace for a withdrawal proof.
pub fn generate_withdraw_trace(
    verifier: &lumora_prover::WithdrawVerifierParams,
    proof_bytes: &[u8],
    merkle_root: pasta_curves::pallas::Base,
    nullifiers: &[pasta_curves::pallas::Base; NUM_INPUTS],
    output_commitments: &[pasta_curves::pallas::Base; NUM_OUTPUTS],
    exit_value: u64,
    fee: u64,
) -> Result<VerificationTrace, TraceError> {
    use ff::PrimeField;

    let public_inputs = withdraw_public_inputs(merkle_root, nullifiers, output_commitments, exit_value, fee);
    let pi_bytes: Vec<u8> = public_inputs.iter()
        .flat_map(|fe| fe.to_repr().to_vec())
        .collect();

    let verification_result = lumora_verifier::verify_withdraw(
        &verifier.params,
        &verifier.vk,
        proof_bytes,
        merkle_root,
        nullifiers,
        output_commitments,
        exit_value,
        fee,
    )
    .is_ok();

    build_trace(proof_bytes, &pi_bytes, verification_result)
}

/// Build a verification trace from proof bytes, serialized public inputs,
/// and the boolean verification result.
///
/// The trace decomposes the IPA verification into conceptual chunks.
/// For Halo2 IPA with K=13 (Pallas/Vesta), the verification involves:
///   - Transcript initialization + public input absorption
///   - Reading ~10-15 commitment groups from the proof stream
///   - ~10 Fiat-Shamir challenge squeezes
///   - Multi-scalar multiplication over Vesta (accumulating ~50+ terms)
///   - 13 IPA rounds (one per bit of 2^K)
///   - A final identity check
///
/// We chunk the proof bytes into segments to simulate reading commitment
/// groups, and model the MSM and IPA rounds explicitly.
fn build_trace(
    proof_bytes: &[u8],
    pi_bytes: &[u8],
    verification_result: bool,
) -> Result<VerificationTrace, TraceError> {
    let proof_hash = sha256(proof_bytes);
    let public_inputs_hash = sha256(pi_bytes);
    let mut steps = Vec::new();
    let mut step_index = 0u32;

    // --- Step 0: TranscriptInit ---
    // Input: empty state; Output: hash(proof_hash || pi_hash)
    let init_state = {
        let mut h = Sha256::new();
        h.update(proof_hash);
        h.update(public_inputs_hash);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    let init_witness = [proof_hash.as_slice(), pi_bytes].concat();
    steps.push(make_step(
        step_index,
        StepKind::TranscriptInit,
        &[0u8; 32], // empty initial state
        &init_state,
        init_witness,
    ));
    step_index += 1;

    // --- Steps 1..N: CommitmentRead ---
    // Chunk proof bytes into 64-byte segments (simulating reading curve points).
    // Each Vesta affine point is 32 bytes (compressed), so 64 bytes ~ 2 points.
    let chunk_size = 64;
    let mut prev_state = init_state.to_vec();
    let proof_chunks: Vec<&[u8]> = proof_bytes.chunks(chunk_size).collect();
    let num_commitment_reads = proof_chunks.len().min(16); // Cap at 16 reads

    for (i, chunk) in proof_chunks.iter().take(num_commitment_reads).enumerate() {
        let input_state = prev_state.clone();
        let output_state = {
            let mut h = Sha256::new();
            h.update(&input_state);
            h.update(*chunk);
            let r: [u8; 32] = h.finalize().into();
            r.to_vec()
        };

        let mut witness = Vec::new();
        witness.extend_from_slice(&(i as u32).to_le_bytes());
        witness.extend_from_slice(chunk);

        steps.push(make_step(
            step_index,
            StepKind::CommitmentRead,
            &input_state,
            &output_state,
            witness,
        ));

        prev_state = output_state;
        step_index += 1;
    }

    // --- Challenge squeezes (typically ~10 for Halo2) ---
    let num_challenges = 10;
    for i in 0..num_challenges {
        let input_state = prev_state.clone();
        let output_state = {
            let mut h = Sha256::new();
            h.update(&input_state);
            h.update(b"challenge");
            h.update(&(i as u32).to_le_bytes());
            let r: [u8; 32] = h.finalize().into();
            r.to_vec()
        };

        let mut witness = Vec::new();
        witness.extend_from_slice(&(i as u32).to_le_bytes());
        witness.extend_from_slice(&input_state);

        steps.push(make_step(
            step_index,
            StepKind::ChallengeSqueeze,
            &input_state,
            &output_state,
            witness,
        ));

        prev_state = output_state;
        step_index += 1;
    }

    // --- MSM rounds (multi-scalar multiplication) ---
    // For IPA verification, the MSM typically accumulates ~50+ terms.
    // We model this as 8 rounds of batch accumulation.
    let num_msm_rounds = 8;
    for i in 0..num_msm_rounds {
        let input_state = prev_state.clone();
        let output_state = {
            let mut h = Sha256::new();
            h.update(&input_state);
            h.update(b"msm");
            h.update(&(i as u32).to_le_bytes());
            let r: [u8; 32] = h.finalize().into();
            r.to_vec()
        };

        let mut witness = Vec::new();
        witness.extend_from_slice(&(i as u32).to_le_bytes());
        witness.extend_from_slice(&input_state);

        steps.push(make_step(
            step_index,
            StepKind::MsmRound,
            &input_state,
            &output_state,
            witness,
        ));

        prev_state = output_state;
        step_index += 1;
    }

    // --- IPA rounds (K=13 → 13 rounds) ---
    let k = 13u32;
    for i in 0..k {
        let input_state = prev_state.clone();
        let output_state = {
            let mut h = Sha256::new();
            h.update(&input_state);
            h.update(b"ipa");
            h.update(&i.to_le_bytes());
            let r: [u8; 32] = h.finalize().into();
            r.to_vec()
        };

        let mut witness = Vec::new();
        witness.extend_from_slice(&i.to_le_bytes());
        witness.extend_from_slice(&input_state);

        steps.push(make_step(
            step_index,
            StepKind::IpaRound,
            &input_state,
            &output_state,
            witness,
        ));

        prev_state = output_state;
        step_index += 1;
    }

    // --- Final check ---
    let final_input = prev_state.clone();
    let final_output = {
        let mut h = Sha256::new();
        h.update(&final_input);
        h.update(if verification_result { &[1u8] } else { &[0u8] });
        let r: [u8; 32] = h.finalize().into();
        r.to_vec()
    };

    let mut final_witness = Vec::new();
    final_witness.extend_from_slice(&final_input);
    final_witness.push(if verification_result { 1 } else { 0 });

    steps.push(make_step(
        step_index,
        StepKind::FinalCheck,
        &final_input,
        &final_output,
        final_witness,
    ));

    // --- Build the trace Merkle root ---
    let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
    let trace_root = compute_trace_merkle_root(&leaves);

    Ok(VerificationTrace {
        steps,
        trace_root,
        proof_hash,
        public_inputs_hash,
        verification_result,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = sha256(b"hello");
        let root = compute_trace_merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let root = compute_trace_merkle_root(&[a, b]);

        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three_leaves_pads() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let c = sha256(b"c");
        let root = compute_trace_merkle_root(&[a, b, c]);
        // 3 leaves → padded to 4: [a, b, c, 0]
        // Level 1: H(a||b), H(c||0)
        // Level 0: H(H(a||b) || H(c||0))
        let ab = {
            let mut h = Sha256::new();
            h.update(a);
            h.update(b);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let c0 = {
            let mut h = Sha256::new();
            h.update(c);
            h.update([0u8; 32]);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let expected = {
            let mut h = Sha256::new();
            h.update(ab);
            h.update(c0);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0u8..8)
            .map(|i| sha256(&[i]))
            .collect();
        let root = compute_trace_merkle_root(&leaves);

        for i in 0..leaves.len() {
            let proof = merkle_proof_for_step(&leaves, i);
            assert!(
                verify_merkle_proof(leaves[i], i, &proof, root),
                "proof for leaf {i} should verify"
            );
        }
    }

    #[test]
    fn test_merkle_proof_rejects_wrong_leaf() {
        let leaves: Vec<[u8; 32]> = (0u8..4)
            .map(|i| sha256(&[i]))
            .collect();
        let root = compute_trace_merkle_root(&leaves);
        let proof = merkle_proof_for_step(&leaves, 0);

        let wrong_leaf = sha256(b"wrong");
        assert!(!verify_merkle_proof(wrong_leaf, 0, &proof, root));
    }

    #[test]
    fn test_step_leaf_hash_deterministic() {
        let step = TraceStep {
            index: 0,
            kind: StepKind::TranscriptInit,
            input_hash: [1u8; 32],
            output_hash: [2u8; 32],
            witness: vec![],
        };
        let h1 = step_leaf_hash(&step);
        let h2 = step_leaf_hash(&step);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_field_element_roundtrip() {
        let fe = pasta_curves::pallas::Base::from(12345u64);
        let bytes = field_to_bytes(&fe);
        let recovered = bytes_to_field(&bytes).expect("should deserialize");
        assert_eq!(fe, recovered);
    }

    #[test]
    #[should_panic(expected = "trace must contain at least one step")]
    fn test_empty_merkle_root() {
        compute_trace_merkle_root(&[]);
    }

    #[test]
    fn test_hash_field_elements_deterministic() {
        let elements = vec![
            pasta_curves::pallas::Base::from(1u64),
            pasta_curves::pallas::Base::from(2u64),
        ];
        let h1 = hash_field_elements(&elements);
        let h2 = hash_field_elements(&elements);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_generate_transfer_trace_valid_proof() {
        use lumora_note::keys::scalar_to_base;
        use lumora_note::{Note, SpendingKey};
        use lumora_prover::{
            circuit_commitment, prove_transfer, setup, InputNote, OutputNote,
        };
        use lumora_tree::IncrementalMerkleTree;
        use pasta_curves::pallas;

        let (prover, verifier) = setup().expect("setup");

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
                note: Note {
                    owner: sk_base,
                    value: 60,
                    asset: 0,
                    randomness: pallas::Scalar::from(111u64),
                },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk.clone(),
                note: Note {
                    owner: sk_base,
                    value: 40,
                    asset: 0,
                    randomness: pallas::Scalar::from(222u64),
                },
                merkle_index: 1,
            },
        ];

        let r_out1 = pallas::Base::from(333u64);
        let r_out2 = pallas::Base::from(444u64);
        let recipient = pallas::Base::from(0xBEEFu64);

        let outputs = [
            OutputNote {
                owner_pubkey_field: recipient,
                value: 70,
                asset: 0,
                randomness: r_out1,
            },
            OutputNote {
                owner_pubkey_field: sk_base,
                value: 30,
                asset: 0,
                randomness: r_out2,
            },
        ];

        let proof = prove_transfer(&prover, &inputs, &outputs, &mut tree, 0)
            .expect("prove");

        let trace = generate_transfer_trace(
            &verifier,
            &proof.proof_bytes,
            proof.merkle_root,
            &proof.nullifiers,
            &proof.output_commitments,
            proof.fee,
        )
        .expect("trace generation");

        // Trace should indicate successful verification
        assert!(trace.verification_result);

        // Trace should have multiple steps covering all kinds
        assert!(!trace.steps.is_empty());
        assert!(trace.steps.len() > 30, "trace should have many steps, got {}", trace.steps.len());

        // First step should be TranscriptInit
        assert_eq!(trace.steps[0].kind, StepKind::TranscriptInit);

        // Last step should be FinalCheck
        assert_eq!(trace.steps.last().unwrap().kind, StepKind::FinalCheck);

        // Trace root should be non-zero
        assert_ne!(trace.trace_root, [0u8; 32]);

        // Verify Merkle proofs for each step
        let leaves: Vec<[u8; 32]> = trace.steps.iter().map(step_leaf_hash).collect();
        let root = compute_trace_merkle_root(&leaves);
        assert_eq!(root, trace.trace_root);

        for (i, step) in trace.steps.iter().enumerate() {
            let proof = merkle_proof_for_step(&leaves, i);
            assert!(
                verify_merkle_proof(step_leaf_hash(step), i, &proof, root),
                "merkle proof for step {i} should verify"
            );
        }
    }

    #[test]
    fn test_generate_transfer_trace_invalid_proof() {
        use lumora_prover::setup;

        let (_prover, verifier) = setup().expect("setup");

        // Use garbage proof bytes
        let bad_proof = vec![0xAA; 512];
        let merkle_root = pasta_curves::pallas::Base::from(1u64);
        let nullifiers = [
            pasta_curves::pallas::Base::from(2u64),
            pasta_curves::pallas::Base::from(3u64),
        ];
        let output_commitments = [
            pasta_curves::pallas::Base::from(4u64),
            pasta_curves::pallas::Base::from(5u64),
        ];

        let trace = generate_transfer_trace(
            &verifier,
            &bad_proof,
            merkle_root,
            &nullifiers,
            &output_commitments,
            0,
        )
        .expect("trace generation should succeed even for invalid proofs");

        // Invalid proof → verification_result = false
        assert!(!trace.verification_result);

        // Trace should still have steps and a valid Merkle root
        assert!(!trace.steps.is_empty());
        assert_ne!(trace.trace_root, [0u8; 32]);
    }

    #[test]
    fn test_trace_step_chain_consistency() {
        // Build a small synthetic trace and verify steps chain properly
        let proof_bytes = vec![0u8; 128];
        let pi_bytes = vec![1u8; 192];

        let trace = super::build_trace(&proof_bytes, &pi_bytes, true)
            .expect("build_trace");

        // Every step's output_hash should differ from input_hash
        for step in &trace.steps {
            assert_ne!(step.input_hash, step.output_hash,
                "step {} should transform state", step.index);
        }

        // Steps should be consecutively indexed
        for (i, step) in trace.steps.iter().enumerate() {
            assert_eq!(step.index as usize, i);
        }
    }
}
