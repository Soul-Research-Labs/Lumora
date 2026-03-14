//! IPA verification trace model and generation.
//!
//! Decomposes Halo2 IPA verification into discrete steps, each producing
//! a SHA-256 commitment over its intermediate state. The full trace is
//! committed via a Merkle tree; only a disputed step needs on-chain
//! verification in Bitcoin Script.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
pub fn compute_trace_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
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
    if leaves.is_empty() {
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
    fn test_empty_merkle_root() {
        let root = compute_trace_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
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
}
