//! #53 — Proof aggregation foundation.
//!
//! Provides the structural scaffolding for aggregating multiple Halo2 IPA
//! proofs into a single proof bundle. The module provides:
//!
//! - **Blake2b digest accumulation** — each pushed proof is absorbed into a
//!   running Blake2b-256 hash, producing a cryptographic commitment to the
//!   entire bundle.
//! - **Batch verification** via [`verify_and_aggregate`] — runs Halo2's
//!   `BatchVerifier` over the collected proofs and returns a verified result.

use halo2_proofs::{
    plonk::{self, BatchVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{pallas, vesta};
use serde::{Deserialize, Serialize};

/// Opaque wrapper for a serialised Halo2 IPA proof.
#[derive(Clone, Debug)]
pub struct SerializedProof {
    pub bytes: Vec<u8>,
    pub public_inputs: Vec<pallas::Base>,
}

/// An aggregation bundle — collects individual proofs for later aggregation.
#[derive(Clone, Debug)]
pub struct AggregationBundle {
    /// Individual proofs in submission order.
    proofs: Vec<SerializedProof>,
    /// Running Blake2b-256 state (we re-hash from scratch on push for
    /// simplicity; could be incremental with a streaming hasher).
    digest: [u8; 32],
}

impl Default for AggregationBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl AggregationBundle {
    pub fn new() -> Self {
        Self {
            proofs: Vec::new(),
            digest: [0u8; 32],
        }
    }

    /// Add a proof to the bundle, updating the Blake2b digest.
    pub fn push(&mut self, proof: SerializedProof) {
        self.proofs.push(proof);
        self.recompute_digest();
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn proofs(&self) -> &[SerializedProof] {
        &self.proofs
    }

    /// Recompute the Blake2b-256 digest over all proof bytes in order.
    fn recompute_digest(&mut self) {
        use blake2b_simd::Params;
        let mut state = Params::new().hash_length(32).to_state();
        for p in &self.proofs {
            state.update(&(p.bytes.len() as u64).to_le_bytes());
            state.update(&p.bytes);
        }
        self.digest.copy_from_slice(state.finalize().as_bytes());
    }
}

/// Strategy for how proofs are grouped before aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationStrategy {
    /// Aggregate all proofs in a single pass (simplest).
    Flat,
    /// Binary-tree aggregation — aggregate pairs recursively.
    BinaryTree,
}

/// Configuration for the aggregation pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// Maximum proofs per bundle before forced aggregation.
    pub max_bundle_size: usize,
    /// Strategy for grouping.
    pub strategy: AggregationStrategy,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            max_bundle_size: 64,
            strategy: AggregationStrategy::Flat,
        }
    }
}

/// Result of an aggregation step.
#[derive(Clone, Debug)]
pub struct AggregationResult {
    /// Blake2b-256 digest covering all aggregated proofs.
    pub aggregated_proof: Vec<u8>,
    /// Number of individual proofs that were aggregated.
    pub proof_count: usize,
    /// Whether batch verification succeeded (only `true` when
    /// [`verify_and_aggregate`] was used).
    pub verified: bool,
    /// Per-proof verification results; populated when a batch fails and
    /// individual re-verification is performed.
    pub individual_results: Vec<bool>,
}

/// Aggregate a bundle — returns the cryptographic digest and count.
///
/// This does **not** verify the proofs. Use [`verify_and_aggregate`] when
/// you also need batch verification.
pub fn aggregate(bundle: &AggregationBundle) -> AggregationResult {
    AggregationResult {
        aggregated_proof: bundle.digest().to_vec(),
        proof_count: bundle.len(),
        verified: false,
        individual_results: Vec::new(),
    }
}

/// Verify every proof in the bundle via Halo2 `BatchVerifier`, then return
/// the aggregation result.
///
/// If batch verification fails, falls back to individual verification so the
/// caller can identify which proof(s) are invalid.
pub fn verify_and_aggregate(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    bundle: &AggregationBundle,
) -> AggregationResult {
    let mut batch = BatchVerifier::new();
    for p in bundle.proofs() {
        batch.add_proof(
            vec![vec![p.public_inputs.clone()]],
            p.bytes.clone(),
        );
    }

    let batch_ok = batch.finalize(params, vk);

    let individual_results = if batch_ok {
        Vec::new()
    } else {
        // Re-verify individually to pinpoint failures.
        bundle
            .proofs()
            .iter()
            .map(|p| {
                let strategy = plonk::SingleVerifier::new(params);
                let mut transcript =
                    Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&p.bytes[..]);
                plonk::verify_proof(
                    params,
                    vk,
                    strategy,
                    &[&[&p.public_inputs]],
                    &mut transcript,
                )
                .is_ok()
            })
            .collect()
    };

    AggregationResult {
        aggregated_proof: bundle.digest().to_vec(),
        proof_count: bundle.len(),
        verified: batch_ok,
        individual_results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_proof(byte: u8) -> SerializedProof {
        SerializedProof {
            bytes: vec![byte; 64],
            public_inputs: vec![pallas::Base::zero()],
        }
    }

    #[test]
    fn bundle_accumulates() {
        let mut bundle = AggregationBundle::new();
        bundle.push(dummy_proof(0xAA));
        bundle.push(dummy_proof(0xBB));
        assert_eq!(bundle.len(), 2);
        assert!(!bundle.is_empty());
    }

    #[test]
    fn digest_is_blake2b() {
        let mut b1 = AggregationBundle::new();
        b1.push(dummy_proof(0xAA));
        b1.push(dummy_proof(0xBB));

        let mut b2 = AggregationBundle::new();
        b2.push(dummy_proof(0xAA));
        b2.push(dummy_proof(0xBB));

        // Same inputs → same digest (deterministic).
        assert_eq!(b1.digest(), b2.digest());

        // Different order → different digest.
        let mut b3 = AggregationBundle::new();
        b3.push(dummy_proof(0xBB));
        b3.push(dummy_proof(0xAA));
        assert_ne!(b1.digest(), b3.digest());
    }

    #[test]
    fn aggregate_returns_count() {
        let mut bundle = AggregationBundle::new();
        for i in 0..5u8 {
            bundle.push(dummy_proof(i));
        }
        let result = aggregate(&bundle);
        assert_eq!(result.proof_count, 5);
        assert_eq!(result.aggregated_proof.len(), 32);
        assert!(!result.verified);
    }

    #[test]
    fn empty_bundle() {
        let bundle = AggregationBundle::new();
        assert!(bundle.is_empty());
        assert_eq!(bundle.len(), 0);
        let result = aggregate(&bundle);
        assert_eq!(result.proof_count, 0);
    }

    #[test]
    fn single_proof_bundle() {
        let mut bundle = AggregationBundle::new();
        bundle.push(dummy_proof(0xFF));
        assert_eq!(bundle.len(), 1);
        let digest = *bundle.digest();
        // Digest should be non-zero.
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn config_defaults() {
        let cfg = AggregationConfig::default();
        assert_eq!(cfg.max_bundle_size, 64);
        assert_eq!(cfg.strategy, AggregationStrategy::Flat);
    }

    #[test]
    fn strategy_serializable() {
        // Verify AggregationStrategy variants are distinct.
        assert_ne!(AggregationStrategy::Flat, AggregationStrategy::BinaryTree);
    }
}
