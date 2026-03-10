//! #54 — Recursive proving interface.
//!
//! Defines the trait and infrastructure for recursive proof composition in
//! Halo2 IPA. Two concrete implementations are provided:
//!
//! - [`IdentityRecursiveProver`] — pass-through for testing.
//! - [`VerifyingRecursiveProver`] — verifies the inner proof with a real
//!   Halo2 `verify_proof` call before passing it forward. This ensures
//!   every step in a proof chain is cryptographically validated.

use halo2_proofs::{
    plonk::{self, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{pallas, vesta};

/// Errors from recursive proving.
#[derive(Debug)]
pub enum RecursiveError {
    /// Inner proof verification failed.
    InnerVerifyFailed,
    /// Proof generation failed.
    ProveFailed(String),
    /// Configuration error.
    Config(String),
}

impl std::fmt::Display for RecursiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InnerVerifyFailed => write!(f, "inner proof verification failed"),
            Self::ProveFailed(e) => write!(f, "recursive proving failed: {e}"),
            Self::Config(e) => write!(f, "recursive config error: {e}"),
        }
    }
}

impl std::error::Error for RecursiveError {}

/// A pair of (proof_bytes, public_inputs) representing a single proof step.
#[derive(Clone, Debug)]
pub struct ProofStep {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<pallas::Base>,
}

/// Trait for recursive proof composition.
///
/// Implementors wrap an inner proof inside a new proof that attests to the
/// inner proof's validity. The resulting proof can itself be fed as input
/// to another recursion step.
pub trait RecursiveProver {
    /// Compose a single recursion step: verify `inner` inside a new circuit
    /// and return the outer proof.
    fn recurse(&self, inner: &ProofStep) -> Result<ProofStep, RecursiveError>;

    /// Chain N recursion steps starting from `base`.
    fn chain(&self, base: &ProofStep, depth: usize) -> Result<ProofStep, RecursiveError> {
        let mut current = base.clone();
        for _ in 0..depth {
            current = self.recurse(&current)?;
        }
        Ok(current)
    }
}

/// Placeholder recursive prover — passes through the inner proof unchanged.
///
/// Useful in tests where you want the chain/recurse API but don't need
/// real verification.
pub struct IdentityRecursiveProver;

impl RecursiveProver for IdentityRecursiveProver {
    fn recurse(&self, inner: &ProofStep) -> Result<ProofStep, RecursiveError> {
        Ok(inner.clone())
    }
}

/// Recursive prover that verifies the inner proof using a real Halo2 IPA
/// `verify_proof` call before forwarding it.
///
/// Each recursion step guarantees that the inner proof is valid against the
/// supplied verifying key. The outer proof is the verified inner proof
/// itself (i.e. proof data is preserved, but validity is confirmed).
pub struct VerifyingRecursiveProver {
    params: Params<vesta::Affine>,
    vk: VerifyingKey<vesta::Affine>,
}

impl VerifyingRecursiveProver {
    pub fn new(params: Params<vesta::Affine>, vk: VerifyingKey<vesta::Affine>) -> Self {
        Self { params, vk }
    }
}

impl RecursiveProver for VerifyingRecursiveProver {
    fn recurse(&self, inner: &ProofStep) -> Result<ProofStep, RecursiveError> {
        let strategy = plonk::SingleVerifier::new(&self.params);
        let mut transcript =
            Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&inner.proof_bytes[..]);
        plonk::verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &[&[&inner.public_inputs]],
            &mut transcript,
        )
        .map_err(|_| RecursiveError::InnerVerifyFailed)?;

        // Inner proof is valid — forward it as the outer step.
        Ok(inner.clone())
    }
}

/// Configuration for a recursive proving pipeline.
#[derive(Clone, Debug)]
pub struct RecursiveConfig {
    /// Maximum recursion depth allowed.
    pub max_depth: usize,
    /// Circuit size parameter for the verifier circuit.
    pub verifier_k: u32,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            max_depth: 8,
            verifier_k: 15,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_prover_passthrough() {
        let prover = IdentityRecursiveProver;
        let step = ProofStep {
            proof_bytes: vec![1, 2, 3],
            public_inputs: vec![pallas::Base::zero()],
        };
        let result = prover.recurse(&step).unwrap();
        assert_eq!(result.proof_bytes, step.proof_bytes);
    }

    #[test]
    fn chain_identity() {
        let prover = IdentityRecursiveProver;
        let step = ProofStep {
            proof_bytes: vec![42],
            public_inputs: vec![],
        };
        let result = prover.chain(&step, 5).unwrap();
        assert_eq!(result.proof_bytes, vec![42]);
    }

    #[test]
    fn recursive_config_defaults() {
        let cfg = RecursiveConfig::default();
        assert_eq!(cfg.max_depth, 8);
        assert_eq!(cfg.verifier_k, 15);
    }

    #[test]
    fn recursive_error_display() {
        assert_eq!(
            RecursiveError::InnerVerifyFailed.to_string(),
            "inner proof verification failed"
        );
        assert!(RecursiveError::ProveFailed("oops".into())
            .to_string()
            .contains("oops"));
        assert!(RecursiveError::Config("bad".into())
            .to_string()
            .contains("bad"));
    }

    #[test]
    fn identity_chain_zero_depth() {
        let prover = IdentityRecursiveProver;
        let step = ProofStep {
            proof_bytes: vec![1, 2, 3],
            public_inputs: vec![pallas::Base::zero()],
        };
        let result = prover.chain(&step, 0).unwrap();
        assert_eq!(result.proof_bytes, step.proof_bytes);
    }
}
