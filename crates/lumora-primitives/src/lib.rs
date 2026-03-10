//! LUMORA Primitives — core cryptographic building blocks.
//!
//! Provides:
//! - Pallas/Vesta curve re-exports and helpers
//! - Poseidon hash (ZK-friendly, used for Merkle tree + nullifiers)
//! - Pedersen commitment on Pallas curve: `C = v·G + r·H`

pub mod envelope;
pub mod pedersen;
pub mod poseidon;
pub mod serde_field;

// Re-export commonly used types so downstream crates don't juggle curve crates directly.
pub use pasta_curves::pallas;
pub use pasta_curves::vesta;

/// The base field of the Pallas curve (= scalar field of Vesta).
/// This is the field we do most arithmetic in inside Halo2 circuits.
pub type Fp = pasta_curves::pallas::Base;

/// The scalar field of the Pallas curve.
pub type Fq = pasta_curves::pallas::Scalar;

/// A point on the Pallas curve (projective coordinates).
pub type PallasPoint = pasta_curves::pallas::Point;

/// Affine representation of a Pallas point.
pub type PallasAffine = pasta_curves::pallas::Affine;
