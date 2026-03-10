//! The Note type — a private UTXO.
//!
//! A note is the fundamental unit of private value in LUMORA.
//! It is **never stored on-chain**; only its commitment is.

use ff::Field;
use pasta_curves::pallas;
use rand_core::RngCore;
use serde::{Serialize, Deserialize};

use crate::keys::SpendingKey;

/// Identifies the token type. `0` = native BTC (or wrapped BTC on the rollup).
pub type AssetId = u64;

/// The native asset (BTC / wrapped BTC).
pub const NATIVE_ASSET: AssetId = 0;

/// A private note representing hidden value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// The owner's public key (x-coordinate, as Fp).
    #[serde(with = "lumora_primitives::serde_field::base")]
    pub owner: pallas::Base,
    /// The hidden value.
    pub value: u64,
    /// Token type.
    pub asset: AssetId,
    /// Blinding factor for the Pedersen commitment.
    #[serde(with = "lumora_primitives::serde_field::scalar")]
    pub randomness: pallas::Scalar,
}

impl Note {
    /// Create a new note owned by the given spending key.
    pub fn new(owner: &SpendingKey, value: u64, asset: AssetId, rng: impl RngCore) -> Self {
        Self {
            owner: owner.public_key_field(),
            value,
            asset,
            randomness: pallas::Scalar::random(rng),
        }
    }

    /// Create a note with explicit randomness (for testing / deterministic replay).
    pub fn with_randomness(
        owner: &SpendingKey,
        value: u64,
        asset: AssetId,
        randomness: pallas::Scalar,
    ) -> Self {
        Self {
            owner: owner.public_key_field(),
            value,
            asset,
            randomness,
        }
    }
}
