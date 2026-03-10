//! Note commitment — a Poseidon-based commitment to a note's contents.
//!
//! The commitment is computed as:
//!
//!   commitment = PoseidonHash(PoseidonHash(PoseidonHash(owner, value), asset), randomness)
//!
//! This binds the owner, value, and asset type into a single field element,
//! blinded by the randomness. The Poseidon-based scheme works entirely in the
//! base field, making it efficient inside Halo2 circuits.

use pasta_curves::pallas;

use lumora_primitives::poseidon;

use crate::note::Note;

/// A commitment to a note, stored in the on-chain Merkle tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteCommitment(pub pallas::Base);

impl NoteCommitment {
    /// Compute the commitment for a note.
    ///
    /// `commitment = PoseidonHash(PoseidonHash(PoseidonHash(owner, value), asset), randomness)`
    ///
    /// Note: `owner` is the spending key mapped to the base field (the circuit uses sk
    /// directly as the owner identifier for simplicity and security).
    pub fn from_note(note: &Note) -> Self {
        let value_field = pallas::Base::from(note.value);
        let asset_field = pallas::Base::from(note.asset);

        // Convert randomness (Fq scalar) to base field (Fp) for Poseidon hashing.
        let randomness_base = scalar_to_base(note.randomness);

        // Three-step hash to absorb four elements with width-3 Poseidon (rate 2).
        let inner = poseidon::hash_two(note.owner, value_field);
        let content = poseidon::hash_two(inner, asset_field);
        let commitment = poseidon::hash_two(content, randomness_base);

        Self(commitment)
    }

    /// Compute commitment from raw field elements (matching circuit computation exactly).
    pub fn from_parts(
        owner: pallas::Base,
        value: u64,
        asset: u64,
        randomness: pallas::Base,
    ) -> Self {
        let inner = poseidon::hash_two(owner, pallas::Base::from(value));
        let content = poseidon::hash_two(inner, pallas::Base::from(asset));
        let commitment = poseidon::hash_two(content, randomness);
        Self(commitment)
    }

    /// The raw field element.
    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

/// Convert a Pallas scalar to a Pallas base field element.
/// Delegates to `keys::scalar_to_base` for a single canonical implementation.
pub(crate) fn scalar_to_base(s: pallas::Scalar) -> pallas::Base {
    crate::keys::scalar_to_base(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use crate::note::{Note, NATIVE_ASSET};
    use proptest::prelude::*;

    #[test]
    fn commitment_deterministic() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let r = pallas::Scalar::from(999u64);
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, r);
        let c1 = NoteCommitment::from_note(&note);
        let c2 = NoteCommitment::from_note(&note);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_values_different_commitments() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let r = pallas::Scalar::from(999u64);
        let n1 = Note::with_randomness(&sk, 100, NATIVE_ASSET, r);
        let n2 = Note::with_randomness(&sk, 200, NATIVE_ASSET, r);
        assert_ne!(NoteCommitment::from_note(&n1), NoteCommitment::from_note(&n2));
    }

    #[test]
    fn different_randomness_different_commitments() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let n1 = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let n2 = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(2u64));
        assert_ne!(NoteCommitment::from_note(&n1), NoteCommitment::from_note(&n2));
    }

    #[test]
    fn from_parts_matches_from_note() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let r = pallas::Scalar::from(999u64);
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, r);
        let c1 = NoteCommitment::from_note(&note);
        let c2 = NoteCommitment::from_parts(
            note.owner,
            note.value,
            note.asset,
            scalar_to_base(note.randomness),
        );
        assert_eq!(c1, c2);
    }

    // -- Property-based tests --

    proptest! {
        /// Commitment is deterministic for any key/value/randomness.
        #[test]
        fn prop_commitment_deterministic(key in 1u64..u64::MAX, val in 0u64..u64::MAX, r in 1u64..u64::MAX) {
            let sk = SpendingKey::from_scalar(pallas::Scalar::from(key));
            let note = Note::with_randomness(&sk, val, NATIVE_ASSET, pallas::Scalar::from(r));
            prop_assert_eq!(NoteCommitment::from_note(&note), NoteCommitment::from_note(&note));
        }

        /// Different values produce different commitments (binding property).
        #[test]
        fn prop_different_values_different_commitments(key in 1u64..u64::MAX, v1 in 0u64..u64::MAX, v2 in 0u64..u64::MAX, r in 1u64..u64::MAX) {
            prop_assume!(v1 != v2);
            let sk = SpendingKey::from_scalar(pallas::Scalar::from(key));
            let n1 = Note::with_randomness(&sk, v1, NATIVE_ASSET, pallas::Scalar::from(r));
            let n2 = Note::with_randomness(&sk, v2, NATIVE_ASSET, pallas::Scalar::from(r));
            prop_assert_ne!(NoteCommitment::from_note(&n1), NoteCommitment::from_note(&n2));
        }

        /// from_parts matches from_note for all inputs.
        #[test]
        fn prop_from_parts_matches(key in 1u64..u64::MAX, val in 0u64..u64::MAX, asset in 0u64..10u64, r in 1u64..u64::MAX) {
            let sk = SpendingKey::from_scalar(pallas::Scalar::from(key));
            let note = Note::with_randomness(&sk, val, asset, pallas::Scalar::from(r));
            let c1 = NoteCommitment::from_note(&note);
            let c2 = NoteCommitment::from_parts(
                note.owner, note.value, note.asset,
                scalar_to_base(note.randomness),
            );
            prop_assert_eq!(c1, c2);
        }
    }
}
