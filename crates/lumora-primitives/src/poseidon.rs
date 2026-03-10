//! Poseidon hash — a ZK-circuit-friendly hash function.
//!
//! We use Poseidon over the Pallas base field (Fp). Uses the standard
//! P128Pow5T3 spec from halo2_poseidon (width 3, rate 2, x^5 sbox,
//! R_F=8 full rounds, R_P=56 partial rounds — 128-bit security).
//!
//! The same spec is used both natively (out-of-circuit for Merkle tree / prover)
//! and in-circuit (via the Pow5Chip gadget).

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas;

/// Re-export the spec so circuit code can reference it.
pub type PoseidonSpec = P128Pow5T3;

/// Hash two field elements: `H(left, right)`.
/// Used for Merkle tree internal nodes and nullifier derivation.
pub fn hash_two(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    Hash::<_, PoseidonSpec, ConstantLength<2>, 3, 2>::init().hash([left, right])
}

/// Hash a single field element with domain separation (pad with zero).
pub fn hash_one(input: pallas::Base) -> pallas::Base {
    Hash::<_, PoseidonSpec, ConstantLength<1>, 3, 2>::init().hash([input])
}

/// Hash four field elements by chaining: `H(H(a, b), H(c, d))`.
///
/// Used for domain-separated nullifier derivation where four inputs
/// (spending_key, commitment, chain_id, app_id) are combined.
pub fn hash_four(a: pallas::Base, b: pallas::Base, c: pallas::Base, d: pallas::Base) -> pallas::Base {
    let left = hash_two(a, b);
    let right = hash_two(c, d);
    hash_two(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn poseidon_deterministic() {
        let a = pallas::Base::from(42u64);
        let b = pallas::Base::from(99u64);
        let h1 = hash_two(a, b);
        let h2 = hash_two(a, b);
        assert_eq!(h1, h2, "Poseidon must be deterministic");
    }

    #[test]
    fn poseidon_different_inputs_different_outputs() {
        let a = pallas::Base::from(1u64);
        let b = pallas::Base::from(2u64);
        let h1 = hash_two(a, b);
        let h2 = hash_two(b, a);
        assert_ne!(h1, h2, "Swapping inputs must change the hash");
    }

    #[test]
    fn poseidon_nonzero() {
        let h = hash_two(pallas::Base::zero(), pallas::Base::zero());
        // Poseidon(0,0) should produce a non-trivial output
        assert_ne!(h, pallas::Base::zero());
    }

    // -- Property-based tests --

    proptest! {
        /// hash_two is deterministic for any inputs.
        #[test]
        fn prop_hash_two_deterministic(a in 0u64..u64::MAX, b in 0u64..u64::MAX) {
            let fa = pallas::Base::from(a);
            let fb = pallas::Base::from(b);
            prop_assert_eq!(hash_two(fa, fb), hash_two(fa, fb));
        }

        /// hash_two is non-commutative (when a ≠ b).
        #[test]
        fn prop_hash_two_non_commutative(a in 1u64..u64::MAX, b in 1u64..u64::MAX) {
            prop_assume!(a != b);
            let fa = pallas::Base::from(a);
            let fb = pallas::Base::from(b);
            prop_assert_ne!(hash_two(fa, fb), hash_two(fb, fa));
        }

        /// hash_one is deterministic for any input.
        #[test]
        fn prop_hash_one_deterministic(a in 0u64..u64::MAX) {
            let fa = pallas::Base::from(a);
            prop_assert_eq!(hash_one(fa), hash_one(fa));
        }

        /// hash_two differs from hash_one on the same value (domain separation).
        #[test]
        fn prop_hash_domain_separation(a in 0u64..u64::MAX) {
            let fa = pallas::Base::from(a);
            prop_assert_ne!(hash_one(fa), hash_two(fa, pallas::Base::zero()));
        }
    }
}
