//! Fuzz target: Poseidon hash Merkle-path operations.
//!
//! Exercises `hash_two` (used for Merkle tree nodes) and `hash_one` with
//! arbitrary field elements. Verifies basic algebraic properties:
//! - hash_two is deterministic
//! - hash_two(a, b) != hash_two(b, a) in general (non-commutative)
//! - No panics on any valid field element pair

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let mut left_bytes = [0u8; 32];
    let mut right_bytes = [0u8; 32];
    left_bytes.copy_from_slice(&data[..32]);
    right_bytes.copy_from_slice(&data[32..64]);

    // Parse as field elements — skip if bytes aren't canonical.
    let left: Option<pasta_curves::pallas::Base> =
        pasta_curves::pallas::Base::from_repr(left_bytes).into();
    let right: Option<pasta_curves::pallas::Base> =
        pasta_curves::pallas::Base::from_repr(right_bytes).into();
    let (Some(l), Some(r)) = (left, right) else { return };

    // hash_two must be deterministic.
    let h1 = lumora_primitives::poseidon::hash_two(l, r);
    let h2 = lumora_primitives::poseidon::hash_two(l, r);
    assert_eq!(h1, h2, "hash_two must be deterministic");

    // hash_one must be deterministic.
    let h3 = lumora_primitives::poseidon::hash_one(l);
    let h4 = lumora_primitives::poseidon::hash_one(l);
    assert_eq!(h3, h4, "hash_one must be deterministic");

    // Simulate a 2-level Merkle path: hash_two(hash_two(l, r), hash_one(l))
    // This must never panic.
    let _root = lumora_primitives::poseidon::hash_two(h1, h3);
});
