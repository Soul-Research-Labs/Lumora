//! Fuzz target: Pedersen commitment operations.
//!
//! Ensures that `commit` and `commit_u64` never panic on arbitrary inputs,
//! and that `commit_u64(v, r)` is consistent with `commit(Scalar::from(v), r)`.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }

    // Extract a u64 value and 32 bytes for the randomness scalar.
    let value = u64::from_le_bytes(data[..8].try_into().unwrap());
    let mut rand_bytes = [0u8; 32];
    rand_bytes.copy_from_slice(&data[8..40]);

    // Attempt to parse randomness as a scalar — skip if invalid.
    let randomness: Option<pasta_curves::pallas::Scalar> =
        pasta_curves::pallas::Scalar::from_repr(rand_bytes).into();
    let Some(r) = randomness else { return };

    // commit_u64 must never panic.
    let c1 = lumora_primitives::pedersen::commit_u64(value, r);

    // commit with Scalar::from(value) must produce the same result.
    let c2 = lumora_primitives::pedersen::commit(
        pasta_curves::pallas::Scalar::from(value),
        r,
    );

    assert_eq!(c1, c2, "commit_u64 and commit must agree");
});
