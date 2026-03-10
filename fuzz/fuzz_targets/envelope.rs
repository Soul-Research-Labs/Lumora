//! Fuzz target: ProofEnvelope seal/open roundtrip.
//!
//! Ensures that `open(seal(payload))` always recovers the original payload,
//! and that arbitrary byte sequences never cause panics in `open()`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    // Test 1: `open()` must never panic on arbitrary input.
    let _ = lumora_primitives::envelope::open(data);

    // Test 2: roundtrip — if the payload fits, seal→open must return the
    // original payload verbatim.
    if data.len() <= lumora_primitives::envelope::MAX_PAYLOAD_SIZE {
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD);
        if let Ok(envelope) = lumora_primitives::envelope::seal(data, &mut rng) {
            let recovered = lumora_primitives::envelope::open(&envelope)
                .expect("open(seal(x)) must succeed");
            assert_eq!(recovered, data, "roundtrip mismatch");
        }
    }
});
