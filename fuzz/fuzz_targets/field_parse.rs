//! Fuzz target: field element hex parsing.
//!
//! Exercises the code path that converts arbitrary strings to
//! `pallas::Base` field elements. Must never panic — invalid input
//! must always produce an `Err`.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Treat the input as a UTF-8 string (skip if invalid).
    let Ok(hex_str) = std::str::from_utf8(data) else {
        return;
    };

    // Attempt hex decode → field element parse.
    // This mirrors the RPC handler's parse_field() logic.
    let Ok(bytes) = hex::decode(hex_str) else {
        return; // invalid hex — fine
    };

    if bytes.len() != 32 {
        return; // wrong length — fine
    }

    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);

    // from_repr must never panic, even on non-canonical encodings.
    use ff::PrimeField;
    let _: Option<pasta_curves::pallas::Base> =
        pasta_curves::pallas::Base::from_repr(repr).into();
});
