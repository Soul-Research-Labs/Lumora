//! Fuzz target: BitVM adapter RPC response parsing.
//!
//! Exercises `parse_remote_nullifier_roots` with arbitrary JSON values
//! to find panics in the adapter parsing layer.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON array
    let Ok(values) = serde_json::from_slice::<Vec<serde_json::Value>>(data) else {
        return;
    };

    // Exercise the parser — should never panic, only return Ok or Err
    let _ = lumora_bitvm::adapters::parse_remote_nullifier_roots(values);
});
