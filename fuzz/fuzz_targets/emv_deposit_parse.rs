//! Fuzz target: EMV deposit and withdrawal JSON parsing.
//!
//! Exercises `RpcEmvDeposit` and `RpcEmvWithdrawalResult` deserialization with
//! arbitrary byte slices to find panics in serde parsing.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse as EMV deposit
    let _ = serde_json::from_slice::<lumora_bitvm::adapters::emv::RpcEmvDeposit>(data);

    // Attempt to parse as EMV withdrawal result
    let _ = serde_json::from_slice::<lumora_bitvm::adapters::emv::RpcEmvWithdrawalResult>(data);

    // Attempt to parse as EMV payment status
    let _ = serde_json::from_slice::<lumora_bitvm::adapters::emv::RpcEmvPaymentStatus>(data);

    // Attempt to parse as EmvConfig
    let _ = serde_json::from_slice::<lumora_bitvm::adapters::emv::EmvConfig>(data);
});
