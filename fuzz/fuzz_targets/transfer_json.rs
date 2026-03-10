//! Fuzz target: TransferRequest / WithdrawRequest JSON deserialization.
//!
//! Ensures that arbitrary JSON never panics when deserialized into
//! the RPC request types.

#![no_main]
use libfuzzer_sys::fuzz_target;

/// Mirrors the RPC `TransferReq` shape for deserialization testing.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct TransferReq {
    proof_bytes: Option<String>,
    merkle_root: Option<String>,
    nullifiers: Option<Vec<String>>,
    output_commitments: Option<Vec<String>>,
    fee: Option<u64>,
    domain_chain_id: Option<u64>,
    domain_app_id: Option<u64>,
}

/// Mirrors the RPC `WithdrawReq` shape for deserialization testing.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct WithdrawReq {
    proof_bytes: Option<String>,
    merkle_root: Option<String>,
    nullifiers: Option<Vec<String>>,
    output_commitments: Option<Vec<String>>,
    amount: Option<u64>,
    recipient: Option<String>,
    fee: Option<u64>,
    domain_chain_id: Option<u64>,
    domain_app_id: Option<u64>,
}

fuzz_target!(|data: &[u8]| {
    // Deserialization of arbitrary bytes must never panic.
    let _ = serde_json::from_slice::<TransferReq>(data);
    let _ = serde_json::from_slice::<WithdrawReq>(data);

    // Also test with serde_json::Value to catch any deep-nesting panics.
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});
