//! Fuzz target: BitVM protocol state machine.
//!
//! Exercises the ProtocolManager with arbitrary sequences of
//! register / challenge / response / slash / finalize operations
//! to find panics or invalid state transitions.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut mgr = lumora_bitvm::protocol::ProtocolManager::new(64);

    // Pre-register a deterministic assertion so operations have something to act on
    let trace_root = lumora_bitvm::trace::sha256(b"fuzz-trace");
    let proof_hash = lumora_bitvm::trace::sha256(b"fuzz-proof");
    let pi_hash = lumora_bitvm::trace::sha256(b"fuzz-pi");
    let assertion = lumora_bitvm::protocol::Assertion {
        id: lumora_bitvm::protocol::AssertionId(lumora_bitvm::trace::sha256(b"fuzz-id")),
        trace_root,
        proof_hash,
        public_inputs_hash: pi_hash,
        claimed_result: true,
        num_steps: 8,
        step_kinds: vec![lumora_bitvm::trace::StepKind::MsmRound; 8],
        assert_height: 100,
        bond_sats: 10_000_000,
    };

    let _ = mgr.register_assertion(assertion.clone());

    // Interpret remaining bytes as operations
    let mut i = 0;
    while i < data.len() {
        let op = data[i] % 5;
        i += 1;

        match op {
            0 => {
                // Register another assertion with fuzz-derived id
                if i + 32 > data.len() {
                    break;
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&data[i..i + 32]);
                i += 32;
                let new_a = lumora_bitvm::protocol::Assertion {
                    id: lumora_bitvm::protocol::AssertionId(id),
                    trace_root,
                    proof_hash,
                    public_inputs_hash: pi_hash,
                    claimed_result: true,
                    num_steps: 8,
                    step_kinds: vec![lumora_bitvm::trace::StepKind::MsmRound; 8],
                    assert_height: 100,
                    bond_sats: 10_000_000,
                };
                let _ = mgr.register_assertion(new_a);
            }
            1 => {
                // Challenge the original assertion
                let step = if i < data.len() {
                    data[i] as u32 % 16
                } else {
                    0
                };
                i += 1;
                let challenge = lumora_bitvm::protocol::Challenge {
                    assertion_id: assertion.id.clone(),
                    disputed_step: step,
                    challenger_bond_sats: 5_000_000,
                };
                let _ = mgr.process_challenge(&challenge);
            }
            2 => {
                // Respond to challenge
                let step = if i < data.len() {
                    data[i] as u32 % 16
                } else {
                    0
                };
                i += 1;
                let merkle_proof = vec![[0u8; 32]; 3];
                let response = lumora_bitvm::protocol::ChallengeResponse {
                    assertion_id: assertion.id.clone(),
                    disputed_step: step,
                    step_kind: lumora_bitvm::trace::StepKind::TranscriptInit,
                    input_hash: [0u8; 32],
                    output_hash: [0u8; 32],
                    witness: vec![0xAB; 16],
                    merkle_proof,
                    response_height: 200,
                };
                let _ = mgr.process_response(&response);
            }
            3 => {
                // Slash
                let _ = mgr.slash(&assertion.id);
            }
            4 => {
                // Finalize expired
                let height = if i + 3 < data.len() {
                    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
                } else {
                    1000
                };
                i += 4;
                let _ = mgr.finalize_expired(height as u64);
            }
            _ => {}
        }
    }

    // Must never panic — just verify we can read state
    let _ = mgr.get_state(&assertion.id);
    let _ = mgr.active_count();
});
