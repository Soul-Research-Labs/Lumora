//! Fuzz target: BitVM trace step validation.
//!
//! Feeds arbitrary step kind + input/output/witness data into
//! `validate_step` and `recompute_step_output` to find panics
//! or inconsistencies in the Script verification logic.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 66 {
        return; // need: 1 byte kind + 32 input + 32 output + 1+ witness
    }

    let kind_byte = data[0] % 6;
    let kind = match kind_byte {
        0 => lumora_bitvm::trace::StepKind::TranscriptInit,
        1 => lumora_bitvm::trace::StepKind::CommitmentRead,
        2 => lumora_bitvm::trace::StepKind::ChallengeSqueeze,
        3 => lumora_bitvm::trace::StepKind::MsmRound,
        4 => lumora_bitvm::trace::StepKind::IpaRound,
        _ => lumora_bitvm::trace::StepKind::FinalCheck,
    };

    let mut input_hash = [0u8; 32];
    input_hash.copy_from_slice(&data[1..33]);
    let mut output_hash = [0u8; 32];
    output_hash.copy_from_slice(&data[33..65]);
    let witness = &data[65..];

    // Must never panic
    let recomputed = lumora_bitvm::script::recompute_step_output(kind, &input_hash, witness);

    // Validate step: should return true iff recomputed == output_hash
    let valid = lumora_bitvm::script::validate_step(kind, &input_hash, &output_hash, witness);
    let expected_valid = recomputed == output_hash;
    assert_eq!(valid, expected_valid, "validate_step inconsistency");
});
