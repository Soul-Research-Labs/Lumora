//! Bitcoin Script fragments for single-step verification.
//!
//! Each trace step type has a corresponding Script that takes the step's
//! input commitment + witness data and asserts the output commitment matches.
//! These scripts are embedded as Taproot leaf scripts in the disprove
//! transaction.
//!
//! # Design
//!
//! Bitcoin Script natively supports SHA-256 (OP_SHA256) and basic arithmetic,
//! but not elliptic curve operations. For BitVM2, we represent verification
//! scripts as a portable `ScriptFragment` type that encodes the opcodes
//! needed. The actual Bitcoin Script compilation targets Taproot (P2TR)
//! leaf scripts.
//!
//! ## Stack protocol for disprove scripts
//!
//! The witness stack for a disprove script is:
//! ```text
//! <step_witness> <output_hash> <input_hash>
//! ```
//!
//! The script:
//! 1. Verifies `SHA256(input_hash || step_witness_data)` equals
//!    the claimed `output_hash` for an honest step.
//! 2. If the operator's claimed output doesn't match the re-computed
//!    output, the script succeeds (proving fraud).

use sha2::{Digest, Sha256};

use crate::trace::StepKind;

// ---------------------------------------------------------------------------
// Portable Script representation
// ---------------------------------------------------------------------------

/// A single opcode in our portable Script representation.
///
/// These map directly to Bitcoin Script opcodes for Taproot leaf scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Push raw bytes onto the stack.
    Push(Vec<u8>),
    /// OP_SHA256: Pop top, push SHA-256 hash.
    Sha256,
    /// OP_CAT: Concatenate top two stack items (available in Taproot).
    Cat,
    /// OP_EQUAL: Pop two items, push 1 if equal, 0 otherwise.
    Equal,
    /// OP_EQUALVERIFY: Like EQUAL but fails script if not equal.
    EqualVerify,
    /// OP_NOT: Boolean NOT.
    Not,
    /// OP_VERIFY: Fail if top is not truthy.
    Verify,
    /// OP_DUP: Duplicate top stack item.
    Dup,
    /// OP_DROP: Remove top stack item.
    Drop,
    /// OP_SWAP: Swap top two items.
    Swap,
    /// OP_ROT: Rotate top three items.
    Rot,
    /// OP_OVER: Copy second-to-top to top.
    Over,
    /// OP_SIZE: Push the byte length of the top element.
    Size,
    /// OP_TOALTSTACK: Move top to alt stack.
    ToAltStack,
    /// OP_FROMALTSTACK: Move from alt stack to main.
    FromAltStack,
    /// OP_TRUE (OP_1): Push 1.
    True,
    /// OP_FALSE (OP_0): Push empty byte vector.
    False,
}

/// A compiled script fragment for a single trace step verification.
#[derive(Debug, Clone)]
pub struct ScriptFragment {
    /// The step kind this script verifies.
    pub kind: StepKind,
    /// The opcodes comprising the script.
    pub ops: Vec<Op>,
    /// Estimated byte size when serialized to Bitcoin Script.
    pub estimated_size: usize,
}

// ---------------------------------------------------------------------------
// Script builders for each step kind
// ---------------------------------------------------------------------------

/// Build a disprove script for a given step kind.
///
/// The script verifies that `SHA256(input_hash || witness_data)` produces
/// the expected `output_hash`. If the operator's committed output_hash
/// doesn't match, the script succeeds (fraud proven).
///
/// ## Witness stack (provided by challenger):
/// ```text
/// <expected_output_hash> <witness_data> <input_hash>
/// ```
///
/// ## Script logic (pseudo):
/// ```text
/// // Stack: expected_output input_hash witness_data step_tag
/// OP_CAT         // input_hash || witness_data
/// OP_CAT         // (input_hash || witness_data) || step_tag
/// OP_SHA256      // hash = SHA256(input_hash || witness_data || step_tag)
/// OP_EQUALVERIFY // assert hash == expected_output
/// OP_TRUE        // success
/// ```
pub fn build_disprove_script(kind: StepKind) -> ScriptFragment {
    let tag = step_kind_tag(kind);

    let ops = vec![
        // Stack (bottom→top): <expected_output> <input_hash> <witness>
        Op::Push(tag.to_vec()),   // <expected> <input> <witness> <tag>
        // Cat concatenates second-from-top || top:
        Op::Cat,                  // <expected> <input> <witness||tag>
        Op::Cat,                  // <expected> <input||witness||tag>
        Op::Sha256,               // <expected> SHA256(input||witness||tag)
        Op::Equal,                // <expected == hash>
        Op::Not,                  // fraud = (expected != hash)
    ];

    let estimated_size = estimate_script_size(&ops);

    ScriptFragment {
        kind,
        ops,
        estimated_size,
    }
}

/// Build a verification script that the challenger uses to prove that
/// the operator's claimed step output is incorrect.
///
/// This is the "positive" verification: given the correct input and witness,
/// recompute the output and compare against the operator's claim.
pub fn build_step_verifier_script(kind: StepKind) -> ScriptFragment {
    let tag = step_kind_tag(kind);

    // Script: recompute output from (input_hash, witness) and verify
    // Stack: <operator_claimed_output> <correct_input_hash> <witness>
    let ops = vec![
        // Concatenate input || witness || tag and hash
        Op::Push(tag.to_vec()),   // <claimed> <input> <witness> <tag>
        Op::Cat,                  // <claimed> <input> <witness||tag>
        Op::Cat,                  // <claimed> <input||witness||tag>
        Op::Sha256,               // <claimed> <recomputed_hash>
        Op::EqualVerify,          // assert claimed == recomputed
        Op::True,                 // success: operator was honest for this step
    ];

    let estimated_size = estimate_script_size(&ops);

    ScriptFragment {
        kind,
        ops,
        estimated_size,
    }
}

// ---------------------------------------------------------------------------
// Step-kind-specific tags (domain separation in SHA-256)
// ---------------------------------------------------------------------------

/// Return a unique tag for each step kind, used as domain separation
/// in the SHA-256 hash computation.
pub fn step_kind_tag(kind: StepKind) -> &'static [u8] {
    match kind {
        StepKind::TranscriptInit => b"lumora-bitvm:transcript-init",
        StepKind::CommitmentRead => b"lumora-bitvm:commitment-read",
        StepKind::ChallengeSqueeze => b"lumora-bitvm:challenge-squeeze",
        StepKind::MsmRound => b"lumora-bitvm:msm-round",
        StepKind::IpaRound => b"lumora-bitvm:ipa-round",
        StepKind::FinalCheck => b"lumora-bitvm:final-check",
    }
}

// ---------------------------------------------------------------------------
// Native re-execution (for challenger-side validation)
// ---------------------------------------------------------------------------

/// Re-execute a trace step natively and return the expected output hash.
///
/// This is what a challenger computes locally to check if an operator's
/// trace is honest. If the recomputed output differs from the operator's
/// claimed output_hash, the step is fraudulent.
pub fn recompute_step_output(
    kind: StepKind,
    input_hash: &[u8; 32],
    witness: &[u8],
) -> [u8; 32] {
    let tag = step_kind_tag(kind);
    let mut hasher = Sha256::new();
    hasher.update(input_hash);
    hasher.update(witness);
    hasher.update(tag);
    hasher.finalize().into()
}

/// Validate a single trace step by recomputing the output and comparing.
///
/// Returns `true` if the step is honestly computed.
pub fn validate_step(
    kind: StepKind,
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
    witness: &[u8],
) -> bool {
    let recomputed = recompute_step_output(kind, input_hash, witness);
    recomputed == *output_hash
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Estimate the serialized byte size of a script fragment.
fn estimate_script_size(ops: &[Op]) -> usize {
    ops.iter()
        .map(|op| match op {
            Op::Push(data) => {
                if data.len() <= 75 {
                    1 + data.len() // OP_PUSHBYTES_N + data
                } else if data.len() <= 255 {
                    2 + data.len() // OP_PUSHDATA1 + len + data
                } else {
                    3 + data.len() // OP_PUSHDATA2 + len + data
                }
            }
            _ => 1, // Most opcodes are 1 byte
        })
        .sum()
}

/// Compute total estimated script sizes for all step kinds.
pub fn total_script_sizes() -> Vec<(StepKind, usize)> {
    let kinds = [
        StepKind::TranscriptInit,
        StepKind::CommitmentRead,
        StepKind::ChallengeSqueeze,
        StepKind::MsmRound,
        StepKind::IpaRound,
        StepKind::FinalCheck,
    ];

    kinds
        .iter()
        .map(|&k| (k, build_disprove_script(k).estimated_size))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_disprove_script_all_kinds() {
        let kinds = [
            StepKind::TranscriptInit,
            StepKind::CommitmentRead,
            StepKind::ChallengeSqueeze,
            StepKind::MsmRound,
            StepKind::IpaRound,
            StepKind::FinalCheck,
        ];

        for kind in &kinds {
            let script = build_disprove_script(*kind);
            assert_eq!(script.kind, *kind);
            assert!(!script.ops.is_empty());
            assert!(
                script.estimated_size > 0,
                "script for {:?} should have non-zero size",
                kind
            );
            // Taproot script size limit: 520 bytes per witness element,
            // but full script can be larger under Taproot rules
            assert!(
                script.estimated_size < 1000,
                "script for {:?} should be reasonably small: {} bytes",
                kind,
                script.estimated_size
            );
        }
    }

    #[test]
    fn test_build_step_verifier_script_all_kinds() {
        let kinds = [
            StepKind::TranscriptInit,
            StepKind::CommitmentRead,
            StepKind::ChallengeSqueeze,
            StepKind::MsmRound,
            StepKind::IpaRound,
            StepKind::FinalCheck,
        ];

        for kind in &kinds {
            let script = build_step_verifier_script(*kind);
            assert_eq!(script.kind, *kind);
            assert!(!script.ops.is_empty());
        }
    }

    #[test]
    fn test_step_tags_are_unique() {
        let kinds = [
            StepKind::TranscriptInit,
            StepKind::CommitmentRead,
            StepKind::ChallengeSqueeze,
            StepKind::MsmRound,
            StepKind::IpaRound,
            StepKind::FinalCheck,
        ];

        let tags: Vec<&[u8]> = kinds.iter().map(|k| step_kind_tag(*k)).collect();
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(
                    tags[i], tags[j],
                    "tags for {:?} and {:?} should differ",
                    kinds[i], kinds[j]
                );
            }
        }
    }

    #[test]
    fn test_recompute_step_output_deterministic() {
        let input = [0xABu8; 32];
        let witness = b"some witness data";

        let h1 = recompute_step_output(StepKind::MsmRound, &input, witness);
        let h2 = recompute_step_output(StepKind::MsmRound, &input, witness);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_recompute_step_differs_by_kind() {
        let input = [0xABu8; 32];
        let witness = b"same witness";

        let h1 = recompute_step_output(StepKind::MsmRound, &input, witness);
        let h2 = recompute_step_output(StepKind::IpaRound, &input, witness);
        assert_ne!(h1, h2, "different step kinds should produce different outputs");
    }

    #[test]
    fn test_validate_step_honest() {
        let input = [0x11u8; 32];
        let witness = b"honest witness";
        let kind = StepKind::CommitmentRead;

        let output = recompute_step_output(kind, &input, witness);
        assert!(validate_step(kind, &input, &output, witness));
    }

    #[test]
    fn test_validate_step_dishonest() {
        let input = [0x11u8; 32];
        let witness = b"honest witness";
        let kind = StepKind::CommitmentRead;

        let fake_output = [0xFFu8; 32];
        assert!(!validate_step(kind, &input, &fake_output, witness));
    }

    #[test]
    fn test_total_script_sizes() {
        let sizes = total_script_sizes();
        assert_eq!(sizes.len(), 6);
        for (kind, size) in &sizes {
            assert!(*size > 0, "{:?} should have positive size", kind);
        }
    }

    #[test]
    fn test_estimate_script_size_push_variants() {
        // Small push: 1 + len
        let small = estimate_script_size(&[Op::Push(vec![0u8; 10])]);
        assert_eq!(small, 11);

        // Medium push: 2 + len  (76-255 bytes)
        let medium = estimate_script_size(&[Op::Push(vec![0u8; 100])]);
        assert_eq!(medium, 102);

        // Single opcode: 1 byte
        let single = estimate_script_size(&[Op::Sha256]);
        assert_eq!(single, 1);
    }
}
