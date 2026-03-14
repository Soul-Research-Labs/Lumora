//! Fuzz target: BitVM Merkle proof verification.
//!
//! Builds random trace leaves, computes the Merkle root,
//! generates proofs, and verifies them. Also tests that
//! corrupted proofs are rejected.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least: 1 byte num_leaves + some leaf data
    if data.len() < 33 {
        return;
    }

    // Derive number of leaves (2..=16 to keep it fast)
    let num_leaves = ((data[0] as usize) % 15) + 2;
    let needed = 1 + num_leaves * 32;
    if data.len() < needed {
        return;
    }

    let mut leaves = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&data[1 + i * 32..1 + (i + 1) * 32]);
        leaves.push(leaf);
    }

    let root = lumora_bitvm::trace::compute_trace_merkle_root(&leaves);

    // Verify proof for each leaf
    for i in 0..num_leaves {
        let proof = lumora_bitvm::trace::merkle_proof_for_step(&leaves, i);
        assert!(
            lumora_bitvm::trace::verify_merkle_proof(leaves[i], i, &proof, root),
            "valid proof must verify"
        );

        // Corrupted leaf should fail
        let mut bad_leaf = leaves[i];
        bad_leaf[0] ^= 0xFF;
        assert!(
            !lumora_bitvm::trace::verify_merkle_proof(bad_leaf, i, &proof, root),
            "corrupted leaf must not verify"
        );
    }
});
