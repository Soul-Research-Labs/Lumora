# ADR-004: Merkle Tree Depth 32

## Status

Accepted

## Context

The shielded pool uses an incremental Merkle tree to store note commitments. The tree depth determines both capacity and circuit cost (each level adds a Poseidon hash per membership proof).

## Decision

Use a fixed depth of **32** for the incremental Merkle tree.

## Rationale

- **Capacity**: 2^32 ≈ 4.3 billion leaf slots — sufficient for any realistic deployment.
- **Sparse initialization**: Empty leaves use precomputed zero-chain hashes (`zero[i] = Poseidon(zero[i-1], zero[i-1])`), making the tree cheap to initialize without storing empty subtrees.
- **Append-only design**: The `IncrementalMerkleTree` supports `insert`, `root`, `witness`, and `verify`. Append-only semantics avoid state mutation complexities.
- **Root history**: `ROOT_HISTORY_SIZE = 256` keeps the last 256 roots so proofs generated against slightly-stale trees remain valid, tolerating delays between proof generation and submission.
- **Standard depth**: 32 is the standard choice in Zcash and similar systems, balancing capacity against circuit cost.

## Consequences

- Each Merkle membership check requires 32 Poseidon hashes + 32 conditional swaps in the circuit (×2 for two inputs = 64 hash evaluations).
- Circuit witness includes a 32-element sibling path and a 32-bit index per input.
- Deeper trees (e.g., 40) would require a larger K value and slower proving.
